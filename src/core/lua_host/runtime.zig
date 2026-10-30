//! Lua hooks in a build that embeds Lua: loads trusted extensions when a
//! session starts and runs `fx extensions` actions.

const std = @import("std");
const engine = @import("../../lua/engine.zig");
const hooks = @import("../hooks/hooks.zig");
const settings_store = @import("../config/settings_store.zig");
const io_mod = @import("../shared/io.zig");
const debug_trace = @import("../shared/debug_trace.zig");
const adapter = @import("adapter.zig");
const catalog_mod = @import("catalog.zig");
const listing = @import("listing.zig");

const Allocator = std.mem.Allocator;

pub const RegisterOptions = struct {
    /// The profile home; null reads `HOME`.
    home: ?[]const u8 = null,
};

/// What `register` found, for the session-start notice. Names live as long
/// as the `Hooks` that returned them.
pub const Summary = struct {
    loaded: usize = 0,
    needs_review: []const []const u8 = &.{},
    load_failures: []const LoadFailure = &.{},
};

pub const LoadFailure = struct {
    name: []const u8,
    message: []const u8,
};

pub const Hooks = struct {
    gpa: Allocator = undefined,
    arena: ?std.heap.ArenaAllocator = null,
    loaded: std.ArrayList(*adapter.Loaded) = .empty,

    /// Loads every trusted extension in `~/.fx/extensions/` and registers
    /// its handlers on `runtime`, which must not be frozen yet. With no
    /// extension folder this costs one failed directory open.
    pub fn register(
        self: *Hooks,
        gpa: Allocator,
        runtime: *hooks.Runtime,
        options: RegisterOptions,
    ) !Summary {
        std.debug.assert(self.arena == null);
        self.gpa = gpa;
        const home = options.home orelse io_mod.homeDir() orelse return .{};
        var catalog = catalog_mod.Catalog.load(gpa, home) catch |err| {
            debug_trace.logf("lua_hooks", "event=discovery_failed error={s}", .{@errorName(err)});
            return .{};
        };
        defer catalog.deinit();
        if (catalog.extensions.len == 0) return .{};

        self.arena = .init(gpa);
        const a = self.arena.?.allocator();
        const owned_home = try a.dupe(u8, home);
        var needs_review: std.ArrayList([]const u8) = .empty;
        var load_failures: std.ArrayList(LoadFailure) = .empty;
        for (catalog.extensions) |extension| {
            if (extension.state == .needs_review) try needs_review.append(a, try a.dupe(u8, extension.name));
            if (!extension.state.runs()) continue;
            const manifest = extension.manifest.?;
            var diagnostic: engine.Diagnostic = .{};
            const lua = engine.Extension.load(gpa, io_mod.getIo(), .{
                .name = extension.name,
                .files = extension.files,
                .main = manifest.main,
                .events = manifest.events,
                .kv = manifest.kv,
                .limits = manifest.limits,
                .log = .{ .write = writeLog },
            }, &diagnostic) catch |err| {
                const message = if (err == error.OutOfMemory) "not enough memory" else diagnostic.message();
                debug_trace.logf("lua_hooks", "event=load_failed extension={s} error={s}", .{ extension.name, message });
                catalog_mod.recordFailure(gpa, home, extension.name, extension.sha256, message);
                try load_failures.append(a, .{ .name = try a.dupe(u8, extension.name), .message = try a.dupe(u8, message) });
                continue;
            };
            const loaded = gpa.create(adapter.Loaded) catch |err| {
                lua.deinit();
                return err;
            };
            loaded.* = .{
                .gpa = gpa,
                .home = owned_home,
                .name = try a.dupe(u8, extension.name),
                .sha256 = try a.dupe(u8, extension.sha256),
                .scopes = manifest.scopes,
                .lua = lua,
                .hooks = .initFill(.{}),
            };
            self.loaded.append(gpa, loaded) catch |err| {
                loaded.deinit();
                gpa.destroy(loaded);
                return err;
            };
            try loaded.register(runtime);
        }
        debug_trace.logf("lua_hooks", "event=registered loaded={d} needs_review={d} load_failures={d}", .{
            self.loaded.items.len,
            needs_review.items.len,
            load_failures.items.len,
        });
        return .{
            .loaded = self.loaded.items.len,
            .needs_review = needs_review.items,
            .load_failures = load_failures.items,
        };
    }

    /// Frees the extensions. The hook runtime must no longer dispatch to
    /// them.
    pub fn deinit(self: *Hooks) void {
        for (self.loaded.items) |loaded| {
            loaded.deinit();
            self.gpa.destroy(loaded);
        }
        if (self.loaded.capacity > 0) self.loaded.deinit(self.gpa);
        if (self.arena) |*arena| arena.deinit();
        self.* = .{};
    }
};

fn writeLog(_: ?*anyopaque, extension: []const u8, level: engine.LogLevel, message: []const u8) void {
    debug_trace.logf("lua_hooks", "event=log extension={s} level={s} message={s}", .{ extension, @tagName(level), message });
}

/// Runs `action` against `~/.fx/extensions/` and the profile's trust
/// records, and returns the resulting listing, which the caller owns.
pub fn execute(gpa: Allocator, action: listing.Action, home_override: ?[]const u8) !listing.Listing {
    const home = home_override orelse io_mod.homeDir() orelse return error.HomeNotSet;
    if (action.target()) |name| {
        var before = try catalog_mod.Catalog.load(gpa, home);
        defer before.deinit();
        try apply(gpa, home, &before, action, name);
    }
    var catalog = try catalog_mod.Catalog.load(gpa, home);
    errdefer catalog.deinit();
    return catalog.intoListing(action);
}

fn apply(gpa: Allocator, home: []const u8, catalog: *catalog_mod.Catalog, action: listing.Action, name: []const u8) !void {
    const extension = catalog.find(name) orelse return error.UnknownExtension;
    const mutation: settings_store.ExtensionMutation = switch (action) {
        .list => unreachable,
        .trust => blk: {
            if (extension.state == .invalid) return error.ExtensionInvalid;
            break :blk .{ .name = name, .action = .{ .trust = .{
                .sha256 = extension.sha256,
                .files = extension.hashes,
            } } };
        },
        .disable => .{ .name = name, .action = .{ .set_disabled = true } },
        .enable => .{ .name = name, .action = .{ .set_disabled = false } },
    };
    var store = try settings_store.Store.initFromHome(gpa, home, .writable);
    defer store.deinit(gpa);
    var outcome = try store.applyExtensionMutation(gpa, mutation);
    outcome.deinit(gpa);
    if (action == .trust) catalog_mod.clearFailures(gpa, home, name);
}

const TestHome = struct {
    tmp: std.testing.TmpDir,
    home: []u8,

    fn init() !TestHome {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        try tmp.dir.createDirPath(std.testing.io, ".fx/extensions/policy");
        try tmp.dir.writeFile(std.testing.io, .{
            .sub_path = ".fx/extensions/policy/manifest.lua",
            .data = "return { name = \"policy\", events = { \"pre_tool_use\", \"stop\" }, scopes = { \"ask\" } }",
        });
        try tmp.dir.writeFile(std.testing.io, .{
            .sub_path = ".fx/extensions/policy/main.lua",
            .data =
            \\agent.on("pre_tool_use", function(ev)
            \\  if ev.tool_name == "shell" and ev.arguments.command:find("rm %-rf") then
            \\    return { block = "no recursive deletes" }
            \\  end
            \\  if ev.tool_name == "read_file" then
            \\    return { arguments = { path = "safe.txt" } }
            \\  end
            \\  if ev.tool_name == "explode" then error("kaboom") end
            \\end)
            \\agent.on("stop", function(ev)
            \\  if ev.can_continue then return { continue = "check the tests" } end
            \\end)
            ,
        });
        const home = try io_mod.dirRealpathAlloc(std.testing.allocator, tmp.dir, ".");
        return .{ .tmp = tmp, .home = home };
    }

    fn deinit(self: *TestHome) void {
        std.testing.allocator.free(self.home);
        self.tmp.cleanup();
    }
};

fn testPreToolUse(view: hooks.RuntimeView, scope: hooks.ScopeKind, tool: []const u8, arguments: []const u8) !hooks.PreToolUseOutcome {
    return view.runPreToolUse(std.testing.allocator, .{
        .invocation = .{ .scope = .{ .kind = scope, .workspace_root = "/Users/example/project" }, .turn_id = 1 },
        .step_index = 0,
        .call_id = "call_1",
        .tool_name = tool,
        .arguments_json = arguments,
    });
}

test "only trusted extensions register, and their hooks run through fx's runtime" {
    var home = try TestHome.init();
    defer home.deinit();

    {
        var runtime = hooks.Runtime.init(std.testing.allocator);
        defer runtime.deinit();
        var lua_hooks: Hooks = .{};
        defer lua_hooks.deinit();
        const summary = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home.home });
        try std.testing.expectEqual(@as(usize, 0), summary.loaded);
        try std.testing.expectEqual(@as(usize, 1), summary.needs_review.len);
        try std.testing.expect(!runtime.freeze().hasPreToolUse());
    }

    var trusted = try execute(std.testing.allocator, .{ .trust = "policy" }, home.home);
    try std.testing.expectEqual(listing.State.trusted, trusted.find("policy").?.state);
    trusted.deinit();

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    const summary = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home.home });
    try std.testing.expectEqual(@as(usize, 1), summary.loaded);
    const view = runtime.freeze();
    try std.testing.expectEqualStrings("lua.policy.pre_tool_use", view.pre_tool_use_handlers[0].hook.name);

    var blocked = try testPreToolUse(view, .ask, "shell", "{\"action\":\"run\",\"command\":\"rm -rf build\"}");
    defer blocked.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("no recursive deletes", blocked.blocked);

    var rewritten = try testPreToolUse(view, .ask, "read_file", "{\"path\":\"secret.txt\"}");
    defer rewritten.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("{\"path\":\"safe.txt\"}", rewritten.rewritten);

    var failed = try testPreToolUse(view, .ask, "explode", "{}");
    defer failed.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.find(u8, failed.blocked, "Lua hook lua.policy.pre_tool_use failed") != null);
    try std.testing.expect(std.mem.find(u8, failed.blocked, "kaboom") != null);
    try std.testing.expect(std.mem.find(u8, failed.blocked, "fx extensions disable policy") != null);

    // The manifest lists only the ask scope.
    var other_scope = try testPreToolUse(view, .interactive, "shell", "{\"action\":\"run\",\"command\":\"rm -rf build\"}");
    defer other_scope.deinit(std.testing.allocator);
    try std.testing.expect(other_scope == .unchanged);

    var stop = view.runStop(std.testing.allocator, .{
        .invocation = .{ .scope = .{ .kind = .ask, .workspace_root = "/Users/example/project" } },
        .step_index = 0,
        .assistant_text = "done",
        .provider_disposition = .completed,
        .can_continue = true,
    });
    defer stop.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("check the tests", stop.continue_once);

    var after = try execute(std.testing.allocator, .list, home.home);
    defer after.deinit();
    const entry = after.find("policy").?;
    try std.testing.expectEqual(listing.State.failing, entry.state);
    try std.testing.expectEqual(@as(u64, 1), entry.failures);
}

test "disable and enable switch a trusted extension without forgetting its review" {
    var home = try TestHome.init();
    defer home.deinit();
    var result = try execute(std.testing.allocator, .{ .disable = "policy" }, home.home);
    try std.testing.expectEqual(listing.State.needs_review, result.find("policy").?.state);
    result.deinit();
    result = try execute(std.testing.allocator, .{ .trust = "policy" }, home.home);
    try std.testing.expectEqual(listing.State.trusted, result.find("policy").?.state);
    result.deinit();
    result = try execute(std.testing.allocator, .{ .disable = "policy" }, home.home);
    try std.testing.expectEqual(listing.State.disabled, result.find("policy").?.state);
    result.deinit();
    result = try execute(std.testing.allocator, .{ .enable = "policy" }, home.home);
    try std.testing.expectEqual(listing.State.trusted, result.find("policy").?.state);
    result.deinit();
    try std.testing.expectError(error.UnknownExtension, execute(std.testing.allocator, .{ .trust = "absent" }, home.home));
}

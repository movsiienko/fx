//! Lua hooks in a build that embeds Lua: loads trusted extensions when a
//! session starts and runs `fx extensions` actions.

const std = @import("std");
const engine = @import("../../lua/engine.zig");
const hooks = @import("../hooks/hooks.zig");
const settings_store = @import("../config/settings_store.zig");
const io_mod = @import("../shared/io.zig");
const debug_trace = @import("../shared/debug_trace.zig");
const profile_paths = @import("../shared/profile_paths.zig");
const text_utils = @import("../shared/text_utils.zig");
const adapter = @import("adapter.zig");
const catalog_mod = @import("catalog.zig");
const listing = @import("listing.zig");

const Allocator = std.mem.Allocator;

const RegisterOptions = struct {
    /// The profile home; null reads `HOME`.
    home: ?[]const u8 = null,
};

/// What `register` found, for the session-start notice. Names live as long
/// as the `Hooks` that returned them.
pub const Summary = struct {
    loaded: usize = 0,
    needs_review: []const []const u8 = &.{},
    load_failures: []const LoadFailure = &.{},
    /// Trusted extensions that are now invalid, so they stopped running.
    /// Each message is the catalog's problem.
    stopped_invalid: []const LoadFailure = &.{},
    /// Set when `~/.fx/extensions/` exists but cannot be read, so no
    /// extension loaded.
    unreadable_folder: ?UnreadableFolder = null,
};

const LoadFailure = struct {
    name: []const u8,
    message: []const u8,
};

const UnreadableFolder = struct {
    path: []const u8,
    /// The error name, such as `SymLinkLoop`.
    reason: []const u8,
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
        var catalog = catalog_mod.Catalog.load(gpa, home, .session) catch |err| {
            debug_trace.logf("lua_hooks", "event=discovery_failed error={s}", .{@errorName(err)});
            // Nothing runs, so say so: a policy extension that silently stops
            // enforcing is worse than a notice.
            self.arena = .init(gpa);
            const a = self.arena.?.allocator();
            return .{ .unreadable_folder = .{
                .path = try std.Io.Dir.path.join(a, &.{ try profile_paths.rootDir(a, home), catalog_mod.extensions_dir_name }),
                .reason = @errorName(err),
            } };
        };
        defer catalog.deinit();
        if (catalog.extensions.len == 0) return .{};

        self.arena = .init(gpa);
        const a = self.arena.?.allocator();
        const owned_home = try a.dupe(u8, home);
        var needs_review: std.ArrayList([]const u8) = .empty;
        var load_failures: std.ArrayList(LoadFailure) = .empty;
        var stopped_invalid: std.ArrayList(LoadFailure) = .empty;
        for (catalog.extensions) |extension| {
            if (extension.state == .needs_review) try needs_review.append(a, try a.dupe(u8, extension.name));
            if (extension.stopped_by_problem) try stopped_invalid.append(a, .{
                .name = try a.dupe(u8, extension.name),
                .message = try a.dupe(u8, extension.problem.?),
            });
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
        debug_trace.logf("lua_hooks", "event=registered loaded={d} needs_review={d} load_failures={d} stopped_invalid={d}", .{
            self.loaded.items.len,
            needs_review.items.len,
            load_failures.items.len,
            stopped_invalid.items.len,
        });
        return .{
            .loaded = self.loaded.items.len,
            .needs_review = needs_review.items,
            .load_failures = load_failures.items,
            .stopped_invalid = stopped_invalid.items,
        };
    }

    /// Writes the failures each extension has counted but not yet
    /// recorded. For an exit that skips `deinit`: it runs no Lua, frees
    /// nothing, and hooks may still run.
    pub fn flushFailures(self: *Hooks) void {
        for (self.loaded.items) |loaded| loaded.flushFailures();
    }

    /// Frees the extensions, after writing their unrecorded failures. The
    /// hook runtime must no longer dispatch to them.
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
    var catalog = try catalog_mod.Catalog.load(gpa, home, .full);
    errdefer catalog.deinit();
    if (action.target()) |name| {
        try apply(gpa, home, &catalog, action, name);
        // The listing shows the files the action applied to.
        try catalog.refresh(home, name);
    }
    return catalog.intoListing(action);
}

fn apply(gpa: Allocator, home: []const u8, catalog: *catalog_mod.Catalog, action: listing.Action, name: []const u8) !void {
    const extension = catalog.find(name) orelse return error.UnknownExtension;
    const mutation: settings_store.ExtensionMutation = switch (action) {
        .list => unreachable,
        .trust => |trust| blk: {
            if (extension.state == .invalid) return error.ExtensionInvalid;
            // Pins trust to the files the user reviewed, not whatever is
            // on disk by the time they run trust.
            if (trust.sha256) |reviewed| {
                if (!std.mem.startsWith(u8, extension.sha256, reviewed)) return error.ExtensionChanged;
            }
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
    if (action == .trust) catalog_mod.clearFailures(gpa, home, name) catch |err| {
        debug_trace.logf("lua_hooks", "event=clear_failures_failed extension={s} error={s}", .{ name, @errorName(err) });
        return error.FailuresNotCleared;
    };
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
            \\  if ev.tool_name == "clipboard" then error("\27]52;c;aGk=\7") end
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

    var trusted = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, home.home);
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

test "a Lua error's terminal sequences do not reach the block reason" {
    var home = try TestHome.init();
    defer home.deinit();
    var trusted = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, home.home);
    trusted.deinit();

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    _ = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home.home });
    const view = runtime.freeze();

    var failed = try testPreToolUse(view, .ask, "clipboard", "{}");
    defer failed.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.findAny(u8, failed.blocked, "\x1b\x07") == null);
    try std.testing.expect(std.mem.find(u8, failed.blocked, "policy/main.lua:9: \\x1b]52;c;aGk=\\x07") != null);
    try std.testing.expect(failed.blocked.len <= hooks.Limits.reason_bytes);
}

test "tool arguments that are not a JSON object skip the Lua hook without counting a failure" {
    var home = try TestHome.init();
    defer home.deinit();
    var trusted = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, home.home);
    trusted.deinit();

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    _ = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home.home });
    const view = runtime.freeze();

    // The policy indexes `ev.arguments.command`, which would raise on nil.
    var malformed = try testPreToolUse(view, .ask, "shell", "{\"command\":");
    defer malformed.deinit(std.testing.allocator);
    try std.testing.expectEqual(.unchanged, std.meta.activeTag(malformed));
    var array = try testPreToolUse(view, .ask, "shell", "[\"rm -rf build\"]");
    defer array.deinit(std.testing.allocator);
    try std.testing.expectEqual(.unchanged, std.meta.activeTag(array));

    var after = try execute(std.testing.allocator, .list, home.home);
    defer after.deinit();
    const entry = after.find("policy").?;
    try std.testing.expectEqual(listing.State.trusted, entry.state);
    try std.testing.expectEqual(@as(u64, 0), entry.failures);
}

test "input fx cannot pass to a Lua hook blocks the tool call without counting a failure" {
    var home = try TestHome.init();
    defer home.deinit();
    var trusted = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, home.home);
    trusted.deinit();

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    _ = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home.home });
    const view = runtime.freeze();

    var refused = try testPreToolUse(view, .ask, "shell\xff", "{\"command\":\"ls\"}");
    defer refused.deinit(std.testing.allocator);
    try std.testing.expectStringStartsWith(refused.blocked, "fx could not pass this tool call to Lua hook lua.policy.pre_tool_use");
    try std.testing.expect(std.mem.find(u8, refused.blocked, "fx extensions disable") == null);

    // Other hooks fail open.
    var stop = view.runStop(std.testing.allocator, .{
        .invocation = .{ .scope = .{ .kind = .ask, .workspace_root = "/Users/example/project" } },
        .step_index = 0,
        .assistant_text = "done\xff",
        .provider_disposition = .completed,
        .can_continue = true,
    });
    defer stop.deinit(std.testing.allocator);
    try std.testing.expect(stop == .allow);

    var before_failure = try execute(std.testing.allocator, .list, home.home);
    const entry = before_failure.find("policy").?;
    try std.testing.expectEqual(listing.State.trusted, entry.state);
    try std.testing.expectEqual(@as(u64, 0), entry.failures);
    before_failure.deinit();

    // A hook that errors is still the extension's failure.
    var failed = try testPreToolUse(view, .ask, "explode", "{}");
    defer failed.deinit(std.testing.allocator);
    try std.testing.expectStringStartsWith(failed.blocked, "Lua hook lua.policy.pre_tool_use failed, so fx blocked this tool call: policy/main.lua:8: kaboom.");
    try std.testing.expect(std.mem.find(u8, failed.blocked, "fx extensions disable policy") != null);
    var after = try execute(std.testing.allocator, .list, home.home);
    defer after.deinit();
    try std.testing.expectEqual(listing.State.failing, after.find("policy").?.state);
    try std.testing.expectEqual(@as(u64, 1), after.find("policy").?.failures);
}

test "arguments nested too deeply for Lua block the tool call without counting a failure" {
    var home = try TestHome.init();
    defer home.deinit();
    var trusted = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, home.home);
    trusted.deinit();

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    _ = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home.home });
    const view = runtime.freeze();

    const deep = "{\"command\":\"ls\",\"nested\":" ++ text_utils.repeat("[", 100) ++ text_utils.repeat("]", 100) ++ "}";
    var refused = try testPreToolUse(view, .ask, "shell", deep);
    defer refused.deinit(std.testing.allocator);
    try std.testing.expectStringStartsWith(refused.blocked, "fx could not pass this tool call to Lua hook lua.policy.pre_tool_use");
    try std.testing.expect(std.mem.find(u8, refused.blocked, "nested") != null);

    var after = try execute(std.testing.allocator, .list, home.home);
    defer after.deinit();
    try std.testing.expectEqual(listing.State.trusted, after.find("policy").?.state);
    try std.testing.expectEqual(@as(u64, 0), after.find("policy").?.failures);
}

test "disable and enable switch a trusted extension without forgetting its review" {
    var home = try TestHome.init();
    defer home.deinit();
    var result = try execute(std.testing.allocator, .{ .disable = "policy" }, home.home);
    try std.testing.expectEqual(listing.State.needs_review, result.find("policy").?.state);
    result.deinit();
    result = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, home.home);
    try std.testing.expectEqual(listing.State.trusted, result.find("policy").?.state);
    result.deinit();
    result = try execute(std.testing.allocator, .{ .disable = "policy" }, home.home);
    try std.testing.expectEqual(listing.State.disabled, result.find("policy").?.state);
    result.deinit();
    result = try execute(std.testing.allocator, .{ .enable = "policy" }, home.home);
    try std.testing.expectEqual(listing.State.trusted, result.find("policy").?.state);
    result.deinit();
    try std.testing.expectError(error.UnknownExtension, execute(std.testing.allocator, .{ .trust = .{ .name = "absent" } }, home.home));
}

test "trust with a digest refuses files that changed since they were listed" {
    var home = try TestHome.init();
    defer home.deinit();
    var reviewed = try execute(std.testing.allocator, .list, home.home);
    const prefix = try std.testing.allocator.dupe(u8, reviewed.find("policy").?.sha256[0..12]);
    defer std.testing.allocator.free(prefix);
    reviewed.deinit();

    try home.tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".fx/extensions/policy/main.lua", .data = "-- weakened\n" });
    try std.testing.expectError(error.ExtensionChanged, execute(std.testing.allocator, .{ .trust = .{ .name = "policy", .sha256 = prefix } }, home.home));
    var after = try execute(std.testing.allocator, .list, home.home);
    defer after.deinit();
    try std.testing.expectEqual(listing.State.needs_review, after.find("policy").?.state);

    var current = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy", .sha256 = after.find("policy").?.sha256[0..12] } }, home.home);
    defer current.deinit();
    try std.testing.expectEqual(listing.State.trusted, current.find("policy").?.state);
}

test "an untrusted extension needs review at session start without fx reading its files" {
    var home = try TestHome.init();
    defer home.deinit();
    var trusted = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, home.home);
    trusted.deinit();
    try home.tmp.dir.createDirPath(std.testing.io, ".fx/extensions/fresh");
    try home.tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".fx/extensions/fresh/manifest.lua",
        .data = "return { name = \"fresh\", events = { \"stop\" } }",
    });
    // Reading a link to itself fails for root too.
    try home.tmp.dir.symLink(std.testing.io, "main.lua", ".fx/extensions/fresh/main.lua", .{});

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    const summary = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home.home });
    try std.testing.expectEqual(@as(usize, 1), summary.loaded);
    try std.testing.expectEqual(@as(usize, 1), summary.needs_review.len);
    try std.testing.expectEqualStrings("fresh", summary.needs_review[0]);
    try std.testing.expectEqual(@as(usize, 0), summary.load_failures.len);
    try std.testing.expectEqual(@as(usize, 0), summary.stopped_invalid.len);
}

test "a disabled extension gets nothing at session start, even after its files change" {
    var home = try TestHome.init();
    defer home.deinit();
    var result = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, home.home);
    result.deinit();
    result = try execute(std.testing.allocator, .{ .disable = "policy" }, home.home);
    result.deinit();
    // Only hashing the files would show this change.
    try home.tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".fx/extensions/policy/main.lua", .data = "-- changed\n" });

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    const summary = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home.home });
    try std.testing.expectEqual(@as(usize, 0), summary.loaded);
    try std.testing.expectEqual(@as(usize, 0), summary.needs_review.len);
    try std.testing.expectEqual(@as(usize, 0), summary.load_failures.len);
    try std.testing.expectEqual(@as(usize, 0), summary.stopped_invalid.len);
}

test "an extensions folder that cannot be read is reported at session start" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".fx");
    // A link to itself fails to open for root too.
    try tmp.dir.symLink(std.testing.io, "extensions", ".fx/extensions", .{ .is_directory = true });
    const home = try io_mod.dirRealpathAlloc(std.testing.allocator, tmp.dir, ".");
    defer std.testing.allocator.free(home);

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    const summary = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home });
    try std.testing.expectEqual(@as(usize, 0), summary.loaded);
    try std.testing.expectEqual(@as(usize, 0), summary.load_failures.len);
    const directory = try std.testing.allocator.print("{s}/.fx/extensions", .{home});
    defer std.testing.allocator.free(directory);
    try std.testing.expectEqualStrings(directory, summary.unreadable_folder.?.path);
    try std.testing.expectEqualStrings("SymLinkLoop", summary.unreadable_folder.?.reason);
}

test "registration reads only the home it is given, not HOME" {
    var given = try TestHome.init();
    defer given.deinit();
    var trusted = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, given.home);
    trusted.deinit();

    // HOME names another profile whose trusted extension fails to load,
    // which would leave a failure record there.
    var other = std.testing.tmpDir(.{});
    defer other.cleanup();
    try other.dir.createDirPath(std.testing.io, ".fx/extensions/broken");
    try other.dir.writeFile(std.testing.io, .{
        .sub_path = ".fx/extensions/broken/manifest.lua",
        .data = "return { name = \"broken\", events = { \"stop\" } }",
    });
    try other.dir.writeFile(std.testing.io, .{ .sub_path = ".fx/extensions/broken/main.lua", .data = "error(\"loaded from HOME\")" });
    const other_home = try io_mod.dirRealpathAlloc(std.testing.allocator, other.dir, ".");
    defer std.testing.allocator.free(other_home);
    var other_trusted = try execute(std.testing.allocator, .{ .trust = .{ .name = "broken" } }, other_home);
    other_trusted.deinit();
    var environ = std.process.Environ.Map.init(std.testing.allocator);
    defer environ.deinit();
    try environ.put("HOME", other_home);
    io_mod.setEnvironMap(&environ);
    defer io_mod.resetEnvironForTest();

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    const summary = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = given.home });
    try std.testing.expectEqual(@as(usize, 1), summary.loaded);
    try std.testing.expectEqual(@as(usize, 0), summary.load_failures.len);
    const view = runtime.freeze();
    try std.testing.expectEqual(@as(usize, 1), view.stop_handlers.len);
    try std.testing.expectEqualStrings("lua.policy.stop", view.stop_handlers[0].hook.name);
    try std.testing.expectError(error.FileNotFound, other.dir.access(std.testing.io, ".fx/extension-failures", .{}));
}

test "failures from concurrent hook calls are all counted and outlive the session" {
    var home = try TestHome.init();
    defer home.deinit();
    var trusted = try execute(std.testing.allocator, .{ .trust = .{ .name = "policy" } }, home.home);
    trusted.deinit();

    var runtime = hooks.Runtime.init(std.testing.allocator);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    _ = try lua_hooks.register(std.testing.allocator, &runtime, .{ .home = home.home });
    const view = runtime.freeze();

    const Caller = struct {
        fn run(caller_view: hooks.RuntimeView, unblocked: *std.atomic.Value(usize)) void {
            for (0..25) |_| {
                var outcome = testPreToolUse(caller_view, .ask, "explode", "{}") catch {
                    _ = unblocked.fetchAdd(1, .monotonic);
                    continue;
                };
                defer outcome.deinit(std.testing.allocator);
                if (outcome != .blocked) _ = unblocked.fetchAdd(1, .monotonic);
            }
        }
    };
    var unblocked: std.atomic.Value(usize) = .init(0);
    var threads: [8]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Caller.run, .{ view, &unblocked });
    for (threads) |thread| thread.join();
    lua_hooks.deinit();
    try std.testing.expectEqual(@as(usize, 0), unblocked.load(.monotonic));

    var after = try execute(std.testing.allocator, .list, home.home);
    defer after.deinit();
    const entry = after.find("policy").?;
    try std.testing.expectEqual(listing.State.failing, entry.state);
    try std.testing.expectEqual(@as(u64, 200), entry.failures);
    try std.testing.expectEqualStrings("policy/main.lua:8: kaboom", entry.last_error.?);
}

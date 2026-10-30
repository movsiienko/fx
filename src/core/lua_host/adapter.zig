//! Wraps each Lua handler as an ordinary fx hook handler named
//! `lua.<extension>.<event>`, so fx's hook runtime orders, limits, and
//! dispatches it like its built-in handlers.
//!
//! `PreToolUse` fails closed: when a Lua hook errors, runs out of budget, or
//! returns something fx does not understand, the tool call is blocked with a
//! reason that names the hook and how to turn it off. The other hooks fail
//! open. A rewrite changes only arguments, and the rewritten call still goes
//! through fx's validation and permissions, so a hook can narrow what the
//! agent does but never approve anything.

const std = @import("std");
const engine = @import("../../lua/engine.zig");
const hooks = @import("../hooks/hooks.zig");
const io_mod = @import("../shared/io.zig");
const debug_trace = @import("../shared/debug_trace.zig");
const catalog = @import("catalog.zig");

const Allocator = std.mem.Allocator;

/// One trusted extension with a running Lua state.
pub const Loaded = struct {
    gpa: Allocator,
    home: []const u8,
    name: []const u8,
    sha256: []const u8,
    scopes: engine.ScopeSet,
    lua: *engine.Extension,
    hooks: std.EnumArray(engine.Event, LuaHook),

    pub fn deinit(self: *Loaded) void {
        for (&self.hooks.values) |*hook| hook.results.deinit(self.gpa);
        self.lua.deinit();
    }

    pub fn register(self: *Loaded, runtime: *hooks.Runtime) !void {
        inline for (@typeInfo(engine.Event).@"enum".field_names) |field| {
            const event = @field(engine.Event, field);
            if (self.lua.subscribed(event)) {
                const hook = self.hooks.getPtr(event);
                hook.* = .{ .loaded = self, .event = event };
                const name = try hook.handlerName();
                switch (event) {
                    .pre_tool_use => try runtime.registerPreToolUse(.{ .name = name, .ctx = hook, .run = runPreToolUse }),
                    .stop => try runtime.registerStop(.{ .name = name, .ctx = hook, .run = runStop }),
                    .post_turn_end => try runtime.registerPostTurnEnd(.{ .name = name, .ctx = hook, .run = runPostTurnEnd }),
                    .attention_required => try runtime.registerAttentionRequired(.{ .name = name, .ctx = hook, .run = runAttentionRequired }),
                }
            }
        }
    }
};

pub const LuaHook = struct {
    loaded: *Loaded = undefined,
    event: engine.Event = .pre_tool_use,
    name_buffer: [hooks.Limits.handler_name_bytes]u8 = undefined,
    name_len: usize = 0,
    results: ResultSlots = .{},

    fn handlerName(self: *LuaHook) ![]const u8 {
        const text = try std.mem.print(&self.name_buffer, "lua.{s}.{s}", .{ self.loaded.name, @tagName(self.event) });
        self.name_len = text.len;
        return text;
    }

    fn name(self: *const LuaHook) []const u8 {
        return self.name_buffer[0..self.name_len];
    }

    fn inScope(self: *const LuaHook, invocation: hooks.Invocation) bool {
        return self.loaded.scopes.contains(switch (invocation.scope.kind) {
            .interactive => .interactive,
            .ask => .ask,
            .acp => .acp,
            .subagent => .subagent,
        });
    }

    /// Calls the Lua handler. A failure is counted and its reason returned.
    fn call(self: *LuaHook, arena: Allocator, input: anytype) CallOutcome {
        var out: std.Io.Writer.Allocating = .init(arena);
        std.json.Stringify.value(input, .{ .emit_null_optional_fields = false }, &out.writer) catch
            return self.failed(arena, "not enough memory to build the hook input");
        var diagnostic: engine.Diagnostic = .{};
        const result = self.loaded.lua.call(arena, self.event, out.written(), &diagnostic) catch |err| {
            if (err == error.OutOfMemory) return self.failed(arena, "not enough memory");
            return self.failed(arena, diagnostic.message());
        };
        const bytes = result orelse return .{ .value = .null };
        const value = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch
            return self.failed(arena, "the hook returned a value fx cannot read");
        return .{ .value = value };
    }

    fn failed(self: *LuaHook, arena: Allocator, message: []const u8) CallOutcome {
        debug_trace.logf("lua_hooks", "event=hook_failed handler={s} error={s}", .{ self.name(), message });
        catalog.recordFailure(self.loaded.gpa, self.loaded.home, self.loaded.name, self.loaded.sha256, message);
        return .{ .failure = arena.dupe(u8, message) catch "not enough memory" };
    }

    /// Counts a return value fx does not understand and says what it wanted.
    fn invalid(self: *LuaHook, arena: Allocator, comptime expected: []const u8) []const u8 {
        return self.failed(arena, "the hook must return " ++ expected).failure;
    }

    /// The block reason for a failed `PreToolUse` hook, within fx's limit.
    fn failClosed(self: *LuaHook, arena: Allocator, message: []const u8) hooks.HandlerError!hooks.PreToolUseAction {
        const reason = arena.print(
            "Lua hook {s} failed, so fx blocked this tool call: {s}. Turn the extension off with `fx extensions disable {s}`.",
            .{ self.name(), message, self.loaded.name },
        ) catch return error.Failed;
        return .{ .block = try self.keep(truncateUtf8(reason, hooks.Limits.reason_bytes)) };
    }

    /// Keeps `bytes` alive until this thread calls the hook again; fx copies
    /// what a handler returns before then.
    fn keep(self: *LuaHook, bytes: []const u8) hooks.HandlerError![]const u8 {
        return self.results.keep(self.loaded.gpa, bytes) catch error.Failed;
    }
};

const CallOutcome = union(enum) {
    value: std.json.Value,
    failure: []const u8,
};

/// What each calling thread's hook returned last. Subagents can call one
/// hook from several threads at once, so each thread gets its own slot.
const ResultSlots = struct {
    mutex: std.Io.Mutex = .init,
    slots: std.AutoHashMapUnmanaged(std.Thread.Id, []u8) = .empty,

    fn keep(self: *ResultSlots, gpa: Allocator, bytes: []const u8) Allocator.Error![]const u8 {
        const copy = try gpa.dupe(u8, bytes);
        errdefer gpa.free(copy);
        const io = io_mod.getIo();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const slot = try self.slots.getOrPut(gpa, std.Thread.getCurrentId());
        if (slot.found_existing) gpa.free(slot.value_ptr.*);
        slot.value_ptr.* = copy;
        return copy;
    }

    fn deinit(self: *ResultSlots, gpa: Allocator) void {
        var it = self.slots.valueIterator();
        while (it.next()) |bytes| gpa.free(bytes.*);
        self.slots.deinit(gpa);
    }
};

fn truncateUtf8(text: []const u8, max: usize) []const u8 {
    if (text.len <= max) return text;
    var end = max;
    while (end > 0 and (text[end] & 0xC0) == 0x80) end -= 1;
    return text[0..end];
}

const ScopeInput = struct {
    kind: []const u8,
    workspace_root: []const u8,
    session_id: ?[]const u8,
    subagent_id: ?u64,

    fn of(invocation: hooks.Invocation) ScopeInput {
        return .{
            .kind = @tagName(invocation.scope.kind),
            .workspace_root = invocation.scope.workspace_root,
            .session_id = invocation.scope.session_id,
            .subagent_id = invocation.scope.subagent_id,
        };
    }
};

fn hookFrom(ctx: *anyopaque) *LuaHook {
    return @ptrCast(@alignCast(ctx));
}

fn runPreToolUse(ctx: *anyopaque, input: hooks.PreToolUseInput) hooks.HandlerError!hooks.PreToolUseAction {
    const hook = hookFrom(ctx);
    if (!hook.inScope(input.invocation)) return .continue_;
    var arena_state: std.heap.ArenaAllocator = .init(hook.loaded.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Arguments arrive before validation, so they may not be a JSON object.
    const arguments = std.json.parseFromSliceLeaky(std.json.Value, arena, input.arguments_json, .{}) catch null;
    const valid_arguments = arguments != null and arguments.? == .object;
    const outcome = hook.call(arena, .{
        .event = "pre_tool_use",
        .scope = ScopeInput.of(input.invocation),
        .turn_id = input.invocation.turn_id,
        .step_index = input.step_index,
        .call_id = input.call_id,
        .tool_name = input.tool_name,
        .arguments = if (valid_arguments) arguments else null,
        // The raw text only when it is not a JSON object, so a large write
        // reaches Lua once.
        .arguments_json = if (valid_arguments) null else input.arguments_json,
    });
    const value = switch (outcome) {
        .failure => |message| return hook.failClosed(arena, message),
        .value => |value| value,
    };
    const expected = "nothing, { arguments = {...} } or { block = \"reason\" }";
    if (value == .null) return .continue_;
    if (value != .object) return hook.failClosed(arena, hook.invalid(arena, expected));
    const object = value.object;
    if (object.count() == 0) return .continue_;
    if (object.count() != 1) return hook.failClosed(arena, hook.invalid(arena, expected));
    if (object.get("block")) |reason| {
        if (reason != .string or reason.string.len == 0) {
            return hook.failClosed(arena, hook.invalid(arena, "a non-empty string as its block reason"));
        }
        return .{ .block = try hook.keep(truncateUtf8(reason.string, hooks.Limits.reason_bytes)) };
    }
    if (object.get("arguments")) |rewritten| {
        if (rewritten != .object) {
            return hook.failClosed(arena, hook.invalid(arena, "a table of named arguments as its rewrite"));
        }
        var out: std.Io.Writer.Allocating = .init(arena);
        std.json.Stringify.value(rewritten, .{}, &out.writer) catch return error.Failed;
        if (out.written().len > hooks.Limits.arguments_json_bytes) {
            return hook.failClosed(arena, hook.invalid(arena, "rewritten arguments of at most 1 MiB"));
        }
        return .{ .rewrite_arguments = try hook.keep(out.written()) };
    }
    return hook.failClosed(arena, hook.invalid(arena, expected));
}

fn runStop(ctx: *anyopaque, input: hooks.StopInput) hooks.HandlerError!hooks.StopAction {
    const hook = hookFrom(ctx);
    if (!hook.inScope(input.invocation)) return .allow;
    var arena_state: std.heap.ArenaAllocator = .init(hook.loaded.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = hook.call(arena, .{
        .event = "stop",
        .scope = ScopeInput.of(input.invocation),
        .turn_id = input.invocation.turn_id,
        .step_index = input.step_index,
        .assistant_text = input.assistant_text,
        .provider_disposition = @tagName(input.provider_disposition),
        .can_continue = input.can_continue,
    });
    const value = switch (outcome) {
        // Fails open: the turn completes.
        .failure => return .allow,
        .value => |value| value,
    };
    if (value == .null or (value == .object and value.object.count() == 0)) return .allow;
    if (value == .object and value.object.count() == 1) {
        if (value.object.get("continue")) |context| {
            if (context == .string and context.string.len > 0) {
                return .{ .continue_once = try hook.keep(truncateUtf8(context.string, hooks.Limits.context_bytes)) };
            }
        }
    }
    _ = hook.invalid(arena, "nothing or { continue = \"context\" }");
    return .allow;
}

fn runPostTurnEnd(ctx: *anyopaque, input: hooks.PostTurnEndInput) hooks.HandlerError!void {
    const hook = hookFrom(ctx);
    if (!hook.inScope(input.invocation)) return;
    var arena_state: std.heap.ArenaAllocator = .init(hook.loaded.gpa);
    defer arena_state.deinit();
    const outcome = hook.call(arena_state.allocator(), .{
        .event = "post_turn_end",
        .scope = ScopeInput.of(input.invocation),
        .turn_id = input.invocation.turn_id,
        .outcome = @tagName(input.outcome),
        .provider_disposition = if (input.provider_disposition) |disposition| @tagName(disposition) else null,
    });
    if (outcome == .failure) return error.Failed;
}

fn runAttentionRequired(ctx: *anyopaque, input: hooks.AttentionRequiredInput) hooks.HandlerError!void {
    const hook = hookFrom(ctx);
    if (!hook.inScope(input.invocation)) return;
    var arena_state: std.heap.ArenaAllocator = .init(hook.loaded.gpa);
    defer arena_state.deinit();
    const outcome = hook.call(arena_state.allocator(), .{
        .event = "attention_required",
        .scope = ScopeInput.of(input.invocation),
        .turn_id = input.invocation.turn_id,
        .kind = @tagName(input.kind),
    });
    if (outcome == .failure) return error.Failed;
}

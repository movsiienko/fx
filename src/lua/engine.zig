//! The sandboxed Lua 5.4 engine behind fx's Lua hooks. This file is the
//! engine's front door: code outside `src/lua/` imports only this file, and
//! the engine imports only the standard library and the vendored Lua C
//! source. `scripts/check-lua-boundary.sh` enforces both rules.
//!
//! Each extension gets its own `lua_State` with a memory cap, an instruction
//! budget per call, and only the `base`, `string`, `table`, `math` and `utf8`
//! libraries. The host hands in every file the extension may load, so the
//! engine never reads the filesystem: what the user trusted is what runs.

const std = @import("std");
const c = @import("c.zig");
const budget_mod = @import("budget.zig");
const bridge = @import("bridge.zig");
const manifest_mod = @import("manifest.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;

pub const Event = types.Event;
const EventSet = types.EventSet;
pub const Scope = types.Scope;
pub const ScopeSet = types.ScopeSet;
const Limits = types.Limits;
pub const Diagnostic = types.Diagnostic;
pub const Manifest = manifest_mod.Manifest;
pub const parseManifest = manifest_mod.parse;
pub const validExtensionName = manifest_mod.validName;
pub const validModulePath = manifest_mod.validModulePath;

/// The largest JSON value a hook call may return.
const max_result_bytes = 2 * 1024 * 1024;
const max_log_bytes = 2 * 1024;
const max_module_name_bytes = 128;

pub const SourceFile = struct {
    path: []const u8,
    bytes: []const u8,
};

pub const LogLevel = enum { debug, info, warn, @"error" };

const LogSink = struct {
    ctx: ?*anyopaque = null,
    write: *const fn (ctx: ?*anyopaque, extension: []const u8, level: LogLevel, message: []const u8) void = discardLog,

    fn discardLog(_: ?*anyopaque, _: []const u8, _: LogLevel, _: []const u8) void {}
};

const LoadOptions = struct {
    name: []const u8,
    /// Every file `main` and `require` may load, plus `state.json` for
    /// `agent.kv`. The engine copies them.
    files: []const SourceFile,
    main: []const u8 = "main.lua",
    events: EventSet,
    kv: bool = false,
    limits: Limits = .{},
    log: LogSink = .{},
};

const LoadError = error{ OutOfMemory, LoadFailed };
const CallError = error{ OutOfMemory, InvalidInput, HookFailed, InvalidResult };

const bootstrap =
    \\local raw_load = load
    \\load = function(chunk, chunkname, _, ...)
    \\  if select("#", ...) > 0 then return raw_load(chunk, chunkname, "t", ...) end
    \\  return raw_load(chunk, chunkname, "t")
    \\end
;

pub const Extension = struct {
    gpa: Allocator,
    io: std.Io,
    budget: budget_mod.Budget,
    L: *c.State,
    mutex: std.Io.Mutex = .init,
    /// Scratch memory for the current call, inside the budget.
    scratch: std.heap.ArenaAllocator,
    /// `state.json`, parsed once at load, inside the budget.
    kv_arena: std.heap.ArenaAllocator,
    kv_state: ?std.json.ObjectMap = null,
    name: []u8,
    main: []u8,
    files: []SourceFile,
    events: EventSet,
    kv: bool,
    limits: Limits,
    log: LogSink,
    loading: bool = false,
    refs: std.EnumArray(Event, c_int) = .initFill(c.LUA_NOREF),
    tags: bridge.Tags = .{},
    loaded_ref: c_int = c.LUA_NOREF,

    /// Creates the sandbox and runs the extension's main file, which
    /// subscribes to hooks with `agent.on`. The caller owns the result and
    /// frees it with `deinit`. On `LoadFailed`, `diagnostic` says why.
    pub fn load(
        gpa: Allocator,
        io: std.Io,
        options: LoadOptions,
        diagnostic: *Diagnostic,
    ) LoadError!*Extension {
        const self = try gpa.create(Extension);
        errdefer gpa.destroy(self);
        const name = try gpa.dupe(u8, options.name);
        errdefer gpa.free(name);
        const main = try gpa.dupe(u8, options.main);
        errdefer gpa.free(main);
        const files = try copyFiles(gpa, options.files);
        errdefer freeFiles(gpa, files);

        self.* = .{
            .gpa = gpa,
            .io = io,
            .budget = .init(gpa, options.limits.memory_bytes),
            .L = undefined,
            .scratch = undefined,
            .kv_arena = undefined,
            .name = name,
            .main = main,
            .files = files,
            .events = options.events,
            .kv = options.kv,
            .limits = options.limits,
            .log = options.log,
        };
        self.scratch = .init(self.budget.allocator());
        self.kv_arena = .init(self.budget.allocator());
        self.L = c.lua_newstate(budget_mod.luaAlloc, &self.budget) orelse {
            self.kv_arena.deinit();
            self.scratch.deinit();
            return error.OutOfMemory;
        };
        errdefer self.close();

        if (self.kv) try self.loadKvState(diagnostic);
        try self.runProtected(setupState, self, diagnostic);
        self.loading = true;
        defer self.loading = false;
        try self.runProtected(loadMain, self, diagnostic);
        return self;
    }

    pub fn deinit(self: *Extension) void {
        const gpa = self.gpa;
        self.close();
        freeFiles(gpa, self.files);
        gpa.free(self.main);
        gpa.free(self.name);
        gpa.destroy(self);
    }

    fn close(self: *Extension) void {
        // Finalizers run at close; the budget stops a loop in one.
        types.armInstructionBudget(self.L, self.limits.instructions_per_call);
        c.lua_close(self.L);
        self.kv_arena.deinit();
        self.scratch.deinit();
    }

    pub fn subscribed(self: *const Extension, event: Event) bool {
        return self.refs.get(event) != c.LUA_NOREF;
    }

    /// Calls the extension's handler for `event` with the JSON value `input`
    /// and returns what the handler returned as a JSON value allocated in
    /// `arena`, or null when it returned nothing. The result is at most
    /// `max_result_bytes` as JSON. Only the Lua copy of the input counts
    /// against the extension's memory limit. Safe to call from several
    /// threads; calls into one extension run one at a time.
    pub fn call(
        self: *Extension,
        arena: Allocator,
        event: Event,
        input: std.json.Value,
        diagnostic: *Diagnostic,
    ) CallError!?std.json.Value {
        const ref = self.refs.get(event);
        std.debug.assert(ref != c.LUA_NOREF);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const L = self.L;
        defer c.lua_settop(L, 0);
        // Scratch memory counts against the budget, so keep little of it.
        _ = self.scratch.reset(.{ .retain_with_limit = 64 * 1024 });
        bridge.checkValue(input) catch |err| {
            diagnostic.print("hook input is not valid JSON ({s})", .{bridge.describe(err)});
            return error.InvalidInput;
        };

        var job = CallJob{ .ext = self, .ref = ref, .input = input };
        self.runProtected(callHandler, &job, diagnostic) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.LoadFailed => error.HookFailed,
        };
        if (c.lua_type(L, -1) == c.LUA_TNIL) return null;

        return bridge.toValue(L, self.tags, -1, arena, max_result_bytes) catch |err| {
            diagnostic.print("the hook's return value is not valid: {s}", .{bridge.describe(err)});
            return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidResult;
        };
    }

    /// Runs `function(job)` as a protected call under the instruction
    /// budget, leaving its one result on the stack.
    fn runProtected(self: *Extension, function: c.CFunction, job: *anyopaque, diagnostic: *Diagnostic) LoadError!void {
        const L = self.L;
        if (c.lua_checkstack(L, 2) == 0) return error.OutOfMemory;
        c.pushCFunction(L, function);
        c.lua_pushlightuserdata(L, job);
        types.armInstructionBudget(L, self.limits.instructions_per_call);
        const status = c.pcall(L, 1, 1);
        types.disarmInstructionBudget(L);
        if (status != c.LUA_OK) {
            diagnostic.capture(L, status);
            return error.LoadFailed;
        }
    }

    fn loadKvState(self: *Extension, diagnostic: *Diagnostic) LoadError!void {
        const file = self.findFile("state.json") orelse return;
        const value = std.json.parseFromSliceLeaky(std.json.Value, self.kv_arena.allocator(), file.bytes, .{}) catch |err| {
            if (err == error.OutOfMemory) {
                diagnostic.set("state.json does not fit in the extension's memory limit");
            } else {
                diagnostic.set("state.json is not valid JSON");
            }
            return error.LoadFailed;
        };
        if (value != .object) {
            diagnostic.set("state.json must hold a JSON object");
            return error.LoadFailed;
        }
        self.kv_state = value.object;
    }

    fn findFile(self: *const Extension, path: []const u8) ?SourceFile {
        for (self.files) |file| {
            if (std.mem.eql(u8, file.path, path)) return file;
        }
        return null;
    }
};

fn copyFiles(gpa: Allocator, files: []const SourceFile) Allocator.Error![]SourceFile {
    const copies = try gpa.alloc(SourceFile, files.len);
    var copied: usize = 0;
    errdefer {
        for (copies[0..copied]) |file| {
            gpa.free(file.path);
            gpa.free(file.bytes);
        }
        gpa.free(copies);
    }
    for (files) |file| {
        const path = try gpa.dupe(u8, file.path);
        const bytes = gpa.dupe(u8, file.bytes) catch |err| {
            gpa.free(path);
            return err;
        };
        copies[copied] = .{ .path = path, .bytes = bytes };
        copied += 1;
    }
    return copies;
}

fn freeFiles(gpa: Allocator, files: []SourceFile) void {
    for (files) |file| {
        gpa.free(file.path);
        gpa.free(file.bytes);
    }
    gpa.free(files);
}

const CallJob = struct {
    ext: *Extension,
    ref: c_int,
    input: std.json.Value,
};

// Everything below runs inside a protected call. Lua raises errors with
// `longjmp`, so these functions hold nothing that needs cleaning up.

fn jobFrom(comptime T: type, L: ?*c.State) *T {
    return @ptrCast(@alignCast(c.lua_touserdata(L, 1).?));
}

fn extFrom(L: ?*c.State) *Extension {
    return @ptrCast(@alignCast(c.lua_touserdata(L, c.upvalueIndex(1)).?));
}

fn raiseFmt(L: ?*c.State, comptime fmt: []const u8, args: anytype) noreturn {
    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    writer.print(fmt, args) catch {};
    c.raise(L, writer.buffered());
}

fn pushExtFunction(L: ?*c.State, ext: *Extension, function: c.CFunction) void {
    c.lua_pushlightuserdata(L, ext);
    c.lua_pushcclosure(L, function, 1);
}

fn setupState(L: ?*c.State) callconv(.c) c_int {
    const ext = jobFrom(Extension, L);
    const libraries = [_]struct { name: [*:0]const u8, open: c.CFunction }{
        .{ .name = "_G", .open = c.luaopen_base },
        .{ .name = "string", .open = c.luaopen_string },
        .{ .name = "table", .open = c.luaopen_table },
        .{ .name = "math", .open = c.luaopen_math },
        .{ .name = "utf8", .open = c.luaopen_utf8 },
    };
    for (libraries) |library| {
        c.luaL_requiref(L, library.name, library.open, 1);
        c.pop(L, 1);
    }
    for ([_][*:0]const u8{ "dofile", "loadfile", "collectgarbage" }) |name| {
        c.lua_pushnil(L);
        c.lua_setglobal(L, name);
    }
    _ = c.lua_getglobal(L, "string");
    c.lua_pushnil(L);
    c.lua_setfield(L, -2, "dump");
    c.pop(L, 1);

    c.newTable(L);
    ext.tags.array_mt_ref = c.luaL_ref(L, c.LUA_REGISTRYINDEX);
    c.newTable(L);
    ext.loaded_ref = c.luaL_ref(L, c.LUA_REGISTRYINDEX);

    pushExtFunction(L, ext, luaRequire);
    c.lua_setglobal(L, "require");
    pushExtFunction(L, ext, luaPrint);
    c.lua_setglobal(L, "print");

    c.newTable(L);
    pushExtFunction(L, ext, agentOn);
    c.lua_setfield(L, -2, "on");
    pushExtFunction(L, ext, agentLog);
    c.lua_setfield(L, -2, "log");
    c.newTable(L);
    pushExtFunction(L, ext, jsonEncode);
    c.lua_setfield(L, -2, "encode");
    pushExtFunction(L, ext, jsonDecode);
    c.lua_setfield(L, -2, "decode");
    pushExtFunction(L, ext, jsonArray);
    c.lua_setfield(L, -2, "array");
    bridge.pushNull(L);
    c.lua_setfield(L, -2, "null");
    c.lua_setfield(L, -2, "json");
    if (ext.kv) {
        c.newTable(L);
        pushExtFunction(L, ext, kvGet);
        c.lua_setfield(L, -2, "get");
        c.lua_setfield(L, -2, "kv");
    }
    c.lua_setglobal(L, "agent");

    if (c.luaL_loadbufferx(L, bootstrap, bootstrap.len, "=fx", "t") != c.LUA_OK) _ = c.lua_error(L);
    c.call(L, 0, 0);
    return 0;
}

fn loadChunk(L: ?*c.State, ext: *Extension, path: []const u8) void {
    const file = ext.findFile(path) orelse raiseFmt(L, "{s} is not in the extension folder", .{path});
    var chunkname: [manifest_mod.max_name_bytes + manifest_mod.max_path_bytes + 3]u8 = undefined;
    const name = std.mem.print(&chunkname, "@{s}/{s}\x00", .{ ext.name, path }) catch
        c.raise(L, "module path is too long");
    if (c.luaL_loadbufferx(L, file.bytes.ptr, file.bytes.len, @ptrCast(name.ptr), "t") != c.LUA_OK) {
        _ = c.lua_error(L);
    }
}

fn loadMain(L: ?*c.State) callconv(.c) c_int {
    const ext = jobFrom(Extension, L);
    loadChunk(L, ext, ext.main);
    c.call(L, 0, 0);
    return 0;
}

fn callHandler(L: ?*c.State) callconv(.c) c_int {
    const job = jobFrom(CallJob, L);
    _ = c.lua_rawgeti(L, c.LUA_REGISTRYINDEX, job.ref);
    bridge.push(L, job.ext.tags, job.input);
    c.call(L, 1, 1);
    return 1;
}

fn agentOn(L: ?*c.State) callconv(.c) c_int {
    const ext = extFrom(L);
    if (!ext.loading) c.raise(L, "agent.on is only valid while the extension loads");
    const name = c.stringAt(L, 1) orelse c.raise(L, "agent.on: the event must be a string");
    const event = std.meta.stringToEnum(Event, name) orelse
        raiseFmt(L, "agent.on: '{s}' is not an fx hook (pre_tool_use, stop, post_turn_end, attention_required)", .{name});
    if (!ext.events.contains(event)) raiseFmt(L, "agent.on: '{s}' is not listed in the manifest's events", .{name});
    if (ext.subscribed(event)) raiseFmt(L, "agent.on: this extension already handles '{s}'", .{name});
    if (c.lua_type(L, 2) != c.LUA_TFUNCTION) c.raise(L, "agent.on: the handler must be a function");
    c.lua_settop(L, 2);
    ext.refs.set(event, c.luaL_ref(L, c.LUA_REGISTRYINDEX));
    return 0;
}

fn agentLog(L: ?*c.State) callconv(.c) c_int {
    const ext = extFrom(L);
    const level_name = c.stringAt(L, 1) orelse c.raise(L, "agent.log: the level must be a string");
    const level = std.meta.stringToEnum(LogLevel, level_name) orelse
        c.raise(L, "agent.log: the level must be debug, info, warn or error");
    var len: usize = 0;
    const message = c.luaL_tolstring(L, 2, &len);
    writeLog(ext, level, message[0..len]);
    return 0;
}

fn luaPrint(L: ?*c.State) callconv(.c) c_int {
    const ext = extFrom(L);
    // Like the stock `print`, convert one argument at a time and pop it, so
    // any number of arguments fits in the stack space a C function gets.
    // One byte past the log limit lets `writeLog` cut at a UTF-8 boundary.
    var buffer: [max_log_bytes + 1]u8 = undefined;
    var line: std.Io.Writer = .fixed(&buffer);
    const count = c.lua_gettop(L);
    var i: c_int = 1;
    while (i <= count) : (i += 1) {
        var len: usize = 0;
        const text = c.luaL_tolstring(L, i, &len);
        if (i > 1) line.writeAll("\t") catch {};
        line.writeAll(text[0..len]) catch {};
        c.pop(L, 1);
    }
    writeLog(ext, .info, line.buffered());
    return 0;
}

fn writeLog(ext: *Extension, level: LogLevel, message: []const u8) void {
    var end = @min(message.len, max_log_bytes);
    while (end < message.len and end > 0 and (message[end] & 0xC0) == 0x80) end -= 1;
    ext.log.write(ext.log.ctx, ext.name, level, message[0..end]);
}

fn jsonEncode(L: ?*c.State) callconv(.c) c_int {
    const ext = extFrom(L);
    c.lua_settop(L, 1);
    var out: std.Io.Writer.Allocating = .init(ext.scratch.allocator());
    bridge.encode(L, ext.tags, 1, &out, ext.limits.memory_bytes) catch |err|
        raiseFmt(L, "agent.json.encode: {s}", .{bridge.describe(err)});
    c.pushString(L, out.written());
    return 1;
}

fn jsonDecode(L: ?*c.State) callconv(.c) c_int {
    const ext = extFrom(L);
    const text = c.stringAt(L, 1) orelse c.raise(L, "agent.json.decode: expected a string");
    const value = std.json.parseFromSliceLeaky(std.json.Value, ext.scratch.allocator(), text, .{}) catch |err| switch (err) {
        error.OutOfMemory => c.raise(L, "agent.json.decode: not enough memory"),
        else => c.raise(L, "agent.json.decode: invalid JSON"),
    };
    bridge.push(L, ext.tags, value);
    return 1;
}

fn jsonArray(L: ?*c.State) callconv(.c) c_int {
    const ext = extFrom(L);
    if (c.lua_type(L, 1) != c.LUA_TTABLE) c.raise(L, "agent.json.array: expected a table");
    c.lua_settop(L, 1);
    _ = c.lua_rawgeti(L, c.LUA_REGISTRYINDEX, ext.tags.array_mt_ref);
    _ = c.lua_setmetatable(L, 1);
    return 1;
}

fn kvGet(L: ?*c.State) callconv(.c) c_int {
    const ext = extFrom(L);
    const key = c.stringAt(L, 1) orelse c.raise(L, "agent.kv.get: the key must be a string");
    const state = ext.kv_state orelse {
        c.lua_pushnil(L);
        return 1;
    };
    if (state.get(key)) |value| {
        bridge.push(L, ext.tags, value);
    } else {
        c.lua_pushnil(L);
    }
    return 1;
}

fn luaRequire(L: ?*c.State) callconv(.c) c_int {
    const ext = extFrom(L);
    const name = c.stringAt(L, 1) orelse c.raise(L, "require: the module name must be a string");
    var path_buffer: [max_module_name_bytes + ".lua".len]u8 = undefined;
    if (name.len == 0 or name.len > max_module_name_bytes) c.raise(L, "require: invalid module name");
    for (name, 0..) |byte, i| path_buffer[i] = if (byte == '.') '/' else byte;
    @memcpy(path_buffer[name.len..][0..".lua".len], ".lua");
    const path = path_buffer[0 .. name.len + ".lua".len];
    if (!manifest_mod.validModulePath(path)) raiseFmt(L, "require: invalid module name '{s}'", .{name});

    c.lua_settop(L, 1);
    _ = c.lua_rawgeti(L, c.LUA_REGISTRYINDEX, ext.loaded_ref);
    c.lua_pushvalue(L, 1);
    if (c.lua_rawget(L, 2) != c.LUA_TNIL) return 1;
    c.pop(L, 1);

    if (ext.findFile(path) == null) raiseFmt(L, "require: module '{s}' is not in the extension folder", .{name});
    loadChunk(L, ext, path);
    c.call(L, 0, 1);
    if (c.lua_type(L, -1) == c.LUA_TNIL) {
        c.pop(L, 1);
        c.lua_pushboolean(L, 1);
    }
    c.lua_pushvalue(L, 1);
    c.lua_pushvalue(L, -2);
    c.lua_rawset(L, 2);
    return 1;
}

const TestLog = struct {
    lines: std.ArrayList(u8) = .empty,

    fn sink(self: *TestLog) LogSink {
        return .{ .ctx = self, .write = write };
    }

    fn write(ctx: ?*anyopaque, extension: []const u8, level: LogLevel, message: []const u8) void {
        const self: *TestLog = @ptrCast(@alignCast(ctx.?));
        self.lines.print(std.testing.allocator, "{s} {s} {s}\n", .{ extension, @tagName(level), message }) catch {};
    }
};

fn loadForTest(main: []const u8, extra: []const SourceFile, options: struct {
    events: EventSet = .full,
    kv: bool = false,
    limits: Limits = .{ .memory_bytes = 2 * 1024 * 1024, .instructions_per_call = 200_000 },
    log: LogSink = .{},
}) !*Extension {
    var files: std.ArrayList(SourceFile) = .empty;
    defer files.deinit(std.testing.allocator);
    try files.append(std.testing.allocator, .{ .path = "main.lua", .bytes = main });
    try files.appendSlice(std.testing.allocator, extra);
    var diagnostic: Diagnostic = .{};
    return Extension.load(std.testing.allocator, std.testing.io, .{
        .name = "test",
        .files = files.items,
        .events = options.events,
        .kv = options.kv,
        .limits = options.limits,
        .log = options.log,
    }, &diagnostic) catch |err| {
        std.debug.print("load failed: {s}\n", .{diagnostic.message()});
        return err;
    };
}

/// Calls with the JSON text `input` and compares the result as JSON text.
fn expectCall(ext: *Extension, event: Event, input: []const u8, expected: ?[]const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), input, .{});
    var diagnostic: Diagnostic = .{};
    const result = ext.call(arena.allocator(), event, value, &diagnostic) catch |err| {
        std.debug.print("call failed: {s}\n", .{diagnostic.message()});
        return err;
    };
    if (expected) |want| {
        var out: std.Io.Writer.Allocating = .init(arena.allocator());
        try std.json.Stringify.value(result orelse return error.TestUnexpectedResult, .{}, &out.writer);
        try std.testing.expectEqualStrings(want, out.written());
    } else {
        try std.testing.expect(result == null);
    }
}

fn expectCallFails(ext: *Extension, event: Event, input: []const u8, expected: CallError, message: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), input, .{});
    try expectValueCallFails(ext, arena.allocator(), event, value, expected, message);
}

fn expectValueCallFails(ext: *Extension, arena: Allocator, event: Event, input: std.json.Value, expected: CallError, message: []const u8) !void {
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(expected, ext.call(arena, event, input, &diagnostic));
    if (std.mem.find(u8, diagnostic.message(), message) == null) {
        std.debug.print("unexpected diagnostic: {s}\n", .{diagnostic.message()});
        return error.TestUnexpectedResult;
    }
}

const policy_main =
    \\local deny = { "rm%s+%-rf%s+/", "git%s+push%s+%-%-force" }
    \\agent.on("pre_tool_use", function(ev)
    \\  if ev.tool_name ~= "shell" or ev.arguments.action ~= "run" then return end
    \\  local cmd = ev.arguments.command or ""
    \\  for _, p in ipairs(deny) do
    \\    if cmd:find(p) then return { block = "matches deny rule " .. p } end
    \\  end
    \\end)
;

test "a policy hook blocks a matching shell command and passes others" {
    const ext = try loadForTest(policy_main, &.{}, .{});
    defer ext.deinit();
    try std.testing.expect(ext.subscribed(.pre_tool_use));
    try std.testing.expect(!ext.subscribed(.stop));
    try expectCall(ext, .pre_tool_use,
        \\{"tool_name":"shell","arguments":{"action":"run","command":"rm -rf /tmp/x"}}
    ,
        \\{"block":"matches deny rule rm%s+%-rf%s+/"}
    );
    try expectCall(ext, .pre_tool_use,
        \\{"tool_name":"shell","arguments":{"action":"run","command":"ls"}}
    , null);
    try expectCall(ext, .pre_tool_use,
        \\{"tool_name":"read_file","arguments":{"path":"a"}}
    , null);
}

test "values keep their JSON shape across the bridge" {
    const ext = try loadForTest(
        \\agent.on("pre_tool_use", function(ev) return { arguments = ev.arguments } end)
        \\agent.on("stop", function(ev)
        \\  local decoded = agent.json.decode('{"a":[],"b":null,"c":[1,2.5,"x"]}')
        \\  return { continue = agent.json.encode({ decoded.a, decoded.b == agent.json.null, decoded.c[2] }) }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCall(ext, .pre_tool_use,
        \\{"arguments":{"paths":[],"opts":{},"n":3,"neg":-1.5,"none":null}}
    ,
        \\{"arguments":{"n":3,"neg":-1.5,"none":null,"opts":{},"paths":[]}}
    );
    try expectCall(ext, .stop, "{}",
        \\{"continue":"[[],true,2.5]"}
    );
}

test "a large string argument reaches Lua and comes back intact" {
    const ext = try loadForTest(
        \\agent.on("pre_tool_use", function(ev)
        \\  return { arguments = { content = ev.arguments.content, length = #ev.arguments.content } }
        \\end)
    , &.{}, .{ .limits = .{ .memory_bytes = 8 * 1024 * 1024, .instructions_per_call = 200_000 } });
    defer ext.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const content = try arena.alloc(u8, 1536 * 1024);
    @memset(content, 'x');
    var arguments: std.json.ObjectMap = .empty;
    try arguments.put(arena, "content", .{ .string = content });
    var input: std.json.ObjectMap = .empty;
    try input.put(arena, "arguments", .{ .object = arguments });

    var diagnostic: Diagnostic = .{};
    const result = (try ext.call(arena, .pre_tool_use, .{ .object = input }, &diagnostic)).?;
    const returned = result.object.get("arguments").?.object;
    try std.testing.expectEqual(@as(i64, 1572864), returned.get("length").?.integer);
    const echoed = returned.get("content").?.string;
    try std.testing.expectEqual(@as(usize, 1572864), echoed.len);
    try std.testing.expect(std.mem.allEqual(u8, echoed, 'x'));
}

test "the sandbox leaves out unsafe libraries and binary chunks" {
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  local missing = {}
        \\  for _, name in ipairs({ "io", "os", "debug", "package", "coroutine", "dofile", "loadfile", "collectgarbage" }) do
        \\    if _G[name] ~= nil then missing[#missing + 1] = name end
        \\  end
        \\  if string.dump ~= nil then missing[#missing + 1] = "string.dump" end
        \\  local ok, err = load("\27Lua")
        \\  local text = load("return 1 + 1")
        \\  return { continue = table.concat(missing, ",") .. "|" .. tostring(ok) .. "|" .. err .. "|" .. text() }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCall(ext, .stop, "{}",
        \\{"continue":"|nil|attempt to load a binary chunk (mode is 't')|2"}
    );
}

test "the instruction budget stops loops even when the hook catches errors" {
    const ext = try loadForTest(
        \\agent.on("stop", function() while true do end end)
        \\agent.on("pre_tool_use", function()
        \\  while true do pcall(function() while true do end end) end
        \\end)
        \\agent.on("post_turn_end", function() return { ok = true } end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "instruction budget exceeded");
    try expectCallFails(ext, .pre_tool_use, "{}", error.HookFailed, "instruction budget exceeded");
    // The next call gets a fresh budget.
    try expectCall(ext, .post_turn_end, "{}",
        \\{"ok":true}
    );
}

test "the memory cap stops a memory bomb and the state stays usable" {
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  local t = {}
        \\  for i = 1, 1e9 do t[i] = string.rep("x", 1024) .. i end
        \\end)
        \\agent.on("post_turn_end", function() return string.rep("y", 3) end)
    , &.{}, .{ .limits = .{ .memory_bytes = 1024 * 1024, .instructions_per_call = 100_000_000 } });
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "not enough memory");
    try std.testing.expect(ext.budget.used <= 1024 * 1024);
    try expectCall(ext, .post_turn_end, "{}", "\"yyy\"");
}

test "a backtracking pattern is cut off inside its C call" {
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  local s = string.rep("a", 4000)
        \\  return { continue = tostring(s:find(".-.-.-.-b")) }
        \\end)
    , &.{}, .{ .limits = .{ .memory_bytes = 2 * 1024 * 1024, .instructions_per_call = 1_000_000 } });
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "pattern too complex");
}

test "a worst-case plain find is cut off inside its C call" {
    // Every position of s starts a 4 MiB near match, so a search that
    // compares the whole needle at each one does about 2^44 byte compares.
    const ext = try loadForTest(
        \\local s = string.rep("a", 8 * 1024 * 1024)
        \\local p = string.rep("a", 4 * 1024 * 1024) .. "b"
        \\agent.on("stop", function() return { continue = tostring(s:find(p, 1, true)) } end)
        \\agent.on("post_turn_end", function() return { continue = tostring(s:find(p)) } end)
    , &.{}, .{ .limits = .{ .memory_bytes = 32 * 1024 * 1024, .instructions_per_call = 1_000_000 } });
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "pattern too complex");
    try expectCallFails(ext, .post_turn_end, "{}", error.HookFailed, "pattern too complex");
}

test "plain finds return the same positions as stock Lua" {
    const ext = try loadForTest(
        \\local function r(...) local a, b = ... return tostring(a) .. ":" .. tostring(b) end
        \\agent.on("stop", function()
        \\  local long = string.rep("a", 1000000) .. "b"
        \\  return { continue = table.concat({
        \\    r(("hello world"):find("o", 1, true)),
        \\    r(("hello world"):find("o", 6, true)),
        \\    r(("hello world"):find("o", -4, true)),
        \\    r(("hello world"):find("o", -3, true)),
        \\    r(("hello"):find("", 1, true)),
        \\    r(("hello"):find("", 6, true)),
        \\    r(("hello"):find("", 7, true)),
        \\    r(("aaab"):find("aab", 1, true)),
        \\    r(("abc"):find("abc", 1, true)),
        \\    r(("abc"):find("abcd", 1, true)),
        \\    r(("a.b"):find(".", 1, true)),
        \\    r(("foo bar"):find("bar")),
        \\    r(("abcabc"):find("c", -1)),
        \\    r(long:find("aab", 1, true)),
        \\  }, " ") }
        \\end)
    , &.{}, .{ .limits = .{ .memory_bytes = 8 * 1024 * 1024, .instructions_per_call = 1_000_000 } });
    defer ext.deinit();
    try expectCall(ext, .stop, "{}",
        \\{"continue":"5:5 8:8 8:8 nil:nil 1:0 6:5 nil:nil 2:4 1:3 nil:nil 2:2 5:7 6:6 999999:1000001"}
    );
}

test "string.rep of an empty result returns at once" {
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  local a = string.rep("", math.maxinteger)
        \\  local b = string.rep("", math.maxinteger, "")
        \\  return { continue = "[" .. a .. "][" .. b .. "][" .. string.rep("ab", 3, ",") .. "]" }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCall(ext, .stop, "{}",
        \\{"continue":"[][][ab,ab,ab]"}
    );
}

test "table.move over a huge range fails instead of hanging" {
    const ext = try loadForTest(
        \\agent.on("stop", function() table.move({}, 1, math.maxinteger - 1, 2) end)
        \\agent.on("post_turn_end", function()
        \\  return { continue = table.concat(table.move({ "a", "b", "c" }, 1, 3, 2), ",") }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "too many elements to move");
    try expectCall(ext, .post_turn_end, "{}",
        \\{"continue":"a,a,b,c"}
    );
}

test "table.concat over a huge range of a proxy fails instead of hanging" {
    // A C function as __index answers every index with "" without running
    // a Lua instruction or growing the result.
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  local proxy = setmetatable({}, { __index = table.concat })
        \\  return { continue = table.concat(proxy, "", 1, math.maxinteger) }
        \\end)
        \\agent.on("post_turn_end", function()
        \\  local proxy = setmetatable({}, { __index = table.concat })
        \\  return { continue = "[" .. table.concat(proxy, "", 1, 3) .. "]" }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "too many elements to concatenate");
    try expectCall(ext, .post_turn_end, "{}",
        \\{"continue":"[]"}
    );
}

test "table.insert and table.remove under a huge __len fail instead of hanging" {
    const ext = try loadForTest(
        \\local function huge() return setmetatable({}, { __len = function() return math.maxinteger - 1 end }) end
        \\agent.on("stop", function() table.insert(huge(), 1, "x") end)
        \\agent.on("pre_tool_use", function() table.remove(huge(), 1) end)
        \\agent.on("post_turn_end", function()
        \\  local t = { "a", "c" }
        \\  table.insert(t, 2, "b")
        \\  local removed = table.remove(t, 1)
        \\  return { continue = removed .. ":" .. table.concat(t, ",") }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "too many elements to move");
    try expectCallFails(ext, .pre_tool_use, "{}", error.HookFailed, "too many elements to move");
    try expectCall(ext, .post_turn_end, "{}",
        \\{"continue":"a:b,c"}
    );
}

test "table.sort under a huge __len fails instead of running for hours" {
    // C functions as __index and __newindex read 0 and store nothing, so
    // the sort neither runs Lua instructions nor allocates.
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  local proxy = setmetatable({}, {
        \\    __len = function() return 2147483646 end,
        \\    __index = rawlen,
        \\    __newindex = rawequal,
        \\  })
        \\  table.sort(proxy)
        \\end)
        \\agent.on("post_turn_end", function()
        \\  local t = { 3, 1, 2 }
        \\  table.sort(t)
        \\  return { continue = table.concat(t, ",") }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "array too big");
    try expectCall(ext, .post_turn_end, "{}",
        \\{"continue":"1,2,3"}
    );
}

test "agent.on is valid only while loading and only for manifest events" {
    var diagnostic: Diagnostic = .{};
    const files = [_]SourceFile{.{ .path = "main.lua", .bytes = "agent.on(\"stop\", function() end)" }};
    try std.testing.expectError(error.LoadFailed, Extension.load(std.testing.allocator, std.testing.io, .{
        .name = "test",
        .files = &files,
        .events = .initOne(.pre_tool_use),
    }, &diagnostic));
    try std.testing.expect(std.mem.find(u8, diagnostic.message(), "not listed in the manifest's events") != null);

    const ext = try loadForTest(
        \\agent.on("stop", function() agent.on("pre_tool_use", function() end) end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "only valid while the extension loads");
}

test "require loads modules from the extension files once" {
    const ext = try loadForTest(
        \\local rules = require("lib.rules")
        \\local again = require("lib.rules")
        \\agent.on("stop", function()
        \\  local ok, err = pcall(require, "missing")
        \\  return { continue = rules.word .. tostring(rules == again) .. "|" .. err }
        \\end)
    , &.{.{ .path = "lib/rules.lua", .bytes = "return { word = 'deny' }" }}, .{});
    defer ext.deinit();
    try expectCall(ext, .stop, "{}",
        \\{"continue":"denytrue|require: module 'missing' is not in the extension folder"}
    );
}

test "agent.kv reads state.json and print goes to the log" {
    var log: TestLog = .{};
    defer log.lines.deinit(std.testing.allocator);
    const ext = try loadForTest(
        \\print("loaded", 1, true)
        \\agent.on("stop", function()
        \\  agent.log("warn", "checking")
        \\  local words = agent.kv.get("deny")
        \\  return { continue = words[1] .. #words .. tostring(agent.kv.get("absent")) }
        \\end)
    , &.{.{ .path = "state.json", .bytes = "{\"deny\":[\"force\",\"push\"]}" }}, .{ .kv = true, .log = log.sink() });
    defer ext.deinit();
    try expectCall(ext, .stop, "{}",
        \\{"continue":"force2nil"}
    );
    try std.testing.expectEqualStrings("test info loaded\t1\ttrue\ntest warn checking\n", log.lines.items);
}

test "print with hundreds of values logs one line and the hook returns" {
    var log: TestLog = .{};
    defer log.lines.deinit(std.testing.allocator);
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  local t = {}
        \\  for i = 1, 200 do t[i] = i % 10 end
        \\  print(table.unpack(t))
        \\  return { ok = true }
        \\end)
    , &.{}, .{ .log = log.sink() });
    defer ext.deinit();
    try expectCall(ext, .stop, "{}",
        \\{"ok":true}
    );
    const expected = comptime blk: {
        const run = "1\t2\t3\t4\t5\t6\t7\t8\t9\t0";
        var line: []const u8 = "test info " ++ run;
        for (1..20) |_| line = line ++ "\t" ++ run;
        break :blk line ++ "\n";
    };
    try std.testing.expectEqualStrings(expected, log.lines.items);
}

test "invalid return values and inputs are reported" {
    const ext = try loadForTest(
        \\agent.on("stop", function() return { print } end)
        \\agent.on("pre_tool_use", function() return { [1] = "a", x = "b" } end)
        \\agent.on("post_turn_end", function() return 0/0 end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.InvalidResult, "only nil, booleans");
    try expectCallFails(ext, .pre_tool_use, "{}", error.InvalidResult, "only the keys 1..n");
    try expectCallFails(ext, .post_turn_end, "{}", error.InvalidResult, "NaN");

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var input: std.json.ObjectMap = .empty;
    try input.put(arena.allocator(), "text", .{ .string = "\xff" });
    try expectValueCallFails(ext, arena.allocator(), .post_turn_end, .{ .object = input }, error.InvalidInput, "not valid JSON");
    try expectValueCallFails(ext, arena.allocator(), .post_turn_end, .{ .float = std.math.inf(f64) }, error.InvalidInput, "not valid JSON");
}

test "the value bridge round-trips fuzzed JSON" {
    try std.testing.fuzz({}, fuzzValueBridge, .{
        .corpus = &(@import("fuzz_seed").slices(.{
            "{}",
            "{\"a\":[1,2,{\"b\":null}],\"c\":\"\\u00e9\",\"d\":-0.5}",
            "[[],[[]],{}]",
            "\"text\"",
            "123456789012345678901234567890",
            "[1e308,-1e-308,true,false,null]",
        }) ++ @import("fuzz_corpus").lua_value_bridge.*),
    });
}

fn fuzzValueBridge(_: void, smith: *std.testing.Smith) !void {
    var buffer: [4096]u8 = undefined;
    const len: usize = @intCast(smith.slice(&buffer));
    const input = buffer[0..len];
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), input, .{}) catch return;

    var wrapped: std.json.ObjectMap = .empty;
    try wrapped.put(arena.allocator(), "v", parsed);

    const ext = try loadForTest(
        \\agent.on("stop", function(ev) return ev.v end)
    , &.{}, .{});
    defer ext.deinit();
    var diagnostic: Diagnostic = .{};
    const result = ext.call(arena.allocator(), .stop, .{ .object = wrapped }, &diagnostic) catch |err| switch (err) {
        // Nesting past the bridge's depth limit is refused, not crashed on.
        error.HookFailed, error.InvalidResult => return,
        else => return err,
    };
    // JSON null arrives as agent.json.null, which converts back to null.
    const round_trip = result orelse return error.TestUnexpectedResult;
    if (!jsonEquivalent(parsed, round_trip)) {
        var out: std.Io.Writer.Allocating = .init(arena.allocator());
        try std.json.Stringify.value(round_trip, .{}, &out.writer);
        std.debug.print("bridge changed {s} into {s}\n", .{ input, out.written() });
        return error.TestUnexpectedResult;
    }
}

/// Equal JSON, except that a number Lua cannot hold exactly may come back
/// as the nearest float.
fn jsonEquivalent(a: std.json.Value, b: std.json.Value) bool {
    if (a == .number_string or b == .number_string) return true;
    if (a == .float or b == .float) {
        const x: f64 = switch (a) {
            .float => |f| f,
            .integer => |i| @floatFromInt(i),
            else => return false,
        };
        const y: f64 = switch (b) {
            .float => |f| f,
            .integer => |i| @floatFromInt(i),
            else => return false,
        };
        return x == y;
    }
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => |x| x == b.bool,
        .integer => |x| x == b.integer,
        .string => |x| std.mem.eql(u8, x, b.string),
        .array => |x| blk: {
            if (x.items.len != b.array.items.len) break :blk false;
            for (x.items, b.array.items) |left, right| {
                if (!jsonEquivalent(left, right)) break :blk false;
            }
            break :blk true;
        },
        .object => |x| blk: {
            if (x.count() != b.object.count()) break :blk false;
            var it = x.iterator();
            while (it.next()) |entry| {
                const other = b.object.get(entry.key_ptr.*) orelse break :blk false;
                if (!jsonEquivalent(entry.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
        .float, .number_string => unreachable,
    };
}

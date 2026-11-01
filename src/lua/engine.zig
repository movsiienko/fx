//! The sandboxed Lua 5.4 engine behind fx's Lua hooks. This file is the
//! engine's front door: code outside `src/lua/` imports only this file, and
//! the engine imports only the standard library and Lua's C API.
//! `scripts/check-lua-boundary.sh` enforces both rules.
//!
//! Each extension gets its own `lua_State` with a memory cap, an instruction
//! budget per call, a time limit per call, and only the `base`, `string`,
//! `table`, `math` and `utf8` libraries. The host hands in every file the
//! extension may load, so the engine never reads the filesystem: what the
//! user trusted is what runs.
//!
//! fx builds stock Lua. A few library functions can loop for a long time
//! inside one C call, where the instruction budget does not reach: pattern
//! matching, a plain `string.find`, and loops over a huge range or a
//! huge `__len`. The engine bounds them without patching Lua. The bootstrap
//! below wraps the functions whose loops could otherwise run for years,
//! `setmetatable` refuses `__gc` (Lua runs finalizers with hooks off), and
//! every call runs on a worker thread under the extension's time limit. A
//! call that misses it is abandoned: the extension is stopped for the rest
//! of the session, and the worker frees it once Lua's C code returns.

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
const CallError = error{ OutOfMemory, InvalidInput, HookFailed, InvalidResult, TimedOut };
const RunError = error{ OutOfMemory, LoadFailed, TimedOut };

/// Worker threads run Lua's C code and fx's own C functions, none of which
/// recurse deeply: Lua caps its C recursion at `LUAI_MAXCCALLS`.
const worker_stack_bytes = 4 * 1024 * 1024;

/// Workers still running, including abandoned ones. Tests wait for it to
/// reach zero so the testing allocator sees every extension freed.
var live_workers: std.atomic.Value(usize) = .init(0);

/// Runs before the extension's own code, so it captures the stock
/// functions first. The wrappers fail fast where stock Lua would loop in C
/// for longer than any time limit: `string.rep` of an empty result, and
/// table functions over a range or a `__len` far past what memory can hold.
/// A real table never comes near `limit`, because the memory cap is 64 MiB.
const bootstrap =
    \\local raw_load = load
    \\load = function(chunk, chunkname, _, ...)
    \\  if select("#", ...) > 0 then return raw_load(chunk, chunkname, "t", ...) end
    \\  return raw_load(chunk, chunkname, "t")
    \\end
    \\
    \\local error, type, rawget, tonumber, tointeger = error, type, rawget, tonumber, math.tointeger
    \\local raw_setmetatable = setmetatable
    \\setmetatable = function(t, mt)
    \\  if type(mt) == "table" and rawget(mt, "__gc") ~= nil then
    \\    error("setmetatable: fx extensions cannot use __gc finalizers", 2)
    \\  end
    \\  return raw_setmetatable(t, mt)
    \\end
    \\
    \\local limit = 1 << 24
    \\local function int(x)
    \\  if x == nil then return nil end
    \\  return tointeger(tonumber(x))
    \\end
    \\local function too_wide(first, last)
    \\  return first and last and last >= first and (last - first >= limit or last - first < 0)
    \\end
    \\local function check_length(name, list)
    \\  if type(list) ~= "table" then return end
    \\  local n = int(#list)
    \\  if n and n >= limit then error("table." .. name .. ": the table is too long", 3) end
    \\end
    \\
    \\local rep = string.rep
    \\string.rep = function(s, n, sep)
    \\  if s == "" and (sep == nil or sep == "") and int(n) then return "" end
    \\  return rep(s, n, sep)
    \\end
    \\
    \\local move, concat, insert, remove, sort = table.move, table.concat, table.insert, table.remove, table.sort
    \\table.move = function(a1, f, e, t, a2)
    \\  if too_wide(int(f), int(e)) then error("table.move: too many elements to move", 2) end
    \\  return move(a1, f, e, t, a2)
    \\end
    \\table.concat = function(list, sep, i, j)
    \\  local first = i == nil and 1 or int(i)
    \\  local last
    \\  if j ~= nil then last = int(j) elseif type(list) == "table" then last = int(#list) end
    \\  if too_wide(first, last) then error("table.concat: too many elements to concatenate", 2) end
    \\  return concat(list, sep, i, j)
    \\end
    \\table.insert = function(list, ...)
    \\  check_length("insert", list)
    \\  return insert(list, ...)
    \\end
    \\table.remove = function(list, ...)
    \\  check_length("remove", list)
    \\  return remove(list, ...)
    \\end
    \\table.sort = function(list, ...)
    \\  check_length("sort", list)
    \\  return sort(list, ...)
    \\end
;

pub const Extension = struct {
    gpa: Allocator,
    io: std.Io,
    budget: budget_mod.Budget,
    L: *c.State,
    meter: types.Meter = .{},
    /// Serializes calls. Held by the caller, never by a worker.
    mutex: std.Io.Mutex = .init,
    /// One for the owner plus one for each running worker. Whoever lets go
    /// last frees the extension, so an abandoned worker never touches freed
    /// memory.
    holders: std.atomic.Value(u32) = .init(1),
    /// Held around each log write and around the stop, so no log line
    /// reaches the host after a call is abandoned.
    log_mutex: std.Io.Mutex = .init,
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
        const self = try create(gpa, io, options);
        errdefer self.release();

        if (self.kv) try self.loadKvState(diagnostic);
        self.runLoadStep(setupState, diagnostic) catch |err| return loadError(err);
        self.loading = true;
        self.runLoadStep(loadMain, diagnostic) catch |err| return loadError(err);
        self.loading = false;
        return self;
    }

    fn create(gpa: Allocator, io: std.Io, options: LoadOptions) Allocator.Error!*Extension {
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
        self.meter.attach(self.L);
        return self;
    }

    fn runLoadStep(self: *Extension, function: c.CFunction, diagnostic: *Diagnostic) RunError!void {
        try self.runProtected(function, self, false, diagnostic);
        c.lua_settop(self.L, 0);
    }

    fn loadError(err: RunError) LoadError {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.LoadFailed, error.TimedOut => error.LoadFailed,
        };
    }

    /// Lets go of the extension. When a call that missed its time limit is
    /// still running, its worker frees the extension after it returns.
    pub fn deinit(self: *Extension) void {
        self.release();
    }

    fn release(self: *Extension) void {
        if (self.holders.fetchSub(1, .acq_rel) == 1) self.destroy();
    }

    fn destroy(self: *Extension) void {
        const gpa = self.gpa;
        // `setmetatable` refuses `__gc`, so closing runs no extension code.
        c.lua_close(self.L);
        self.kv_arena.deinit();
        self.scratch.deinit();
        freeFiles(gpa, self.files);
        gpa.free(self.main);
        gpa.free(self.name);
        gpa.destroy(self);
    }

    pub fn subscribed(self: *const Extension, event: Event) bool {
        return self.refs.get(event) != c.LUA_NOREF;
    }

    /// Calls the extension's handler for `event` with the JSON value `input`
    /// and returns what the handler returned as a JSON value allocated in
    /// `arena`, or null when it returned nothing. The result is at most
    /// `max_result_bytes` as JSON. Only the Lua copy of the input counts
    /// against the extension's memory limit. Safe to call from several
    /// threads; calls into one extension run one at a time. A call that
    /// runs past the time limit returns `TimedOut`, and so does every later
    /// call to this extension.
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
        if (self.meter.isStopped()) return self.stoppedError(diagnostic);

        bridge.checkValue(input) catch |err| {
            diagnostic.print("hook input is not valid JSON ({s})", .{bridge.describe(err)});
            return error.InvalidInput;
        };
        // Scratch memory counts against the budget, so keep little of it.
        _ = self.scratch.reset(.{ .retain_with_limit = 64 * 1024 });

        const L = self.L;
        var job = CallJob{ .ext = self, .ref = ref, .input = input };
        self.runProtected(callHandler, &job, true, diagnostic) catch |err| switch (err) {
            // The abandoned worker may still be using the state.
            error.TimedOut => return error.TimedOut,
            error.OutOfMemory => {
                c.lua_settop(L, 0);
                return error.OutOfMemory;
            },
            error.LoadFailed => {
                c.lua_settop(L, 0);
                return error.HookFailed;
            },
        };
        defer c.lua_settop(L, 0);
        if (c.lua_type(L, -1) == c.LUA_TNIL) return null;

        return bridge.toValue(L, self.tags, -1, arena, max_result_bytes) catch |err| {
            diagnostic.print("the hook's return value is not valid: {s}", .{bridge.describe(err)});
            return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidResult;
        };
    }

    fn stoppedError(self: *const Extension, diagnostic: *Diagnostic) error{TimedOut} {
        diagnostic.print("a call ran past the {d} ms time limit, so fx stopped this extension until it restarts", .{self.limits.timeout_ms});
        return error.TimedOut;
    }

    /// Runs `function(job)` as a protected call under the instruction budget
    /// on a worker thread, and waits at most `limits.timeout_ms` for it,
    /// leaving its one result on the stack. When `job` holds the caller's
    /// input, the worker reports when that input is in Lua, and the time
    /// limit starts then, so the caller's memory is never read after this
    /// returns. Past the limit, the worker is abandoned and owns the
    /// extension until it returns, and nothing may touch the state.
    fn runProtected(
        self: *Extension,
        function: c.CFunction,
        job: *anyopaque,
        job_holds_input: bool,
        diagnostic: *Diagnostic,
    ) RunError!void {
        if (self.meter.isStopped()) return self.stoppedError(diagnostic);
        const io = self.io;
        const run = try self.gpa.create(Run);
        run.* = .{ .ext = self, .function = function, .job = job, .job_holds_input = job_holds_input };
        _ = self.holders.fetchAdd(1, .monotonic);
        _ = live_workers.fetchAdd(1, .monotonic);
        const thread = std.Thread.spawn(.{ .stack_size = worker_stack_bytes }, Run.work, .{run}) catch {
            _ = live_workers.fetchSub(1, .monotonic);
            _ = self.holders.fetchSub(1, .monotonic);
            self.gpa.destroy(run);
            diagnostic.set("fx could not start a thread to run the extension");
            return error.LoadFailed;
        };

        const cancel_protection = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(cancel_protection);
        run.input_taken.waitUncancelable(io);
        const deadline = (std.Io.Timeout{ .duration = .{
            .raw = .fromMilliseconds(self.limits.timeout_ms),
            .clock = .awake,
        } }).toDeadline(io);
        while (!run.finished.isSet()) {
            // A timeout may also be a spurious wakeup, so check the clock.
            run.finished.waitTimeout(io, deadline) catch {};
            if (run.finished.isSet()) break;
            const left = deadline.toDurationFromNow(io) orelse break;
            if (left.raw.nanoseconds <= 0) break;
        }

        if (!run.finished.isSet() and run.state.cmpxchgStrong(.running, .abandoned, .acq_rel, .acquire) == null) {
            self.log_mutex.lockUncancelable(io);
            self.meter.stop();
            self.log_mutex.unlock(io);
            thread.detach();
            diagnostic.print("the hook ran past its {d} ms time limit, so fx stopped this extension until it restarts", .{self.limits.timeout_ms});
            return error.TimedOut;
        }
        run.finished.waitUncancelable(io);
        thread.join();
        defer self.gpa.destroy(run);
        if (run.status != c.LUA_OK) {
            // Running out of the extension's own memory is its failure.
            diagnostic.set(run.diagnostic.message());
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

/// One protected call on a worker thread. The caller and the worker share
/// it; whichever of them is last frees it.
const Run = struct {
    ext: *Extension,
    function: c.CFunction,
    /// Valid only until `input_taken` is set.
    job: *anyopaque,
    job_holds_input: bool,
    status: c_int = c.LUA_OK,
    diagnostic: Diagnostic = .{},
    /// Set once the worker no longer reads `job`.
    input_taken: std.Io.Event = .unset,
    finished: std.Io.Event = .unset,
    state: std.atomic.Value(State) = .init(.running),

    const State = enum(u8) { running, finished, abandoned };

    fn work(run: *Run) void {
        defer _ = live_workers.fetchSub(1, .monotonic);
        const ext = run.ext;
        const io = ext.io;
        const L = ext.L;
        if (!run.job_holds_input) run.input_taken.set(io);
        if (c.lua_checkstack(L, 2) == 0) {
            run.status = c.LUA_ERRMEM;
            run.diagnostic.set("not enough memory (the extension's memory limit)");
        } else {
            c.pushCFunction(L, run.function);
            c.lua_pushlightuserdata(L, run);
            ext.meter.arm(L, ext.limits.instructions_per_call);
            run.status = c.pcall(L, 1, 1);
            ext.meter.disarm(L);
            if (run.status != c.LUA_OK) run.diagnostic.capture(L, run.status);
        }
        run.input_taken.set(io);
        if (run.state.cmpxchgStrong(.running, .finished, .acq_rel, .acquire) != null) {
            // The caller gave up on this run and left the extension to it.
            c.lua_settop(L, 0);
            ext.gpa.destroy(run);
            ext.release();
            return;
        }
        run.finished.set(io);
        ext.release();
    }
};

// Everything below runs inside a protected call. Lua raises errors with
// `longjmp`, so these functions hold nothing that needs cleaning up.

fn jobFrom(comptime T: type, L: ?*c.State) *T {
    const run: *Run = @ptrCast(@alignCast(c.lua_touserdata(L, 1).?));
    return @ptrCast(@alignCast(run.job));
}

fn runFrom(L: ?*c.State) *Run {
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
    const run = runFrom(L);
    const job = jobFrom(CallJob, L);
    const ext = job.ext;
    _ = c.lua_rawgeti(L, c.LUA_REGISTRYINDEX, job.ref);
    bridge.push(L, ext.tags, job.input);
    // From here on nothing reads the caller's input, and its time starts.
    run.input_taken.set(ext.io);
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
    ext.log_mutex.lockUncancelable(ext.io);
    defer ext.log_mutex.unlock(ext.io);
    // An abandoned call's host may be gone.
    if (ext.meter.isStopped()) return;
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

test {
    _ = bridge;
    _ = budget_mod;
    _ = manifest_mod;
    _ = types;
}

/// Waits for abandoned workers to finish and free their extensions, so the
/// testing allocator sees no leak.
fn waitForWorkers() !void {
    var waited_ms: u32 = 0;
    while (live_workers.load(.acquire) != 0) : (waited_ms += 10) {
        if (waited_ms > 120_000) return error.TestWorkerStillRunning;
        try std.testing.io.sleep(.fromMilliseconds(10), .awake);
    }
}

test "a pattern that backtracks for seconds is stopped at the time limit" {
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  local s = string.rep("a", 600)
        \\  return { continue = tostring(s:find(".-.-b")) }
        \\end)
        \\agent.on("post_turn_end", function() return { ok = true } end)
    , &.{}, .{ .limits = .{ .memory_bytes = 2 * 1024 * 1024, .instructions_per_call = 1_000_000, .timeout_ms = 10 } });
    const started = std.Io.Clock.awake.now(std.testing.io);
    try expectCallFails(ext, .stop, "{}", error.TimedOut, "ran past its 10 ms time limit");
    const elapsed = started.untilNow(std.testing.io, .awake);
    try std.testing.expect(elapsed.toMilliseconds() < 5_000);
    // The extension stays stopped, even for a hook that would be quick.
    try expectCallFails(ext, .post_turn_end, "{}", error.TimedOut, "stopped this extension until it restarts");
    ext.deinit();
    try waitForWorkers();
}

test "a worst-case plain find is stopped at the time limit" {
    const ext = try loadForTest(
        \\local s = string.rep("a", 1024 * 1024)
        \\local p = string.rep("a", 2048) .. "b"
        \\agent.on("stop", function() return { continue = tostring(s:find(p, 1, true)) } end)
    , &.{}, .{ .limits = .{ .memory_bytes = 8 * 1024 * 1024, .instructions_per_call = 1_000_000, .timeout_ms = 10 } });
    try expectCallFails(ext, .stop, "{}", error.TimedOut, "time limit");
    ext.deinit();
    try waitForWorkers();
}

test "main code that runs past the time limit fails the load" {
    var diagnostic: Diagnostic = .{};
    const files = [_]SourceFile{.{ .path = "main.lua", .bytes =
        \\local s = string.rep("a", 600)
        \\s:find(".-.-b")
    }};
    try std.testing.expectError(error.LoadFailed, Extension.load(std.testing.allocator, std.testing.io, .{
        .name = "test",
        .files = &files,
        .events = .full,
        .limits = .{ .timeout_ms = 10 },
    }, &diagnostic));
    try std.testing.expect(std.mem.find(u8, diagnostic.message(), "ran past its 10 ms time limit") != null);
    try waitForWorkers();
}

test "a stopped extension writes no more log lines" {
    var log: TestLog = .{};
    defer log.lines.deinit(std.testing.allocator);
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  print("before")
        \\  local s = string.rep("a", 600)
        \\  s:find(".-.-b")
        \\  print("after")
        \\end)
    , &.{}, .{ .limits = .{ .memory_bytes = 2 * 1024 * 1024, .instructions_per_call = 1_000_000, .timeout_ms = 10 }, .log = log.sink() });
    try expectCallFails(ext, .stop, "{}", error.TimedOut, "time limit");
    ext.deinit();
    try waitForWorkers();
    try std.testing.expectEqualStrings("test info before\n", log.lines.items);
}

test "setmetatable refuses __gc, because finalizers run with hooks off" {
    const ext = try loadForTest(
        \\agent.on("stop", function()
        \\  local ok, err = pcall(setmetatable, {}, { __gc = function() while true do end end })
        \\  local plain = setmetatable({}, { __index = function() return "x" end })
        \\  return { continue = tostring(ok) .. "|" .. err .. "|" .. plain.anything }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCall(ext, .stop, "{}",
        \\{"continue":"false|setmetatable: fx extensions cannot use __gc finalizers|x"}
    );
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
        \\  local b = ("").rep("", math.maxinteger, "")
        \\  local c = string.rep("", 1e18)
        \\  local ok, err = pcall(string.rep, "", {})
        \\  return { continue = "[" .. a .. "][" .. b .. "][" .. c .. "][" .. string.rep("ab", 3, ",") .. "]" .. tostring(ok) }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCall(ext, .stop, "{}",
        \\{"continue":"[][][][ab,ab,ab]false"}
    );
}

test "table.move over a huge range fails instead of hanging" {
    const ext = try loadForTest(
        \\agent.on("stop", function() table.move({}, 1, math.maxinteger - 1, 2) end)
        \\agent.on("pre_tool_use", function() table.move({}, math.mininteger, math.maxinteger, 2) end)
        \\agent.on("post_turn_end", function()
        \\  return { continue = table.concat(table.move({ "a", "b", "c" }, 1, 3, 2), ",") }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "too many elements to move");
    try expectCallFails(ext, .pre_tool_use, "{}", error.HookFailed, "too many elements to move");
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
        \\agent.on("pre_tool_use", function()
        \\  local proxy = setmetatable({}, { __index = table.concat, __len = function() return math.maxinteger end })
        \\  return { continue = table.concat(proxy) }
        \\end)
        \\agent.on("post_turn_end", function()
        \\  local proxy = setmetatable({}, { __index = table.concat })
        \\  return { continue = "[" .. table.concat(proxy, "", 1, 3) .. "][" .. table.concat({ 1, 2, 3 }, "-") .. "]" }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "too many elements to concatenate");
    try expectCallFails(ext, .pre_tool_use, "{}", error.HookFailed, "too many elements to concatenate");
    try expectCall(ext, .post_turn_end, "{}",
        \\{"continue":"[][1-2-3]"}
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
        \\  table.insert(t, "d")
        \\  local removed = table.remove(t, 1)
        \\  local last = table.remove(t)
        \\  local ok = pcall(table.insert, t, 1, 2, 3)
        \\  return { continue = removed .. last .. ":" .. table.concat(t, ",") .. ":" .. tostring(ok) }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "table.insert: the table is too long");
    try expectCallFails(ext, .pre_tool_use, "{}", error.HookFailed, "table.remove: the table is too long");
    try expectCall(ext, .post_turn_end, "{}",
        \\{"continue":"ad:b,c:false"}
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
        \\  local u = { 3, 1, 2 }
        \\  table.sort(u, function(a, b) return a > b end)
        \\  return { continue = table.concat(t, ",") .. ":" .. table.concat(u, ",") }
        \\end)
    , &.{}, .{});
    defer ext.deinit();
    try expectCallFails(ext, .stop, "{}", error.HookFailed, "table.sort: the table is too long");
    try expectCall(ext, .post_turn_end, "{}",
        \\{"continue":"1,2,3:3,2,1"}
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

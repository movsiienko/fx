//! Parses an extension's `manifest.lua`. The manifest is data: it runs in a
//! state with no libraries and an empty global table, under a small memory
//! cap and instruction budget, and must return one table.

const std = @import("std");
const c = @import("c.zig");
const budget_mod = @import("budget.zig");
const bridge = @import("bridge.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;

pub const max_name_bytes = 64;
pub const max_path_bytes = 256;
const manifest_memory_bytes = 256 * 1024;
const manifest_instructions = 200_000;
const manifest_json_bytes = 64 * 1024;

pub const Manifest = struct {
    name: []const u8,
    version: []const u8 = "",
    main: []const u8 = "main.lua",
    events: types.EventSet,
    scopes: types.ScopeSet = default_scopes,
    kv: bool = false,
    limits: types.Limits = .{},
};

/// Hooks skip subagents unless the manifest lists them.
const default_scopes = types.ScopeSet.init(.{
    .interactive = true,
    .ask = true,
    .acp = true,
});

const ParseError = error{ OutOfMemory, InvalidManifest };

/// Parses `bytes`. Strings in the result are allocated in `arena`; `gpa`
/// backs the short-lived Lua state.
pub fn parse(
    arena: Allocator,
    gpa: Allocator,
    bytes: []const u8,
    diagnostic: *types.Diagnostic,
) ParseError!Manifest {
    const json = try evaluate(arena, gpa, bytes, diagnostic);
    const value = std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return invalid(diagnostic, "manifest.lua must return a table", .{}),
    };
    return fromValue(value, diagnostic);
}

fn evaluate(
    arena: Allocator,
    gpa: Allocator,
    bytes: []const u8,
    diagnostic: *types.Diagnostic,
) ParseError![]const u8 {
    var budget = budget_mod.Budget.init(gpa, manifest_memory_bytes);
    var meter: types.Meter = .{};
    const L = c.lua_newstate(budget_mod.luaAlloc, &budget) orelse return error.OutOfMemory;
    meter.attach(L);
    // With no libraries open, a manifest cannot set a finalizer or call into
    // Lua's C library, so the instruction budget bounds all of its work.
    defer c.lua_close(L);

    const load_status = c.luaL_loadbufferx(L, bytes.ptr, bytes.len, "=manifest.lua", "t");
    if (load_status != c.LUA_OK) {
        diagnostic.capture(L, load_status);
        return error.InvalidManifest;
    }
    meter.arm(L, manifest_instructions);
    const status = c.pcall(L, 0, 1);
    meter.disarm(L);
    if (status != c.LUA_OK) {
        diagnostic.capture(L, status);
        return error.InvalidManifest;
    }
    if (c.lua_type(L, -1) != c.LUA_TTABLE) {
        return invalid(diagnostic, "manifest.lua must return a table, not a {s} value", .{c.typeName(L, -1)});
    }

    var out: std.Io.Writer.Allocating = .init(arena);
    bridge.encode(L, .{}, -1, &out, manifest_json_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return invalid(diagnostic, "manifest.lua: {s}", .{bridge.describe(err)}),
    };
    return out.written();
}

fn invalid(diagnostic: *types.Diagnostic, comptime fmt: []const u8, args: anytype) error{InvalidManifest} {
    diagnostic.print(fmt, args);
    return error.InvalidManifest;
}

fn fromValue(value: std.json.Value, diagnostic: *types.Diagnostic) ParseError!Manifest {
    if (value != .object) return invalid(diagnostic, "manifest.lua must return a table with named fields", .{});
    const object = value.object;
    var it = object.iterator();
    while (it.next()) |entry| {
        const known = [_][]const u8{ "name", "version", "main", "events", "scopes", "kv", "limits" };
        for (known) |key| {
            if (std.mem.eql(u8, key, entry.key_ptr.*)) break;
        } else return invalid(diagnostic, "manifest field '{s}' is not recognized", .{entry.key_ptr.*});
    }

    const name = try requiredString(object, "name", diagnostic);
    if (!validName(name)) {
        return invalid(diagnostic, "manifest name must be 1 to {d} lowercase letters, digits, '_' or '-', starting with a letter or digit", .{max_name_bytes});
    }
    var manifest = Manifest{ .name = name, .events = .empty };

    if (object.get("version")) |version| {
        if (version != .string or version.string.len > 64) return invalid(diagnostic, "manifest version must be a string of at most 64 bytes", .{});
        manifest.version = version.string;
    }
    if (object.get("main")) |main| {
        if (main != .string or !validModulePath(main.string)) {
            return invalid(diagnostic, "manifest main must be a relative path to a .lua file inside the extension folder", .{});
        }
        manifest.main = main.string;
    }

    const events = object.get("events") orelse return invalid(diagnostic, "manifest events must list at least one hook", .{});
    manifest.events = try enumSet(types.Event, events, "events", diagnostic);
    if (manifest.events.count() == 0) return invalid(diagnostic, "manifest events must list at least one hook", .{});

    if (object.get("scopes")) |scopes| {
        manifest.scopes = try enumSet(types.Scope, scopes, "scopes", diagnostic);
        if (manifest.scopes.count() == 0) return invalid(diagnostic, "manifest scopes must list at least one scope", .{});
    }
    if (object.get("kv")) |kv| {
        if (kv != .bool) return invalid(diagnostic, "manifest kv must be true or false", .{});
        manifest.kv = kv.bool;
    }
    if (object.get("limits")) |limits| manifest.limits = try parseLimits(limits, diagnostic);
    return manifest;
}

fn requiredString(object: std.json.ObjectMap, key: []const u8, diagnostic: *types.Diagnostic) ParseError![]const u8 {
    const value = object.get(key) orelse return invalid(diagnostic, "manifest {s} is required", .{key});
    if (value != .string) return invalid(diagnostic, "manifest {s} must be a string", .{key});
    return value.string;
}

fn enumSet(
    comptime E: type,
    value: std.json.Value,
    comptime field: []const u8,
    diagnostic: *types.Diagnostic,
) ParseError!std.EnumSet(E) {
    var set: std.EnumSet(E) = .empty;
    // An empty Lua table encodes as an object.
    if (value == .object and value.object.count() == 0) return set;
    if (value != .array) return invalid(diagnostic, "manifest " ++ field ++ " must be a list of names", .{});
    for (value.array.items) |item| {
        if (item != .string) return invalid(diagnostic, "manifest " ++ field ++ " must be a list of names", .{});
        const parsed = std.meta.stringToEnum(E, item.string) orelse
            return invalid(diagnostic, "manifest " ++ field ++ " has an unknown name '{s}'", .{item.string});
        if (set.contains(parsed)) return invalid(diagnostic, "manifest " ++ field ++ " lists '{s}' twice", .{item.string});
        set.insert(parsed);
    }
    return set;
}

fn parseLimits(value: std.json.Value, diagnostic: *types.Diagnostic) ParseError!types.Limits {
    var limits: types.Limits = .{};
    if (value != .object) return invalid(diagnostic, "manifest limits must be a table", .{});
    var it = value.object.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const number = entry.value_ptr.*;
        if (std.mem.eql(u8, key, "memory_mb")) {
            if (number != .integer or number.integer < 1 or number.integer > types.Limits.max_memory_mb) {
                return invalid(diagnostic, "manifest limits.memory_mb must be a whole number from 1 to {d}", .{types.Limits.max_memory_mb});
            }
            limits.memory_bytes = @as(usize, @intCast(number.integer)) * 1024 * 1024;
        } else if (std.mem.eql(u8, key, "instructions_per_call")) {
            if (number != .integer or number.integer < types.Limits.min_instructions_per_call or
                number.integer > types.Limits.max_instructions_per_call)
            {
                return invalid(diagnostic, "manifest limits.instructions_per_call must be a whole number from {d} to {d}", .{
                    types.Limits.min_instructions_per_call,
                    types.Limits.max_instructions_per_call,
                });
            }
            limits.instructions_per_call = @intCast(number.integer);
        } else if (std.mem.eql(u8, key, "timeout_ms")) {
            if (number != .integer or number.integer < types.Limits.min_timeout_ms or
                number.integer > types.Limits.max_timeout_ms)
            {
                return invalid(diagnostic, "manifest limits.timeout_ms must be a whole number from {d} to {d}", .{
                    types.Limits.min_timeout_ms,
                    types.Limits.max_timeout_ms,
                });
            }
            limits.timeout_ms = @intCast(number.integer);
        } else {
            return invalid(diagnostic, "manifest limits field '{s}' is not recognized", .{key});
        }
    }
    return limits;
}

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_bytes) return false;
    if (!std.ascii.isLower(name[0]) and !std.ascii.isDigit(name[0])) return false;
    for (name) |byte| {
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '_' and byte != '-') return false;
    }
    return true;
}

/// A relative `.lua` path inside the extension folder: segments of letters,
/// digits, `_` and `-`, joined by `/`.
pub fn validModulePath(path: []const u8) bool {
    if (path.len == 0 or path.len > max_path_bytes) return false;
    if (!std.mem.endsWith(u8, path, ".lua")) return false;
    var segments = std.mem.splitScalar(u8, path[0 .. path.len - ".lua".len], '/');
    while (segments.next()) |segment| {
        if (segment.len == 0) return false;
        for (segment) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-') return false;
        }
    }
    return true;
}

fn parseForTest(source: []const u8, diagnostic: *types.Diagnostic) ParseError!Manifest {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const manifest = try parse(arena.allocator(), std.testing.allocator, source, diagnostic);
    // Strings live in the arena; the tests read only the scalar fields.
    var copy = manifest;
    copy.name = "";
    copy.version = "";
    copy.main = "";
    return copy;
}

test "a manifest table becomes a typed manifest" {
    var diagnostic: types.Diagnostic = .{};
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const manifest = try parse(arena.allocator(), std.testing.allocator,
        \\return {
        \\  name = "policy",
        \\  version = "0.1.0",
        \\  main = "main.lua",
        \\  events = { "pre_tool_use", "stop" },
        \\  scopes = { "interactive", "ask", "acp", "subagent" },
        \\  kv = true,
        \\  limits = { memory_mb = 2, instructions_per_call = 100000, timeout_ms = 250 },
        \\}
    , &diagnostic);
    try std.testing.expectEqualStrings("policy", manifest.name);
    try std.testing.expectEqualStrings("0.1.0", manifest.version);
    try std.testing.expect(manifest.events.contains(.pre_tool_use));
    try std.testing.expect(manifest.events.contains(.stop));
    try std.testing.expect(!manifest.events.contains(.post_turn_end));
    try std.testing.expect(manifest.scopes.contains(.subagent));
    try std.testing.expect(manifest.kv);
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), manifest.limits.memory_bytes);
    try std.testing.expectEqual(@as(u32, 100000), manifest.limits.instructions_per_call);
    try std.testing.expectEqual(@as(u32, 250), manifest.limits.timeout_ms);
}

test "a manifest leaves subagents out unless it lists them" {
    var diagnostic: types.Diagnostic = .{};
    const manifest = try parseForTest("return { name = \"x\", events = { \"stop\" } }", &diagnostic);
    try std.testing.expect(manifest.scopes.contains(.interactive));
    try std.testing.expect(!manifest.scopes.contains(.subagent));
    try std.testing.expectEqual(types.Limits.default_instructions_per_call, manifest.limits.instructions_per_call);
    try std.testing.expectEqual(@as(u32, 1000), manifest.limits.timeout_ms);
}

test "manifest errors name the problem" {
    const cases = [_]struct { source: []const u8, message: []const u8 }{
        .{ .source = "return 42", .message = "must return a table" },
        .{ .source = "return { name = \"Bad Name\", events = { \"stop\" } }", .message = "manifest name" },
        .{ .source = "return { name = \"x\", events = { \"on_boot\" } }", .message = "unknown name 'on_boot'" },
        .{ .source = "return { name = \"x\", events = {} }", .message = "at least one hook" },
        .{ .source = "return { name = \"x\", events = { \"stop\" }, typo = 1 }", .message = "'typo' is not recognized" },
        .{ .source = "return { name = \"x\", events = { \"stop\" }, main = \"../escape.lua\" }", .message = "manifest main" },
        .{ .source = "return { name = \"x\", events = { \"stop\" }, limits = { memory_mb = 9000 } }", .message = "memory_mb" },
        .{ .source = "return { name = \"x\", events = { \"stop\" }, limits = { timeout_ms = 5 } }", .message = "timeout_ms must be a whole number from 10 to 60000" },
        .{ .source = "return { name = \"x\", events = { \"stop\" }, limits = { timeout_ms = 60001 } }", .message = "timeout_ms" },
        .{ .source = "return { name = \"x\", events = { \"stop\" }, limits = { timeout_ms = 1.5 } }", .message = "timeout_ms" },
        .{ .source = "return {", .message = "manifest.lua:1:" },
        .{ .source = "while true do end", .message = "instruction budget exceeded" },
        .{ .source = "local t = {} for i = 1, 1e9 do t[i] = i end", .message = "not enough memory" },
        .{ .source = "return { name = string.upper(\"x\") }", .message = "attempt to index a nil value" },
        .{ .source = "\x1bLua", .message = "attempt to load a binary chunk" },
    };
    for (cases) |case| {
        var diagnostic: types.Diagnostic = .{};
        try std.testing.expectError(error.InvalidManifest, parseForTest(case.source, &diagnostic));
        if (std.mem.find(u8, diagnostic.message(), case.message) == null) {
            std.debug.print("manifest {s}: {s}\n", .{ case.source, diagnostic.message() });
            return error.TestUnexpectedResult;
        }
    }
}

test "manifest parsing stays bounded on fuzzed bytes" {
    try std.testing.fuzz({}, fuzzManifest, .{
        .corpus = &(@import("fuzz_seed").slices(.{
            "",
            "return { name = \"policy\", events = { \"pre_tool_use\" } }",
            "return { name = \"x\", events = { \"stop\" }, limits = { memory_mb = 1 } }",
            "while true do end",
            "local s = \"x\" for i = 1, 40 do s = s .. s end return s",
            "return setmetatable({}, { __gc = function() while true do end end })",
        }) ++ @import("fuzz_corpus").lua_manifest.*),
    });
}

fn fuzzManifest(_: void, smith: *std.testing.Smith) !void {
    var buffer: [4096]u8 = undefined;
    const len: usize = @intCast(smith.slice(&buffer));
    var diagnostic: types.Diagnostic = .{};
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const manifest = parse(arena.allocator(), std.testing.allocator, buffer[0..len], &diagnostic) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.InvalidManifest => return,
    };
    try std.testing.expect(validName(manifest.name));
    try std.testing.expect(manifest.events.count() > 0);
}

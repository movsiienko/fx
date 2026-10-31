//! Converts between JSON values and Lua values.
//!
//! JSON null is the `agent.json.null` light userdata. A decoded JSON array
//! carries the array metatable, so an empty array encodes back as `[]`. An
//! untagged table encodes as an array when its keys are exactly 1..n, and as
//! an object when every key is a string; an empty one encodes as `{}`.

const std = @import("std");
const c = @import("c.zig");

const max_depth = 64;

/// The address behind `agent.json.null`.
var json_null_marker: u8 = 0;

pub fn pushNull(L: ?*c.State) void {
    c.lua_pushlightuserdata(L, &json_null_marker);
}

fn isNull(L: ?*c.State, idx: c_int) bool {
    return c.lua_touserdata(L, idx) == @as(?*anyopaque, @ptrCast(&json_null_marker));
}

/// Where the array metatable lives: a registry reference, or none in a
/// state that has no `agent` API, such as the manifest sandbox.
pub const Tags = struct {
    array_mt_ref: c_int = c.LUA_NOREF,

    fn pushArrayMetatable(self: Tags, L: ?*c.State) bool {
        if (self.array_mt_ref == c.LUA_NOREF) return false;
        _ = c.lua_rawgeti(L, c.LUA_REGISTRYINDEX, self.array_mt_ref);
        return true;
    }
};

/// Pushes `value`. Must run inside a protected call: it raises on a stack
/// overflow, on nesting past `max_depth`, and when Lua runs out of memory.
pub fn push(L: ?*c.State, tags: Tags, value: std.json.Value) void {
    pushAt(L, tags, value, 0);
}

fn pushAt(L: ?*c.State, tags: Tags, value: std.json.Value, depth: usize) void {
    if (depth > max_depth) c.raise(L, "JSON value is nested too deeply");
    if (c.lua_checkstack(L, 4) == 0) c.raise(L, "Lua stack overflow");
    switch (value) {
        .null => pushNull(L),
        .bool => |b| c.lua_pushboolean(L, @intFromBool(b)),
        .integer => |i| c.lua_pushinteger(L, i),
        .float => |f| c.lua_pushnumber(L, f),
        .number_string => |s| pushNumberString(L, s),
        .string => |s| c.pushString(L, s),
        .array => |items| {
            c.lua_createtable(L, @intCast(@min(items.items.len, std.math.maxInt(c_int))), 0);
            if (tags.pushArrayMetatable(L)) _ = c.lua_setmetatable(L, -2);
            for (items.items, 1..) |item, i| {
                pushAt(L, tags, item, depth + 1);
                c.lua_rawseti(L, -2, @intCast(i));
            }
        },
        .object => |object| {
            c.lua_createtable(L, 0, @intCast(@min(object.count(), std.math.maxInt(c_int))));
            var it = object.iterator();
            while (it.next()) |entry| {
                c.pushString(L, entry.key_ptr.*);
                pushAt(L, tags, entry.value_ptr.*, depth + 1);
                c.lua_rawset(L, -3);
            }
        },
    }
}

/// A JSON number std.json kept as text, such as an integer past i64 or a
/// long decimal: Lua gets the nearest float.
fn pushNumberString(L: ?*c.State, digits: []const u8) void {
    if (std.fmt.parseInt(i64, digits, 10)) |integer| {
        c.lua_pushinteger(L, integer);
    } else |_| if (std.fmt.parseFloat(f64, digits)) |number| {
        c.lua_pushnumber(L, number);
    } else |_| {
        c.pushString(L, digits);
    }
}

const EncodeError = error{
    OutOfMemory,
    ResultTooLarge,
    NestedTooDeeply,
    UnsupportedValue,
    NonFiniteNumber,
    InvalidUtf8,
    MixedTable,
};

pub fn describe(err: EncodeError) []const u8 {
    return switch (err) {
        error.OutOfMemory => "not enough memory to encode the value",
        error.ResultTooLarge => "the encoded value is too large",
        error.NestedTooDeeply => "the value is nested too deeply",
        error.UnsupportedValue => "only nil, booleans, numbers, strings, tables and agent.json.null convert to JSON",
        error.NonFiniteNumber => "NaN and infinite numbers do not convert to JSON",
        error.InvalidUtf8 => "strings must be valid UTF-8 to convert to JSON",
        error.MixedTable => "a table must have only the keys 1..n or only string keys to convert to JSON",
    };
}

/// Writes the value at `idx` as JSON. It never raises, so it may run outside
/// a protected call: it reads values only through API calls that cannot fail
/// and never runs a metamethod.
pub fn encode(
    L: ?*c.State,
    tags: Tags,
    idx: c_int,
    out: *std.Io.Writer.Allocating,
    max_bytes: usize,
) EncodeError!void {
    var encoder = Encoder{ .L = L, .tags = tags, .out = out, .max_bytes = max_bytes };
    try encoder.value(c.lua_absindex(L, idx), 0);
}

/// Converts the value at `idx` to a JSON value in `arena` by the same rules
/// as `encode`, so a hook's result reaches fx without a JSON round trip. Like
/// `encode` it never raises. `max_bytes` caps the size the value would have
/// as JSON, not counting escapes, so the result stays as bounded as the
/// encoded text would be.
pub fn toValue(
    L: ?*c.State,
    tags: Tags,
    idx: c_int,
    arena: std.mem.Allocator,
    max_bytes: usize,
) EncodeError!std.json.Value {
    var builder = Builder{ .L = L, .tags = tags, .arena = arena, .max_bytes = max_bytes };
    return builder.value(c.lua_absindex(L, idx), 0);
}

/// Checks that `value` holds what valid JSON would: UTF-8 strings and keys,
/// and finite numbers. Past `max_depth` it stops looking, because `push`
/// refuses a value nested that deeply.
pub fn checkValue(value: std.json.Value) EncodeError!void {
    try checkValueAt(value, 0);
}

fn checkValueAt(value: std.json.Value, depth: usize) EncodeError!void {
    if (depth > max_depth) return;
    switch (value) {
        .null, .bool, .integer, .number_string => {},
        .float => |f| if (!std.math.isFinite(f)) return error.NonFiniteNumber,
        .string => |s| if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8,
        .array => |items| for (items.items) |item| try checkValueAt(item, depth + 1),
        .object => |object| {
            var it = object.iterator();
            while (it.next()) |entry| {
                if (!std.unicode.utf8ValidateSlice(entry.key_ptr.*)) return error.InvalidUtf8;
                try checkValueAt(entry.value_ptr.*, depth + 1);
            }
        },
    }
}

/// How a table converts: a tagged array, or keys exactly 1..n, make an
/// array of that length, and string keys make an object with that many
/// entries. An empty untagged table is an empty object.
const Shape = union(enum) {
    array: usize,
    object: usize,
};

/// The caller restores the stack top, since `MixedTable` leaves a key on it.
fn tableShape(L: ?*c.State, tags: Tags, idx: c_int) EncodeError!Shape {
    if (isTaggedArray(L, tags, idx)) return .{ .array = c.lua_rawlen(L, idx) };

    var count: usize = 0;
    var max_index: i64 = 0;
    var integer_keys = true;
    var string_keys = true;
    c.lua_pushnil(L);
    while (c.lua_next(L, idx) != 0) {
        c.pop(L, 1);
        count += 1;
        if (c.lua_type(L, -1) == c.LUA_TSTRING) {
            integer_keys = false;
        } else if (c.lua_type(L, -1) == c.LUA_TNUMBER and c.lua_isinteger(L, -1) != 0 and
            c.lua_tointegerx(L, -1, null) >= 1)
        {
            string_keys = false;
            max_index = @max(max_index, c.lua_tointegerx(L, -1, null));
        } else {
            return error.MixedTable;
        }
    }
    if (count == 0) return .{ .object = 0 };
    if (integer_keys) {
        if (max_index != @as(i64, @intCast(count))) return error.MixedTable;
        return .{ .array = count };
    }
    if (!string_keys) return error.MixedTable;
    return .{ .object = count };
}

fn isTaggedArray(L: ?*c.State, tags: Tags, idx: c_int) bool {
    if (c.lua_getmetatable(L, idx) == 0) return false;
    defer c.pop(L, 1);
    if (!tags.pushArrayMetatable(L)) return false;
    defer c.pop(L, 1);
    return c.lua_rawequal(L, -1, -2) != 0;
}

/// Copies each key and value of the object at `idx` onto the stack and
/// returns the stack indexes of the keys in sorted order, so equal tables
/// always convert the same way. The copies never allocate inside Lua, so
/// this still cannot raise. The caller frees the result with `allocator`.
fn sortedKeys(L: ?*c.State, idx: c_int, count: usize, allocator: std.mem.Allocator) EncodeError![]c_int {
    if (count > (std.math.maxInt(c_int) - 8) / 2 or c.lua_checkstack(L, @intCast(count * 2 + 4)) == 0) {
        return error.ResultTooLarge;
    }
    const base = c.lua_gettop(L);
    c.lua_pushnil(L);
    while (c.lua_next(L, idx) != 0) c.lua_pushvalue(L, -2);
    const order = allocator.alloc(c_int, count) catch return error.OutOfMemory;
    for (order, 0..) |*slot, i| slot.* = base + 1 + @as(c_int, @intCast(i)) * 2;
    std.mem.sort(c_int, order, L, keyLessThan);
    return order;
}

fn keyLessThan(L: ?*c.State, a: c_int, b: c_int) bool {
    return std.mem.lessThan(u8, c.stringAt(L, a).?, c.stringAt(L, b).?);
}

/// The JSON text of the number at `idx`. The buffer has room for the
/// longest decimal f64, about 330 digits.
fn numberText(L: ?*c.State, idx: c_int, buffer: *[512]u8) EncodeError![]const u8 {
    if (c.lua_isinteger(L, idx) != 0) {
        return std.mem.print(buffer, "{d}", .{c.lua_tointegerx(L, idx, null)}) catch unreachable;
    }
    const number = c.lua_tonumberx(L, idx, null);
    if (!std.math.isFinite(number)) return error.NonFiniteNumber;
    var fixed: std.Io.Writer = .fixed(buffer);
    std.json.Stringify.value(number, .{}, &fixed) catch unreachable;
    return fixed.buffered();
}

const Encoder = struct {
    L: ?*c.State,
    tags: Tags,
    out: *std.Io.Writer.Allocating,
    max_bytes: usize,

    fn write(self: *Encoder, bytes: []const u8) EncodeError!void {
        if (self.out.written().len + bytes.len > self.max_bytes) return error.ResultTooLarge;
        self.out.writer.writeAll(bytes) catch return error.OutOfMemory;
    }

    fn writeString(self: *Encoder, bytes: []const u8) EncodeError!void {
        if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidUtf8;
        if (self.out.written().len + bytes.len + 2 > self.max_bytes) return error.ResultTooLarge;
        std.json.Stringify.value(bytes, .{}, &self.out.writer) catch return error.OutOfMemory;
        if (self.out.written().len > self.max_bytes) return error.ResultTooLarge;
    }

    fn value(self: *Encoder, idx: c_int, depth: usize) EncodeError!void {
        const L = self.L;
        switch (c.lua_type(L, idx)) {
            c.LUA_TNIL, c.LUA_TNONE => try self.write("null"),
            c.LUA_TBOOLEAN => try self.write(if (c.lua_toboolean(L, idx) != 0) "true" else "false"),
            c.LUA_TLIGHTUSERDATA => {
                if (!isNull(L, idx)) return error.UnsupportedValue;
                try self.write("null");
            },
            c.LUA_TNUMBER => {
                var buffer: [512]u8 = undefined;
                try self.write(try numberText(L, idx, &buffer));
            },
            c.LUA_TSTRING => try self.writeString(c.stringAt(L, idx).?),
            c.LUA_TTABLE => try self.table(idx, depth),
            else => return error.UnsupportedValue,
        }
    }

    fn table(self: *Encoder, idx: c_int, depth: usize) EncodeError!void {
        const L = self.L;
        if (depth >= max_depth) return error.NestedTooDeeply;
        if (c.lua_checkstack(L, 4) == 0) return error.NestedTooDeeply;
        const top = c.lua_gettop(L);
        defer c.lua_settop(L, top);

        const count = switch (try tableShape(L, self.tags, idx)) {
            .array => |len| return self.array(idx, len, depth),
            .object => |entries| entries,
        };
        const order = try sortedKeys(L, idx, count, self.out.allocator);
        defer self.out.allocator.free(order);

        try self.write("{");
        for (order, 0..) |key_index, i| {
            if (i > 0) try self.write(",");
            try self.writeString(c.stringAt(L, key_index).?);
            try self.write(":");
            try self.value(key_index + 1, depth + 1);
        }
        try self.write("}");
    }

    fn array(self: *Encoder, idx: c_int, len: usize, depth: usize) EncodeError!void {
        const L = self.L;
        try self.write("[");
        var i: usize = 1;
        while (i <= len) : (i += 1) {
            if (i > 1) try self.write(",");
            _ = c.lua_rawgeti(L, idx, @intCast(i));
            try self.value(c.lua_absindex(L, -1), depth + 1);
            c.pop(L, 1);
        }
        try self.write("]");
    }
};

/// Builds a JSON value by the encoder's rules, counting the bytes the value
/// would take as JSON so it stays within `max_bytes`.
const Builder = struct {
    L: ?*c.State,
    tags: Tags,
    arena: std.mem.Allocator,
    max_bytes: usize,
    used: usize = 0,

    fn charge(self: *Builder, bytes: usize) EncodeError!void {
        if (bytes > self.max_bytes - self.used) return error.ResultTooLarge;
        self.used += bytes;
    }

    /// Copies the string at `idx` out of Lua, which may free it once the
    /// call returns.
    fn string(self: *Builder, idx: c_int) EncodeError![]const u8 {
        const bytes = c.stringAt(self.L, idx).?;
        if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidUtf8;
        try self.charge(bytes.len + 2);
        return self.arena.dupe(u8, bytes) catch error.OutOfMemory;
    }

    fn value(self: *Builder, idx: c_int, depth: usize) EncodeError!std.json.Value {
        const L = self.L;
        switch (c.lua_type(L, idx)) {
            c.LUA_TNIL, c.LUA_TNONE => {
                try self.charge("null".len);
                return .null;
            },
            c.LUA_TBOOLEAN => {
                const b = c.lua_toboolean(L, idx) != 0;
                try self.charge(if (b) "true".len else "false".len);
                return .{ .bool = b };
            },
            c.LUA_TLIGHTUSERDATA => {
                if (!isNull(L, idx)) return error.UnsupportedValue;
                try self.charge("null".len);
                return .null;
            },
            c.LUA_TNUMBER => {
                var buffer: [512]u8 = undefined;
                try self.charge((try numberText(L, idx, &buffer)).len);
                if (c.lua_isinteger(L, idx) != 0) return .{ .integer = c.lua_tointegerx(L, idx, null) };
                return .{ .float = c.lua_tonumberx(L, idx, null) };
            },
            c.LUA_TSTRING => return .{ .string = try self.string(idx) },
            c.LUA_TTABLE => return self.table(idx, depth),
            else => return error.UnsupportedValue,
        }
    }

    fn table(self: *Builder, idx: c_int, depth: usize) EncodeError!std.json.Value {
        const L = self.L;
        if (depth >= max_depth) return error.NestedTooDeeply;
        if (c.lua_checkstack(L, 4) == 0) return error.NestedTooDeeply;
        const top = c.lua_gettop(L);
        defer c.lua_settop(L, top);

        // The brackets, then a separator before each item but the first.
        try self.charge(2);
        const count = switch (try tableShape(L, self.tags, idx)) {
            .array => |len| return self.array(idx, len, depth),
            .object => |entries| entries,
        };
        const order = try sortedKeys(L, idx, count, self.arena);
        defer self.arena.free(order);

        // The map keeps the sorted order, so the value serializes the way
        // `encode` writes it.
        var object: std.json.ObjectMap = .empty;
        for (order, 0..) |key_index, i| {
            if (i > 0) try self.charge(1);
            const key = try self.string(key_index);
            try self.charge(1);
            const item = try self.value(key_index + 1, depth + 1);
            object.putNoClobber(self.arena, key, item) catch return error.OutOfMemory;
        }
        return .{ .object = object };
    }

    fn array(self: *Builder, idx: c_int, len: usize, depth: usize) EncodeError!std.json.Value {
        const L = self.L;
        var items: std.json.Array = .init(self.arena);
        var i: usize = 1;
        while (i <= len) : (i += 1) {
            if (i > 1) try self.charge(1);
            _ = c.lua_rawgeti(L, idx, @intCast(i));
            const item = try self.value(c.lua_absindex(L, -1), depth + 1);
            c.pop(L, 1);
            items.append(item) catch return error.OutOfMemory;
        }
        return .{ .array = items };
    }
};

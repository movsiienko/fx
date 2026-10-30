//! Converts between JSON values and Lua values.
//!
//! JSON null is the `agent.json.null` light userdata. A decoded JSON array
//! carries the array metatable, so an empty array encodes back as `[]`. An
//! untagged table encodes as an array when its keys are exactly 1..n, and as
//! an object when every key is a string; an empty one encodes as `{}`.

const std = @import("std");
const c = @import("c.zig");

pub const max_depth = 64;

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

pub const EncodeError = error{
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
                // Room for the longest decimal f64, about 330 digits.
                var buffer: [512]u8 = undefined;
                if (c.lua_isinteger(L, idx) != 0) {
                    const text = std.mem.print(&buffer, "{d}", .{c.lua_tointegerx(L, idx, null)}) catch unreachable;
                    try self.write(text);
                } else {
                    const number = c.lua_tonumberx(L, idx, null);
                    if (!std.math.isFinite(number)) return error.NonFiniteNumber;
                    var fixed: std.Io.Writer = .fixed(&buffer);
                    std.json.Stringify.value(number, .{}, &fixed) catch unreachable;
                    try self.write(fixed.buffered());
                }
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

        if (self.isTaggedArray(idx)) return self.array(idx, c.lua_rawlen(L, idx), depth);

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
        if (count == 0) return self.write("{}");
        if (integer_keys) {
            if (max_index != @as(i64, @intCast(count))) return error.MixedTable;
            return self.array(idx, count, depth);
        }
        if (!string_keys) return error.MixedTable;

        // Keys go out sorted, so equal tables always encode the same way.
        // Each key and value is copied onto the stack, which never
        // allocates inside Lua, so this still cannot raise.
        if (count > (std.math.maxInt(c_int) - 8) / 2 or c.lua_checkstack(L, @intCast(count * 2 + 4)) == 0) {
            return error.ResultTooLarge;
        }
        const base = c.lua_gettop(L);
        c.lua_pushnil(L);
        while (c.lua_next(L, idx) != 0) c.lua_pushvalue(L, -2);
        const order = self.out.allocator.alloc(c_int, count) catch return error.OutOfMemory;
        defer self.out.allocator.free(order);
        for (order, 0..) |*slot, i| slot.* = base + 1 + @as(c_int, @intCast(i)) * 2;
        std.mem.sort(c_int, order, L, keyLessThan);

        try self.write("{");
        for (order, 0..) |key_index, i| {
            if (i > 0) try self.write(",");
            try self.writeString(c.stringAt(L, key_index).?);
            try self.write(":");
            try self.value(key_index + 1, depth + 1);
        }
        try self.write("}");
    }

    fn keyLessThan(L: ?*c.State, a: c_int, b: c_int) bool {
        return std.mem.lessThan(u8, c.stringAt(L, a).?, c.stringAt(L, b).?);
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

    fn isTaggedArray(self: *Encoder, idx: c_int) bool {
        const L = self.L;
        if (c.lua_getmetatable(L, idx) == 0) return false;
        defer c.pop(L, 1);
        if (!self.tags.pushArrayMetatable(L)) return false;
        defer c.pop(L, 1);
        return c.lua_rawequal(L, -1, -2) != 0;
    }
};

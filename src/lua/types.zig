//! Types the engine's files share and its front door re-exports.

const std = @import("std");
const c = @import("c.zig");

/// The fx hook an extension subscribes to with `agent.on`.
pub const Event = enum {
    pre_tool_use,
    stop,
    post_turn_end,
    attention_required,
};

pub const EventSet = std.EnumSet(Event);

/// The agent surfaces an extension's hooks may run in.
pub const Scope = enum {
    interactive,
    ask,
    acp,
    subagent,
};

pub const ScopeSet = std.EnumSet(Scope);

pub const Limits = struct {
    pub const default_memory_bytes: usize = 4 * 1024 * 1024;
    pub const max_memory_mb: usize = 64;
    pub const default_instructions_per_call: u32 = 5_000_000;
    pub const min_instructions_per_call: u32 = 1_000;
    pub const max_instructions_per_call: u32 = 1_000_000_000;

    memory_bytes: usize = default_memory_bytes,
    instructions_per_call: u32 = default_instructions_per_call,
};

/// A readable reason for the last failure, kept in a fixed buffer so a
/// failure never needs memory of its own.
pub const Diagnostic = struct {
    pub const max_bytes = 1024;

    buffer: [max_bytes]u8 = undefined,
    len: usize = 0,

    pub fn message(self: *const Diagnostic) []const u8 {
        return self.buffer[0..self.len];
    }

    pub fn set(self: *Diagnostic, text: []const u8) void {
        var end = @min(text.len, max_bytes);
        // Never cut a UTF-8 sequence in half.
        while (end < text.len and end > 0 and (text[end] & 0xC0) == 0x80) end -= 1;
        @memcpy(self.buffer[0..end], text[0..end]);
        self.len = end;
    }

    pub fn print(self: *Diagnostic, comptime fmt: []const u8, args: anytype) void {
        var scratch: [max_bytes]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&scratch);
        writer.print(fmt, args) catch {};
        self.set(writer.buffered());
    }

    /// Takes the error a failed protected call left on top of the stack.
    pub fn capture(self: *Diagnostic, L: ?*c.State, status: c_int) void {
        if (status == c.LUA_ERRMEM) {
            self.set("not enough memory (the extension's memory limit)");
        } else if (c.stringAt(L, -1)) |text| {
            self.set(text);
        } else {
            self.print("error object is a {s} value", .{c.typeName(L, -1)});
        }
        c.pop(L, 1);
    }
};

/// Count hook for the instruction budget. Once the budget is spent it fires
/// on every instruction, so a `pcall` in the extension cannot catch the
/// error and keep running.
pub fn onInstructionBudget(L: ?*c.State, _: ?*c.Debug) callconv(.c) void {
    c.lua_sethook(L, onInstructionBudget, c.LUA_MASKCOUNT, 1);
    c.raise(L, "instruction budget exceeded");
}

pub fn armInstructionBudget(L: ?*c.State, instructions: u32) void {
    c.lua_sethook(L, onInstructionBudget, c.LUA_MASKCOUNT, @intCast(@min(instructions, std.math.maxInt(c_int))));
}

pub fn disarmInstructionBudget(L: ?*c.State) void {
    c.lua_sethook(L, null, 0, 0);
}

test "diagnostics keep UTF-8 whole when they truncate" {
    var diagnostic: Diagnostic = .{};
    var long: [1200]u8 = undefined;
    for (0..600) |i| @memcpy(long[i * 2 ..][0..2], "é");
    diagnostic.set(&long);
    try std.testing.expect(diagnostic.len <= Diagnostic.max_bytes);
    try std.testing.expect(std.unicode.utf8ValidateSlice(diagnostic.message()));
}

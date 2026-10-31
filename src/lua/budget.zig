//! A memory cap for one extension. Every byte the extension's Lua state and
//! its scratch memory hold goes through `Budget`, which refuses an
//! allocation that would take the total past `cap`. Lua turns a refusal into
//! a "not enough memory" error inside the extension.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

/// `max_align_t` on every target fx embeds Lua in.
const lua_alignment: Alignment = .@"16";

pub const Budget = struct {
    gpa: Allocator,
    cap: usize,
    used: usize = 0,

    pub fn init(gpa: Allocator, cap: usize) Budget {
        return .{ .gpa = gpa, .cap = cap };
    }

    pub fn allocator(self: *Budget) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn reserve(self: *Budget, len: usize) bool {
        if (len > self.cap - self.used) return false;
        self.used += len;
        return true;
    }

    fn release(self: *Budget, len: usize) void {
        std.debug.assert(len <= self.used);
        self.used -= len;
    }

    const vtable: Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (!self.reserve(len)) return null;
        return self.gpa.rawAlloc(len, alignment, ret_addr) orelse {
            self.release(len);
            return null;
        };
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len) {
            if (!self.reserve(new_len - memory.len)) return false;
            if (self.gpa.rawResize(memory, alignment, new_len, ret_addr)) return true;
            self.release(new_len - memory.len);
            return false;
        }
        if (!self.gpa.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.release(memory.len - new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len) {
            if (!self.reserve(new_len - memory.len)) return null;
            return self.gpa.rawRemap(memory, alignment, new_len, ret_addr) orelse {
                self.release(new_len - memory.len);
                return null;
            };
        }
        const moved = self.gpa.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.release(memory.len - new_len);
        return moved;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        self.gpa.rawFree(memory, alignment, ret_addr);
        self.release(memory.len);
    }
};

/// The `lua_Alloc` function for a state whose `ud` is a `*Budget`. Lua
/// passes the old size on every call, so blocks need no size header.
pub fn luaAlloc(ud: ?*anyopaque, ptr: ?*anyopaque, osize: usize, nsize: usize) callconv(.c) ?*anyopaque {
    const budget: *Budget = @ptrCast(@alignCast(ud.?));
    const a = budget.allocator();
    // With no block, `osize` holds the kind of object Lua is creating.
    const old: []u8 = if (ptr) |p| @as([*]u8, @ptrCast(p))[0..osize] else &.{};
    if (nsize == 0) {
        if (old.len != 0) a.rawFree(old, lua_alignment, @returnAddress());
        return null;
    }
    if (old.len == 0) return a.rawAlloc(nsize, lua_alignment, @returnAddress());
    if (a.rawRemap(old, lua_alignment, nsize, @returnAddress())) |moved| return moved;
    const fresh = a.rawAlloc(nsize, lua_alignment, @returnAddress()) orelse return null;
    @memcpy(fresh[0..@min(old.len, nsize)], old[0..@min(old.len, nsize)]);
    a.rawFree(old, lua_alignment, @returnAddress());
    return fresh;
}

test "budget refuses allocations past its cap and returns freed bytes" {
    var budget = Budget.init(std.testing.allocator, 64);
    const a = budget.allocator();
    const first = try a.alloc(u8, 40);
    try std.testing.expectEqual(@as(usize, 40), budget.used);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 32));
    a.free(first);
    try std.testing.expectEqual(@as(usize, 0), budget.used);
    const second = try a.alloc(u8, 64);
    defer a.free(second);
    try std.testing.expectEqual(@as(usize, 64), budget.used);
}

test "the Lua allocator grows, shrinks, and frees within the budget" {
    var budget = Budget.init(std.testing.allocator, 1024);
    const block = luaAlloc(&budget, null, 0, 100) orelse return error.TestUnexpectedResult;
    @memset(@as([*]u8, @ptrCast(block))[0..100], 7);
    const grown = luaAlloc(&budget, block, 100, 400) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 7), @as([*]u8, @ptrCast(grown))[99]);
    try std.testing.expectEqual(@as(usize, 400), budget.used);
    try std.testing.expect(luaAlloc(&budget, grown, 400, 2000) == null);
    try std.testing.expectEqual(@as(usize, 400), budget.used);
    const shrunk = luaAlloc(&budget, grown, 400, 50) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 50), budget.used);
    _ = luaAlloc(&budget, shrunk, 50, 0);
    try std.testing.expectEqual(@as(usize, 0), budget.used);
}

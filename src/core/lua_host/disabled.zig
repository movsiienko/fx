//! Lua hooks in a build without Lua: nothing loads, and `fx extensions`
//! reports that extensions are unavailable.

const std = @import("std");
const hooks = @import("../hooks/hooks.zig");
const listing = @import("listing.zig");

pub const RegisterOptions = struct {
    home: ?[]const u8 = null,
};

pub const Summary = struct {
    loaded: usize = 0,
    needs_review: []const []const u8 = &.{},
    load_failures: []const LoadFailure = &.{},
    unreadable_folder: ?UnreadableFolder = null,
};

pub const LoadFailure = struct {
    name: []const u8,
    message: []const u8,
};

pub const UnreadableFolder = struct {
    path: []const u8,
    reason: []const u8,
};

pub const Hooks = struct {
    pub fn register(_: *Hooks, _: std.mem.Allocator, _: *hooks.Runtime, _: RegisterOptions) !Summary {
        return .{};
    }

    pub fn deinit(_: *Hooks) void {}
};

pub fn execute(_: std.mem.Allocator, _: listing.Action, _: ?[]const u8) !listing.Listing {
    return error.ExtensionsUnavailable;
}

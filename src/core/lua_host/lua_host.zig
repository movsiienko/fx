//! fx's host for Lua extension hooks, and the front door of
//! `src/core/lua_host/`. It adapts the Lua engine in `src/lua/` to fx's
//! Hooks v1.0 runtime: each trusted extension's handlers register as
//! ordinary handlers before the runtime freezes, so they run on fx's four
//! hook points with fx's own contracts, ordering, and limits.
//!
//! Extensions come only from `~/.fx/extensions/`, and run only after the
//! user trusts their current contents with `fx extensions trust`. Builds
//! without Lua (libfx) get the same surface, which finds nothing to load.

const std = @import("std");
const build_options = @import("build_options");
const listing = @import("listing.zig");

pub const enabled = build_options.lua_hooks;
const impl = if (enabled) @import("runtime.zig") else @import("disabled.zig");

pub const Hooks = impl.Hooks;
pub const RegisterOptions = impl.RegisterOptions;
pub const Summary = impl.Summary;
pub const execute = impl.execute;

pub const State = listing.State;
pub const Entry = listing.Entry;
pub const Action = listing.Action;
pub const Listing = listing.Listing;
pub const parseAction = listing.parseAction;
pub const errorMessage = listing.errorMessage;

/// Registers Lua hooks for an interactive app and tells the user about
/// extensions waiting for review. `App` holds `lua_hooks: Hooks`, the
/// unfrozen `lifecycle_runtime`, and `appendDomainNotice`.
pub fn AppRuntime(comptime App: type) type {
    return struct {
        /// Must run before the lifecycle runtime freezes.
        pub fn configure(app: *App) !void {
            const summary = try app.lua_hooks.register(app.alloc, &app.lifecycle_runtime, .{});
            const notice = try noticeText(app.alloc, summary, "/extensions") orelse return;
            defer app.alloc.free(notice);
            _ = try app.appendDomainNotice(.{ .topic = "extensions", .tone = .warning, .body = notice });
        }
    };
}

/// The session-start notice for `summary`, or null when there is nothing
/// to say. `review_command` is how the user lists extensions from here.
/// The caller owns the result.
pub fn noticeText(alloc: std.mem.Allocator, summary: Summary, review_command: []const u8) !?[]u8 {
    if (summary.needs_review.len == 0 and summary.load_failures.len == 0) return null;
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;
    if (summary.needs_review.len == 1) {
        try w.print("Lua extension {s} is new or changed and won't run until you review it. Run {s} to see it.", .{
            summary.needs_review[0],
            review_command,
        });
    } else if (summary.needs_review.len > 1) {
        try w.print("{d} Lua extensions are new or changed and won't run until you review them: ", .{summary.needs_review.len});
        for (summary.needs_review, 0..) |name, i| {
            if (i > 0) try w.writeAll(", ");
            try w.writeAll(name);
        }
        try w.print(". Run {s} to see them.", .{review_command});
    }
    for (summary.load_failures) |failure| {
        if (out.written().len > 0) try w.writeByte('\n');
        try w.print("Lua extension {s} failed to load: {s}", .{ failure.name, failure.message });
    }
    return try out.toOwnedSlice();
}

test "the session-start notice names extensions waiting for review" {
    const alloc = std.testing.allocator;
    try std.testing.expect(try noticeText(alloc, .{}, "/extensions") == null);
    const one = (try noticeText(alloc, .{ .needs_review = &.{"policy"} }, "/extensions")).?;
    defer alloc.free(one);
    try std.testing.expectEqualStrings("Lua extension policy is new or changed and won't run until you review it. Run /extensions to see it.", one);
    const two = (try noticeText(alloc, .{
        .needs_review = &.{ "a", "b" },
        .load_failures = &.{.{ .name = "c", .message = "main.lua:1: boom" }},
    }, "fx extensions list")).?;
    defer alloc.free(two);
    try std.testing.expectEqualStrings(
        "2 Lua extensions are new or changed and won't run until you review them: a, b. Run fx extensions list to see them.\n" ++
            "Lua extension c failed to load: main.lua:1: boom",
        two,
    );
}

test {
    _ = listing;
    _ = impl;
    if (enabled) {
        _ = @import("catalog.zig");
        _ = @import("adapter.zig");
    }
}

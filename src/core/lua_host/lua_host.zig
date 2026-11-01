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
const text_utils = @import("../shared/text_utils.zig");
const listing = @import("listing.zig");

const enabled = build_options.lua_hooks;
const impl = if (enabled) @import("runtime.zig") else @import("disabled.zig");

pub const Hooks = impl.Hooks;
const Summary = impl.Summary;
pub const execute = impl.execute;

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
/// Folder names and Lua error text reach the terminal as visible escapes,
/// since anything that can write to `~/.fx/extensions/` chooses them.
/// The caller owns the result.
pub fn noticeText(alloc: std.mem.Allocator, summary: Summary, review_command: []const u8) !?[]u8 {
    if (summary.needs_review.len == 0 and summary.load_failures.len == 0 and summary.stopped_invalid.len == 0 and
        summary.unreadable_folder == null) return null;
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;
    if (summary.unreadable_folder) |folder| {
        try w.writeAll("Lua extensions in ");
        try writeTerminalSafe(w, alloc, folder.path);
        try w.writeAll(" cannot be read (");
        try writeTerminalSafe(w, alloc, folder.reason);
        try w.writeAll("), so none of them run.");
    }
    if (summary.needs_review.len == 1) {
        try w.writeAll("Lua extension ");
        try writeTerminalSafe(w, alloc, summary.needs_review[0]);
        try w.print(" is new or changed and won't run until you review it. Run {s} to see it.", .{review_command});
    } else if (summary.needs_review.len > 1) {
        try w.print("{d} Lua extensions are new or changed and won't run until you review them: ", .{summary.needs_review.len});
        for (summary.needs_review, 0..) |name, i| {
            if (i > 0) try w.writeAll(", ");
            try writeTerminalSafe(w, alloc, name);
        }
        try w.print(". Run {s} to see them.", .{review_command});
    }
    for (summary.stopped_invalid) |stopped| {
        if (out.written().len > 0) try w.writeByte('\n');
        try w.writeAll("Lua extension ");
        try writeTerminalSafe(w, alloc, stopped.name);
        try w.writeAll(" is trusted but invalid, so it won't run: ");
        try writeTerminalSafe(w, alloc, stopped.message);
        try w.print(". Run {s} to see it.", .{review_command});
    }
    for (summary.load_failures) |failure| {
        if (out.written().len > 0) try w.writeByte('\n');
        try w.writeAll("Lua extension ");
        try writeTerminalSafe(w, alloc, failure.name);
        try w.writeAll(" failed to load: ");
        try writeTerminalSafe(w, alloc, failure.message);
    }
    return try out.toOwnedSlice();
}

fn writeTerminalSafe(w: *std.Io.Writer, alloc: std.mem.Allocator, raw: []const u8) !void {
    const encoded = try text_utils.encodeTerminalSafe(alloc, raw, std.math.maxInt(usize));
    defer alloc.free(encoded.bytes);
    try w.writeAll(encoded.bytes);
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

test "the session-start notice escapes control bytes in names and Lua errors" {
    const alloc = std.testing.allocator;
    for ([_]Summary{
        .{ .needs_review = &.{"x\x1b]52;c;aGk=\x07"} },
        .{
            .needs_review = &.{ "a\x1b[2K", "b" },
            .load_failures = &.{.{ .name = "c\x07", .message = "main.lua:1: \x1b]0;pwned\x07\r\nboom" }},
        },
    }) |summary| {
        const notice = (try noticeText(alloc, summary, "fx extensions list")).?;
        defer alloc.free(notice);
        for (notice) |byte| {
            if (byte == '\n') continue;
            try std.testing.expect(byte >= 0x20 and byte != 0x7f);
        }
    }
    const two = (try noticeText(alloc, .{
        .needs_review = &.{ "a\x1b[2K", "b" },
        .load_failures = &.{.{ .name = "c\x07", .message = "main.lua:1: \x1b]0;pwned\x07\r\nboom" }},
    }, "fx extensions list")).?;
    defer alloc.free(two);
    try std.testing.expectEqualStrings(
        "2 Lua extensions are new or changed and won't run until you review them: a\\x1b[2K, b. Run fx extensions list to see them.\n" ++
            "Lua extension c\\x07 failed to load: main.lua:1: \\x1b]0;pwned\\x07\\x0d\\x0aboom",
        two,
    );
}

test "the session-start notice says when the whole extensions folder cannot be read" {
    if (!enabled) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const io_mod = @import("../shared/io.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".fx");
    // A link to itself fails to open for root too.
    try tmp.dir.symLink(std.testing.io, "extensions", ".fx/extensions", .{ .is_directory = true });
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var runtime = @import("../hooks/hooks.zig").Runtime.init(alloc);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    const summary = try lua_hooks.register(alloc, &runtime, .{ .home = home });
    const notice = (try noticeText(alloc, summary, "/extensions")).?;
    defer alloc.free(notice);
    const expected = try alloc.print("Lua extensions in {s}/.fx/extensions cannot be read (SymLinkLoop), so none of them run.", .{home});
    defer alloc.free(expected);
    try std.testing.expectEqualStrings(expected, notice);
}

/// Writes extension `policy`, trusts it when `trust` is set, then makes
/// it invalid with a main.lua over the 1 MiB limit, which fails for root
/// too. Returns the session-start notice, which the caller owns.
fn noticeAfterBreakingExtension(trust: bool) !?[]u8 {
    const alloc = std.testing.allocator;
    const io_mod = @import("../shared/io.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".fx/extensions/policy");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".fx/extensions/policy/manifest.lua",
        .data = "return { name = \"policy\", events = { \"stop\" } }",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".fx/extensions/policy/main.lua", .data = "agent.on(\"stop\", function() end)" });
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);
    if (trust) {
        var trusted = try execute(alloc, .{ .trust = .{ .name = "policy" } }, home);
        trusted.deinit();
    }

    const oversized = try alloc.alloc(u8, 1024 * 1024 + 1);
    defer alloc.free(oversized);
    @memset(oversized, '-');
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".fx/extensions/policy/main.lua", .data = oversized });

    var runtime = @import("../hooks/hooks.zig").Runtime.init(alloc);
    defer runtime.deinit();
    var lua_hooks: Hooks = .{};
    defer lua_hooks.deinit();
    const summary = try lua_hooks.register(alloc, &runtime, .{ .home = home });
    return noticeText(alloc, summary, "fx extensions list");
}

test "the session-start notice names a trusted extension that became invalid" {
    if (!enabled) return error.SkipZigTest;
    const notice = (try noticeAfterBreakingExtension(true)) orelse return error.TestExpectedNotice;
    defer std.testing.allocator.free(notice);
    try std.testing.expectEqualStrings(
        "Lua extension policy is trusted but invalid, so it won't run: main.lua is larger than 1 MiB. Run fx extensions list to see it.",
        notice,
    );
}

test "an invalid extension that was never trusted gets no session-start notice" {
    if (!enabled) return error.SkipZigTest;
    const notice = try noticeAfterBreakingExtension(false);
    defer if (notice) |text| std.testing.allocator.free(text);
    try std.testing.expectEqual(null, notice);
}

test {
    _ = listing;
    _ = impl;
    if (enabled) {
        _ = @import("catalog.zig");
        _ = @import("adapter.zig");
    }
}

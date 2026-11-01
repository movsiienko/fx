//! The typed contract of `fx extensions` and `/extensions`: the actions they
//! take and the listing they report. Nothing here needs Lua, so output code
//! can render a listing in every build.

const std = @import("std");

pub const State = enum {
    /// New, or a file changed since it was trusted. Does not run.
    needs_review,
    /// Every file matches the trusted hashes. Runs.
    trusted,
    /// Trusted, but switched off. Does not run.
    disabled,
    /// Trusted, but recent calls failed. Runs; a failing `PreToolUse` hook
    /// blocks the tool call.
    failing,
    /// The folder or its manifest cannot be loaded. Does not run.
    invalid,

    pub fn runs(self: State) bool {
        return self == .trusted or self == .failing;
    }
};

pub const Entry = struct {
    name: []const u8,
    version: []const u8 = "",
    state: State,
    events: []const []const u8 = &.{},
    scopes: []const []const u8 = &.{},
    kv: bool = false,
    memory_mb: usize = 0,
    instructions_per_call: u32 = 0,
    timeout_ms: u32 = 0,
    file_count: usize = 0,
    sha256: []const u8 = "",
    /// Files added, changed, or removed since the extension was trusted.
    changed_files: []const []const u8 = &.{},
    failures: u64 = 0,
    last_error: ?[]const u8 = null,
    /// Why an invalid extension cannot load.
    problem: ?[]const u8 = null,

    /// The digest prefix listings show and `trust` accepts.
    pub fn digestPrefix(self: Entry) []const u8 {
        return self.sha256[0..@min(self.sha256.len, digest_prefix_len)];
    }
};

/// The shortest digest prefix `trust` accepts, and the one listings show.
const digest_prefix_len = 12;
const digest_len = 64;

const Trust = struct {
    name: []const u8,
    /// The digest, or a prefix of it, of the files the user reviewed.
    /// When set, trust refuses files that no longer match it.
    sha256: ?[]const u8 = null,
};

pub const Action = union(enum) {
    list,
    trust: Trust,
    disable: []const u8,
    enable: []const u8,

    pub fn verb(self: Action) []const u8 {
        return @tagName(self);
    }

    pub fn target(self: Action) ?[]const u8 {
        return switch (self) {
            .list => null,
            .trust => |trust| trust.name,
            .disable, .enable => |name| name,
        };
    }
};

const ParseError = error{InvalidExtensionsArgs};

/// Parses `[list | trust NAME [SHA256] | disable NAME | enable NAME]`.
pub fn parseAction(words: []const []const u8) ParseError!Action {
    if (words.len == 0) return .list;
    const verb = words[0];
    if (std.mem.eql(u8, verb, "list")) {
        if (words.len != 1) return error.InvalidExtensionsArgs;
        return .list;
    }
    if (words.len < 2 or words[1].len == 0) return error.InvalidExtensionsArgs;
    if (std.mem.eql(u8, verb, "trust")) {
        if (words.len > 3) return error.InvalidExtensionsArgs;
        const sha256 = if (words.len == 3) words[2] else null;
        if (sha256) |digest| if (!isDigestPrefix(digest)) return error.InvalidExtensionsArgs;
        return .{ .trust = .{ .name = words[1], .sha256 = sha256 } };
    }
    if (words.len != 2) return error.InvalidExtensionsArgs;
    if (std.mem.eql(u8, verb, "disable")) return .{ .disable = words[1] };
    if (std.mem.eql(u8, verb, "enable")) return .{ .enable = words[1] };
    return error.InvalidExtensionsArgs;
}

fn isDigestPrefix(text: []const u8) bool {
    if (text.len < digest_prefix_len or text.len > digest_len) return false;
    for (text) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

/// What `fx extensions` reports. `entries` and everything they point to
/// live in `arena`, which the listing owns.
pub const Listing = struct {
    arena: std.heap.ArenaAllocator,
    directory: []const u8,
    entries: []const Entry,
    action: Action = .list,

    pub fn deinit(self: *Listing) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn find(self: *const Listing, name: []const u8) ?*const Entry {
        for (self.entries) |*entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry;
        }
        return null;
    }
};

pub fn errorMessage(err: anyerror) ?[]const u8 {
    return switch (err) {
        error.InvalidExtensionsArgs => null,
        error.UnknownExtension => "no extension with that name in ~/.fx/extensions",
        error.ExtensionInvalid => "the extension cannot load; fix the problem fx extensions list reports first",
        error.ExtensionChanged => "the extension's files changed since you reviewed them; list it again and review the new files",
        error.ExtensionsUnavailable => "Lua extensions are not available in this build",
        error.HomeNotSet => "HOME is not set",
        error.SettingsCommitIndeterminate => "settings durability is uncertain; run fx extensions list to check the result",
        error.SettingsLockBusy => "another fx process is updating settings; try again",
        error.FailuresNotCleared => "the extension is trusted, but its failure record could not be cleared, as another fx process may be writing it; run fx extensions trust again",
        error.InvalidSettingsFormat => "~/.fx/settings.json is not valid",
        else => "extensions update failed",
    };
}

test "extension actions parse from words" {
    try std.testing.expectEqual(Action.list, try parseAction(&.{}));
    try std.testing.expectEqual(Action.list, try parseAction(&.{"list"}));
    try std.testing.expectEqualStrings("policy", (try parseAction(&.{ "trust", "policy" })).trust.name);
    try std.testing.expectEqualStrings("policy", (try parseAction(&.{ "disable", "policy" })).disable);
    try std.testing.expectEqualStrings("policy", (try parseAction(&.{ "enable", "policy" })).enable);
    try std.testing.expectError(error.InvalidExtensionsArgs, parseAction(&.{"trust"}));
    try std.testing.expectError(error.InvalidExtensionsArgs, parseAction(&.{ "list", "extra" }));
    try std.testing.expectError(error.InvalidExtensionsArgs, parseAction(&.{ "remove", "policy" }));
}

test "trust takes an optional digest of the reviewed files" {
    const bare = try parseAction(&.{ "trust", "policy" });
    try std.testing.expectEqualStrings("policy", bare.trust.name);
    try std.testing.expect(bare.trust.sha256 == null);
    try std.testing.expectEqualStrings("policy", bare.target().?);

    const prefix = try parseAction(&.{ "trust", "policy", "0123456789ab" });
    try std.testing.expectEqualStrings("policy", prefix.trust.name);
    try std.testing.expectEqualStrings("0123456789ab", prefix.trust.sha256.?);

    const full = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try std.testing.expectEqualStrings(full, (try parseAction(&.{ "trust", "policy", full })).trust.sha256.?);

    // Too short, too long, not hex, or uppercase.
    try std.testing.expectError(error.InvalidExtensionsArgs, parseAction(&.{ "trust", "policy", "0123456789a" }));
    try std.testing.expectError(error.InvalidExtensionsArgs, parseAction(&.{ "trust", "policy", full ++ "0" }));
    try std.testing.expectError(error.InvalidExtensionsArgs, parseAction(&.{ "trust", "policy", "0123456789ag" }));
    try std.testing.expectError(error.InvalidExtensionsArgs, parseAction(&.{ "trust", "policy", "0123456789AB" }));
    // Only trust takes a digest.
    try std.testing.expectError(error.InvalidExtensionsArgs, parseAction(&.{ "disable", "policy", "0123456789ab" }));
    try std.testing.expectError(error.InvalidExtensionsArgs, parseAction(&.{ "trust", "policy", "0123456789ab", "extra" }));
}

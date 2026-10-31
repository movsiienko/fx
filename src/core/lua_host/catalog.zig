//! Finds the extensions in `~/.fx/extensions/`, hashes what each may load,
//! and decides from the profile's trust records whether it runs.
//!
//! An extension runs only when every file it can load matches the hashes
//! the user trusted with `fx extensions trust`, so a change, by the agent or
//! anything else that can write files, sends it back for review. The files
//! are read once into memory, and the engine loads from that copy, so what
//! was hashed is exactly what runs.

const std = @import("std");
const builtin = @import("builtin");
const engine = @import("../../lua/engine.zig");
const settings_store = @import("../config/settings_store.zig");
const io_mod = @import("../shared/io.zig");
const profile_paths = @import("../shared/profile_paths.zig");
const listing = @import("listing.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const extensions_dir_name = "extensions";
const failures_dir_name = "extension-failures";
const manifest_file = "manifest.lua";
const kv_file = "state.json";

const max_files = settings_store.max_extension_files;
const max_file_bytes = 1024 * 1024;
const max_total_bytes = 4 * 1024 * 1024;
const max_depth = 4;
const max_failure_record_bytes = 16 * 1024;

const Hex = [Sha256.digest_length * 2]u8;

const Extension = struct {
    name: []const u8,
    files: []const engine.SourceFile = &.{},
    hashes: []const settings_store.ExtensionFileHash = &.{},
    sha256: []const u8 = "",
    manifest: ?engine.Manifest = null,
    problem: ?[]const u8 = null,
    state: listing.State = .invalid,
    changed_files: []const []const u8 = &.{},
    failures: u64 = 0,
    last_error: ?[]const u8 = null,
};

pub const Catalog = struct {
    arena: std.heap.ArenaAllocator,
    home: []const u8,
    directory: []const u8,
    extensions: []Extension,

    /// Reads every extension and the profile's trust records. The catalog
    /// owns everything it returns; free it with `deinit` or `intoListing`.
    pub fn load(gpa: Allocator, home: []const u8) !Catalog {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const fx_root = try profile_paths.rootDir(a, home);
        const directory = try std.Io.Dir.path.join(a, &.{ fx_root, extensions_dir_name });
        const extensions = try discover(a, gpa, directory);
        // Without extensions there is nothing to trust, so settings stay unread.
        const records = if (extensions.len == 0) TrustRecords{} else try loadTrustRecords(a, home);
        for (extensions) |*extension| {
            try decideState(a, extension, records);
            if (extension.state == .trusted) try readFailures(a, fx_root, extension);
        }
        return .{
            .arena = arena,
            .home = try a.dupe(u8, home),
            .directory = directory,
            .extensions = extensions,
        };
    }

    pub fn deinit(self: *Catalog) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn find(self: *Catalog, name: []const u8) ?*Extension {
        for (self.extensions) |*extension| {
            if (std.mem.eql(u8, extension.name, name)) return extension;
        }
        return null;
    }

    /// Moves the catalog into a listing for `fx extensions`.
    pub fn intoListing(self: *Catalog, action: listing.Action) !listing.Listing {
        const a = self.arena.allocator();
        const entries = try a.alloc(listing.Entry, self.extensions.len);
        for (self.extensions, entries) |extension, *entry| {
            entry.* = .{
                .name = extension.name,
                .state = extension.state,
                .file_count = extension.files.len,
                .sha256 = extension.sha256,
                .changed_files = extension.changed_files,
                .failures = extension.failures,
                .last_error = extension.last_error,
                .problem = extension.problem,
            };
            if (extension.manifest) |manifest| {
                entry.version = manifest.version;
                entry.events = try enumNames(a, engine.Event, manifest.events);
                entry.scopes = try enumNames(a, engine.Scope, manifest.scopes);
                entry.kv = manifest.kv;
                entry.memory_mb = manifest.limits.memory_bytes / (1024 * 1024);
                entry.instructions_per_call = manifest.limits.instructions_per_call;
            }
        }
        const result: listing.Listing = .{
            .arena = self.arena,
            .directory = self.directory,
            .entries = entries,
            .action = action,
        };
        self.* = undefined;
        return result;
    }
};

fn enumNames(a: Allocator, comptime E: type, set: std.EnumSet(E)) ![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    inline for (@typeInfo(E).@"enum".field_names) |field| {
        if (set.contains(@field(E, field))) try names.append(a, field);
    }
    return names.items;
}

const TrustRecord = struct {
    sha256: ?[]const u8 = null,
    files: ?std.json.ObjectMap = null,
    disabled: bool = false,
};

const TrustRecords = struct {
    object: ?std.json.ObjectMap = null,

    fn get(self: TrustRecords, name: []const u8) TrustRecord {
        const records = self.object orelse return .{};
        const value = records.get(name) orelse return .{};
        if (value != .object) return .{};
        var record: TrustRecord = .{};
        if (value.object.get("sha256")) |digest| {
            if (digest == .string) record.sha256 = digest.string;
        }
        if (value.object.get("files")) |files| {
            if (files == .object) record.files = files.object;
        }
        if (value.object.get("disabled")) |disabled| {
            if (disabled == .bool) record.disabled = disabled.bool;
        }
        return record;
    }
};

/// Reads the `extensions` key of `~/.fx/settings.json`. A missing or
/// unreadable file trusts nothing, so nothing runs.
fn loadTrustRecords(a: Allocator, home: []const u8) !TrustRecords {
    var store = settings_store.Store.initFromHome(a, home, .read_only) catch return .{};
    defer store.deinit(a);
    var primary = store.loadPrimary(a) catch return .{};
    defer primary.deinit(a);
    const bytes = switch (primary) {
        .valid => |bytes| bytes,
        else => return .{},
    };
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}) catch return .{};
    if (root != .object) return .{};
    const extensions = root.object.get(settings_store.extensions_key) orelse return .{};
    if (extensions != .object) return .{};
    return .{ .object = extensions.object };
}

fn discover(a: Allocator, gpa: Allocator, directory: []const u8) ![]Extension {
    const io = io_mod.getIo();
    var dir = std.Io.Dir.openDirAbsolute(io, directory, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return &.{},
        else => return err,
    };
    defer dir.close(io);

    var extensions: std.ArrayList(Extension) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.name.len == 0 or entry.name[0] == '.') continue;
        switch (entry.kind) {
            .directory => {},
            .sym_link => {
                try extensions.append(a, .{
                    .name = try a.dupe(u8, entry.name),
                    .problem = "the extension folder is a symbolic link",
                });
                continue;
            },
            else => continue,
        }
        const name = try a.dupe(u8, entry.name);
        if (!engine.validExtensionName(name)) {
            try extensions.append(a, .{
                .name = name,
                .problem = "the folder name must be lowercase letters, digits, '_' or '-'",
            });
            continue;
        }
        try extensions.append(a, try readExtension(a, gpa, dir, name));
    }
    std.mem.sort(Extension, extensions.items, {}, extensionLessThan);
    return extensions.items;
}

fn extensionLessThan(_: void, lhs: Extension, rhs: Extension) bool {
    return std.mem.lessThan(u8, lhs.name, rhs.name);
}

const FileWalk = struct {
    a: Allocator,
    files: std.ArrayList(engine.SourceFile) = .empty,
    total_bytes: usize = 0,
    problem: ?[]const u8 = null,

    fn walk(self: *FileWalk, dir: std.Io.Dir, prefix: []const u8, depth: usize) !void {
        const io = io_mod.getIo();
        var it = dir.iterate();
        while (true) {
            const next = it.next(io) catch |err| switch (err) {
                error.Canceled => return err,
                else => {
                    const folder = if (prefix.len == 0) "the extension folder" else prefix;
                    self.problem = try self.a.print("{s} cannot be listed ({s})", .{ folder, @errorName(err) });
                    return;
                },
            };
            const entry = next orelse return;
            if (self.problem != null) return;
            if (entry.name.len == 0 or entry.name[0] == '.') continue;
            const path = if (prefix.len == 0)
                try self.a.dupe(u8, entry.name)
            else
                try std.mem.concat(self.a, u8, &.{ prefix, "/", entry.name });
            switch (entry.kind) {
                .file => {
                    if (!isLoadable(path)) continue;
                    if (self.files.items.len >= max_files) {
                        self.problem = "the extension has more than 64 .lua and state.json files";
                        return;
                    }
                    const bytes = dir.readFileAlloc(io, entry.name, self.a, .limited(max_file_bytes + 1)) catch |err| switch (err) {
                        error.StreamTooLong => {
                            self.problem = try self.a.print("{s} is larger than 1 MiB", .{path});
                            return;
                        },
                        error.OutOfMemory, error.Canceled => |e| return e,
                        else => {
                            self.problem = try self.a.print("{s} cannot be read ({s})", .{ path, @errorName(err) });
                            return;
                        },
                    };
                    if (bytes.len > max_file_bytes) {
                        self.problem = try self.a.print("{s} is larger than 1 MiB", .{path});
                        return;
                    }
                    self.total_bytes += bytes.len;
                    if (self.total_bytes > max_total_bytes) {
                        self.problem = "the extension's files add up to more than 4 MiB";
                        return;
                    }
                    try self.files.append(self.a, .{ .path = path, .bytes = bytes });
                },
                .directory => {
                    if (depth >= max_depth) continue;
                    var child = dir.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
                        error.Canceled => return err,
                        else => {
                            self.problem = try self.a.print("the folder {s} cannot be opened ({s})", .{ path, @errorName(err) });
                            return;
                        },
                    };
                    defer child.close(io);
                    try self.walk(child, path, depth + 1);
                },
                .sym_link => {
                    self.problem = try self.a.print("{s} is a symbolic link, which extensions may not contain", .{path});
                    return;
                },
                else => {},
            }
        }
    }
};

/// Files the engine can load: `.lua` modules, and `state.json` for
/// `agent.kv`. Other files are neither hashed nor reachable from Lua.
fn isLoadable(path: []const u8) bool {
    return std.mem.eql(u8, path, kv_file) or engine.validModulePath(path);
}

fn readExtension(a: Allocator, gpa: Allocator, parent: std.Io.Dir, name: []const u8) !Extension {
    const io = io_mod.getIo();
    var extension: Extension = .{ .name = name };
    var dir = parent.openDir(io, name, .{ .iterate = true, .follow_symlinks = false }) catch |err| {
        extension.problem = try a.print("the extension folder cannot be opened ({s})", .{@errorName(err)});
        return extension;
    };
    defer dir.close(io);

    var walk: FileWalk = .{ .a = a };
    try walk.walk(dir, "", 0);
    std.mem.sort(engine.SourceFile, walk.files.items, {}, fileLessThan);
    extension.files = walk.files.items;
    try hashFiles(a, &extension);
    if (walk.problem) |problem| {
        extension.problem = problem;
        return extension;
    }

    const manifest_source = findFile(extension.files, manifest_file) orelse {
        extension.problem = "manifest.lua is missing";
        return extension;
    };
    var diagnostic: engine.Diagnostic = .{};
    const manifest = engine.parseManifest(a, gpa, manifest_source, &diagnostic) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.InvalidManifest => {
            extension.problem = try a.dupe(u8, diagnostic.message());
            return extension;
        },
    };
    if (!std.mem.eql(u8, manifest.name, name)) {
        extension.problem = try a.print("the manifest name '{s}' does not match the folder name", .{manifest.name});
        return extension;
    }
    if (findFile(extension.files, manifest.main) == null) {
        extension.problem = try a.print("the main file {s} is missing", .{manifest.main});
        return extension;
    }
    extension.manifest = manifest;
    return extension;
}

fn fileLessThan(_: void, lhs: engine.SourceFile, rhs: engine.SourceFile) bool {
    return std.mem.lessThan(u8, lhs.path, rhs.path);
}

fn findFile(files: []const engine.SourceFile, path: []const u8) ?[]const u8 {
    for (files) |file| {
        if (std.mem.eql(u8, file.path, path)) return file.bytes;
    }
    return null;
}

/// Each file's SHA-256, and one digest over every sorted path and hash.
fn hashFiles(a: Allocator, extension: *Extension) !void {
    const hashes = try a.alloc(settings_store.ExtensionFileHash, extension.files.len);
    var digest = Sha256.init(.{});
    for (extension.files, hashes) |file, *hash| {
        const hex = try a.create(Hex);
        hex.* = hexDigest(file.bytes);
        hash.* = .{ .path = file.path, .sha256 = hex };
        digest.update(file.path);
        digest.update(&.{0});
        digest.update(hex);
        digest.update("\n");
    }
    var out: [Sha256.digest_length]u8 = undefined;
    digest.final(&out);
    const total = try a.create(Hex);
    total.* = std.fmt.bytesToHex(out, .lower);
    extension.hashes = hashes;
    extension.sha256 = total;
}

fn hexDigest(bytes: []const u8) Hex {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &out, .{});
    return std.fmt.bytesToHex(out, .lower);
}

fn decideState(a: Allocator, extension: *Extension, records: TrustRecords) !void {
    if (extension.problem != null) {
        extension.state = .invalid;
        return;
    }
    const record = records.get(extension.name);
    const trusted = record.sha256 orelse {
        extension.state = .needs_review;
        return;
    };
    if (!std.mem.eql(u8, trusted, extension.sha256)) {
        extension.state = .needs_review;
        extension.changed_files = try changedFiles(a, extension.hashes, record.files);
        return;
    }
    extension.state = if (record.disabled) .disabled else .trusted;
}

fn changedFiles(
    a: Allocator,
    current: []const settings_store.ExtensionFileHash,
    trusted: ?std.json.ObjectMap,
) ![]const []const u8 {
    var changed: std.ArrayList([]const u8) = .empty;
    for (current) |file| {
        const previous = if (trusted) |files| files.get(file.path) else null;
        if (previous == null or previous.? != .string or !std.mem.eql(u8, previous.?.string, file.sha256)) {
            try changed.append(a, if (previous == null) try a.print("{s} (new)", .{file.path}) else file.path);
        }
    }
    if (trusted) |files| {
        var it = files.iterator();
        while (it.next()) |entry| {
            for (current) |file| {
                if (std.mem.eql(u8, file.path, entry.key_ptr.*)) break;
            } else try changed.append(a, try a.print("{s} (removed)", .{entry.key_ptr.*}));
        }
    }
    return changed.items;
}

// Failure records live in `~/.fx/extension-failures/<name>.json`, outside
// the extension folder, so recording a failure never changes the hash. A
// record counts only for the contents it was written against.

fn failurePath(a: Allocator, fx_root: []const u8, name: []const u8) ![]u8 {
    const file_name = try a.print("{s}.json", .{name});
    defer a.free(file_name);
    return std.Io.Dir.path.join(a, &.{ fx_root, failures_dir_name, file_name });
}

fn readFailures(a: Allocator, fx_root: []const u8, extension: *Extension) !void {
    const path = try failurePath(a, fx_root, extension.name);
    const io = io_mod.getIo();
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(max_failure_record_bytes)) catch return;
    const value = std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}) catch return;
    if (value != .object) return;
    const digest = value.object.get("sha256") orelse return;
    if (digest != .string or !std.mem.eql(u8, digest.string, extension.sha256)) return;
    const failures = value.object.get("failures") orelse return;
    if (failures != .integer or failures.integer <= 0) return;
    extension.failures = @intCast(failures.integer);
    if (value.object.get("last_error")) |last_error| {
        if (last_error == .string) extension.last_error = last_error.string;
    }
    extension.state = .failing;
}

/// Counts one failed call. Best effort: a hook failure must never fail
/// because its record could not be written.
pub fn recordFailure(gpa: Allocator, home: []const u8, name: []const u8, sha256: []const u8, message: []const u8) void {
    recordFailures(gpa, home, name, sha256, 1, message) catch {};
}

/// Adds `count` failed calls to the record, whose last error is `message`.
/// The count is added to what the record holds now, so failures another
/// process counted stay counted and failures `fx extensions trust` cleared
/// stay cleared.
pub fn recordFailures(gpa: Allocator, home: []const u8, name: []const u8, sha256: []const u8, count: u64, message: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const fx_root = try profile_paths.rootDir(a, home);
    var previous: Extension = .{ .name = name, .sha256 = sha256 };
    readFailures(a, fx_root, &previous) catch {};

    const io = io_mod.getIo();
    const directory = try std.Io.Dir.path.join(a, &.{ fx_root, failures_dir_name });
    try std.Io.Dir.cwd().createDirPath(io, directory);
    var out: std.Io.Writer.Allocating = .init(a);
    try std.json.Stringify.value(.{
        .sha256 = sha256,
        .failures = previous.failures + count,
        .last_error = message,
        .last_failure_ms = io_mod.milliTimestamp(),
    }, .{}, &out.writer);
    try io_mod.writeFileAtomic(a, try failurePath(a, fx_root, name), out.written());
}

/// Forgets the failures of an extension, as trusting it again does.
pub fn clearFailures(gpa: Allocator, home: []const u8, name: []const u8) void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const fx_root = profile_paths.rootDir(a, home) catch return;
    const path = failurePath(a, fx_root, name) catch return;
    std.Io.Dir.deleteFileAbsolute(io_mod.getIo(), path) catch {};
}

const TestHome = struct {
    tmp: std.testing.TmpDir,
    home: []u8,

    fn init() !TestHome {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        try tmp.dir.createDirPath(std.testing.io, ".fx/extensions");
        const home = try io_mod.dirRealpathAlloc(std.testing.allocator, tmp.dir, ".");
        return .{ .tmp = tmp, .home = home };
    }

    fn deinit(self: *TestHome) void {
        std.testing.allocator.free(self.home);
        self.tmp.cleanup();
    }

    fn write(self: *TestHome, path: []const u8, bytes: []const u8) !void {
        const full = try std.mem.concat(std.testing.allocator, u8, &.{ ".fx/extensions/", path });
        defer std.testing.allocator.free(full);
        if (std.Io.Dir.path.dirname(full)) |parent| try self.tmp.dir.createDirPath(std.testing.io, parent);
        try self.tmp.dir.writeFile(std.testing.io, .{ .sub_path = full, .data = bytes });
    }

    fn writeSettings(self: *TestHome, bytes: []const u8) !void {
        try self.tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".fx/settings.json", .data = bytes });
    }
};

const policy_manifest = "return { name = \"policy\", events = { \"pre_tool_use\" } }";

/// Leaves the process exactly `spare` free file descriptors, so the open
/// after them fails with error.ProcessFdQuotaExceeded. Unlike file modes,
/// root obeys this too.
const OpenFileLimit = struct {
    const max_held = 64;

    saved: std.posix.rlimit,
    held: [max_held]std.Io.Dir = undefined,
    held_len: usize = 0,

    fn init(tmp_dir: std.Io.Dir, spare: usize) !OpenFileLimit {
        const io = std.testing.io;
        var limit: OpenFileLimit = .{ .saved = try std.posix.getrlimit(.NOFILE) };
        const probe = try tmp_dir.openDir(io, ".", .{});
        const lowest_free: u64 = @intCast(probe.handle);
        probe.close(io);
        try std.posix.setrlimit(.NOFILE, .{ .cur = lowest_free + max_held, .max = limit.saved.max });
        errdefer limit.restore();
        // Descriptors in use above the lowest free one leave gaps, so fill
        // every free one below the limit, then free `spare` of them.
        while (tmp_dir.openDir(io, ".", .{})) |dir| {
            limit.held[limit.held_len] = dir;
            limit.held_len += 1;
        } else |err| if (err != error.ProcessFdQuotaExceeded) return err;
        if (limit.held_len < spare) return error.TestUnexpectedResult;
        for (0..spare) |_| {
            limit.held_len -= 1;
            limit.held[limit.held_len].close(io);
        }
        return limit;
    }

    fn restore(self: *OpenFileLimit) void {
        for (self.held[0..self.held_len]) |dir| dir.close(std.testing.io);
        self.held_len = 0;
        std.posix.setrlimit(.NOFILE, self.saved) catch {};
    }
};

test "a new extension needs review and a trusted one runs until it changes" {
    var home = try TestHome.init();
    defer home.deinit();
    try home.write("policy/manifest.lua", policy_manifest);
    try home.write("policy/main.lua", "agent.on('pre_tool_use', function() end)");
    try home.write("policy/README.md", "not hashed");

    var catalog = try Catalog.load(std.testing.allocator, home.home);
    const first = catalog.find("policy").?;
    try std.testing.expectEqual(listing.State.needs_review, first.state);
    try std.testing.expectEqual(@as(usize, 2), first.files.len);
    const digest = try std.testing.allocator.dupe(u8, first.sha256);
    defer std.testing.allocator.free(digest);
    const main_hash = try std.testing.allocator.dupe(u8, first.hashes[0].sha256);
    defer std.testing.allocator.free(main_hash);
    catalog.deinit();

    const settings = try std.testing.allocator.print(
        \\{{"extensions":{{"policy":{{"sha256":"{s}","files":{{"main.lua":"{s}"}}}}}}}}
    , .{ digest, main_hash });
    defer std.testing.allocator.free(settings);
    try home.writeSettings(settings);
    catalog = try Catalog.load(std.testing.allocator, home.home);
    try std.testing.expectEqual(listing.State.trusted, catalog.find("policy").?.state);
    catalog.deinit();

    try home.write("policy/README.md", "still not hashed");
    catalog = try Catalog.load(std.testing.allocator, home.home);
    try std.testing.expectEqual(listing.State.trusted, catalog.find("policy").?.state);
    catalog.deinit();

    try home.write("policy/main.lua", "-- weakened");
    catalog = try Catalog.load(std.testing.allocator, home.home);
    defer catalog.deinit();
    const changed = catalog.find("policy").?;
    try std.testing.expectEqual(listing.State.needs_review, changed.state);
    try std.testing.expectEqual(@as(usize, 2), changed.changed_files.len);
    try std.testing.expectEqualStrings("main.lua", changed.changed_files[0]);
    try std.testing.expectEqualStrings("manifest.lua (new)", changed.changed_files[1]);
}

test "a broken folder or manifest makes the extension invalid" {
    var home = try TestHome.init();
    defer home.deinit();
    try home.write("nomanifest/main.lua", "");
    try home.write("mismatch/manifest.lua", policy_manifest);
    try home.write("mismatch/main.lua", "");
    try home.write("Upper/manifest.lua", policy_manifest);
    try home.write("nomain/manifest.lua", "return { name = \"nomain\", events = { \"stop\" } }");

    var catalog = try Catalog.load(std.testing.allocator, home.home);
    defer catalog.deinit();
    try std.testing.expectEqual(@as(usize, 4), catalog.extensions.len);
    try std.testing.expectEqualStrings("manifest.lua is missing", catalog.find("nomanifest").?.problem.?);
    try std.testing.expect(std.mem.find(u8, catalog.find("mismatch").?.problem.?, "does not match") != null);
    try std.testing.expect(std.mem.find(u8, catalog.find("Upper").?.problem.?, "folder name") != null);
    try std.testing.expectEqualStrings("the main file main.lua is missing", catalog.find("nomain").?.problem.?);
    for (catalog.extensions) |extension| try std.testing.expectEqual(listing.State.invalid, extension.state);
}

test "failure records count only for the contents they were written for" {
    var home = try TestHome.init();
    defer home.deinit();
    try home.write("policy/manifest.lua", policy_manifest);
    try home.write("policy/main.lua", "");
    var catalog = try Catalog.load(std.testing.allocator, home.home);
    const digest = try std.testing.allocator.dupe(u8, catalog.find("policy").?.sha256);
    defer std.testing.allocator.free(digest);
    catalog.deinit();
    const settings = try std.testing.allocator.print(
        \\{{"extensions":{{"policy":{{"sha256":"{s}"}}}}}}
    , .{digest});
    defer std.testing.allocator.free(settings);
    try home.writeSettings(settings);

    recordFailure(std.testing.allocator, home.home, "policy", digest, "boom");
    recordFailure(std.testing.allocator, home.home, "policy", digest, "boom again");
    catalog = try Catalog.load(std.testing.allocator, home.home);
    var entry = catalog.find("policy").?;
    try std.testing.expectEqual(listing.State.failing, entry.state);
    try std.testing.expectEqual(@as(u64, 2), entry.failures);
    try std.testing.expectEqualStrings("boom again", entry.last_error.?);
    catalog.deinit();

    clearFailures(std.testing.allocator, home.home, "policy");
    catalog = try Catalog.load(std.testing.allocator, home.home);
    defer catalog.deinit();
    entry = catalog.find("policy").?;
    try std.testing.expectEqual(listing.State.trusted, entry.state);
}

test "a folder that cannot be opened makes only its extension invalid" {
    if (builtin.target.os.tag != .linux and builtin.target.os.tag != .macos) return error.SkipZigTest;
    var home = try TestHome.init();
    defer home.deinit();
    try home.write("policy/manifest.lua", policy_manifest);
    try home.write("policy/main.lua", "");
    try home.write("broken/manifest.lua", "return { name = \"broken\", events = { \"stop\" } }");
    try home.write("broken/main.lua", "");
    try home.write("broken/a/b/c/deep.lua", "");

    // Four spare descriptors hold the extensions folder, the extension
    // folder, a, and b, so opening broken/a/b/c fails.
    var limit = try OpenFileLimit.init(home.tmp.dir, 4);
    var catalog = Catalog.load(std.testing.allocator, home.home);
    limit.restore();
    defer if (catalog) |*loaded| loaded.deinit() else |_| {};

    const extensions = &(try catalog);
    try std.testing.expectEqual(listing.State.needs_review, extensions.find("policy").?.state);
    const broken = extensions.find("broken").?;
    try std.testing.expectEqual(listing.State.invalid, broken.state);
    try std.testing.expectEqualStrings("the folder a/b/c cannot be opened (ProcessFdQuotaExceeded)", broken.problem.?);
}

test "a file that cannot be read makes only its extension invalid" {
    if (builtin.target.os.tag != .linux and builtin.target.os.tag != .macos) return error.SkipZigTest;
    var home = try TestHome.init();
    defer home.deinit();
    try home.write("policy/manifest.lua", policy_manifest);
    try home.write("policy/main.lua", "");
    try home.write("broken/manifest.lua", "return { name = \"broken\", events = { \"stop\" } }");
    try home.write("broken/main.lua", "");
    try home.write("broken/a/deep.lua", "");

    // Three spare descriptors hold the extensions folder, the extension
    // folder, and a, so reading broken/a/deep.lua fails.
    var limit = try OpenFileLimit.init(home.tmp.dir, 3);
    var catalog = Catalog.load(std.testing.allocator, home.home);
    limit.restore();
    defer if (catalog) |*loaded| loaded.deinit() else |_| {};

    const extensions = &(try catalog);
    try std.testing.expectEqual(listing.State.needs_review, extensions.find("policy").?.state);
    const broken = extensions.find("broken").?;
    try std.testing.expectEqual(listing.State.invalid, broken.state);
    try std.testing.expectEqualStrings("a/deep.lua cannot be read (ProcessFdQuotaExceeded)", broken.problem.?);
}

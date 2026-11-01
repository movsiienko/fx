//! Lowers the CPU priority of a worker that ran past its time limit. Lua
//! runs no hook inside its C library, so a worker stuck in a long pattern
//! match keeps running until that C call returns, and no thread can be
//! killed safely. At the lowest priority it only gets CPU time that fx and
//! the rest of the machine leave idle.

const std = @import("std");
const builtin = @import("builtin");

const os = builtin.target.os.tag;
const supported = builtin.link_libc and (os == .linux or os == .macos);

/// `struct sched_param`. macOS keeps four more bytes in it.
const SchedParam = switch (os) {
    .macos => extern struct { sched_priority: c_int, reserved: [4]u8 = @splat(0) },
    else => extern struct { sched_priority: c_int },
};

const sched_other: c_int = switch (os) {
    .macos => 1,
    else => 0,
};
/// Linux's idle class: the thread runs only when nothing else wants the CPU.
const sched_idle: c_int = 5;

extern "c" fn pthread_setschedparam(thread: std.c.pthread_t, policy: c_int, param: *const SchedParam) c_int;
extern "c" fn pthread_getschedparam(thread: std.c.pthread_t, policy: *c_int, param: *SchedParam) c_int;
extern "c" fn sched_get_priority_min(policy: c_int) c_int;

/// The calling thread's scheduling policy and priority.
fn currentScheduling() struct { c_int, c_int } {
    if (!supported) return .{ -1, -1 };
    var policy: c_int = -1;
    var param: SchedParam = .{ .sched_priority = -1 };
    if (pthread_getschedparam(std.c.pthread_self(), &policy, &param) != 0) return .{ -1, -1 };
    return .{ policy, param.sched_priority };
}

/// Gives `thread` the lowest CPU priority the system offers. Does nothing
/// where fx cannot change another thread's priority.
pub fn lowest(thread: std.Thread) void {
    if (comptime !supported or std.Thread.Handle != std.c.pthread_t) return;
    const handle = thread.getHandle();
    // Best effort: a thread at normal priority still finishes the same way.
    switch (os) {
        .linux => _ = pthread_setschedparam(handle, sched_idle, &.{ .sched_priority = 0 }),
        .macos => _ = pthread_setschedparam(handle, sched_other, &.{ .sched_priority = sched_get_priority_min(sched_other) }),
        else => {},
    }
}

test "a worker can be given the lowest CPU priority" {
    const Probe = struct {
        lowered: std.Io.Event = .unset,
        checked: std.Io.Event = .unset,
        policy: c_int = -1,
        priority: c_int = -1,

        fn run(probe: *@This()) void {
            probe.lowered.waitUncancelable(std.testing.io);
            probe.policy, probe.priority = currentScheduling();
            probe.checked.set(std.testing.io);
        }
    };
    var probe: Probe = .{};
    const thread = try std.Thread.spawn(.{}, Probe.run, .{&probe});
    lowest(thread);
    probe.lowered.set(std.testing.io);
    probe.checked.waitUncancelable(std.testing.io);
    thread.join();

    switch (builtin.target.os.tag) {
        .linux => try std.testing.expectEqual(@as(c_int, 5), probe.policy), // SCHED_IDLE
        .macos => try std.testing.expectEqual(sched_get_priority_min(sched_other), probe.priority),
        else => return error.SkipZigTest,
    }
}

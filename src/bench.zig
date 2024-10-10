const std = @import("std");
const zbench = @import("zbench");
const attobyte = @import("root.zig");

const KV_COUNT: usize = 500;
const DELETIONS_COUNT: usize = 100;

const ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn randomChar() u8 {
    const rand = std.crypto.random;
    const index = rand.intRangeAtMost(usize, 0, 61);
    return ALPHANUMERIC[index];
}

fn randomWord(allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    const rand = std.crypto.random;
    const len = rand.intRangeAtMost(usize, 16, 32);
    const str = try allocator.alloc(u8, len);

    for (str) |*c| {
        c.* = randomChar();
    }

    return str;
}

var keys: [KV_COUNT][]u8 = [1][]u8{&.{}} ** KV_COUNT;
var values: [KV_COUNT][]u8 = [1][]u8{&.{}} ** KV_COUNT;

fn generateKV() void {
    for (0..KV_COUNT) |i| {
        keys[i] = randomWord(std.heap.page_allocator) catch "";
        values[i] = randomWord(std.heap.page_allocator) catch "";
    }
}

fn deinitKV() void {
    const allocator = std.heap.page_allocator;
    for (0..KV_COUNT) |i| {
        allocator.free(keys[i]);
        allocator.free(values[i]);
    }
}

fn myBench(allocator: std.mem.Allocator) void {
    var tree = attobyte.Tree.init(allocator);

    for (0..KV_COUNT) |i| {
        const key = keys[i];
        const val = values[i];

        tree.insert(key, val);
        _ = tree.get(key);
    }
    var j = KV_COUNT;
    for (0..KV_COUNT) |i| {
        j -= 1;
        const key = keys[i];
        const val = values[j];

        tree.insert(key, val);
        _ = tree.get(key);
    }
}

pub fn main() !void {
    const config = zbench.Config{ .hooks = .{ .before_all = generateKV, .after_all = deinitKV } };
    var bench = zbench.Benchmark.init(std.heap.page_allocator, config);
    defer bench.deinit();
    try bench.add("My Bench", myBench, .{});
    try bench.run(std.io.getStdOut().writer());
}

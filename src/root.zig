const std = @import("std");
const testing = std.testing;

const MAGIC: [8]u8 = .{ 0x61, 0x74, 0x74, 0x6F, 0x62, 0x79, 0x74, 0x65 };
const ROOT_OFFSET: U24 = .{ .bytes = .{ 0x00, 0x00, 0x0D } };

pub const Tree = struct {
    buf: TreeBuf,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Tree {
        var list = std.ArrayList(u8).init(allocator);
        const header = Header{
            .magic = MAGIC,
            .version = 0,
            .depth = 1,
            .leak = U24.ZERO,
        };
        const root_node = Node{
            .parent_offset = U24.ZERO,
            .parent_index = 0,
            .len = 0,
            .hashes = [1]U24{U24.ZERO} ** 19,
            .kv_offset = [1]U24{U24.ZERO} ** 19,
            .children_offset = [1]U24{U24.ZERO} ** 20,
        };

        list.appendSlice(header.asSlice()) catch |e| {
            std.debug.panic("Allocator Error: {}", .{e});
        };
        list.appendSlice(root_node.asSlice()) catch |e| {
            std.debug.panic("Allocator Error: {}", .{e});
        };

        return Tree{ .buf = .{ .alloc_buf = list }, .allocator = allocator };
    }

    pub fn deinit(self: Tree) void {
        switch (self.buf) {
            .alloc_buf => |alloc_buf| {
                alloc_buf.deinit();
            },
            else => {},
        }
    }

    pub fn get(self: *const Tree, key: []const u8) ?[]const u8 {
        const key_hash = hashKey(key);
        const key_location = self._findKey(key, key_hash);

        var self_: *Tree = @constCast(self);

        if (key_location.status == KeyStatus.Matched) {
            const node = self_._getNode(key_location.node_offset);
            const entry_offset = node.kv_offset[key_location.entry_index];
            const entry = self_._getEntry(entry_offset);
            return entry.val();
        }
        return null;
    }

    pub fn insert(self: *Tree, key: []const u8, value: []const u8) void {
        const key_hash = hashKey(key);
        const key_location = self._findKey(key, key_hash);

        std.log.debug("Found suitable key location {}\n", .{key_location});

        switch (key_location.status) {
            .Empty => {
                self._insertNewEntry(key_location.node_offset, key_location.entry_index, key, key_hash, value);
            },
            .Matched, .Deleted => {
                self._updateExistingEntry(key_location.node_offset, key_location.entry_index, value);
            },
            .RequiresShift => {
                self._insertEntryWithShift(key_location.node_offset, key_location.entry_index, key, key_hash, value);
            },
        }
    }

    fn _findKey(_self: *const Tree, key: []const u8, key_hash: U24) KeyLocation {
        var current_node_offset = ROOT_OFFSET;
        std.log.debug("Searching for hash {}\n", .{key_hash});

        var self: *Tree = @constCast(_self);

        for (1..self._getHeader().depth) |_| {
            const node = self._getNode(current_node_offset);
            const len = @as(usize, node.len);

            var found_child = false;

            for (0..len) |i| {
                const entry_hash = node.hashes[i];

                if (key_hash.cmp(entry_hash) == .Less) {
                    current_node_offset = node.children_offset[i];
                    found_child = true;
                    break;
                }
            }

            if (!found_child) {
                current_node_offset = node.children_offset[len];
            }
        }

        const node = self._getNode(current_node_offset);

        const len = @as(usize, node.len);

        for (0..len) |i| {
            const entry_hash = node.hashes[i];

            switch (entry_hash.cmp(key_hash)) {
                .Equal => {
                    const entry = self._getEntry(node.kv_offset[i]);
                    const entry_key = entry.key();
                    switch (sliceCmp(u8, entry_key, key)) {
                        .Equal => {
                            return KeyLocation{
                                .node_offset = current_node_offset,
                                .entry_index = i,
                                // TODO: DELETED
                                .status = KeyStatus.Matched,
                            };
                        },
                        .Greater => {
                            return KeyLocation{
                                .node_offset = current_node_offset,
                                .entry_index = i,
                                .status = KeyStatus.RequiresShift,
                            };
                        },
                        .Less => continue,
                    }
                },
                .Greater => {
                    return KeyLocation{
                        .node_offset = current_node_offset,
                        .entry_index = i,
                        .status = KeyStatus.RequiresShift,
                    };
                },
                .Less => continue,
            }
        }

        return KeyLocation{
            .node_offset = current_node_offset,
            .entry_index = len,
            .status = KeyStatus.Empty,
        };
    }

    fn _insertNewEntry(self: *Tree, node_offset: U24, entry_index_: usize, key: []const u8, key_hash: U24, value: []const u8) void {
        var entry_index = entry_index_;

        const entry_offset = self._newEntry(key, value);
        var node = self._getNode(node_offset);

        if (!node.hasSpace()) {
            const split = self._splitNode(node, node_offset, entry_index);
            node = self._getNode(split.node_offset);
            entry_index = split.target_index;
        }

        node.kv_offset[entry_index] = entry_offset;
        node.hashes[entry_index] = key_hash;
        node.len += 1;
    }

    fn _insertEntryWithShift(self: *Tree, node_offset: U24, entry_index_: usize, key: []const u8, key_hash: U24, value: []const u8) void {
        var entry_index = entry_index_;

        const entry_offset = self._newEntry(key, value);
        var node = self._getNode(node_offset);

        if (!node.hasSpace()) {
            const split = self._splitNode(node, node_offset, entry_index);
            node = self._getNode(split.node_offset);
            entry_index = split.target_index;
        }

        var i: usize = node.len + 1;
        while (i > entry_index + 1) {
            i -= 1;
            node.kv_offset[i] = node.kv_offset[i - 1];
            node.hashes[i] = node.hashes[i - 1];
        }

        node.kv_offset[entry_index] = entry_offset;
        node.hashes[entry_index] = key_hash;
        node.len += 1;

        if (entry_index == 0 and node.parent_index > 0) {
            self._updateNominatedHash(node, entry_index, key_hash);
        }
    }

    fn _updateExistingEntry(self: *Tree, node_offset: U24, entry_index: usize, value: []const u8) void {
        var entry_offset = blk: {
            const node = self._getNode(node_offset);
            break :blk node.kv_offset[entry_index];
        };

        const key = blk: {
            const entry = self._getEntry(entry_offset);
            if (value.len <= entry.capacity.to(usize) - entry.key_len.to(usize)) {
                // If the new value fits in the existing entry, just update the value and return.
                entry.setVal(value);
                if (entry.isDeleted()) {
                    entry.unmarkDeleted();
                    const len = entry.len();
                    var header = self._getHeader();
                    header.leak = header.leak.sub(U24.from(usize, len));
                }
                return;
            } else {
                // If the value doesn't fit, delete the entry.
                entry.markDeleted();
                break :blk entry.key();
            }
        };

        // Allocate a new entry with the key and value, because it wouldn't fit in the old entry.
        entry_offset = self._newEntry(key, value);
        const node = self._getNode(node_offset);
        node.kv_offset[entry_index] = entry_offset;
    }

    fn _splitNode(self: *Tree, node_: *Node, node_offset: U24, target_index: usize) SplitResult {
        var node = node_;
        if (node.isRoot()) {
            return self._splitRoot(target_index);
        }

        const parent_node_offset, const parent_target_index: usize = blk: {
            const parent_node = self._getNode(node.parent_offset);

            if (parent_node.hasSpace()) {
                break :blk .{ node.parent_offset, @as(usize, node.parent_index + 1) };
            } else {
                const split = self._splitNode(parent_node, node.parent_offset, @as(usize, node.parent_index + 1));
                break :blk .{ split.node_offset, @as(usize, split.target_index) };
            }
        };

        const new_node_offset = self._getOffset();
        var new_node_hash = U24.ZERO;

        {
            var new_node = self._newNode();
            // Fetch the original node again because `_newNode` may have re-allocated and invalidated the pointer.
            node = self._getNode(node_offset);

            new_node.parent_offset = node.parent_offset;
            new_node.parent_index = @truncate(parent_target_index);

            if (node.isLeaf()) {
                node.len = 10;
                new_node.len = 9;

                // Move hashes 10..19 to new_node
                @memcpy(new_node.hashes[0..9], node.hashes[10..19]);
                @memset(node.hashes[10..19], U24.ZERO);
                // Move kv_offset 10..19 to new_node
                @memcpy(new_node.kv_offset[0..9], node.kv_offset[10..19]);
                @memset(node.hashes[10..19], U24.ZERO);
            } else {
                node.len = 9;
                new_node.len = 9;
                // Split the hashes between the nodes. Leave off the last hash of the left node to
                // ensure there are always <n hashes> + 1 children.
                @memcpy(new_node.hashes[0..9], node.hashes[10..19]);
                @memset(node.hashes[9..19], U24.ZERO);
                // Move children 10..20 to new_node
                @memcpy(new_node.children_offset[0..10], node.children_offset[10..20]);
                @memset(node.children_offset[10..20], U24.ZERO);

                // Update all the new node's childrens' parent offset and index
                for (new_node.children_offset[0..10], 0..) |child_offset, i| {
                    var child = self._getNode(child_offset);
                    child.parent_offset = new_node_offset;
                    child.parent_index = @truncate(i);
                }
            }

            new_node_hash = new_node.hashes[0];
        }

        const parent_node = self._getNode(parent_node_offset);
        self._insertNodeChild(parent_node, parent_target_index, new_node_offset, new_node_hash);

        if (target_index < 10) {
            return .{ .node_offset = node_offset, .target_index = target_index };
        } else {
            return .{ .node_offset = new_node_offset, .target_index = target_index - 10 };
        }
    }

    fn _splitRoot(self: *Tree, target_index: usize) SplitResult {
        var left_node_offset = U24.ZERO;
        var right_node_offset = U24.ZERO;

        const left_node, const right_node = blk: { // Similar to `_newNode`, but allocate both at the same time.
            left_node_offset = self._getOffset();
            right_node_offset = left_node_offset.add(U24.from(usize, @sizeOf(Node)));
            const buf = self._extendBy(2 * @sizeOf(Node));
            const left_node: *Node = @ptrCast(buf);
            const right_node: *Node = @ptrCast(buf[@sizeOf(Node)..]);
            break :blk .{ left_node, right_node };
        };

        left_node.parent_offset = ROOT_OFFSET;
        right_node.parent_offset = ROOT_OFFSET;
        left_node.parent_index = 0;
        right_node.parent_index = 1;

        const root_node = self._getNode(ROOT_OFFSET);

        if (root_node.isLeaf()) {
            left_node.len = 10;
            right_node.len = 9;
            @memcpy(left_node.hashes[0..10], root_node.hashes[0..10]);
            @memcpy(right_node.hashes[0..9], root_node.hashes[10..19]);
            @memcpy(left_node.kv_offset[0..10], root_node.kv_offset[0..10]);
            @memcpy(right_node.kv_offset[0..9], root_node.kv_offset[10..19]);
            @memset(&root_node.kv_offset, U24.ZERO);
        } else {
            left_node.len = 9;
            right_node.len = 9;
            // Split the hashes between the nodes. Leave off the last hash of the left node to
            // ensure there are always <n hashes> + 1 children.
            @memcpy(left_node.hashes[0..9], root_node.hashes[0..9]);
            @memcpy(right_node.hashes[0..9], root_node.hashes[10..19]);
            @memcpy(left_node.children_offset[0..10], root_node.children_offset[0..10]);
            @memcpy(right_node.children_offset[0..10], root_node.children_offset[10..20]);
            @memset(&root_node.children_offset, U24.ZERO);
            // Update the children of both new nodes to point to their new parent.
            for (left_node.children_offset[0..10]) |child_offset| {
                const child = self._getNode(child_offset);
                child.parent_offset = left_node_offset;
            }

            for (right_node.children_offset[0..10], 0..) |child_offset, i| {
                const child = self._getNode(child_offset);
                child.parent_offset = right_node_offset;
                child.parent_index = @truncate(i);
            }
        }

        @memset(&root_node.hashes, U24.ZERO);
        // All hashes in the right node should be greater than or equal to the nominated hash.
        root_node.hashes[0] = right_node.hashes[0];

        // An internal node's len is # of children - 1.
        root_node.len = 1;
        root_node.children_offset[0] = left_node_offset;
        root_node.children_offset[1] = right_node_offset;
        self._getHeader().depth += 1;

        if (target_index < 10) {
            return .{ .node_offset = left_node_offset, .target_index = target_index };
        } else {
            return .{ .node_offset = right_node_offset, .target_index = target_index - 10 };
        }
    }

    /// INVARIANTS: NOT FULL + NOT LEAF + INDEX > 0
    fn _insertNodeChild(self: *Tree, parent_node: *Node, index: usize, offset: U24, hash: U24) void {
        std.debug.assert(parent_node.len < 19);
        std.debug.assert(!parent_node.isLeaf());
        std.debug.assert(index > 0);

        const index_u8: u8 = @truncate(index);
        if (index_u8 <= parent_node.len) {
            // Shift the hashes and children offset to the right
            var i = @as(usize, parent_node.len + 2);
            while (i > index + 1) {
                i -= 1;
                const child_offset = parent_node.children_offset[i - 1];
                var child = self._getNode(child_offset);
                child.parent_index += 1;
                parent_node.children_offset[i] = child_offset;
            }
            i = @as(usize, parent_node.len + 1);
            while (i > index) {
                i -= 1;
                parent_node.hashes[i] = parent_node.hashes[i - 1];
            }
        }

        // The hash at the index is greater than or equal to all hashes of the child at the index.
        parent_node.hashes[index - 1] = hash;
        // We insert the node offset to <hash index> + 1.
        parent_node.children_offset[index] = offset;
        parent_node.len += 1;
    }

    // For child nodes which are not the first node in the parent, they have a hash in the
    // parent which is their lowest hash. If we are inserting to index 0, the node has a new
    // lowest hash, so their representation in the parent needs updating.
    // This is recursive because we may update the first hash in parent, so they will need to update
    // their nominated hash in their parent.
    fn _updateNominatedHash(self: *Tree, node: *Node, index: usize, key_hash: U24) void {
        std.debug.assert(index == 0);
        std.debug.assert(node.parent_index > 0);
        std.debug.assert(!node.parent_offset.eq(U24.ZERO));

        const parent_node = self._getNode(node.parent_offset);
        const hash_index = @as(usize, node.parent_index) - 1;
        parent_node.hashes[hash_index] = key_hash;

        if (hash_index == 0 and parent_node.parent_index > 0) {
            self._updateNominatedHash(parent_node, hash_index, key_hash);
        }
    }

    fn _getHeader(self: *Tree) *Header {
        return @ptrCast(&self._buf()[0]);
    }

    fn _getOffset(self: Tree) U24 {
        return U24.from(usize, self._len());
    }

    fn _getNode(self: *Tree, offset: U24) *Node {
        std.log.debug("Fetching Node at {}\n", .{offset.to(usize)});
        const ptr: [*]u8 = self._buf().ptr + offset.to(usize);
        return @ptrCast(ptr);
    }

    fn _getEntry(self: *Tree, offset: U24) *Entry {
        std.log.debug("Fetching Entry at {}\n", .{offset.to(usize)});
        const ptr: [*]u8 = self._buf().ptr + offset.to(usize);
        return @ptrCast(ptr);
    }

    fn _newNode(self: *Tree) *Node {
        const buf = self._extendBy(@sizeOf(Node));
        return @ptrCast(buf);
    }

    fn _newEntry(self: *Tree, key: []const u8, value: []const u8) U24 {
        const offset = self._getOffset();
        const size_required = Entry.sizeRequired(key.len, value.len);
        const buf = self._extendBy(size_required);

        const entry = Entry{
            .control = 0,
            .capacity = U24.from(usize, size_required - @sizeOf(Entry)),
            .key_len = U24.from(usize, key.len),
            .val_len = U24.from(usize, value.len),
        };

        const entry_ptr: [*]const u8 = @ptrCast(&entry);

        @memcpy(buf[0..@sizeOf(Entry)], entry_ptr);
        @memcpy(buf[@sizeOf(Entry) .. key.len + @sizeOf(Entry)], key);
        @memcpy(buf[key.len + @sizeOf(Entry) .. value.len + key.len + @sizeOf(Entry)], value);
        return offset;
    }

    fn _extendBy(self: *Tree, count: usize) []u8 {
        switch (self.buf) {
            .slice_buf => |slice_buf| {
                const len = slice_buf.len;
                var list = std.ArrayList(u8).initCapacity(self.allocator, len + count) catch |e| {
                    std.debug.panic("Allocator Error: {}", .{e});
                };
                list.appendSliceAssumeCapacity(slice_buf);
                list.appendNTimesAssumeCapacity(0, count);
                self.buf = TreeBuf{ .alloc_buf = list };
                return self._buf()[len .. len + count];
            },
            .alloc_buf => |*alloc_buf| {
                const len = alloc_buf.items.len;
                alloc_buf.appendNTimes(0, count) catch |e| {
                    std.debug.panic("Allocator Error: {}", .{e});
                };
                return self._buf()[len .. len + count];
            },
        }
    }

    fn _buf(self: Tree) []u8 {
        return switch (self.buf) {
            .slice_buf => |buf_| buf_,
            .alloc_buf => |buf_| buf_.items,
        };
    }

    fn _len(self: Tree) usize {
        return switch (self.buf) {
            .slice_buf => |buf_| buf_.len,
            .alloc_buf => |buf_| buf_.items.len,
        };
    }
};

const TreeBuf = union(enum) {
    slice_buf: []u8,
    alloc_buf: std.ArrayList(u8),
};

const KeyLocation = struct {
    node_offset: U24,
    entry_index: usize,
    status: KeyStatus,
};

const KeyStatus = enum {
    Empty,
    Matched,
    Deleted,
    RequiresShift,
};

const SplitResult = struct {
    node_offset: U24,
    target_index: usize,
};

const Header = struct {
    magic: [8]u8,
    version: u8,
    depth: u8,
    leak: U24,

    pub fn asSlice(self: *const Header) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..@sizeOf(Header)];
    }
};

const Node = struct {
    parent_offset: U24,
    parent_index: u8,
    len: u8,
    hashes: [19]U24,
    kv_offset: [19]U24,
    children_offset: [20]U24,

    pub fn hasSpace(self: *Node) bool {
        return self.len < 19;
    }

    pub fn isLeaf(self: *Node) bool {
        return self.children_offset[0].eq(U24.ZERO);
    }

    pub fn isRoot(self: *Node) bool {
        return self.parent_offset.eq(U24.ZERO);
    }

    pub fn asSlice(self: *const Node) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..@sizeOf(Node)];
    }
};

const Entry = struct {
    control: u8,
    capacity: U24,
    key_len: U24,
    val_len: U24,

    const EXTRA_CAPACITY: usize = 16;

    pub fn key(self: *Entry) []u8 {
        const key_val = self.keyVal();
        return key_val[0..self.key_len.to(usize)];
    }

    pub fn val(self: *Entry) []const u8 {
        const key_val = self.keyVal();
        const key_len = self.key_len.to(usize);
        return key_val[key_len .. key_len + self.val_len.to(usize)];
    }

    pub fn len(self: Entry) usize {
        return self.capacity.to(usize) + @sizeOf(Entry);
    }

    pub fn isDeleted(self: Entry) bool {
        return self.control & 0x80 != 0;
    }

    pub fn markDeleted(self: *Entry) void {
        self.control |= 0x80;
    }

    pub fn unmarkDeleted(self: *Entry) void {
        self.control ^= 0x80;
    }

    pub fn setVal(self: *Entry, value: []const u8) void {
        @memcpy(self.keyVal(), value);
    }

    pub fn sizeRequired(key_len: usize, val_len: usize) usize {
        return @sizeOf(Entry) + key_len + val_len + EXTRA_CAPACITY;
    }

    inline fn keyVal(self: *Entry) [*]u8 {
        const base: [*]u8 = @ptrCast(self);
        return base + @sizeOf(Entry);
    }
};

fn hashKey(key: anytype) U24 {
    const val: u32 = std.hash.Fnv1a_32.hash(std.mem.asBytes(key));
    return U24.from(u32, val);
}

const U24 = struct {
    bytes: [3]u8,

    const ZERO: U24 = .{ .bytes = .{ 0, 0, 0 } };

    pub fn from(comptime T: type, val: T) U24 {
        return switch (T) {
            u8, u16 => U24.fromU32(@intCast(val)),
            u32 => U24.fromU32(val),
            u64, usize => U24.fromU32(@truncate(val)),
            else => @compileError("Only unsigned integers accepted"),
        };
    }

    pub fn to(self: U24, comptime T: type) T {
        return switch (T) {
            u8, u16 => @truncate(self.toU32()),
            u32 => self.toU32(),
            u64, usize => @intCast(self.toU32()),
            else => @compileError("Only unsigned integers accepted"),
        };
    }

    pub fn add(self: U24, other: U24) U24 {
        return U24.from(u32, self.to(u32) + other.to(u32));
    }

    pub fn sub(self: U24, other: U24) U24 {
        return U24.from(u32, self.to(u32) - other.to(u32));
    }

    pub fn eq(self: U24, other: U24) bool {
        return self.to(u32) == other.to(u32);
    }

    pub fn cmp(self: U24, other: U24) Ordering {
        const self_ = self.to(u32);
        const other_ = other.to(u32);
        if (self_ == other_) {
            return Ordering.Equal;
        } else if (self_ < other_) {
            return Ordering.Less;
        } else {
            return Ordering.Greater;
        }
    }

    fn fromU32(val: u32) U24 {
        return U24{ .bytes = [3]u8{
            @truncate(val >> 16),
            @truncate(val >> 8),
            @truncate(val),
        } };
    }

    fn toU32(self: U24) u32 {
        return @as(u32, self.bytes[0]) << 16 | @as(u32, self.bytes[1]) << 8 | @as(u32, self.bytes[2]);
    }
};

fn cmp(comptime T: type, a: T, b: T) Ordering {
    if (a == b) {
        return Ordering.Equal;
    } else if (a < b) {
        return Ordering.Less;
    } else {
        return Ordering.Greater;
    }
}

fn sliceCmp(comptime T: type, a: []const T, b: []const T) Ordering {
    switch (cmp(usize, a.len, b.len)) {
        .Equal => {},
        else => |ord| return ord,
    }

    for (a, 0..) |a_e, i| {
        const b_e = b[i];
        switch (cmp(T, a_e, b_e)) {
            .Equal => {},
            else => |ord| return ord,
        }
    }

    return Ordering.Equal;
}

const Ordering = enum {
    Less,
    Equal,
    Greater,
};

test "basic add functionality" {
    var tree = Tree.init(std.testing.allocator);
    tree.insert("greeting", "Hello There!");
    try std.testing.expectEqualStrings(tree.get("greeting").?, "Hello There!");
    tree.deinit();
}

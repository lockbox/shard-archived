const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Union-Find Data structure that stores a list of pointer-pairs
/// that point to the `next` pair, and the `item`. This UF is generic
/// over @TypeOf(item), and takes ownership of all items inserted.
pub fn UnionFind(comptime T: type) type {
    return UnionFindAligned(T, null);
}

pub fn UnionFindAligned(comptime T: type, comptime alignment: ?u29) type {
    if (alignment) |a| {
        if (a == @alignOf(T)) {
            return UnionFindAligned(T, null);
        }
    }
    return struct {
        const Self = @This();

        /// underlying array backing the union find
        nodes: Slice,

        /// how many items can fit in the union find before
        /// we need to allocatet more memory
        capacity: usize,

        /// allocator that get's kept around
        allocator: std.mem.Allocator,

        pub const UnionFindNode = struct {
            const NodeSelf = @This();
            next: *NodeSelf,
            item: *T,

            pub fn initInPlace(ptr: *NodeSelf, item: *T) void {
                ptr.next = ptr;
                ptr.item = item;
            }

            pub fn setNext(self: *NodeSelf, other: *NodeSelf) void {
                self.next = other;
            }

            pub fn setItem(self: *NodeSelf, item: *T) void {
                self.item = item;
            }

            pub fn getItem(self: *NodeSelf) *T {
                return self.item;
            }

            pub fn getNext(self: *NodeSelf) *NodeSelf {
                return self.next;
            }
        };

        pub const Slice = if (alignment) |a| ([]align(a) UnionFindNode) else []UnionFindNode;

        pub fn init(allocator: Allocator) Allocator.Error!Self {
            return Self{ .nodes = &[0]UnionFindNode{}, .capacity = 0, .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            for (self.nodes) |node| {
                self.allocator.destroy(node.item);
            }

            self.allocator.free(self.allocatedSlice());
        }

        pub fn init_capacity(allocator: Allocator, num: usize) Allocator.Error!Self {
            var self = try Self.init(allocator);
            try self.ensureCapacityPrecise(num);
            return self;
        }

        pub fn ensureCapacity(self: *Self, num: usize) Allocator.Error!void {
            if (@sizeOf(T) == 0) {
                self.capacity = std.math.maxInt(usize);
                return;
            }

            if (num <= self.capacity) return;

            // allocate self.capacity * 2 or num
            const alloc_size = @max(num, self.capacity * 2);

            // now actually alloc
            try self.ensureCapacityPrecise(alloc_size);
        }

        /// `self.items` will have exactly `num` capacity if `num` >= `self.capacity`
        pub fn ensureCapacityPrecise(self: *Self, num: usize) Allocator.Error!void {
            // we can fit infinity size `0`
            if (@sizeOf(T) == 0) {
                self.capacity = std.math.maxInt(usize);
                return;
            }

            // no need to resize
            if (num <= self.capacity) return;

            // allocate new backing buffer
            const array = try self.allocator.alignedAlloc(UnionFindNode, alignment, num);

            // 1) memcpy old data to new buffer is we have old data
            // 2) free the buffer
            if (self.capacity > 0) {
                @memcpy(array[0..self.nodes.len], self.nodes);
                self.allocator.free(self.allocatedSlice());
            }

            // swap pointers
            self.nodes.ptr = array.ptr;
            self.capacity = array.len;
        }

        /// Gets the slice of all inserted items
        pub fn slice(self: *Self) Slice {
            return self.nodes;
        }

        /// Gets the entire allocated slice, including the undefined
        /// bytes
        pub fn allocatedSlice(self: *Self) Slice {
            return self.nodes.ptr[0..self.capacity];
        }

        pub fn insert(self: *Self, item: *T) Allocator.Error!usize {
            // resize if neceessary
            if (self.nodes.len == self.capacity) {
                try self.ensureCapacity(self.capacity * 2);
            }

            // make new node
            var insert_idx: usize = self.nodes.len;
            self.nodes.len += 1;

            // add item to node, make the new node
            // self-referential
            var node_ptr = &self.nodes[insert_idx];
            node_ptr.item = item;
            node_ptr.next = node_ptr;
            return insert_idx;
        }

        /// union nodes indecies, bool if success or invalid index
        pub fn union_indecies(self: *Self, child: usize, parent: usize) bool {
            if (child >= self.size() or parent >= self.size()) {
                return false;
            }

            self.nodes[child].next = &self.nodes[parent];

            return true;
        }

        /// unions the nodes containg the data pointers,
        /// returns true if success or bool if pointer is not found
        /// in the table
        pub fn union_items(self: *Self, child: *T, parent: *T) bool {
            var child_node = self.get_node(child) orelse return false;
            var parent_node = self.get_node(parent) orelse return false;

            child_node.next = parent_node;

            return true;
        }

        /// Get root parent
        pub fn find(self: *Self, child: usize) ?*T {
            if (child >= self.size()) return null;

            var current = &self.nodes[child];
            var parent = current.next;

            // each loop, coalesce the parent pointers one level
            while (parent != current) {
                var next_parent = parent.next;
                current.next = next_parent;

                // move next pointers
                current = parent;
                parent = next_parent;
            }

            // we don't return the node -- just the underlying item
            // we're pointing to
            return parent.item;
        }

        /// Gets a pointer to the item at `idx`
        pub fn get(self: *Self, idx: usize) UnionFindError!*T {
            if (idx >= self.nodes.len) {
                return UnionFindError.InvalidIndex;
            }

            return self.nodes[idx].item;
        }

        pub fn size(self: *Self) usize {
            return self.nodes.len;
        }

        pub fn get_index(self: *Self, ptr: *T) ?usize {
            for (self.nodes, 0..) |node, idx| {
                if (node.item == ptr) {
                    return idx;
                }
            }

            return null;
        }

        inline fn get_node(self: *Self, item: *T) ?*UnionFindNode {
            for (0..self.nodes.len) |idx| {
                var node = &self.nodes[idx];

                if (node.item == item) {
                    return node;
                }
            }

            return null;
        }
    };
}

pub const UnionFindError = error{
    InvalidIndex,
};

test "union find init" {
    const allocator = testing.allocator;

    const uf = UnionFind(usize);
    var test_uf = try uf.init(allocator);
    defer test_uf.deinit();

    try testing.expect(test_uf.capacity == 0);
    try testing.expect(test_uf.nodes.len == 0);
    try testing.expect(test_uf.size() == test_uf.nodes.len);
}

test "union find init capacity" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    try testing.expect(test_uf.capacity == capacity);
    try testing.expect(test_uf.nodes.len == 0);
    try testing.expect(test_uf.allocatedSlice().len == capacity);
}

test "union find insert 1" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    item.* = 2;

    _ = try test_uf.insert(item);
    try testing.expect(test_uf.capacity == capacity);
    try testing.expect(test_uf.nodes.len == 1);
    try testing.expect(test_uf.size() == test_uf.nodes.len);
    try testing.expect(test_uf.allocatedSlice().len == capacity);
}

test "union find insert 2" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    var item2 = try allocator.create(usize);

    _ = try test_uf.insert(item);
    _ = try test_uf.insert(item2);

    try testing.expect(test_uf.capacity == capacity);
    try testing.expect(test_uf.nodes.len == 2);
    try testing.expect(test_uf.size() == test_uf.nodes.len);
    try testing.expect(test_uf.allocatedSlice().len == capacity);
}

test "union find node insert self-ref" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    item.* = 2;

    _ = try test_uf.insert(item);

    var ptr = test_uf.nodes[0].next;
    try testing.expect(ptr == &test_uf.nodes[0]);
}

test "union find resize to num" {
    const allocator = testing.allocator;
    const capacity = 1;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    try test_uf.ensureCapacity(10);

    try testing.expect(test_uf.capacity == 10);
}

test "union find resize to 2 * capacity" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    try test_uf.ensureCapacity(7);

    try testing.expect(test_uf.capacity == 10);
}

test "union find insert resize" {
    const allocator = testing.allocator;
    const capacity = 1;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    var item2 = try allocator.create(usize);

    // capacity should still be 1
    _ = try test_uf.insert(item);
    try testing.expect(test_uf.nodes.len == 1);
    try testing.expect(test_uf.capacity == 1);

    // now capacity should be == 2
    _ = try test_uf.insert(item2);
    try testing.expect(test_uf.capacity == 2);
    try testing.expect(test_uf.nodes.len == 2);
}

test "union find get item" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    item.* = 2;

    _ = try test_uf.insert(item);
    try testing.expect(test_uf.capacity == capacity);
    try testing.expect(test_uf.nodes.len == 1);
    try testing.expect(test_uf.size() == test_uf.nodes.len);
    try testing.expect(test_uf.allocatedSlice().len == capacity);

    // is it the right value
    var received_item = try test_uf.get(0);
    try testing.expect(received_item.* == @as(usize, 2));
}

test "union find no parent" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);

    _ = try test_uf.insert(item);
    try testing.expect(test_uf.capacity == capacity);
    try testing.expect(test_uf.nodes.len == 1);
    try testing.expect(test_uf.size() == test_uf.nodes.len);
    try testing.expect(test_uf.allocatedSlice().len == capacity);

    // parent should be index of self (0)
    try testing.expect(test_uf.find(0).? == try test_uf.get(0));
}

test "union find 1 parent" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    var item2 = try allocator.create(usize);

    _ = try test_uf.insert(item);
    _ = try test_uf.insert(item2);

    // set idx1.next to point to idx0
    test_uf.nodes[1].next = &test_uf.nodes[0];
    // we should get the pointer to the item @ idx 0
    try testing.expect(test_uf.find(1).? == try test_uf.get(0));
}

test "union find parent parent" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    var item2 = try allocator.create(usize);
    var item3 = try allocator.create(usize);

    _ = try test_uf.insert(item);
    _ = try test_uf.insert(item2);
    _ = try test_uf.insert(item3);

    // set idx1.next to point to idx0, and idx[2].next to idx[1]
    test_uf.nodes[1].next = &test_uf.nodes[0];
    test_uf.nodes[2].next = &test_uf.nodes[1];

    // we should get the pointer to the item @ idx 0
    try testing.expect(test_uf.find(2).? == try test_uf.get(0));
    // the `.next` of idx1 should now be set to idx0
    try testing.expect(test_uf.nodes[2].next.item == try test_uf.get(0));
}

test "union find get index" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    var item2 = try allocator.create(usize);
    var item3 = try allocator.create(usize);

    // we don't indert item3, to assert that we won't find it
    // in the union find
    _ = try test_uf.insert(item);
    _ = try test_uf.insert(item2);

    try testing.expect(test_uf.get_index(item) == 0);
    try testing.expect(test_uf.get_index(item3) == null);
    try testing.expect(test_uf.get_index(item2) == 1);

    allocator.destroy(item3);
}

test "union find union indecies" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    var item2 = try allocator.create(usize);

    // we don't indert item3, to assert that we won't find it
    // in the union find
    _ = try test_uf.insert(item);
    _ = try test_uf.insert(item2);

    // make sure they currently are not linked
    try testing.expect(test_uf.nodes[0].next == &test_uf.nodes[0]);
    try testing.expect(test_uf.nodes[1].next == &test_uf.nodes[1]);

    // now link 0.next to 1
    try testing.expect(test_uf.union_indecies(0, 1));
    try testing.expect(test_uf.nodes[0].next == &test_uf.nodes[1]);
    try testing.expect(test_uf.nodes[1].next == &test_uf.nodes[1]);

    // assert that we cannot link incorrect indicies
    try testing.expect(!test_uf.union_indecies(0, 5));
}

test "union find union items" {
    const allocator = testing.allocator;
    const capacity = 5;
    const uf = UnionFind(usize);
    var test_uf = try uf.init_capacity(allocator, capacity);
    defer test_uf.deinit();

    var item = try allocator.create(usize);
    var item2 = try allocator.create(usize);
    var item3 = try allocator.create(usize);

    // we don't insert item3, to assert that we won't find it
    // in the union find
    _ = try test_uf.insert(item);
    _ = try test_uf.insert(item2);

    // make sure they currently are not linked
    try testing.expect(test_uf.nodes[0].next == &test_uf.nodes[0]);
    try testing.expect(test_uf.nodes[1].next == &test_uf.nodes[1]);

    // now link 0.next to 1
    try testing.expect(test_uf.union_items(item, item2));
    try testing.expect(test_uf.nodes[0].next == &test_uf.nodes[1]);
    try testing.expect(test_uf.nodes[1].next == &test_uf.nodes[1]);

    // assert that we cannot link incorrect indicies
    try testing.expect(!test_uf.union_items(item2, item3));

    testing.allocator.destroy(item3);
}

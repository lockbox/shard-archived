const std = @import("std");
const testing = std.testing;

/// Represents a region of memory, does not own it's own memory
/// and should be created with an `ArenaAllocator`
pub const ShardMemoryRegion = struct {
    /// Name of region, if applicable
    name: []u8,

    /// Base address of the region, in Targets with multiple areas of memory
    /// (basically all targets), `base_address` of the `ShardMemoryRegion` is
    /// used essentially as an offset from the `ShardInputTarget.base_address`
    base_address: u64,

    /// The backing slice of data for the entire `ShardMemoryRegion`
    data: []u8,

    const Self = @This();

    /// Is the requested address inside the memory region.
    ///
    /// NOTE: this does not take into consideration any `size` constraints of a request,
    /// for that -- see `ShardMemoryRegion::containsRange()`
    pub fn contains(self: *const Self, address: u64) bool {
        if (self.data.len == 0) {
            return false;
        }

        // address must be in the range [base_address, base_address + size)
        if (address >= self.base_address and address <= self.base_address + self.data.len - 1) {
            return true;
        }

        return false;
    }

    /// Checks if the desired range (address + size) can fit inside this
    /// `ShardMemoryRegion`
    ///
    /// Applies failure cases, and fallthrough is `true`
    /// 1. if `address` < `self.base_address` => `false`
    /// *at this point, `address` >= `self.base_address`*
    /// 2. if `address` + `size` > `self.base_address` + `self.data.len` => false
    pub fn containsRange(self: *const Self, address: u64, size: u64) bool {
        if (address < self.base_address) {
            return false;
        }

        if (self.data.len == 0) {
            return false;
        }

        // address + size must be below the upper bound of the region,
        // we can skip the -1 check here by just checking if the provided upper
        // bound is greater than this regions' upper bound
        if (address + size > self.base_address + self.data.len) {
            return false;
        }

        return true;
    }
};

test "contains" {
    var region = ShardMemoryRegion{ .name = &[_]u8{}, .base_address = 0x1000, .data = &[_]u8{} };

    // size 0 should not contain anything
    try testing.expectEqual(false, region.contains(0x1000));

    // manually set len to 0x100
    region.data.len = 0x100;
    try testing.expect(region.contains(0x1000));

    // just inside the bounds
    try testing.expect(region.contains(0x1001));
    try testing.expect(region.contains(0x10FF));

    // just outside the bounds
    try testing.expectEqual(false, region.contains(0x1100));
    try testing.expectEqual(false, region.contains(0xFFF));

    // middle of the bounds
    try testing.expect(region.contains(0x10A0));

    // way outside the bounds
    try testing.expectEqual(false, region.contains(0x5555555555));
}

test "contains range" {
    var region = ShardMemoryRegion{ .name = &[_]u8{}, .base_address = 0x1000, .data = &[_]u8{} };

    // size 0 should not contain anything
    try testing.expectEqual(false, region.containsRange(0x1000, 0));

    // manually set len to 0x100
    region.data.len = 0x100;
    try testing.expect(region.containsRange(0x1000, 1));

    // the exact bounds
    try testing.expect(region.containsRange(0x1000, 0x100));

    // just inside the bounds
    try testing.expect(region.containsRange(0x1001, 0xFE));

    // below to inside the bounds
    try testing.expectEqual(false, region.containsRange(0x100, 0xFF0));

    // inside to outside the bounds
    try testing.expectEqual(false, region.containsRange(0x1010, 0x1000));
    try testing.expectEqual(false, region.containsRange(0x1010, 0xF1));

    // just inside the bounds
    try testing.expect(region.containsRange(0x1001, 0xFF));
    try testing.expect(region.containsRange(0x1000, 0xFF));

    // outside and below the bounds
    try testing.expectEqual(false, region.containsRange(0x100, 0x100));

    // outside and above the bounds
    try testing.expectEqual(false, region.containsRange(0x1100, 0x100));

    // outside below to outside abouve the bounds
    try testing.expectEqual(false, region.containsRange(0x100, 0x1111000));
}

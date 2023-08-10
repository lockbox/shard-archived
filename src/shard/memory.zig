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
        if (address >= self.base_address and address <= self.base_address + self.data.len) {
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

        if (address + size > self.base_address + self.data.len) {
            return false;
        }

        return true;
    }
};

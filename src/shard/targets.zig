const std = @import("std");
const memory = @import("memory.zig");

const ShardMemoryRegion = memory.ShardMemoryRegion;

/// SLEIGH context configuration settings to be passed to the
/// SLEIGH backend
pub const SleighContextPair = struct {
    variable: []const u8,
    value: u64,
};

/// A container for inputs that SHARD can process.
///
/// Generally an entire program, a dump of a program, or a sequence of
/// instructions.
///
/// ## A note on memory regions
///
/// Memory Regions are annoying, in order to simplify certain things in the
/// short term its easy to make a ghidra script that dumps all defined functions
/// as their own region, and in the future it would be very handy to be able
/// to interact with the semantics of memory regions / sections.
///
/// ### What this means
///
/// At the moment, when loading a raw bin, things are pretty straightforward:
/// - load bin
/// - apply base address rebase if necessary
/// - only need to work with 1 underlying memory region
/// - very naive + simple view of the world
///
/// When loading something with multiple `sections` / `segments` / `regions`:
/// - all three of those above terms are abstracted in the same way
/// - load bin / desc file
/// - apply rebase (only to top level target)
/// - all regions have an offset from the top level "base address"
pub const ShardInputTarget = struct {
    base_address: u64,
    size: u64,
    regions: []const ShardMemoryRegion,
    context_pairs: []SleighContextPair = &.{},
    sla_path: []const u8 = &.{},

    const Self = @This();

    /// Retrieves the maximum valid address that belongs to the
    /// `ShardInputTarget`
    pub fn maxAddress(self: *const Self) u64 {
        return self.base_address + self.size;
    }

    /// Gets the list of raw memory regions in the input target, you
    /// almost certainly want to use `getBecasedMemoryRegions` instead
    pub fn getRawMemoryRegions(self: *const Self) []const ShardMemoryRegion {
        return self.regions;
    }

    /// Takes ownership of slice of context pairs
    pub fn setContextPairs(self: *ShardInputTarget, pairs: []SleighContextPair) void {
        self.context_pairs = pairs;
    }

    /// Getter for the slice of `SleighContextPair` that this target
    /// needs in order to properly load
    pub fn getContextPairs(self: *const Self) []SleighContextPair {
        return self.context_pairs;
    }

    /// Returns the total size of all contained `ShardMemoryRegion`'s'
    pub fn size(self: *const Self) u64 {
        return self.size;
    }

    /// Returns the base address of the target
    pub fn baseAddress(self: *const Self) u64 {
        return self.base_address;
    }

    /// Path to the .sla file so that SLEIGH knows how to parse this file
    /// Callee owns the input slice
    pub fn setSlaPath(self: *Self, path: []const u8) void {
        self.sla_path = path;
    }

    /// Getter for path to sla file for this target
    pub fn getSlaPath(self: *const Self) []const u8 {
        return self.sla_path;
    }

    pub fn new(base: u64, regions: []const ShardMemoryRegion) Self {
        // rolling maximum of the region with the largest base address
        // and it's size
        var max_base_address: u64 = 0;
        var max_base_address_size: u64 = 0;

        // rolling minimum base address so we can find our base address
        var min_base_address: u64 = 0xffffffffffffffff;

        for (regions) |region| {

            // update maximum
            if (region.base_address > max_base_address) {
                max_base_address = region.base_address;
                max_base_address_size = region.data.len;
            }

            // update minimum
            if (region.base_address < min_base_address) {
                min_base_address = region.base_address;
            }
        }

        // highest valid address of any region - minimum region address
        const target_size = (max_base_address + max_base_address_size) - min_base_address;
        return ShardInputTarget{ .base_address = base, .size = target_size, .regions = regions };
    }

    /// Utility method to find the internal `ShardMemoryRegion` that
    /// contains `address`
    fn getOwningRegion(self: *const Self, address: u64) ?*const ShardMemoryRegion {
        // is this a valid address
        if (address < self.base_address) {
            return null;
        }

        // convert from the address, to the un-rebased address we're going
        // to need to actually search for
        const searching_address = address - self.base_address;
        for (self.regions) |region| {
            if (region.contains(searching_address)) {
                return region;
            }
        }

        return null;
    }

    /// Gets the list of `ShardMemoryRegion`'s rebased off of the owning
    /// target's base address. The caller is responsible for freeing the
    /// returned `ShardMemoryRegion` objects.
    ///
    /// eg.
    ///
    /// ```zig
    /// var regions = target.getRebasedMemoryRegions();
    /// defer allocator.free(regions);
    /// ```
    pub fn getRebasedMemoryRegions(self: *const Self, allocator: std.mem.Allocator) ![]const ShardMemoryRegion {
        var out = try allocator.alloc(ShardMemoryRegion, self.regions.len);

        // copy over the pointers + base_address
        for (self.regions, 0..) |region, idx| {
            out[idx].base_address = region.base_address + self.base_address;
            out[idx].data = region.data;
            out[idx].name = region.name;
        }

        return out;
    }

    /// Rebases the `base_address` for the current `ShardInputTarget`
    pub fn setBaseAddress(self: *ShardInputTarget, address: u64) void {
        self.base_address = address;
    }

    /// Given an array of regions, blindly construct a new input desc,
    /// if the base address is to be set, do it after the `ShardInputDesc`
    /// has been constructed via `ShardInputDesc::setBaseAddress`, which can
    /// help to rebase things.
    pub fn from_regions(regions: []const ShardMemoryRegion) Self {
        var base: u64 = 0xffffffffffffffff;

        for (regions) |region| {
            base = @min(base, region.base_address);
        }

        return ShardInputTarget.new(base, regions);
    }

    /// Given an address, the target will return the next valid address in the
    /// range that is `equal to or greater` than the provided address.
    ///
    /// eg.
    ///
    /// ```zig
    /// var next_address = target.nextAddress(0);
    /// ```
    ///
    /// Will return the first address in the target, whether it's 0 or something like
    /// `0x60000000`. While something like:
    ///
    /// ```zig
    /// var next_address = target.nextAddress(0xffffffffffffff00);
    /// ```
    ///
    /// will return `null` if the target does not have that address or higher in any
    /// `ShardMemoryRegion`. This allows the creation of an iterator like functionality
    /// over addresses in the target.
    pub fn nextAddress(self: *const Self, address: u64) ?u64 {
        var next_address: ?u64 = null;

        var target_base = self.baseAddress();

        if (address > self.maxAddress()) {
            // exit condition
            next_address = null;
        } else {
            // the address is somewhere in or below our `[]ShardMemoryRegion`, find it

            // search for the next region that either contains this address or is
            // the next address
            for (self.getRawMemoryRegions()) |region| {
                // the region directly owns this address,
                // short circuit and return
                if (region.contains(address - target_base)) {
                    next_address = address;
                    break;
                }

                var region_base = region.base_address + target_base;

                // we already verified that the region does not contain the address,
                // so move on if the address is also larger than the current base
                if (address > region_base) {
                    continue;
                }

                // if we get here, then address is less than `region_base`, and
                // the region does not directly own this address. if `next_address`
                // is set, then see if we are closer to the address than the current
                // `next_address`, if so then overwrite it
                if (next_address) |next| {
                    // keep whichever option is closer to address
                    //logger.debug("next: {}, address: {}", .{ next, address });
                    next_address = @min(next, region_base);
                } else {
                    // `next_address` has not been set, so do so if `next_address` is
                    // larger or equal  to address
                    if (region_base >= address) {
                        //logger.debug("next_address being set to: {}", .{region_base});
                        next_address = region_base;
                        //logger.debug("next_address: {?}", .{next_address});
                    }
                }
            }
        }

        return next_address;
    }
};

test "set base address" {}
test "set sla path" {}
test "set context pairs" {}
test "get base address" {}
test "get size" {}
test "get sla path" {}
test "get context pairs" {}
test "new from regions" {}
test "get raw regions" {}
test "get rebased regions" {}
test "get owning region" {}
test "next address" {}

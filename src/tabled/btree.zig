//! This module introduces Fat-pointer style BTree data structures `BTreeMap` and `BTreeSet`.
//!
//! These data structures are generic over the compared type, where each type *must* implement
//! the `BTreeComparator` interface provided as a `Context` type argument to the `comptime` type
//! definition.
//!
//! This module provides default `BTree` shaping parameters that are currently not exposed to be
//! changed. They are shamelessly copied from the rust implementation of a `BTree`.
//!
//!
//!
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Default size of B, 6 as per Rust default
const B: usize = 6;

/// Capacity of Node list, canonically `2 * B - 1`
const CAPACITY: usize = 2 * B - 1;

/// Minimum length after node split, note that at some points during
/// `BTree` operations theh length may temporarily flucuate to be less
/// than this contant
const MIN_LEN_AFTER_SPLIT: usize = B - 1;

/// Canonical value
const KV_IDX_CENTER = B - 1;

/// Canonical value
const EDGE_IDX_LEFT_OF_CENTER: usize = B - 1;

/// Canonical value
const EDGE_IDX_RIGHT_OF_CENTER: usize = B;

/// Map Backed by a B-Tree. Not thread-safe.
///
/// All lookups are performed via the provided `Context` type, which must be implemented
/// for each `K`.
///
/// Context must be a struct with member functions:
///   - `cmp(self, K, K) i32``
///   - `eql(self, K, K, usize) bool`
///
/// NOTE: this may be reworked to only include `cmp`
///
/// These two funcitons allow for direct comparison of `K`, and to create a total
/// ordering of all `K` stored in the map. The intent is for this to be faster than
/// performing a hashing operation of a standard `HashMap`.
///
pub fn BTreeMap(comptime K: type, comptime V: type, comptime Context: type) type {
    return struct {
        unmanaged: Unmanaged,
        allocator: Allocator,

        /// `BTreeMapUnmanaged` type using the same settings as this managed type
        pub const Unmanaged = BTreeMapUnmanaged(K, V, Context);
    };
}

/// General purpose BTree.
pub fn BTreeMapUnmanaged(comptime K: type, comptime V: type, comptime Context: type) type {
    _ = Context;
    _ = V;
    _ = K;
    return struct {};
}

/// Compile time verification of the provided `Context` type.
fn verifyBTreeContext(comptime RawContext: type, comptime PseudoKey: type, comptime Key: type, comptime Hash: type, comptime is_array: bool) void {
    comptime {
        _ = is_array;
        _ = Hash;
        _ = Key;
        _ = PseudoKey;
        _ = RawContext;
    }
}

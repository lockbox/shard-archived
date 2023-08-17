const std = @import("std");
const log = std.log;
const registers = @import("registers.zig");
const RegisterImpl = registers.RegisterImpl;
const RegisterMap = registers.RegisterMap;
const sleigh = @import("../sleigh.zig");
const shard = @import("../shard.zig");
const ShardError = shard.ShardError;

const logger = log.scoped(.shard_var_references);

/// Represents a reference to memory at `address` with `size`
pub const MemoryReference = struct {
    address: u64,
    size: u64,

    pub fn text(self: *MemoryReference, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "0x{x}", .{self.address});
    }
};

/// Represents a constant `value` with `size`
pub const ConstReference = struct {
    value: u64,
    size: u64,

    pub fn text(self: *ConstReference, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{}", .{self.value});
    }
};

/// Reference to a unique space for data that isn't necessarily tied to an address,
/// but that should be logically tied together with other operations
pub const UniqueReference = struct {
    inner_addr: u64,
    size: u64,

    pub fn text(self: *UniqueReference, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "Unique{{{}}}", .{self.inner_addr});
    }
};

/// This is used to route to the proper var in the
/// respective array. These `VarReference`'s refer to the actual backing
/// storage and are just used to keep a lookup index around
pub const VarReference = union(enum) {
    constant: ConstReference,
    register: *const RegisterImpl,
    memory: MemoryReference,
    unique: UniqueReference,

    const Self = @This();
    pub fn from_varnode(vn: *const sleigh.VarnodeDesc, register_map: *const RegisterMap) !Self {
        // get the enum of valid address spaces
        var var_space = try vn.space_enum();

        // switch on the address space type
        switch (var_space) {
            .CODE, .DATA, .STACK, .RAM => {
                //out_ref.* = VarReference{ .memory = MemoryReference{ .address = vn.offset, .size = vn.size } };
                return VarReference{ .memory = MemoryReference{ .address = vn.offset, .size = vn.size } };
            },
            .CONST => {
                //out_ref.* = VarReference{ .constant = ConstReference{ .value = vn.offset, .size = vn.size } };
                return VarReference{ .constant = ConstReference{ .value = vn.offset, .size = vn.size } };
            },
            .REGISTER => {
                //out_ref.* = VarReference{ .register = register_map.lookup(vn.offset, vn.size) orelse unreachable };
                return VarReference{ .register = register_map.lookup(vn.offset, vn.size) orelse {
                    std.log.err("[REGISTER IMPL] failed to find offset: `{}`, size: `{}`", .{ vn.offset, vn.size });
                    return ShardError.InvalidRegisterLookup;
                } };
            },
            .UNIQUE => {
                //out_ref.* = VarReference{ .unique = UniqueReference{ .inner_addr = vn.offset, .size = vn.size } };
                return VarReference{ .unique = UniqueReference{ .inner_addr = vn.offset, .size = vn.size } };
            },
            else => {
                logger.warn("Got unsupported VarReference Space: {}", .{var_space});
                unreachable;
            },
        }
    }

    /// Returns an allocated char array of the text representation of this
    /// reference
    pub fn text(self: *VarReference, allocator: std.mem.Allocator) ![]const u8 {
        return switch (self.*) {
            inline else => |*case| case.text(allocator),
            .register => self.register.text(allocator),
        };
    }
};

test "code from varnode" {}
test "data from varnode" {}
test "stack from varnode" {}
test "ram from varnode" {}
test "const from varnode" {}
test "register from varnode" {}
test "unique from varnode" {}

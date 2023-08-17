const std = @import("std");
const sleigh = @import("../sleigh.zig");
const log = std.log;

const logger = log.scoped(.shard_registers);

/// Object representation of a register
pub const RegisterImpl = struct {
    /// size in bytes
    size: usize,
    /// runtime allocated
    value: []u8,
    /// Register pnemonic
    name: [16]u8,

    /// SLEIGH offset, used for btree compare
    offset_key: usize,
    /// SLEIGH size, used for btree compare
    size_key: usize,

    const Self = @This();

    /// Converts from the SLEIGH register representation into the impl known
    /// by SHARD in-place, `out` should be a pointer to the outbound register
    pub fn from_sleigh_in_place(reg: *const sleigh.RegisterDesc, out: *Self) void {

        // this is safe -- all register offsets are very small
        out.offset_key = @truncate(reg.varnode.offset);

        // same as above, all sizes are measured in bytes so should technically
        // be like a very very small uint
        out.size_key = @truncate(reg.varnode.size);

        // copy the easy data
        out.size = out.size_key;
        @memcpy(out.name[0..], reg.name[0..out.name.len]);
    }

    pub fn text(self: *const RegisterImpl, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{s}", .{self.name});
    }
};

pub const RegisterMap = struct {
    const Self = @This();

    registers: []RegisterImpl,

    pub fn new(allocator: std.mem.Allocator, len: usize) !Self {
        var array = try allocator.alloc(RegisterImpl, len);

        return Self{ .registers = array };
    }

    pub fn lookup(self: *const Self, offset: usize, size: usize) ?*const RegisterImpl {
        for (self.registers, 0..) |reg, idx| {
            if (reg.offset_key == offset and reg.size == size) {
                return &self.registers[idx];
            }
        }

        // It didn't find a match when looking for the register pair (offset, size) so look  for
        // smaller size by 2, 4, 8 bc ghidra maintainers are rude.
        // Instead of just matching on (offset, size) like you should be able to,
        // ghidra has some *very* poor decisions for architectures like riscv
        // to not have sub registers like (ax into eax into rax),
        // in this case they have `a4` and don't differentiate into smaller variations
        const modifiers = [_]usize{ 2, 4, 8 };
        for (modifiers) |modifier| {
            for (self.registers, 0..) |reg, idx| {
                if (reg.offset_key == offset and (size == reg.size / modifier)) {
                    return &self.registers[idx];
                }
            }
        }
        return null;
    }

    pub fn print_all(self: *const Self) void {
        for (self.registers) |reg| {
            logger.debug("Register{{name: {s}, offset: {}, size: {}}}", .{ reg.name, reg.offset_key, reg.size });
        }
    }
};

test "register from sleigh" {}
test "register to text" {}
test "new register map" {}
test "register map lookup" {}

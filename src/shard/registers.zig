const std = @import("std");
const testing = std.testing;
const log = std.log;
const sleigh = @import("../sleigh.zig");

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

    /// Constructs a register reference from a SLEIGH register varnode
    pub fn from_sleigh(reg: *const sleigh.RegisterDesc) Self {
        var name = [_]u8{0} ** 16;

        @memcpy(name[0..], reg.name[0..name.len]);

        return Self{ .offset_key = @truncate(reg.varnode.offset), .size_key = @truncate(reg.varnode.size), .size = reg.varnode.size, .name = name, .value = &[_]u8{} };
    }

    /// Generates the human readable version of the register
    pub fn text(self: *const RegisterImpl, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{s}", .{self.name});
    }
};

/// Container of `RegisterImpl`'s, thin layet over the backing container
/// to logically segment the implementation
pub const RegisterMap = struct {
    registers: std.ArrayList(RegisterImpl),

    const Self = @This();

    pub fn new(allocator: std.mem.Allocator) !Self {
        return try Self.newWithCapacity(allocator, 8);
    }

    pub fn newWithCapacity(allocator: std.mem.Allocator, capacity: usize) !Self {
        return Self{ .registers = try std.ArrayList(RegisterImpl).initCapacity(allocator, capacity) };
    }

    pub fn ensureCapacity(self: *Self, capacitiy: usize) !void {
        try self.registers.ensureTotalCapacity(capacitiy);
    }

    pub fn items(self: *const Self) []const RegisterImpl {
        return self.registers.items;
    }

    pub fn addRegister(self: *Self, register: RegisterImpl) !void {
        try self.registers.append(register);
    }

    pub fn deinit(self: *Self) void {
        self.registers.deinit();
        self.* = undefined;
    }

    pub fn lookup(self: *const Self, offset: usize, size: usize) ?*const RegisterImpl {
        for (self.items(), 0..) |reg, idx| {
            if (reg.offset_key == offset and reg.size == size) {
                return &self.registers.items[idx];
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
            for (self.items(), 0..) |reg, idx| {
                if (reg.offset_key == offset and (size == reg.size / modifier)) {
                    return &self.registers.items[idx];
                }
            }
        }
        return null;
    }

    pub fn print_all(self: *const Self) void {
        for (self.items()) |reg| {
            logger.debug("Register{{name: {s}, offset: {}, size: {}}}", .{ reg.name, reg.offset_key, reg.size });
        }
    }
};

test "register from sleigh" {
    // make sleigh reg_desc
    var reg_name = [_]u8{0} ** 64;
    var reg = sleigh.RegisterDesc{ .name = reg_name, .varnode = sleigh.VarnodeDesc{ .space = "registerrrrrrrrr".*, .offset = 16, .size = 8 } };

    // now construct new register
    var register = RegisterImpl.from_sleigh(&reg);

    try testing.expect(reg.varnode.size == register.size);
    try testing.expect(reg.varnode.size == register.size_key);
    try testing.expect(reg.varnode.offset == register.offset_key);
    try testing.expectEqualSlices(u8, reg.name[0..16], register.name[0..16]);
}

test "register to text" {
    // make sleigh reg_desc
    var reg_name = [_]u8{0} ** 64;
    @memcpy(reg_name[0..16], "HEllo There hihi");
    var reg = sleigh.RegisterDesc{ .name = reg_name, .varnode = sleigh.VarnodeDesc{ .space = "registerrrrrrrrr".*, .offset = 16, .size = 8 } };

    // now construct new register
    var register = RegisterImpl.from_sleigh(&reg);
    try testing.expectEqualStrings("HEllo There hihi", &register.name);
}

test "new register map" {
    var _r = try RegisterMap.new(testing.allocator);
    defer _r.deinit();

    var reg_map = try RegisterMap.newWithCapacity(testing.allocator, 100);
    defer reg_map.deinit();

    try testing.expect(reg_map.registers.capacity == 100);
    try testing.expect(reg_map.items().len == 0);

    try reg_map.ensureCapacity(3000);
    try testing.expect(reg_map.registers.capacity >= 3000);
}

test "register map add" {
    var reg_map = try RegisterMap.newWithCapacity(testing.allocator, 100);
    defer reg_map.deinit();

    // empty map
    try testing.expect(reg_map.items().len == 0);
    try testing.expect(reg_map.registers.capacity == 100);

    // add a register
    var reg = RegisterImpl{ .name = "1234567890abcdef".*, .offset_key = 8, .size = 9, .size_key = 10, .value = &[_]u8{} };
    try reg_map.addRegister(reg);

    try testing.expect(reg_map.items().len == 1);
    try testing.expect(reg_map.registers.capacity == 100);
    try testing.expect(reg_map.registers.items.len == 1);

    // make sure the register is correct
    try testing.expect(reg_map.registers.items[0].offset_key == 8);
    try testing.expect(reg_map.registers.items[0].size == 9);
    try testing.expect(reg_map.registers.items[0].size_key == 10);
    try testing.expectEqualStrings("1234567890abcdef", &reg_map.registers.items[0].name);
    try testing.expect(reg_map.items()[0].offset_key == 8);
    try testing.expect(reg_map.items()[0].size == 9);
    try testing.expect(reg_map.items()[0].size_key == 10);
    try testing.expectEqualStrings("1234567890abcdef", &reg_map.items()[0].name);
}

test "register map lookup" {
    var reg_map = try RegisterMap.newWithCapacity(testing.allocator, 100);
    defer reg_map.deinit();

    // empty map
    try testing.expect(reg_map.items().len == 0);
    try testing.expect(reg_map.registers.capacity == 100);

    // add a register
    var reg1 = RegisterImpl{ .name = "1234567890abcdef".*, .offset_key = 8, .size = 8, .size_key = 8, .value = &[_]u8{} };
    try reg_map.addRegister(reg1);

    // add a register
    var reg2 = RegisterImpl{ .name = "fedcba0987654321".*, .offset_key = 0, .size = 4, .size_key = 4, .value = &[_]u8{} };
    try reg_map.addRegister(reg2);

    // we should have 2
    try testing.expect(reg_map.items().len == 2);

    // correctly map to reg1 for all sub field searches
    // TODO: handle aliasing multiple to same backing
    var reg1_exact = reg_map.lookup(8, 8);
    try testing.expect(reg1_exact != null);
    try testing.expectEqualStrings("1234567890abcdef", &reg1_exact.?.name);
    var reg1_small = reg_map.lookup(8, 4);
    try testing.expect(reg1_small != null);
    try testing.expectEqualStrings("1234567890abcdef", &reg1_small.?.name);
    var reg1_smallest = reg_map.lookup(8, 2);
    try testing.expect(reg1_smallest != null);
    try testing.expectEqualStrings("1234567890abcdef", &reg1_smallest.?.name);

    // fail to find incorrect
    try testing.expect(null == reg_map.lookup(100, 4));
    try testing.expect(null == reg_map.lookup(2, 4));
}

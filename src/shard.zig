//! Shard Library, made up of a thin IL over SLEIGH, and utilities for
//! loading binary blobs or ghidra dumps for analysis.
const std = @import("std");
const json = std.json;
const sleigh = @import("sleigh.zig");
pub const SleighState = sleigh.SleighState;
pub const SleighError = sleigh.SleighError;
pub const opcodes = @import("shard/opcodes.zig");
pub const loader = @import("shard/loader.zig");
pub const memory = @import("shard/memory.zig");
pub const registers = @import("shard/registers.zig");
pub const var_references = @import("shard/var_references.zig");
pub const targets = @import("shard/targets.zig");

pub const ShardLoader = loader.ShardLoader;
pub const ShardInputTarget = targets.ShardInputTarget;
pub const ShardInputBin = targets.ShardInputBin; // TODO: refactor so we don't need this here
pub const ShardInputDesc = targets.ShardInputDesc; // TODO: refactor so we don't need this here
pub const ShardOperation = opcodes.ShardOperation;
pub const ShardMemoryRegion = memory.ShardMemoryRegion;
pub const VarReference = var_references.VarReference;
pub const RegisterMap = registers.RegisterMap;
pub const RegisterImpl = registers.RegisterImpl;

pub const LOG_SCOPE = .shard_rt;

const logger = std.log.scoped(LOG_SCOPE);

/// Errors that occur during the execution of SHARD
pub const ShardError = error{
    UnableToLoadFile,
    InvalidRegisterLookup,
    NoTarget,
    NoInputMode,
    TargetPresent,
};

/// Runtime that lifts and processes program instructions
///
/// TBD: make a builder struct and leaave all the SLEIGH stuff there
pub const ShardRuntime = struct {
    /// handle to underlying sleigh instance
    sleigh_handle: SleighState,

    target: ?ShardInputTarget = null,

    allocator: std.mem.Allocator,

    /// backing register array
    register_map: RegisterMap,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        var sleigh_rt = SleighState{};
        sleigh_rt.init();

        const empty_registers = RegisterMap{ .registers = &[_]RegisterImpl{} };
        return Self{ .sleigh_handle = sleigh_rt, .allocator = allocator, .register_map = empty_registers };
    }

    /// Sets up the initial state to be able to lift the target from SLEIGH
    ///
    /// TODO: need to grab + populate userops as undefine ops in shard
    fn begin(self: *Self) void {
        if (self.target) |_| {
            self.sleigh_handle.begin();
        } else {
            logger.err("No target, nothing to begin.", .{});
        }
    }

    /// Given a target, loads the required data into the SLEIGH backend,
    /// and prepares SLEIGH + SHARD to lift data
    pub fn load_target(self: *Self, target: ShardInputTarget) !void {
        if (self.target) |_| {
            logger.err("Already have target!", .{});
            return ShardError.TargetPresent;
        }

        self.target = target;

        self.load_target_to_sleigh();
        try self.load_registers();
    }

    // TODO: in actuality this has a massive sleigherror situation
    fn load_target_to_sleigh(self: *Self) void {
        if (self.target) |target| {
            // load sla contents
            self.sleigh_handle.add_specfile(target.getSlaPath());
            self.begin();

            // load pspec context
            for (target.getContextPairs()) |pair| {
                self.sleigh_handle.context_var_set_default(pair.variable, @truncate(pair.value));
            }

            // load regions
            if (target.getRebasedMemoryRegions(self.allocator)) |regions| {
                defer self.allocator.free(regions);
                for (regions) |region| {
                    //logger.debug("Loading region{{name: {s}, base_address: 0x{x}, len: {}}}", .{ region.name, region.base_address, region.data.len });
                    self.load_region_to_sleigh(region);
                }
            } else |_| {
                logger.err("Unable to load target into SLEIGH", .{});
            }
        } else {
            logger.err("No target, nothing to load to sleigh", .{});
        }
    }

    /// Internal method used to pass an individual memory region to
    /// SLEIGH.
    fn load_region_to_sleigh(self: *Self, region: ShardMemoryRegion) void {
        self.sleigh_handle.load_data(region.base_address, region.data);
    }

    /// Get's all the current registers in use from the `SLEIGH` backend
    pub fn load_registers(self: *Self) !void {
        var sleigh_registers = try self.sleigh_handle.get_registers();

        // get new array of register impls
        var register_map = try RegisterMap.new(self.allocator, sleigh_registers.register_count);
        // convert from SLEIGH to SHARD registers
        for (sleigh_registers.slice(), 0..) |reg, idx| {
            RegisterImpl.from_sleigh_in_place(&reg, &register_map.registers[idx]);
            //logger.debug("Register: `{s}`, offset: {}, size: {}, space: `{s}`", .{ reg.name, reg.varnode.offset, reg.varnode.size, reg.varnode.space });
        }

        // swap the pointer for the real list
        // XXX: jank asf
        self.register_map = register_map;
    }

    /// Performs initial translation of the entire input space
    pub fn perform_lift(self: *Self) !std.ArrayList(ShardInsn) {
        var target = self.target orelse {
            logger.err("No target, cannot lift anything", .{});
            return ShardError.NoTarget;
        };
        var address = target.baseAddress();
        var max_address = target.maxAddress();
        logger.debug("Base address: 0x{x}", .{address});

        var insn_list = std.ArrayList(ShardInsn).init(self.allocator);

        while (address < max_address) {
            //logger.debug("[perform lift] looper with address: 0x{x}", .{address});

            // check if next address is valid
            var inner_address = target.nextAddress(address);
            //logger.debug("Inner addr: `0x{?x}`", .{inner_address});
            if (inner_address) |insn_addr| {
                // next address is a valid one, update the top level address
                address = insn_addr;

                // now attempt to parse the insn at the address
                if (try self.sleigh_handle.lift_insn(insn_addr)) |insn| {
                    //logger.debug("[INSN] {s}", .{try insn.to_asm(self.allocator)});

                    // lift insn semantic summary
                    var shard_insn = ShardInsn.from_sleigh(insn, &self.register_map, self.allocator) catch {
                        logger.warn("Failed to xlate insn: {s}", .{try insn.to_asm(self.allocator)});
                        address += insn.size;
                        continue;
                    };
                    try insn_list.append(shard_insn);
                    address += insn.size;
                } else {
                    // failed to parse, continue on
                    logger.err("Failed to parse insn @ `0x{x}`", .{address});
                    address += 2; // TODO: target alignment
                }
            } else {
                // no more insn addresses, exit
                break;
            }
        }

        return insn_list;
    }

    pub fn deinit(self: *Self) void {
        self.sleigh_handle.deinit();
        logger.debug("De-init SHARD-owned SLEIGH-handle", .{});
    }
};

/// Summarization of an affiliated sequence of `ShardOperation`'s.
///
/// This is useful to reduce the completixity of the search space when trying to
/// search for semantics over a large area.
pub const SemanticSummary = struct {
    /// Is this a pure function / operation, ie. will always have the exact same
    /// side effects for the same input
    pure: bool = false,
    /// Is this a `register_pure` function / operation, ie. pure + only modify
    /// registers
    register_pure: bool = false,
    /// Is a part of this summarized container performing atomic operations
    atomic: bool = false,
    /// Is a part of this summarized container accessing model specific registers?
    /// eg. MSR's on x86_64, coprocessor registers or xpsr registers on arm
    msr_access: bool = false,
    /// Is a part of this summarized container performing something semantically
    /// equivalent to a `return`
    ret: bool = false,
    /// Is a part of this summarized container performing something semantically
    /// equivalent to a `jump`, conditional, indirect or not
    jump: bool = false,
    /// Is a part of this summarized container performing something semantically
    /// equivalent of a `call`, indirect or not
    call: bool = false,
    /// Is a part of this summarized container performing an operation that is
    /// semantically equivalent to halting the underlying processor
    halt: bool = false,
    /// Is a part of this summarized container performing an operation that is
    /// semantically equivalent to performing an interrupt operation
    interrupt: bool = false,
    /// Is a part of this summarized container performing an operation that
    /// modifies the stack pointer
    modify_sp: bool = false,
    /// Something in this container is tainted with unimplementation
    unimpl: bool = false,

    const Self = @This();

    /// Construct new `SemanticSummary` with no flags set to `true`
    pub fn empty() Self {
        return Self{};
    }

    /// Attempts to summarize a series of `ShardOperation`, does an okay job.
    ///
    /// Currently only supports summarizing:
    /// - ret
    /// - jump
    /// - call
    /// - unimpl
    /// - modify_sp
    pub fn summarize(ops: []ShardOperation) Self {
        var out = Self.empty();

        for (ops) |op| {
            if (op.modifies_sp()) {
                out.modify_sp = true;
            }

            // apply opcode-based labels
            switch (op) {
                ShardOperation.unimplemented => {
                    out.unimpl = true;
                },
                ShardOperation.ret => {
                    out.ret = true;
                },
                ShardOperation.branch, ShardOperation.branch_conditional, ShardOperation.branch_indirect => {
                    out.jump = true;
                },
                ShardOperation.call, ShardOperation.call_indirect => {
                    out.call = true;
                },
                else => {},
            }
        }
        return out;
    }
};

/// A container that wraps underlying `ShardOperation`'s and holds
/// a semantic summary over the contained members
///
/// TODO: rename to `ShardBlock` or something
pub const ShardInsn = struct {
    summary: SemanticSummary,
    size: u64,
    base_address: u64,
    operations: []ShardOperation,
    text: []const u8,

    const Self = @This();
    pub fn from_sleigh(insn: *const sleigh.InsnDesc, register_map: *const RegisterMap, allocator: std.mem.Allocator) !Self {
        var size = insn.size;
        var base_address = insn.address;
        var text = try insn.to_asm(allocator);

        // now convert the pcode ops and set summary bits
        var operations = try allocator.alloc(ShardOperation, insn.op_count);

        for (insn.pcodes(), 0..) |pcode, idx| {
            operations[idx] = try ShardOperation.from_sleigh_op(&pcode, register_map, allocator);
        }

        // summarize the operations inside this block
        var summary = SemanticSummary.summarize(operations);
        //if (summary.modify_sp) {
        //    logger.debug("INSN: {s} @ 0x{x}, modifies SP", .{ text, base_address });
        //}
        return Self{ .summary = summary, .size = size, .base_address = base_address, .operations = operations, .text = text };
    }
};

/// Applies the callback `func` to each instruction in the `[]ShardMemoryRegion`'s owned by `target`
///
/// NOTE: `func` should return the size of the insn (ex. size to increase the address by).
/// If the provided address is 1. not in an owned `ShardMemoryRegion` but 2. still inside the address range
/// of the `ShardInputTarget`, the iterator will find the next valid address.
///
/// TODO: adapt `ShardRuntime::perform_lift` to use this
///
/// What this means is that the only valid assumption the callback can make is that
/// the next invocation will be **at least** returned `insn size` bytes after the last
/// invocation
pub fn ShardTargetInsnIterator(comptime T: type, target: ShardInputTarget, func: *const fn (user_data: T, address: u64) void, userdata: T) void {
    _ = userdata;
    _ = func;
    var working_address = target.baseAddress();
    _ = working_address;
    const max_address: u64 = target.maxAddress();
    _ = max_address;
}

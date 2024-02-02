const VarReference = @import("var_references.zig").VarReference;
const std = @import("std");
const sleigh = @import("../sleigh.zig");
const registers = @import("registers.zig");
const RegisterMap = registers.RegisterMap;

/// enum of opcode list
///
/// # TODO
/// things to add
/// - vector of opcode sequence
///   - takes lane size, lane #, and base addr ?
/// - system control insns
///   - fence {D,I}
///   - flush {D,I,ITLB,DTLB,Lx Cache {I,D}}
///   - bp
///   - wp
/// - atomic operation
///   - figure out a way to encode load-store architectures (arm,mips, bfin etc)
///     as opposed to x86
/// - privilege/mode check/update
/// - insn insert
/// - tsc check / reset
///   - can encode as a "monotonically increasing" register or something
/// - hint instructions
///   - prefetch
///   - branch pred
///   - indirect branch hint
///   - spec hint
///
pub const ShardOps = enum {
    unimplemented,
    copy,
    store,
    load,
    branch,
    branch_conditional,
    branch_indirect,
    call,
    call_indirect,
    ret,
    not_supported,

    const Self = @This();
    pub fn from_sleigh(op: sleigh.OpCode) Self {
        return switch (op) {
            .CPUI_CALLOTHER => Self.unimplemented,
            .CPUI_COPY => Self.copy,
            .CPUI_LOAD => Self.load,
            .CPUI_STORE => Self.store,
            .CPUI_BRANCH => Self.branch,
            .CPUI_BRANCHIND => Self.branch_indirect,
            .CPUI_CBRANCH => Self.branch_conditional,
            .CPUI_CALL => Self.call,
            .CPUI_CALLIND => Self.call_indirect,
            .CPUI_RETURN => Self.ret,

            else => Self.unimplemented,
        };
    }
};

/// Interface of all operations that Shard is aware of, unimplmeneted operations
/// are "implemented"  (annotated) via the `unimplemented` operation tag.
pub const ShardOperation = union(ShardOps) {
    //Undefined,
    /// Unimplemented, a known operation that does not yet
    /// have translated behavior.
    unimplemented: ShardOpUnimplemented,
    /// Copy
    copy: ShardOpCopy,
    /// Store
    store: ShardOpStore,
    /// Load
    load: ShardOpLoad,
    /// Branch
    branch: ShardOpBranch,
    /// Branch conditional
    branch_conditional: ShardOpBranchCond,
    /// Branch indirect
    branch_indirect: ShardOpBranchIndirect,
    /// Call
    call: ShardOpCall,
    /// Call indirect
    call_indirect: ShardOpCallIndirect,
    /// Return
    ret: ShardOpReturn,

    /// placeholder
    not_supported: ShardOpNotSupported,

    const Self = @This();
    //pub fn evaluate(self: *ShardOperation, inputs: []VarReference) VarReference {
    //    return switch (self.*) {
    //        inline else => |*case| case.evaluate(inputs),
    //    };
    //}

    /// Concretize the output reference based on the input references
    //pub fn concretize(self: *ShardOperation, inputs: []VarReference) VarReference {
    //    return switch (self.*) {
    //        inline else => |*case| case.evaluate(inputs),
    //    };
    //}

    /// Return the built AST expr based on the provided inputs
    //pub fn ast(self: *ShardOperation, inputs: []ShardAstNode) *ShardAstNode {
    //    return switch (self.*) {
    //        inline else => |*case| case.ast(inputs),
    //    };
    //}

    /// Attempt to simplify the current AST input expression
    //pub fn simplify(self: *ShardOperation, inputs: []ShardAstNode) *ShardAstNode {
    //    return switch (self.*) {
    //        inline else => |*case| case.ast(inputs),
    //    };
    //}

    pub fn new(inputs: []VarReference, output: ?VarReference, opcode: ShardOps, allocator: std.mem.Allocator) !Self {
        return switch (opcode) {
            .copy => Self{ .copy = ShardOpCopy.new(inputs, output, allocator) },
            .load => Self{ .load = ShardOpLoad.new(inputs, output, allocator) },
            .ret => Self{ .ret = ShardOpReturn.new(inputs, output, allocator) },
            .branch => Self{ .branch = ShardOpBranch.new(inputs, output, allocator) },
            .branch_conditional => Self{ .branch_conditional = ShardOpBranchCond.new(inputs, output, allocator) },
            .branch_indirect => Self{ .branch_indirect = ShardOpBranchIndirect.new(inputs, output, allocator) },
            .call => Self{ .call = ShardOpCall.new(inputs, output, allocator) },
            .call_indirect => Self{ .call_indirect = ShardOpCallIndirect.new(inputs, output, allocator) },
            else => Self{ .unimplemented = ShardOpUnimplemented.new(inputs, output, allocator) },
        };
    }

    /// Gets the output `VarReference` from the `ShardOperation`
    pub fn output_reference(self: *const ShardOperation) ?VarReference {
        return switch (self.*) {
            inline else => |*case| case.output,
        };
    }

    /// Checks if the output reference is the stack pointer register by
    /// checking if the output reference is a register that ends with `sp`,
    /// which is generally the stack pointer on most architectures
    pub fn modifies_sp(self: *const ShardOperation) bool {
        const output = self.output_reference();

        if (output) |out_ref| {
            switch (out_ref) {
                .register => |reg| {
                    // is the name sp
                    if (std.mem.containsAtLeast(u8, &reg.name, 1, "sp")) {
                        return true;
                    }
                },
                else => {},
            }
        }

        return false;
    }

    /// Creates a caller owned `ShardOperation` from a SLEIGH P-Code operation
    pub fn from_sleigh_op(in_op: *const sleigh.PcodeOp, register_map: *const RegisterMap, allocator: std.mem.Allocator) !Self {
        var inputs = try allocator.alloc(VarReference, in_op.inputs_len);
        errdefer allocator.free(inputs);

        const shard_op = ShardOps.from_sleigh(in_op.opcode);

        // get all the input nodes here
        for (in_op.inputs(), 0..) |vn, idx| {
            inputs[idx] = VarReference.from_varnode(&vn, register_map) catch |err| {
                std.log.err("Input vn construction failed: `{}`", .{err});
                std.process.exit(1);
            };
        }

        // we have an output pcode node
        if (in_op.output) |out_vn| {
            const out = try VarReference.from_varnode(out_vn, register_map);

            return Self.new(inputs, out, shard_op, allocator);
        }

        // no output
        return Self.new(inputs, null, shard_op, allocator);
    }
};

pub const ShardAstNode = struct {};
pub const SilLocation = struct {};

pub const ShardOpUnimplemented = struct {
    inputs: []VarReference,
    output: ?VarReference,
    const Self = @This();

    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpCopy = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpStore = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpLoad = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpCall = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpCallIndirect = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpBranch = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpBranchIndirect = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpBranchCond = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpReturn = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

pub const ShardOpNotSupported = struct {
    inputs: []VarReference,
    output: ?VarReference,

    const Self = @This();
    pub fn new(inputs: []VarReference, output: ?VarReference, allocator: std.mem.Allocator) Self {
        _ = allocator;
        const out = Self{ .inputs = inputs, .output = output };
        return out;
    }
};

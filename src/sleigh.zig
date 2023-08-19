//! Wrapper around the loading of images into SLEIGH, and the
//! P-Code object emitted in translation of instructions.
//!
//! Currently the stub loader on the C++ side only manages
//! one section for us and will need to be updated in the
//! future to handle arbitrary sections.
//!
//! At the moment everything is behind a pretty simple C-style
//! API:
//!
//! ```c
//! typedef struct VarnodeDesc
//! {
//!     char space[16];
//!     uint64_t offset;
//!     uint64_t size;
//! };
//!
//! typedef struct PcodeOp
//! {
//!     ghidra::OpCode opcode;
//!     VarnodeDesc *output;
//!     uint64_t input_len;
//!     VarnodeDesc *inputVarnodes;
//! };
//!
//! typedef struct InsnPcode
//! {
//!     uint64_t op_count;
//!     PcodeOp *ops;
//! };
//!
//! typedef struct ArbitraryManager
//! {
//!     int foo;
//! };
//!
//! ArbitraryManager* arbitrary_manager_new(void);
//! void arbitrary_manager_free(*ArbitraryManager);
//! void arbitrary_manager_load_region(ArbitraryManager *mgr,
//!                        uint64_t address,
//!                        uint64_t size,
//!                        uint8_t *data);
//! void arbitrary_manager_specfile(ArbitraryManager *mgr, char path[]);
//! InsnPcode * arbitrary_manager_next_insn(ArbitraryManager *mgr);
//! ```
//!
//! # Limitations
//!
//! - This entire `arbitrary_manager` API needs to be reworked where the bindings
//! return an error enum always, and the output values are pointers that are set.
//! - Alternatively it could also get reworked into something where the returns
//! stay as-is and if `null` is returned there is an API call to get the last error.
//!     - "but wah this isn't going to be nice for concurrent access" - inner brain.
//!         - my guy this is SLEIGH, concurrency isn't a part of the game, we got
//!           processes for that.
//!
const std = @import("std");
const testing = std.testing;
const mem = std.mem;

pub const LOG_SCOPE = .sleigh;

const logger = std.log.scoped(LOG_SCOPE);

const SleighManager = opaque {};

/// Automatically generated from source
///
/// These break up into categories:
///   - Branching operations
///   - Load and Store
///   - Comparison operations
///   - Arithmetic operations
///   - Logical operations
///   - Extension and truncation operations
///
/// Data-flow operations (60-73) starting at opcode 60 are
/// not typically emitted in translation and are generally
/// used only in the SLEIGH simplification process, because
/// all the simplification is not done in SLEIGH, we should
/// (hopefully) never interact with them.
pub const OpCode = enum(c_int) {
    /// Copy one operand to another
    CPUI_COPY = 1,
    /// Load from a pointer into a specified address space
    CPUI_LOAD = 2,
    /// Store at a pointer into a specified address space
    CPUI_STORE = 3,
    /// Always branch
    CPUI_BRANCH = 4,
    /// Conditional branch
    CPUI_CBRANCH = 5,
    /// Indirect branch (jumptable)
    CPUI_BRANCHIND = 6,
    /// Call to an absolute address
    CPUI_CALL = 7,
    /// Call through an indirect address
    CPUI_CALLIND = 8,
    /// User-defined operation
    CPUI_CALLOTHER = 9,
    /// Return from subroutine
    CPUI_RETURN = 10,
    /// Integer comparison, equality (==)
    CPUI_INT_EQUAL = 11,
    /// Integer comparison, in-equality (!=)
    CPUI_INT_NOTEQUAL = 12,
    /// Integer comparison, signed less-than (<)
    CPUI_INT_SLESS = 13,
    /// Integer comparison, signed less-than-or-equal (<=)
    CPUI_INT_SLESSEQUAL = 14,
    /// Integer comparison, unsigned less-than (<)
    CPUI_INT_LESS = 15,
    /// Integer comparison, unsigned less-than-or-equal (<=)
    /// This also indicates a borrow on unsigned subtraction.
    CPUI_INT_LESSEQUAL = 16,
    /// Zero extension
    CPUI_INT_ZEXT = 17,
    /// Sign extension
    CPUI_INT_SEXT = 18,
    /// Addition, signed or unsigned (+)
    CPUI_INT_ADD = 19,
    /// Subtraction, signed or unsigned (-)
    CPUI_INT_SUB = 20,
    /// Test for unsigned carry
    CPUI_INT_CARRY = 21,
    /// Test for signed carry
    CPUI_INT_SCARRY = 22,
    /// Test for signed borrow
    CPUI_INT_SBORROW = 23,
    /// Twos complement
    CPUI_INT_2COMP = 24,
    /// Logical/bitwise negation (~)
    CPUI_INT_NEGATE = 25,
    /// Logical/bitwise exclusive-or (^)
    CPUI_INT_XOR = 26,
    /// Logical/bitwise and (&)
    CPUI_INT_AND = 27,
    /// Logical/bitwise or (|)
    CPUI_INT_OR = 28,
    /// Left shift (<<)
    CPUI_INT_LEFT = 29,
    /// Right shift, logical (>>)
    CPUI_INT_RIGHT = 30,
    /// Right shift, arithmetic (>>)
    CPUI_INT_SRIGHT = 31,
    /// Integer multiplication, signed and unsigned (*)
    CPUI_INT_MULT = 32,
    /// Integer division, unsigned (/)
    CPUI_INT_DIV = 33,
    /// Integer division, signed (/)
    CPUI_INT_SDIV = 34,
    /// Remainder/modulo, unsigned (%)
    CPUI_INT_REM = 35,
    /// Remainder/modulo, signed (%)
    CPUI_INT_SREM = 36,
    /// Boolean negate (!)
    CPUI_BOOL_NEGATE = 37,
    /// Boolean exclusive-or (^^)
    CPUI_BOOL_XOR = 38,
    /// Boolean and (&&)
    CPUI_BOOL_AND = 39,
    /// Boolean or (||)
    CPUI_BOOL_OR = 40,
    /// Floating-point comparison, equality (==)
    CPUI_FLOAT_EQUAL = 41,
    /// Floating-point comparison, in-equality (!=)
    CPUI_FLOAT_NOTEQUAL = 42,
    /// Floating-point comparison, less-than (<)
    CPUI_FLOAT_LES = 43,
    /// Floating-point comparison, less-than-or-equal (<=)
    CPUI_FLOAT_LESSEQUAL = 44,
    /// Not-a-number test (NaN)
    CPUI_FLOAT_NAN = 46,
    /// Floating-point addition (+)
    CPUI_FLOAT_ADD = 47,
    /// Floating-point division (/)
    CPUI_FLOAT_DIV = 48,
    /// Floating-point multiplication (*)
    CPUI_FLOAT_MULT = 49,
    /// Floating-point subtraction (-)
    CPUI_FLOAT_SUB = 50,
    /// Floating-point negation (-)
    CPUI_FLOAT_NEG = 51,
    /// Floating-point absolute value (abs)
    CPUI_FLOAT_ABS = 52,
    /// Floating-point square root (sqrt)
    CPUI_FLOAT_SQRT = 53,
    /// Convert an integer to a floating-point
    CPUI_FLOAT_INT2FLOAT = 54,
    /// Convert between different floating-point sizes
    CPUI_FLOAT_FLOAT2FLOAT = 55,
    /// Round towards zero
    CPUI_FLOAT_TRUNC = 56,
    /// Round towards +infinity
    CPUI_FLOAT_CEIL = 57,
    /// Round towards -infinity
    CPUI_FLOAT_FLOOR = 58,
    /// Round towards nearest
    CPUI_FLOAT_ROUND = 59,
    /// Phi-node operator
    CPUI_MULTIEQUAL = 60,
    /// Copy with an indirect effect
    CPUI_INDIRECT = 61,
    /// Concatenate
    CPUI_PIECE = 62,
    /// Truncate
    CPUI_SUBPIECE = 63,
    /// Cast from one data-type to another
    CPUI_CAST = 64,
    /// Index into an array ([])
    CPUI_PTRADD = 65,
    /// Drill down to a sub-field  (->)
    CPUI_PTRSUB = 66,
    /// Look-up a segmented address
    CPUI_SEGMENTOP = 67,
    /// Recover a value from the constant pool
    CPUI_CPOOLREF = 68,
    /// Allocate a new object (new)
    CPUI_NEW = 69,
    /// Insert a bit-range
    CPUI_INSERT = 70,
    /// Extract a bit-range
    CPUI_EXTRACT = 71,
    /// Count the 1-bits
    CPUI_POPCOUNT = 72,
    /// Count the leading 0-bits
    CPUI_LZCOUNT = 73,
    /// Value indicating the end of the op-code values
    CPUI_MAX = 74,
};

/// Different `Varnode` spaces used by `SLEIGH`
///
/// Zig enum of the default spaces in `SLEIGH`
pub const VarnodeSpace = enum {
    REGISTER,
    CONST,
    UNIQUE,
    STACK,
    RAM,
    DATA,
    CODE,
    JOIN,
    IOP,
    FSPEC,

    const REGISTER_CONST = "register";
    const CONST_CONST = "const";
    const UNIQUE_CONST = "unique";
    const STACK_CONST = "stack";
    const RAM_CONST = "ram";
    const DATA_CONST = "data";
    const CODE_CONST = "code";
    const JOIN_CONST = "join";
    const IOP_CONST = "iop";
    const FSPEC_CONST = "fspec";
};

/// Zig representation of C-style Varnode in SLEIGH.
///
/// Provides utilities to convert to high level representations
/// and escape C-style limitations.
pub const VarnodeDesc = extern struct {
    space: [16]u8,
    offset: u64,
    size: u64,

    const Self = @This();

    /// Translates the current varnode space into a Zig enum
    ///
    /// Once it is an enum its a lot easier to work with.
    pub fn space_enum(self: *const VarnodeDesc) SleighError!VarnodeSpace {
        if (mem.startsWith(u8, &self.space, VarnodeSpace.REGISTER_CONST)) {
            return VarnodeSpace.REGISTER;
        } else if (mem.startsWith(u8, &self.space, VarnodeSpace.CONST_CONST)) {
            return VarnodeSpace.CONST;
        } else if (mem.startsWith(u8, &self.space, VarnodeSpace.UNIQUE_CONST)) {
            return VarnodeSpace.UNIQUE;
        } else if (mem.startsWith(u8, &self.space, VarnodeSpace.STACK_CONST)) {
            return VarnodeSpace.STACK;
        } else if (mem.startsWith(u8, &self.space, VarnodeSpace.RAM_CONST)) {
            return VarnodeSpace.RAM;
        } else if (mem.startsWith(u8, &self.space, VarnodeSpace.DATA_CONST)) {
            return VarnodeSpace.DATA;
        } else if (mem.startsWith(u8, &self.space, VarnodeSpace.CODE_CONST)) {
            return VarnodeSpace.CODE;
        } else if (mem.startsWith(u8, &self.space, VarnodeSpace.JOIN_CONST)) {
            return VarnodeSpace.JOIN;
        } else if (mem.startsWith(u8, &self.space, VarnodeSpace.IOP_CONST)) {
            return VarnodeSpace.IOP;
        } else if (mem.startsWith(u8, &self.space, VarnodeSpace.FSPEC_CONST)) {
            return VarnodeSpace.FSPEC;
        } else {
            logger.warn("Unhandled varspace: {s}", .{self.space});
            return SleighError.BadVarSpace;
        }
    }

    /// Creates a new `VarnodeDesc` from the necessary components
    pub fn new(space: []const u8, offset: u64, size: u64) Self {
        var space_name = [_]u8{0} ** 16;
        const end_idx = @min(space.len, space_name.len);
        @memcpy(space_name[0..end_idx], space[0..end_idx]);

        return Self{ .space = space_name, .offset = offset, .size = size };
    }
};

test "varnode to enum conversion" {
    const test_inputs = .{ .{ "register", VarnodeSpace.REGISTER }, .{ "const", VarnodeSpace.CONST }, .{ "unique", VarnodeSpace.UNIQUE }, .{ "stack", VarnodeSpace.STACK }, .{ "ram", VarnodeSpace.RAM }, .{ "data", VarnodeSpace.DATA }, .{ "code", VarnodeSpace.CODE }, .{ "join", VarnodeSpace.JOIN }, .{ "iop", VarnodeSpace.IOP }, .{ "fspec", VarnodeSpace.FSPEC } };

    inline for (test_inputs) |input_tuple| {
        const space_name = input_tuple[0];
        const correct_result = input_tuple[1];
        const v = VarnodeDesc.new(space_name, 0, 0);
        try testing.expect(try v.space_enum() == correct_result);
    }
}

/// Minimal wrapper around C-style struct that represents a P-Code operation.
///
/// This struct retains the list of inputs, the optitonal output, and the
/// opcode representation the semantic action. Note that `CALLOTHER` is an
/// overload for an arbitrary number of user-defined operations and requires
/// special handling.
pub const PcodeOp = extern struct {
    opcode: OpCode,
    output: ?*VarnodeDesc,
    inputs_len: u64,
    input_nodes: [*]VarnodeDesc,

    pub fn inputs(self: *const PcodeOp) []const VarnodeDesc {
        return self.input_nodes[0..self.inputs_len];
    }
};

/// Represents the semantics of a lifted instruction in the target.
///
/// Built from an arbitrary number of P-Code operations and an address + size,
/// this container is the lowest level abstraction over an instruction.
pub const InsnDesc = extern struct {
    op_count: u64,
    ops: [*]PcodeOp,
    size: u64,
    address: u64,
    insn: [*]u8,
    insn_len: u64,
    body: [*]u8,
    body_len: u64,

    /// Get the slice of P-Code operations making up this instruction
    pub fn pcodes(self: *const InsnDesc) []const PcodeOp {
        return self.ops[0..self.op_count];
    }

    /// Return the ascii text for the assembly instruction
    pub fn to_asm(self: *const InsnDesc, allocator: std.mem.Allocator) ![]const u8 {
        var out: []u8 = try allocator.alloc(u8, 1 + self.body_len + self.insn_len);

        @memcpy(out[0..self.insn_len], self.insn[0..self.insn_len]);
        out[self.insn_len] = ' ';
        @memcpy(out[self.insn_len + 1 ..], self.body[0..self.body_len]);

        return out;
    }
};

/// Container for Registers.
///
/// Made up of name and backing Varnode. Used as a search key for mapping
/// references to correct registers during analysis
pub const RegisterDesc = extern struct {
    name: [64]u8,
    varnode: VarnodeDesc,
};

/// C-Style list of registers.
///
/// Made up of a count and the array of registers.
pub const RegisterList = extern struct {
    register_count: u64,
    registers: [*]RegisterDesc,

    pub fn slice(self: *const RegisterList) []const RegisterDesc {
        return self.registers[0..self.register_count];
    }
};

/// List of all user defined operations (`CALLOTHER`).
///
/// This is used to turn references to the `CALLOTHER` opcode and
/// an input `const` value into a numbered user-defined operation with
/// a name.
pub const UserOpList = extern struct {
    num: u64,
    name_lens: [*]u64,
    names: [*][*]u8,

    pub fn slice(self: *UserOpList, allocator: std.mem.Allocator) ![]const []const u8 {

        // make 1st dimenstion
        var name_list: [][]u8 = try allocator.alloc([]u8, self.num);
        for (self.names[0..self.num], 0..) |n, idx| {
            var name_length = self.name_lens[idx];
            name_list[idx] = try allocator.alloc(u8, name_length);

            @memcpy(name_list[idx], n[0..name_length]);
        }

        // init the instance variable
        return name_list;
    }
};

extern fn arbitrary_manager_new() callconv(.C) *SleighManager;
extern fn arbitrary_manager_free(mgr: *SleighManager) callconv(.C) void;
extern fn arbitrary_manager_load_region(mgr: *SleighManager, address: u64, size: u64, data: [*]const u8) callconv(.C) void;
/// `path` MUST be a null terminated string
extern fn arbitrary_manager_specfile(mgr: *SleighManager, path: [*]const u8) callconv(.C) LibSlaError;
extern fn arbitrary_manager_begin(mgr: *SleighManager) callconv(.C) void;
extern fn arbitrary_manager_next_insn(mgr: *SleighManager) callconv(.C) *InsnDesc;
extern fn arbitrary_manager_lift_insn(mgr: *SleighManager, address: u64) callconv(.C) ?*InsnDesc;
extern fn arbitrary_manager_context_var_set_default(mgr: *SleighManager, context_key: [*]const u8, value: u32) callconv(.C) LibSlaError;
extern fn arbitrary_manager_get_all_registers(mgr: *SleighManager) callconv(.C) *RegisterList;
extern fn arbitrary_manager_get_user_ops(mgr: *SleighManager) callconv(.C) *UserOpList;

/// Zig error type for errors encountered in SLEIGH
pub const SleighError = error{
    Uninit,
    BadVarSpace,
    BadOperation,
    Fail,
    CallBeginFirst,
    UnableToLift,
    InvalidSlaspec,
    InvalidPspec,
    InsnDecodeError,
    BadContextVariable,
};

/// Represents the C error enum from SLEIGH
pub const LibSlaError = enum(c_int) {
    Ok = 0,
    Uninit = 1,
    BadVarSpace = 2,
    BadOperation = 3,
    Fail = 4,
    CallBeginFirst = 5,
    UnableToLift = 6,
    InvalidSlaspec = 7,
    InvalidPspec = 8,
    InsnDecodeError = 9,
    BadContextVariable = 10,

    const Self = @This();

    /// Helper to detect if the current enum is an error
    /// value or not
    pub fn isError(self: *Self) bool {
        return switch (self.*) {
            .Ok => false,
            inline else => true,
        };
    }

    /// Convert's from the C enum SLEIGH error into a zig error type.
    ///
    /// This panic's if `self` is `Ok`.
    pub fn asSleighError(self: *const Self) SleighError {
        return switch (self.*) {
            Self.Ok => @panic("Cannot convert from Ok into error!"),
            Self.Uninit => SleighError.Uninit,
            Self.BadVarSpace => SleighError.BadVarSpace,
            Self.BadOperation => SleighError.BadOperation,
            Self.Fail => SleighError.Fail,
            Self.CallBeginFirst => SleighError.CallBeginFirst,
            Self.UnableToLift => SleighError.UnableToLift,
            Self.InvalidSlaspec => SleighError.InvalidSlaspec,
            Self.InvalidPspec => SleighError.InvalidPspec,
            Self.InsnDecodeError => SleighError.InsnDecodeError,
            Self.BadContextVariable => SleighError.BadContextVariable,
        };
    }
};

test "libsla error to SleighError" {
    const result_tuples = .{ .{ LibSlaError.Uninit, SleighError.Uninit }, .{ LibSlaError.BadVarSpace, SleighError.BadVarSpace }, .{ LibSlaError.BadOperation, SleighError.BadOperation }, .{ LibSlaError.Fail, SleighError.Fail }, .{ LibSlaError.CallBeginFirst, SleighError.CallBeginFirst }, .{ LibSlaError.UnableToLift, SleighError.UnableToLift }, .{ LibSlaError.InvalidSlaspec, SleighError.InvalidSlaspec }, .{ LibSlaError.InvalidPspec, SleighError.InvalidPspec }, .{ LibSlaError.InsnDecodeError, SleighError.InsnDecodeError }, .{ LibSlaError.BadContextVariable, SleighError.BadContextVariable } };

    inline for (result_tuples) |test_tuple| {
        const enum_val = test_tuple[0];
        const result = test_tuple[1];

        try testing.expectEqual(enum_val.asSleighError(), result);
    }
}

/// Wrapper over the SLEIGH engine. In general this is the lowest level wrapper
/// in `Zig` over an added C ffi layer.
pub const SleighState = struct {
    mgr: *SleighManager,
    began: bool = false,

    const Self = @This();

    /// Constructor
    pub fn init() Self {
        logger.debug("Initializing SLEIGH", .{});
        var inner_manager = arbitrary_manager_new();

        return Self{ .mgr = inner_manager };
    }

    /// Destroys the inner SLEIGH handle
    ///
    /// TODO: add a reset method
    pub fn deinit(self: *SleighState) void {
        arbitrary_manager_free(self.mgr);
        logger.debug("De-init SLEIGH", .{});
        self.mgr = undefined;
        self.* = undefined;
    }

    /// Initialize the inner `SLEIGH` instance with the specific architecture flavor
    /// we want to decode and lift from
    pub fn add_specfile(self: *SleighState, path: []const u8) SleighError!void {
        logger.debug("Adding specfile `{s}`", .{path});

        var result = arbitrary_manager_specfile(self.mgr, path.ptr);
        if (result.isError()) {
            return result.asSleighError();
        }
    }

    /// Puts array of `u8` into SLEIGH memory
    pub fn load_data(self: *SleighState, address: u64, data: []const u8) SleighError!void {
        if (!self.began) {
            return SleighError.CallBeginFirst;
        }

        //logger.debug("Adding data{{size: 0x{x:0>8}, address: 0x{x:0>8}}}", .{ data.len, address });
        arbitrary_manager_load_region(self.mgr, address, data.len, data.ptr);
    }

    /// Actually start the SLEIGH instance
    ///
    /// This must be called AFTER loading the sla file but BEFORE loading the
    /// proper context  variables (.pspec) and binary data or lifting insns
    pub fn begin(self: *SleighState) void {
        arbitrary_manager_begin(self.mgr);
        self.began = true;
    }

    /// Set a `SLEIGH` instance global default context variable
    ///
    /// These are different for each architecture and sub-family
    /// TODO: make a getter for all the context variables
    pub fn context_var_set_default(self: *SleighState, key: []const u8, value: u32) SleighError!void {
        //logger.debug("Setting context var `{s}` default to `{}`", .{ key, value });
        if (!self.began) {
            return SleighError.CallBeginFirst;
        }

        var result = arbitrary_manager_context_var_set_default(self.mgr, key.ptr, value);
        if (result.isError()) {
            return result.asSleighError();
        }
    }

    /// *WARNING*: Deprecated, use `SleighState::lift_insn()` instead
    pub fn next_insn(self: *SleighState) SleighError!*InsnDesc {
        if (!self.began) {
            return SleighError.CallBeginFirst;
        }

        return arbitrary_manager_next_insn(self.mgr);
    }

    /// Lift instruction at `address` into an `InsnDesc` to be processed
    ///
    /// TODO: handle the `SleighError.UnableToLift` case
    pub fn lift_insn(self: *SleighState, address: u64) SleighError!?*InsnDesc {
        //logger.debug("Getting insn @ 0x{x}", .{address});
        if (!self.began) {
            return SleighError.CallBeginFirst;
        }

        return arbitrary_manager_lift_insn(self.mgr, address);
    }

    /// Get the entire list of registers for the current architecture
    pub fn get_registers(self: *SleighState) SleighError!*RegisterList {
        //logger.debug("Getting register list", .{});
        if (!self.began) {
            return SleighError.CallBeginFirst;
        }

        return arbitrary_manager_get_all_registers(self.mgr);
    }

    /// Get entire list of user-defined operations aka `CALLOTHER` ops
    ///
    /// This is used to help navigate the architecture specific semantics
    /// of various architectures and one-off instructions.
    pub fn get_user_ops(self: *SleighState) SleighError!*UserOpList {
        //logger.debug("Getting user op list", .{});
        if (!self.began) {
            return SleighError.CallBeginFirst;
        }

        return arbitrary_manager_get_user_ops(self.mgr);
    }
};

test "can load sleigh" {
    var sleigh_mgr = arbitrary_manager_new();
    defer arbitrary_manager_free(sleigh_mgr);
}

test "init" {
    var sleigh = SleighState.init();
    defer sleigh.deinit();
}

test "load slaspec" {
    {
        // success
        var sleigh = SleighState.init();
        defer sleigh.deinit();
        try sleigh.add_specfile("./specfiles/ARM8_le.sla");
    }

    {
        // make sure we fail correctly
        var sleigh = SleighState.init();
        defer sleigh.deinit();
        try testing.expectError(SleighError.InvalidSlaspec, sleigh.add_specfile("./src/main.zig"));
    }
}

test "call begin before certain actions" {
    var sleigh = SleighState.init();
    defer sleigh.deinit();

    try testing.expectError(SleighError.CallBeginFirst, sleigh.context_var_set_default("TMode", 1));
    try testing.expectError(SleighError.CallBeginFirst, sleigh.load_data(0x00, &[_]u8{}));
    try testing.expectError(SleighError.CallBeginFirst, sleigh.next_insn());
    try testing.expectError(SleighError.CallBeginFirst, sleigh.get_registers());
    try testing.expectError(SleighError.CallBeginFirst, sleigh.get_user_ops());
    try testing.expectError(SleighError.CallBeginFirst, sleigh.lift_insn(0x0));

    // add sla + begin
    try sleigh.add_specfile("./specfiles/ARM8_le.sla");
    sleigh.begin();

    // call methods in same order as above, tho it doesnt really matter
    try sleigh.context_var_set_default("TMode", 1);
    try sleigh.load_data(0x0, &.{ 0, 0, 0, 0 });
    _ = try sleigh.next_insn();
    _ = try sleigh.get_registers();
    _ = try sleigh.get_user_ops();
    _ = try sleigh.lift_insn(0x0);
}

test "load context variable" {
    {
        // success
        var sleigh = SleighState.init();
        defer sleigh.deinit();
        try sleigh.add_specfile("./specfiles/ARM8_le.sla");
        sleigh.begin();
        try sleigh.context_var_set_default("TMode", 1);
    }
    {
        // fail
        var sleigh = SleighState.init();
        defer sleigh.deinit();
        try sleigh.add_specfile("./specfiles/ARM8_le.sla");
        sleigh.begin();
        try testing.expectError(SleighError.BadContextVariable, sleigh.context_var_set_default("DNE", 1));
    }
}

test "load binary data" {
    var sleigh = SleighState.init();
    defer sleigh.deinit();
    try sleigh.add_specfile("./specfiles/ARM8_le.sla");
    sleigh.begin();

    // call methods in same order as above, tho it doesnt really matter
    try sleigh.context_var_set_default("TMode", 1);
    try sleigh.load_data(0x0, &.{ 0, 0, 0, 0 });
}

test "lift binary data" {
    var sleigh = SleighState.init();
    defer sleigh.deinit();
    try sleigh.add_specfile("./specfiles/ARM8_le.sla");
    sleigh.begin();

    // call methods in same order as above, tho it doesnt really matter
    try sleigh.context_var_set_default("TMode", 1);

    // this translates to `movs r0, r0; movs r0, r0` in
    // arm thumb
    try sleigh.load_data(0x0, &.{ 0, 0, 0, 0 });
    _ = try sleigh.lift_insn(0x0);
}

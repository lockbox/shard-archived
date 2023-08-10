//! This module provides a zig lig access to the C ffi for the
//! gluon vm.
const std = @import("std");

pub const LOG_SCOPE = .gluon;

const logger = std.log.scoped(LOG_SCOPE);

const GluVm = opaque {};
const GluFunction = *const fn (*GluVm) callconv(.C) GluReturnCode;
const VmIndex = u32;

const GluReturnCode = enum(c_int) {
    OK = 0,
    ERROR = 1,
};

extern fn glu_new_vm() callconv(.C) *GluVm;
extern fn glu_free_vm(vm: *GluVm) callconv(.C) void;
extern fn glu_len(vm: *GluVm) callconv(.C) usize;
extern fn glu_pop(vm: *GluVm, n: usize) callconv(.C) void;
extern fn glu_push_int(vm: *GluVm, int: i64) callconv(.C) void;
extern fn glu_push_byte(vm: *GluVm, b: u8) callconv(.C) void;
extern fn glu_push_float(vm: *GluVm, float: f64) callconv(.C) void;
extern fn glu_push_bool(vm: *GluVm, b: i8) callconv(.C) void;
extern fn glu_push_function(vm: *GluVm, name: [*]const u8, name_len: usize, function: GluFunction, args: VmIndex) callconv(.C) void;
extern fn glu_call_function(vm: *GluVm, args: VmIndex) callconv(.C) GluReturnCode;
/// Loads a gluon script (`expr`) into the vm as `module`
extern fn glu_load_script(vm: *GluVm, module: *const []const u8, module_len: usize, expr: *const []const u8, expr_len: usize) callconv(.C) GluReturnCode;
/// Compiles and runs `expr`
extern fn glu_run_expr(vm: *GluVm, name: *const []const u8, name_len: usize, expr: *const []const u8, expr_len: usize) callconv(.C) GluReturnCode;

/// Pushes a string to the gluon stack
///
/// * asserts that the string is a valid utf-8, returns `GluReturnCode::Error`
/// otherwise
extern fn glu_push_string(vm: *GluVm, s: [*]const u8, len: usize) callconv(.C) GluReturnCode;

/// Pushes a string to the gluon stack
///
/// * assumes the string is valid utf-8, anything else is undefined behavior
extern fn glu_push_string_unchecked(vm: *GluVm, s: *const []const u8, len: usize) callconv(.C) void;

/// TODO: need to figure out how to do a `push any`
extern fn glu_push_light_userdata(vm: *GluVm, data: *void) callconv(.C) void;
extern fn glu_get_byte(vm: *GluVm, index: VmIndex, out: *u8) callconv(.C) GluReturnCode;
extern fn glu_get_int(vm: *GluVm, index: VmIndex, out: *i64) callconv(.C) GluReturnCode;
extern fn glu_get_float(vm: *GluVm, index: VmIndex, out: *f64) callconv(.C) GluReturnCode;
extern fn glu_get_bool(vm: *GluVm, index: VmIndex, out: *i8) callconv(.C) GluReturnCode;

/// The returned string is garbage collected, and may not be valid after the
/// string is removed from its slot in the stack
///
/// TODO: figure out if that's only in the context of gluon or for us as well
extern fn glu_get_string(vm: *GluVm, index: VmIndex, out: *[*]u8, out_len: *usize) callconv(.C) GluReturnCode;
/// This is supposed to be able to return the arbitrary pointer to user data
extern fn glu_get_light_userdata(vm: *GluVm, index: VmIndex, out: **void) callconv(.C) GluReturnCode;

// Need to figure out a way to actually test this
test "gluon bindings can initialize a vm" {

    // allocate a vm
    var vm: *GluVm = glu_new_vm();
    defer glu_free_vm(vm);

    try std.testing.expect(true);
}

test "push pop bool" {
    var vm = glu_new_vm();
    defer glu_free_vm(vm);

    var correct: i8 = 1;
    glu_push_bool(vm, correct);

    var output: i8 = undefined;

    try std.testing.expect(glu_get_bool(vm, 0, &output) == GluReturnCode.OK);

    try std.testing.expectEqual(correct, output);
}

test "push pop float" {
    var vm = glu_new_vm();
    defer glu_free_vm(vm);

    var correct: f64 = 69.9;
    glu_push_float(vm, correct);

    var output: f64 = undefined;

    try std.testing.expect(glu_get_float(vm, 0, &output) == GluReturnCode.OK);

    try std.testing.expectEqual(correct, output);
}

test "push pop byte" {
    var vm = glu_new_vm();
    defer glu_free_vm(vm);

    var correct: u8 = 0x41;
    glu_push_byte(vm, correct);

    var output: u8 = undefined;

    try std.testing.expect(glu_get_byte(vm, 0, &output) == GluReturnCode.OK);

    try std.testing.expectEqual(correct, output);
}

test "push pop string" {
    var vm = glu_new_vm();
    defer glu_free_vm(vm);

    const correct: []const u8 = "testing string\x00";
    var ret_code = glu_push_string(vm, correct.ptr, correct.len);

    try std.testing.expect(GluReturnCode.OK == ret_code);

    var output: [*]u8 = undefined;
    var output_len: usize = 0;
    try std.testing.expect(glu_get_string(vm, 0, &output, &output_len) == GluReturnCode.OK);

    try std.testing.expect(output_len == correct.len);
    try std.testing.expectEqualSlices(u8, correct, output[0..output_len]);
}

// only used in test `call function`
fn mult(vm: *GluVm) callconv(.C) GluReturnCode {
    var l: f64 = 0.0;
    var r: f64 = 0.0;

    std.debug.assert(glu_get_float(vm, 0, &l) == GluReturnCode.OK);
    std.debug.assert(glu_get_float(vm, 1, &r) == GluReturnCode.OK);

    glu_push_float(vm, l * r);
    return GluReturnCode.OK;
}

test "call function" {
    var vm = glu_new_vm();
    defer glu_free_vm(vm);

    const func_name = "mult";

    glu_push_function(vm, func_name.ptr, func_name.len, mult, 2);
    glu_push_float(vm, 3.0);
    glu_push_float(vm, 2.0);

    try std.testing.expect(glu_call_function(vm, 2) == GluReturnCode.OK);

    var result: f64 = 0.0;
    try std.testing.expect(glu_get_float(vm, 0, &result) == GluReturnCode.OK);
    try std.testing.expect(result == 6.0);
}

pub const GluonVM = struct {
    inner_vm: ?*GluVm = null,

    pub fn init(self: *GluonVM) void {
        // TODO: log or error or assert on this
        if (self.inner_vm == null) {
            logger.debug("Initializing gluon VM", .{});
            self.inner_vm = glu_new_vm();
        } else {
            logger.warn("Attempted double init of gluon VM, this is a bug", .{});
        }
    }

    pub fn deinit(self: *GluonVM) void {
        if (self.inner_vm) |vm| {
            glu_free_vm(vm);
            self.inner_vm = null;
            logger.debug("De-init gluon VM", .{});
        }
    }
};

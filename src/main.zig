const std = @import("std");

const gluon = @import("gluon.zig");
const sleigh = @import("sleigh.zig");
const clap = @import("clap.zig");
const shard = @import("shard.zig");
const config = @import("config.zig");
const ShardInsn = shard.ShardInsn;
const StructFooConfig = config.StructFooConfig;

// logging setup
pub var log_level: std.log.Level = .info;
pub const scope_levels = [_]std.log.ScopeLevel{
    .{ .scope = sleigh.LOG_SCOPE, .level = .info },
    .{ .scope = gluon.LOG_SCOPE, .level = .debug },
    .{ .scope = shard.LOG_SCOPE, .level = .debug },
};
const logger = std.log.scoped(.main);

fn read_raw_bin(path: []const u8, comptime num_bytes: usize) !std.BoundedArray(u8, num_bytes) {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var reader = std.io.bufferedReader(file.reader());
    var read_stream = reader.reader();

    return read_stream.readBoundedBytes(num_bytes);
}

pub const NeedleGadget = struct {
    address: u64,
    size: u64,
    text: []const u8,
};

/// Given a list of lifted instructions, find gadgets that help manipulate
/// control flow
pub fn find_gadgets(insns: std.ArrayList(ShardInsn), allocator: std.mem.Allocator) !std.ArrayList(NeedleGadget) {
    var gadgets = std.ArrayList(NeedleGadget).init(allocator);
    var root_gadget_indicies = std.ArrayList(usize).init(allocator);
    defer root_gadget_indicies.deinit();

    // loop through all the instructions and try to find `root` gadgets
    // where `root` just means "the gadgets does not exist without this node",
    // from there we can do more passes to find other gadgets that include this
    // to provide flexibility in the results
    for (insns.items, 0..) |insn, idx| {
        // check semantic flags for easy root nodes:
        // - ret
        if (insn.summary.ret) {
            try gadgets.append(NeedleGadget{ .address = insn.base_address, .size = insn.size, .text = try std.fmt.allocPrint(allocator, "{s}", .{insn.text}) });
            try root_gadget_indicies.append(idx);
        }
    }

    // done
    return gadgets;
}

/// Dumps gadget list to console
pub fn dump_gadgets(gadgets: std.ArrayList(NeedleGadget)) void {
    logger.info("Root gadgets:", .{});
    for (gadgets.items) |gadget| {
        logger.info("| 0x{x} | {} | {s}", .{ gadget.address, gadget.size, gadget.text });
    }
}

pub fn main() !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help               Display this help and exit.
        \\-c, --config <str>       Path to config json.
        \\-d, --debug              Enable debug logging.
        \\-b, --bin                Input file is raw bin instead of ghidra dump.
        \\--base-address <u64>     Base address of image.
        \\--sla <str>              Name of sla spec.
        \\--pspec <str>            Name of pspec.
        \\--alignment <u64>        Target alignment in bytes.
        \\--root-dir <str>         Path to prefix containing `specfiles`, `configs` and `input-files` directories.
        \\<str>                    Path to input file.
    );

    // parse + setup options
    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    // initialize the allocator
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // handle the cli options
    if (res.args.help != 0) {
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    }

    // set config options
    var c = StructFooConfig.new();
    if (res.args.config) |config_path| {
        logger.debug("Loading config from: `{s}`", .{config_path});
        c.load_json(config_path, allocator) catch {
            logger.warn("Failed to load config file!", .{});
            std.process.exit(1);
        };
    }

    // now parse the flags to override anything from the config file
    if (res.args.debug > 0) {
        c.set_debug(true);
    }

    if (res.args.bin > 0) {
        c.set_input_mode("raw");
    } else {
        c.set_input_mode("dump");
    }

    if (res.args.@"base-address") |addr| {
        c.set_base_address(addr);
    }

    if (res.args.sla) |sla| {
        try c.set_sla(sla, allocator);
    }

    if (res.args.pspec) |pspec| {
        try c.set_pspec(pspec, allocator);
    }

    if (res.args.alignment) |alignment| {
        c.set_alignment(alignment);
    }

    if (res.args.@"root-dir") |root| {
        try c.set_root_dir(root, allocator);
    } else {
        try c.set_root_dir(".", allocator);
    }

    // check for input file
    if (res.positionals.len == 1) {
        try c.set_input_path(res.positionals[0], allocator);
    }

    if (!c.ready()) {
        logger.err("Missing configuration parameters! (need mode, sla, pspec, input path)", .{});
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    }

    var loader = shard.ShardLoader.init(allocator);

    var target = try loader.loadFileFromConfig(&c);

    var shard_rt = shard.ShardRuntime.init(allocator);
    defer shard_rt.deinit();

    try shard_rt.load_target(target);

    // get list of gadget insns
    var haystack = try shard_rt.perform_lift();
    var gadgets = try find_gadgets(haystack, allocator);
    dump_gadgets(gadgets);

    //std.testing.refAllDeclsRecursive(@This());
}

test "Full package test" {
    std.testing.refAllDeclsRecursive(@This());
}

//! # `struct.foo`
//!
//! A Program Analysis library written in `zig` :zap:
//!
//!zig-autodoc-section: Quickstart
//!zig-autodoc-guide: ../docs/quickstart.md
const std = @import("std");

pub const sleigh = @import("sleigh.zig");
pub const clap = @import("clap.zig");
pub const shard = @import("shard.zig");
pub const config = @import("config.zig");
const ShardInsn = shard.ShardInsn;
const StructFooConfig = config.StructFooConfig;

// logging setup
pub const log_level: std.log.Level = .info;
pub const scope_levels = [_]std.log.ScopeLevel{
    .{ .scope = sleigh.LOG_SCOPE, .level = .info },
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

/// Container holding metadata describing a gadget from the target program.
///
/// Holds the address, size, and human readable format for ease of use + debugging.
/// At some point this will also hold the underlying semantic expression for the
/// gadget.
pub const NeedleGadget = struct {
    /// Address of the gadget
    address: u64,
    /// Size of the gadget in bytes
    size: u64,
    /// Human readable representation of gadget
    text: []const u8,

    const Self = @This();

    /// Given a previous gadget, combine the metadata of the provided instruciton
    /// to create....bigger gadget
    pub fn from_parent_gadget(insn: *const ShardInsn, parent: *const Self, allocator: std.mem.Allocator) !Self {
        var out_text = try std.fmt.allocPrint(allocator, "{s}; {s}", .{ insn.text, parent.text });
        var out_size = insn.size + parent.size;
        var out_address = insn.base_address;
        return NeedleGadget{ .address = out_address, .size = out_size, .text = out_text };
    }
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

    //
    // Currently only search for:
    //   - stack modifying instructions
    //
    // now that we have the initial root gadgets, we can work backwards from the
    // addresses that have the `root` nodes, and find all the additional modifiers to
    // get the remaining gadgets
    for (root_gadget_indicies.items, 0..) |insn_index, gadget_index| {
        if (insn_index == 0) {
            // nothing before this index
            continue;
        }

        // parent gadget to start with, as we grow and find
        // more gadgets during this iteration we will swap what this points to
        // as we add new gadgets.
        //
        // The theory here is that as we search further in reverse from the root,
        // the current `parent_gadget` will only ever grow until we move onto the
        // next parent gadget.
        var parent_gadget = &gadgets.items[gadget_index];

        // index of a root gadget, set curr to the index, and keep going until
        // we either hit the beginning of our insns we have lifted, or we stop finding
        // applicable instrucitons to add to our list of gadgets
        var curr_index: usize = insn_index;
        var added_gadget: bool = true;
        while (added_gadget) {
            added_gadget = false;

            // we either started at index 0, or the last iteration
            // was at index 0, exit
            if (curr_index == 0) {
                break;
            }

            // index of insns to check for presence of gadget or not
            var check_idx = curr_index - 1;
            const insn = insns.items[check_idx];
            if (is_gadget(insn)) {
                // add the size of this gadget to the size of the parent gadget
                // add the text of this gadget to the text of the parent gadget
                // make the start address of this new gadget be == address of this insn
                gadgets.append(try NeedleGadget.from_parent_gadget(&insn, parent_gadget, allocator)) catch |err| {
                    logger.err("Failed to add gadget due to error: `{}`", .{err});
                    // move to nex troot gadget, maybe that will work better
                    break;
                };

                // set parent gadget pointer
                parent_gadget = &gadgets.items[gadgets.items.len - 1];

                // set this so we keep looking
                added_gadget = true;
                // dec index to search for gadgets
                curr_index -= 1;
            } else {
                // did not find gadget, we're going to exit here
                added_gadget = false;
            }
        }
    }

    // done
    return gadgets;
}

/// Determines if the current instruction is useful as a gadget, pretty old but it checks out
pub fn is_gadget(insn: ShardInsn) bool {
    if (insn.summary.modify_sp) {
        return true;
    }

    if (insn.summary.jump) {
        return false;
    }

    // non of our short circuits were found
    return true;
}

/// Dumps gadget list to console
pub fn dump_gadgets(gadgets: std.ArrayList(NeedleGadget)) void {
    logger.info("Root gadgets:", .{});
    logger.info("| {s: ^16} | {s:^4} | Gadget", .{ "Address (hex)", "Size" });
    logger.info("|{0s:-^18}|{0s:-^6}|{0s:-^10}", .{"-"});
    for (gadgets.items) |gadget| {
        logger.info("| {x: >16} | {: ^4} | {s}", .{ gadget.address, gadget.size, gadget.text });
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
}

test "Full package test" {
    std.testing.refAllDeclsRecursive(@This());
}

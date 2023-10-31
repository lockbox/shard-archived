const std = @import("std");

pub const LOG_SCOPE = .bfd;

const logger = std.log.scoped(LOG_SCOPE);

const C = @cImport({
    @cDefine("PACKAGE", "1");
    @cDefine("PACKAGE_VERSION", "1");
    @cInclude("bfd.h");
});
const struct_bfd = C.struct_bfd;
const BFD_MAGIC = C.BFD_INIT_MAGIC;

pub const bfd_meta_hash_table = extern struct {
    const Self = @This();

    table: **opaque {}, // struct bfd_hash_entry
    newfunc: *opaque {},
    memory: *opaque {},
    size: u32,
    count: u32,
    entsize: u32,
    frozen: u32,
};

/// Zig translation of this struct. All the good things
/// are inlined so zig cannot import the macros we need
/// :(
pub const bfd_meta = extern struct {
    const Self = @This();

    filename: [*]u8,
    xvec: *opaque {},
    iostream: *opaque {},
    iovec: *opaque {},
    lru_prev: *Self,
    lru_next: *Self,
    where: u64,
    mtime: i64,
    id: u32,
    flags: u32,
    more_flags: u32,
    plugin_dummy_bfd: *Self,
    origin: u64,
    proxy_origin: u64,
    section_htab: bfd_meta_hash_table,
    sections: [*]bfd_meta_section,
    section_last: *bfd_meta_section,
    section_count: u32,
    archive_plugin_fd: i32,
    archive_pugin_fd_open_count: u32,
    archive_pass: i32,
    alloc_size: u64,
    start_address: u64,
    outsymbols: **opaque {}, // struct bfd_symbol **
    symcount: u32,
    dynsymcount: u32,
    arch_info: *opaque {}, // const struct bfd_arch_info *
    size: u64,
    // <.. > complicated unions etc
};

pub const bfd_meta_section = extern struct {
    const Self = @This();

    name: [*]u8,
    next: *Self,
    prev: *Self,
    id: u32,
    section_id: u32,
    index: u32,
    flags: u32,
    internal_flags: u32,
    vma: u64,
    lma: u64,
    size: u64,
    rawsize: u64,
    compressed_size: u64,
    output_offset: u64,
    output_section: *Self,
    relocation: *opaque {}, // struct reloc_cache_entry*
    orelocation: **opaque {}, // struct reloc_cache_entry **
    reloc_count: u32,
    alignment_power: u32,
    filepos: i64,
    rel_filepos: i64,
    line_filepos: i64,
    userdata: *opaque {},
    contents: [*]u8,
    lineno: *opaque {}, // alent
    lineno_count: u32,
    entsize: u32,
    kept_section: *Self,
    moving_line_filepos: i64,
    target_index: i32,
    used_by_bfd: *opaque {},
    constructor_chain: *opaque {}, // struct trelent_chain
    owner: *bfd_meta,
    symbol: *opaque {}, // struct bfd_symbol
    symbol_ptr_ptr: **opaque {}, // struct bfd_symbol_**
    map_head: *opaque {},
    map_tail: *opaque {},
    already_assigned: *Self,
    type: u32,
};

pub const BfdlError = error{
    bfd_error_no_error,
    bfd_error_system_call,
    bfd_error_invalid_target,
    bfd_error_wrong_format,
    bfd_error_wrong_object_format,
    bfd_error_invalid_operation,
    bfd_error_no_memory,
    bfd_error_no_symbols,
    bfd_error_no_armap,
    bfd_error_no_more_archived_files,
    bfd_error_malformed_archive,
    bfd_error_missing_dso,
    bfd_error_file_not_recognized,
    bfd_error_file_ambiguously_recognized,
    bfd_error_no_contents,
    bfd_error_nonrepresentable_section,
    bfd_error_no_debug_section,
    bfd_error_bad_value,
    bfd_error_file_truncated,
    bfd_error_file_too_big,
    bfd_error_sorry,
    bfd_error_on_input,
    bfd_error_invalid_error_code,
};

pub const ShardBinError = error{
    unknown,
};

pub fn bfdl_init() void {
    logger.debug("global init bfd", .{});

    var error_code = C.bfd_init();
    logger.debug("MAGIC: {}", .{error_code});
    // `error_code` is a magic value that zig won't let us have access to
    std.debug.assert(error_code != 0);
}

/// Nasty switch statements to convert the C error enum into a zig error set
pub fn get_bfdl_err_inner() BfdlError!void {
    return switch (C.bfd_get_error()) {
        C.bfd_error_no_error => {},
        C.bfd_error_system_call => BfdlError.bfd_error_system_call,
        C.bfd_error_invalid_target => BfdlError.bfd_error_invalid_target,
        C.bfd_error_wrong_format => BfdlError.bfd_error_wrong_format,
        C.bfd_error_wrong_object_format => BfdlError.bfd_error_wrong_object_format,
        C.bfd_error_invalid_operation => BfdlError.bfd_error_invalid_operation,
        C.bfd_error_no_memory => BfdlError.bfd_error_no_memory,
        C.bfd_error_no_symbols => BfdlError.bfd_error_no_symbols,
        C.bfd_error_no_armap => BfdlError.bfd_error_no_armap,
        C.bfd_error_no_more_archived_files => BfdlError.bfd_error_no_more_archived_files,
        C.bfd_error_malformed_archive => BfdlError.bfd_error_malformed_archive,
        C.bfd_error_missing_dso => BfdlError.bfd_error_missing_dso,
        C.bfd_error_file_not_recognized => BfdlError.bfd_error_file_not_recognized,
        C.bfd_error_file_ambiguously_recognized => BfdlError.bfd_error_file_ambiguously_recognized,
        C.bfd_error_no_contents => BfdlError.bfd_error_no_contents,
        C.bfd_error_nonrepresentable_section => BfdlError.bfd_error_nonrepresentable_section,
        C.bfd_error_no_debug_section => BfdlError.bfd_error_no_debug_section,
        C.bfd_error_bad_value => BfdlError.bfd_error_bad_value,
        C.bfd_error_file_truncated => BfdlError.bfd_error_file_truncated,
        C.bfd_error_file_too_big => BfdlError.bfd_error_file_too_big,
        C.bfd_error_sorry => BfdlError.bfd_error_sorry,
        C.bfd_error_on_input => BfdlError.bfd_error_on_input,
        C.bfd_error_invalid_error_code => BfdlError.bfd_error_invalid_error_code,
        else => unreachable,
    };
}

//extern fn bfd_get_start_address(arg_abfd: ?*const struct_bfd) callconv(.C) u64;
//extern fn bfd_count_sections(arg_abfd: ?*const struct_bfd) callconv(.C) u64;

//extern fn get_start_address(arg_abfd: ?*const struct_bfd) callconv(.C) u64;
//extern fn get_section_count(arg_abfd: ?*const struct_bfd) callconv(.C) u64;
//extern fn get_sections(abfd: *struct_bfd) *C.struct_bfd_section;

/// Converted from a BFD to this translated layer.
///
/// Really just a container for:
/// - what data is there
/// - where does it go
/// - arch / target specific metadata
pub const ShardBin = struct {
    const Self = @This();

    /// Translated from a BFD into ShardBin
    pub fn from_bfd(abfd: *bfd_meta) Self {
        //var start_address: u64 = get_start_address(abfd);
        //var section_count: u64 = get_section_count(abfd);

        //logger.info("Got start address: {x}, section_count: {}", .{ start_address, section_count });

        // attempt to type case

        logger.info("start_address: {}", .{abfd.start_address});
        logger.info("num_sections: {}", .{abfd.section_count});

        C.bfd_check_format(abfd, C.enum_bfd_format);
        bfd_map_over_sections(abfd, &print_section_data, &[_]u8{});

        return Self{};
    }
};

pub extern fn bfd_fopen(filename: [*c]const u8, target: [*c]const u8, mode: [*c]const u8, fd: c_int) ?*bfd_meta;
pub extern fn bfd_map_over_sections(abfd: ?*bfd_meta, func: ?*const fn (?*bfd_meta, ?*bfd_meta_section) callconv(.C) void, obj: ?*anyopaque) void;

fn print_section_data(meta: ?*bfd_meta, section: ?*bfd_meta_section) callconv(.C) void {
    _ = meta;
    logger.err("section", .{});

    if (section != null) {
        logger.debug("Section name: {s}", .{section.?.name[0..5]});
    } else {
        logger.debug("NO SECTION", .{});
    }
}

pub const BfdLibrary = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn new(allocator: std.mem.Allocator) Self {
        return Self{ .allocator = allocator };
    }

    pub fn init(self: *Self) void {
        _ = self;

        bfdl_init();
    }

    /// Returns `Shardbin` or raises error
    pub fn parse_file(self: *Self, input_path: []const u8) !ShardBin {
        _ = self;
        logger.debug("Attempting to parse file: {s}", .{input_path});
        var abfd: [*c]bfd_meta = bfd_fopen(input_path.ptr, "default", "r", -1);

        // if we got a success back then return the new construction,
        // else check for errors
        if (abfd) |bfd_file| {
            logger.debug("Successfully loaded {s} into bfd", .{input_path});

            return ShardBin.from_bfd(bfd_file);
        }

        // we failed to get a success, this is an error (probably)
        try get_bfdl_err_inner();
        logger.warn("No error but failed to parse file: {s}", .{input_path});
        return error.unknown;
    }
};

test "init bfd" {
    // this will assert if fail
    bfdl_init();
}

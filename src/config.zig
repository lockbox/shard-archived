const std = @import("std");
const fs = std.fs;
const json = std.json;
const log = std.log;
const Allocator = std.mem.Allocator;

const logger = log.scoped(.config);

/// Actions for `struct.foo` to perform during runtime
pub const StructFooActions = enum {
    needle,
};

/// Type of input passed in via command line flags or configuration
/// file. `raw` means file from filsystem, `dump` means it was
/// dumped from the packaged ghidra script.
pub const StructFooInputMode = enum {
    none,
    raw,
    dump,
};

/// Loads configuration from command line flags and
/// configuration `json` files to expedite things.
///
/// By default begins search for specified resources from
/// `cwd()`. Jank but works for now.
///
/// Looks for `.sla` and `.pspec` files under `root/specfiles`.
pub const StructFooConfig = struct {
    /// Root dir to begin search from
    root_dir: []u8 = &.{},
    /// Name of `.sla` file to look for
    sla: []u8 = &.{},
    /// Name of `.pspec` file to look for
    pspec: []u8 = &.{},
    /// Default target alignment
    alignment: usize = 2,
    /// Default base address
    base_address: u64 = 0,
    /// Enable debug mode
    debug: bool = false,
    /// Action to perform
    action: StructFooActions = .needle,
    /// Path to input file
    input_path: []u8 = &.{},
    /// Input file type
    input_mode: StructFooInputMode = .none,

    const Self = @This();

    /// Create a new instance of `StructFooConfig`
    pub fn new() Self {
        return Self{};
    }

    /// Does the config have enough information to actually
    /// do anything useful.
    ///
    /// Requires:
    /// - sla
    /// - pspec
    /// - input_path
    pub fn ready(self: *const Self) bool {
        if (self.sla.len > 0 and
            self.pspec.len > 0 and
            self.input_path.len > 0 and
            self.input_mode != .none)
        {
            return true;
        }

        return false;
    }

    /// Given an absolute path, set the new root dir
    pub fn set_root_dir(self: *Self, dir: []const u8, allocator: Allocator) !void {
        self.root_dir = try allocator.alloc(u8, dir.len);
        @memcpy(self.root_dir, dir);
    }

    /// Set the name of the `.sla` to look for
    pub fn set_sla(self: *Self, name: []const u8, allocator: Allocator) !void {
        self.sla = try allocator.alloc(u8, name.len);
        @memcpy(self.sla, name);
    }

    /// Set the name of the `.pspec` to look for
    pub fn set_pspec(self: *Self, name: []const u8, allocator: Allocator) !void {
        self.pspec = try allocator.alloc(u8, name.len);
        @memcpy(self.pspec, name);
    }

    /// Set the alignment in bytes
    pub fn set_alignment(self: *Self, value: u64) void {
        self.alignment = value;
    }

    /// Set the base address
    pub fn set_base_address(self: *Self, value: u64) void {
        self.base_address = value;
    }

    /// Enable debug logging
    pub fn set_debug(self: *Self, value: bool) void {
        self.debug = value;
    }

    /// Sets path relative to `cwd()` to the input binary or dump
    pub fn set_input_path(self: *Self, path: []const u8, allocator: Allocator) !void {
        self.input_path = try allocator.alloc(u8, path.len);
        @memcpy(self.input_path, path);
    }

    /// Resolves the path to `pspec` from `root_dir`, caller owns the
    /// derived slice
    pub fn getPspecPath(self: *const Self, allocator: Allocator) ![]const u8 {
        var root_path = try fs.cwd().openDir(self.root_dir, .{});

        // derive the root -> sla path
        var pspec_prefix = try std.fmt.allocPrint(allocator, "./specfiles/{s}", .{self.pspec});
        defer allocator.free(pspec_prefix);
        var pspec_path = try root_path.realpathAlloc(allocator, pspec_prefix);

        return pspec_path;
    }

    /// Resolves the path to `sla` from `root_dir`, caller owns the
    /// derived slice
    pub fn getSlaPath(self: *const Self, allocator: Allocator) ![]const u8 {
        var root_path = try fs.cwd().openDir(self.root_dir, .{});

        // derive the root -> sla path
        var sla_prefix = try std.fmt.allocPrint(allocator, "./specfiles/{s}", .{self.sla});
        defer allocator.free(sla_prefix);
        var sla_path = try root_path.realpathAlloc(allocator, sla_prefix);

        return sla_path;
    }

    /// Set input mode
    pub fn set_input_mode(self: *Self, mode: []const u8) void {
        if (std.mem.startsWith(u8, mode, "none")) {
            self.input_mode = .none;
        } else if (std.mem.startsWith(u8, mode, "raw")) {
            self.input_mode = .raw;
        } else if (std.mem.startsWith(u8, mode, "dump")) {
            self.input_mode = .dump;
        } else {
            logger.err("Invalid input mode specified: `{s}`", .{mode});
        }
    }

    /// Load from a json `config` at `path` into self, owns allocated memory
    pub fn load_json(self: *Self, path: []const u8, allocator: std.mem.Allocator) !void {
        var file_contents = try std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024);
        defer allocator.free(file_contents);

        var json_config = try json.parseFromSlice(Self, allocator, file_contents, .{});
        defer json_config.deinit();
        var parsed_config = json_config.value;

        self.set_alignment(parsed_config.alignment);
        self.set_base_address(parsed_config.base_address);
        try self.set_pspec(parsed_config.pspec, allocator);
        try self.set_sla(parsed_config.sla, allocator);
        try self.set_input_path(parsed_config.input_path, allocator);
        self.input_mode = parsed_config.input_mode;
    }
};

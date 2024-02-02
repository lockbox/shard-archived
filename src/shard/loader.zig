//! Given metadata and a path to the target, emit a valid
//! `ShardInputTarget` to be consumed by the `ShardRuntime`
const std = @import("std");
const log = std.log;
const json = std.json;

const targets = @import("targets.zig");
const memory = @import("memory.zig");
const xml = @import("../xml.zig");
const config = @import("../config.zig");
const shard = @import("../shard.zig");
const XmlParser = xml.parse;

const ShardError = shard.ShardError;
const StructFooConfig = config.StructFooConfig;
const SleighContextPair = targets.SleighContextPair;
const ShardInputTarget = targets.ShardInputTarget;
const ShardMemoryRegion = memory.ShardMemoryRegion;

const logger = log.scoped(.loader);

/// Default specfiles path
const SPECFILES_PATH = "specfiles/";

/// Gets the count of valid context pairs in the .sla xml
fn count_context_pairs(element: *xml.Element) usize {
    var it = element.findChildrenByTag("set");
    var context_tuple = it.next();
    var child_count: usize = 0;

    while (context_tuple) |ctx_set| {
        const var_name = ctx_set.getAttribute("name") orelse {
            logger.err("Context tuple did not contain `name` attr", .{});
            context_tuple = it.next();
            continue;
        };
        _ = var_name;

        const var_value = ctx_set.getAttribute("val") orelse {
            logger.err("Context tuple did not contain `val` attr", .{});
            context_tuple = it.next();
            continue;
        };
        _ = var_value;

        child_count += 1;
        context_tuple = it.next();
    }

    return child_count;
}

/// Parses the desired `.pspec` and returns the default
/// `ShardContextPair`'s required to properly decode the data.
///
/// The returned slice of pairs is caller-owned
pub fn loadPspecContext(allocator: std.mem.Allocator, path: []const u8) []SleighContextPair {
    var raw_file = std.fs.openFileAbsolute(path, .{}) catch |err| {
        logger.err("Failed to open file: `{}`", .{err});
        return &.{};
    };
    defer raw_file.close();
    const file_contents = raw_file.readToEndAlloc(allocator, 16 * 1024) catch |err| {
        logger.err("Unable to read from file: `{}`", .{err});
        return &.{};
    };
    defer allocator.free(file_contents);

    var document = XmlParser(allocator, file_contents) catch {
        logger.err("Failed to parse xml from pspec", .{});
        return &.{};
    };
    defer document.deinit();

    var root_tag = document.root;
    var context_data = root_tag.findChildByTag("context_data") orelse {
        logger.err("pspec file did not contain `context_data`", .{});
        return &.{};
    };

    var context_set = context_data.findChildByTag("context_set") orelse {
        logger.err("pspec `context_data` did not contain `context_set`", .{});
        return &.{};
    };

    // get the number of valid context pairs
    const pair_count: usize = count_context_pairs(context_set);

    // now allocate a slice and populate with the valid pairs
    var pairs = allocator.alloc(SleighContextPair, pair_count) catch {
        logger.err("Failed to allocate memory required for pairs", .{});
        return &.{};
    };

    var i: usize = 0;
    var it = context_set.findChildrenByTag("set");
    var context_tuple = it.next();
    while (context_tuple) |ctx_set| {
        const var_name = ctx_set.getAttribute("name") orelse {
            logger.err("Context tuple did not contain `name` attr", .{});
            context_tuple = it.next();
            i += 1;
            continue;
        };

        const tmp_variable = allocator.allocSentinel(u8, var_name.len, 0) catch |err| {
            logger.err("Failed to allocate memory for context `name`: {}", .{err});
            return &.{};
        };
        @memcpy(tmp_variable, var_name);
        pairs[i].variable = tmp_variable;

        const var_value = ctx_set.getAttribute("val") orelse {
            logger.err("Context tuple did not contain `val` attr", .{});
            context_tuple = it.next();
            i += 1;
            continue;
        };
        pairs[i].value = std.fmt.parseInt(u64, var_value, 10) catch blk: {
            logger.err("bad value in context set for `{s}`-- setting to 0", .{var_name});
            break :blk 0;
        };

        // increase iterators
        i += 1;
        context_tuple = it.next();
    }

    return pairs;
}

/// Performs the loading of input files from disk and deserializing or
/// parsing them into a `ShardInputTarget` that can be consumed by the
/// remainder of the `SHARD` runtime. The dependencies for this to do
/// anything are:
/// - input file path
/// - input mode
/// - base_address
/// - pspec (get needed context vars for target)
/// - sla (get needed sla path for target)
/// - alignment
pub const ShardLoader = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{ .allocator = allocator };
    }

    /// Given a `StructFooConfig`, take the necesary input arguments
    /// to load a series of `ShardMemoryRegion` from the input file,
    /// after which the region's get packed into a `ShardInputTarget`
    /// and returned to the user.
    pub fn loadFileFromConfig(
        self: *Self,
        cfg: *const StructFooConfig,
    ) !ShardInputTarget {
        // turn the file into regions
        const regions: []ShardMemoryRegion = switch (cfg.input_mode) {
            .raw => try self.rawToRegions(cfg.input_path),
            .dump => try self.ghidraDumpToRegions(cfg.input_path),
            .none => {
                return ShardError.NoInputMode;
            },
        };

        // get context pairs
        const pspec_path = try cfg.getPspecPath(self.allocator);
        defer self.allocator.free(pspec_path);
        const pairs = loadPspecContext(self.allocator, pspec_path);

        // construct target
        var target = ShardInputTarget.from_regions(regions);

        // apply base address to target
        target.setBaseAddress(cfg.base_address);

        // add context pairs to target
        target.setContextPairs(pairs);

        // add sla to target
        const sla_path = try cfg.getSlaPath(self.allocator);
        logger.debug("setting sla path: {s}", .{sla_path});
        target.setSlaPath(sla_path);

        return target;
    }

    /// For now this just treats `path` as a raw binary file, the plan
    /// is for this method to handle the detectino of known object file formats
    /// and load into the proper regions if applicable, else fallback to a single
    /// flat binary blob region. REturned regions are caller-owned.
    pub fn rawToRegions(self: *Self, path: []const u8) ![]ShardMemoryRegion {
        const file_contents = try std.fs.cwd().readFileAlloc(self.allocator, path, 50 * 1024 * 1024);
        defer self.allocator.free(file_contents);

        const name = try self.allocator.alloc(u8, path.len);
        @memcpy(name, path);

        var region = try self.allocator.alloc(ShardMemoryRegion, 1);
        region[0].base_address = 0;
        region[0].name = name;
        region[0].data = file_contents;
        return region;
    }

    /// This method should only be used with json dumps that were created with
    /// the packaged scripts, and will convert the serialized "regions" into
    /// `ShardMemoryRegion`. Returned regions are caller-owned.
    pub fn ghidraDumpToRegions(self: *Self, path: []const u8) ![]ShardMemoryRegion {
        const file_contents = try std.fs.cwd().readFileAlloc(self.allocator, path, 50 * 1024 * 1024);
        defer self.allocator.free(file_contents);

        // reads the file into the json schema for an array of `ShardMemoryRegion`'s'
        var input_regions = try json.parseFromSlice([]ShardMemoryRegion, self.allocator, file_contents, .{});
        defer input_regions.deinit();
        logger.debug("Found {} memory regions", .{input_regions.value.len});

        // we need to covert the data of the regions in-place
        // they are parsed as ascii chars in [0-9A-F] and need to be
        // converted to the proper format
        // TODO: this should probably be a method of `ShardMemoryRegion` that consumes
        // `self` and returns an entirely new `ShardMemoryRegion`
        var memory_regions = try self.allocator.alloc(ShardMemoryRegion, input_regions.value.len);
        for (input_regions.value, 0..) |region, input_idx| {
            var out: *ShardMemoryRegion = &memory_regions[input_idx];

            out.base_address = region.base_address;
            out.name = try self.allocator.alloc(u8, region.name.len);
            @memcpy(out.name, region.name);

            var data = try self.allocator.alloc(u8, region.data.len / 2);
            for (data, 0..) |byte, i| {
                _ = byte;
                const str_byte: []u8 = region.data[i * 2 ..][0..2];

                data[i] = try std.fmt.parseInt(u8, str_byte, 16);
            }
            out.data = data;
        }

        return memory_regions;
    }
};

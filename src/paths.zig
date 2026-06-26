//! Filesystem locations for hush. Everything lives under
//! `~/Library/Application Support/hush/` (macOS convention):
//!   - hushd.sock : unix domain socket (mode 0600)
//!   - vault.bin  : encrypted secret store

const std = @import("std");

const c = @cImport({
    @cInclude("stdlib.h");
});

const subdir = "Library/Application Support/hush";

pub const Error = error{NoHome};

pub const Paths = struct {
    allocator: std.mem.Allocator,
    base: []u8,
    socket: []u8,
    vault: []u8,
    /// SEP-wrapped data key blob (Touch ID provider).
    wrapped_key: []u8,

    pub fn init(allocator: std.mem.Allocator) !Paths {
        const home_z = c.getenv("HOME") orelse return Error.NoHome;
        const home = std.mem.span(home_z);

        const base = try std.fs.path.join(allocator, &.{ home, subdir });
        errdefer allocator.free(base);
        const socket = try std.fs.path.join(allocator, &.{ base, "hushd.sock" });
        errdefer allocator.free(socket);
        const vault = try std.fs.path.join(allocator, &.{ base, "vault.bin" });
        errdefer allocator.free(vault);
        const wrapped_key = try std.fs.path.join(allocator, &.{ base, "datakey.sep" });

        return .{ .allocator = allocator, .base = base, .socket = socket, .vault = vault, .wrapped_key = wrapped_key };
    }

    pub fn deinit(self: *Paths) void {
        self.allocator.free(self.base);
        self.allocator.free(self.socket);
        self.allocator.free(self.vault);
        self.allocator.free(self.wrapped_key);
        self.* = undefined;
    }

    /// Create the base directory (0700) if it does not exist.
    pub fn ensureDir(self: *const Paths, io: std.Io) !void {
        try std.Io.Dir.cwd().createDirPath(io, self.base);
        std.Io.Dir.cwd().setFilePermissions(io, self.base, std.Io.File.Permissions.fromMode(0o700), .{}) catch {};
    }
};

//! Provider federation: a vault value may be a *reference* into an external
//! secret manager instead of an inline secret. References are recognized by URI
//! scheme and resolved on read by shelling out to the provider's CLI, so the
//! real secret never persists on disk — hush brokers over existing vaults.
//!
//!   op://Vault/item/field        -> `op read op://Vault/item/field`   (1Password)
//!   keeper://<record>/field/...  -> `ksm secret notation keeper://...` (Keeper)
//!
//! The provider CLI must be installed and authenticated in the daemon's
//! environment. Anything not matching a known scheme is treated as a literal.

const std = @import("std");

pub const Provider = struct {
    scheme: []const u8,
    /// argv template; the literal token "{ref}" is replaced by the full reference.
    argv: []const []const u8,
};

pub const default_registry = [_]Provider{
    .{ .scheme = "op", .argv = &.{ "op", "read", "--no-newline", "{ref}" } },
    .{ .scheme = "keeper", .argv = &.{ "ksm", "secret", "notation", "{ref}" } },
};

pub const Error = error{ NotAReference, ResolveFailed };

fn match(registry: []const Provider, value: []const u8) ?Provider {
    const sep = std.mem.indexOf(u8, value, "://") orelse return null;
    const scheme = value[0..sep];
    for (registry) |p| {
        if (std.mem.eql(u8, p.scheme, scheme)) return p;
    }
    return null;
}

/// Is `value` a reference to a known provider (vs. a literal secret)?
pub fn isReference(value: []const u8) bool {
    return match(&default_registry, value) != null;
}

/// Resolve a reference to its secret value via the provider CLI. Caller owns
/// the returned slice.
pub fn resolve(gpa: std.mem.Allocator, io: std.Io, value: []const u8) ![]u8 {
    return resolveWith(gpa, io, &default_registry, value);
}

/// Like `resolve`, but against a supplied registry (used for testing).
pub fn resolveWith(gpa: std.mem.Allocator, io: std.Io, registry: []const Provider, value: []const u8) ![]u8 {
    const p = match(registry, value) orelse return Error.NotAReference;

    const argv = try gpa.alloc([]const u8, p.argv.len);
    defer gpa.free(argv);
    for (p.argv, 0..) |arg, i| {
        argv[i] = if (std.mem.eql(u8, arg, "{ref}")) value else arg;
    }

    const res = std.process.run(gpa, io, .{
        .argv = argv,
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(64 << 10),
    }) catch return Error.ResolveFailed;
    defer gpa.free(res.stdout);
    defer gpa.free(res.stderr);

    switch (res.term) {
        .exited => |code| if (code != 0) return Error.ResolveFailed,
        else => return Error.ResolveFailed,
    }

    // Trim a single trailing newline the CLI may add.
    const out = std.mem.trimEnd(u8, res.stdout, "\n");
    return gpa.dupe(u8, out);
}

test "resolveWith substitutes {ref} and captures stdout" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const reg = [_]Provider{.{ .scheme = "mock", .argv = &.{ "printf", "%s", "{ref}" } }};

    const v = try resolveWith(a, io, &reg, "mock://hello/world");
    defer a.free(v);
    try std.testing.expectEqualStrings("mock://hello/world", v);
}

test "resolveWith trims trailing newline" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const reg = [_]Provider{.{ .scheme = "ln", .argv = &.{ "sh", "-c", "printf 'secret\\n'" } }};

    const v = try resolveWith(a, io, &reg, "ln://x");
    defer a.free(v);
    try std.testing.expectEqualStrings("secret", v);
}

test "resolveWith fails on nonzero exit" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const reg = [_]Provider{.{ .scheme = "boom", .argv = &.{ "sh", "-c", "exit 3" } }};

    try std.testing.expectError(Error.ResolveFailed, resolveWith(a, io, &reg, "boom://x"));
}

test "isReference detects known schemes only" {
    try std.testing.expect(isReference("op://Vault/item/field"));
    try std.testing.expect(isReference("keeper://abc/field/login"));
    try std.testing.expect(!isReference("postgres://localhost/db")); // unknown scheme = literal
    try std.testing.expect(!isReference("plain-secret"));
}

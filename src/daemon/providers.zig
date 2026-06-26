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
const hush = @import("hush");
const dotenv = hush.dotenv;
const names = hush.names;

pub const Provider = struct {
    scheme: []const u8,
    /// argv template. Two placeholder tokens are substituted per element:
    ///   "{ref}"  -> the full reference (e.g. "op://Vault/item/field")
    ///   "{path}" -> the part after "scheme://" (e.g. "Vault/item/field")
    argv: []const []const u8,
    /// Optional argv template for *enumerate* expansion (whole-container ->
    /// many vars). Same placeholders. Expected to emit `KEY=value` lines on
    /// stdout. Null means this provider has no whole-container recipe.
    list_argv: ?[]const []const u8 = null,
};

pub const default_registry = [_]Provider{
    // 1Password and Keeper take the full URI.
    .{ .scheme = "op", .argv = &.{ "op", "read", "--no-newline", "{ref}" } },
    .{ .scheme = "keeper", .argv = &.{ "ksm", "secret", "notation", "{ref}" } },
    // These take a bare path/name after the scheme.
    .{ .scheme = "aws", .argv = &.{ "aws", "secretsmanager", "get-secret-value", "--secret-id", "{path}", "--query", "SecretString", "--output", "text" } },
    .{ .scheme = "gopass", .argv = &.{ "gopass", "show", "-o", "{path}" } },
    .{ .scheme = "pass", .argv = &.{ "pass", "show", "{path}" } },
    .{ .scheme = "vault", .argv = &.{ "vault", "kv", "get", "-field=value", "{path}" } },
};

pub const Error = error{ NotAReference, ResolveFailed, UnsupportedMode, BadData };

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
    return runTemplate(gpa, io, p.argv, value);
}

/// Substitute {ref}/{path} into an argv template, run it, and return its
/// stdout (one trailing newline trimmed). Caller owns the slice.
fn runTemplate(gpa: std.mem.Allocator, io: std.Io, argv_tmpl: []const []const u8, value: []const u8) ![]u8 {
    const path = if (std.mem.indexOf(u8, value, "://")) |sep| value[sep + 3 ..] else value;

    const argv = try gpa.alloc([]const u8, argv_tmpl.len);
    defer gpa.free(argv);
    for (argv_tmpl, 0..) |arg, i| {
        argv[i] = if (std.mem.eql(u8, arg, "{ref}"))
            value
        else if (std.mem.eql(u8, arg, "{path}"))
            path
        else
            arg;
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

// --- include expansion: one reference -> many (key, value) pairs -------------
//
// An *include* lets a single stored directive expand into a whole set of env
// vars at injection time. Three modes differ only in how the provider output is
// turned into pairs:
//
//   dotenv     -> read the reference as text, parse `KEY=value` lines
//   json       -> read the reference as text, parse a JSON object's top level
//   enumerate  -> run the provider's `list_argv`, parse its `KEY=value` lines
//
// dotenv/json reuse the normal read recipe (a 1Password secure note, an AWS
// JSON secret, ...). enumerate needs a per-provider whole-container recipe.

pub const Mode = enum { dotenv, json, enumerate };

pub fn parseMode(s: []const u8) ?Mode {
    const eql = std.mem.eql;
    if (eql(u8, s, "dotenv")) return .dotenv;
    if (eql(u8, s, "json")) return .json;
    if (eql(u8, s, "enumerate") or eql(u8, s, "vault")) return .enumerate;
    return null;
}

pub fn modeName(m: Mode) []const u8 {
    return switch (m) {
        .dotenv => "dotenv",
        .json => "json",
        .enumerate => "enumerate",
    };
}

pub const Pair = struct { name: []u8, value: []u8 };

/// Free expanded pairs, securely zeroing the (secret) values.
pub fn freeExpanded(gpa: std.mem.Allocator, pairs: []Pair) void {
    for (pairs) |p| {
        std.crypto.secureZero(u8, p.value);
        gpa.free(p.value);
        gpa.free(p.name);
    }
    gpa.free(pairs);
}

/// Expand an include reference into many pairs via the default registry.
pub fn expand(gpa: std.mem.Allocator, io: std.Io, ref: []const u8, mode: Mode, prefix: []const u8) ![]Pair {
    return expandWith(gpa, io, &default_registry, ref, mode, prefix);
}

/// Like `expand`, but against a supplied registry (used for testing).
pub fn expandWith(
    gpa: std.mem.Allocator,
    io: std.Io,
    registry: []const Provider,
    ref: []const u8,
    mode: Mode,
    prefix: []const u8,
) ![]Pair {
    switch (mode) {
        .dotenv => {
            const text = try resolveWith(gpa, io, registry, ref);
            defer freeText(gpa, text);
            return dotenvToPairs(gpa, text, prefix);
        },
        .json => {
            const text = try resolveWith(gpa, io, registry, ref);
            defer freeText(gpa, text);
            return jsonToPairs(gpa, text, prefix);
        },
        .enumerate => {
            const p = match(registry, ref) orelse return Error.NotAReference;
            const list_argv = p.list_argv orelse return Error.UnsupportedMode;
            const text = try runTemplate(gpa, io, list_argv, ref);
            defer freeText(gpa, text);
            return dotenvToPairs(gpa, text, prefix);
        },
    }
}

fn freeText(gpa: std.mem.Allocator, text: []u8) void {
    std.crypto.secureZero(u8, text);
    gpa.free(text);
}

fn applyPrefix(gpa: std.mem.Allocator, prefix: []const u8, key: []const u8) ![]u8 {
    if (prefix.len == 0) return gpa.dupe(u8, key);
    const out = try gpa.alloc(u8, prefix.len + key.len);
    @memcpy(out[0..prefix.len], prefix);
    @memcpy(out[prefix.len..], key);
    return out;
}

fn freePairs(gpa: std.mem.Allocator, list: *std.ArrayList(Pair)) void {
    for (list.items) |p| {
        std.crypto.secureZero(u8, p.value);
        gpa.free(p.value);
        gpa.free(p.name);
    }
    list.deinit(gpa);
}

fn dotenvToPairs(gpa: std.mem.Allocator, text: []const u8, prefix: []const u8) ![]Pair {
    var parsed = dotenv.parse(gpa, text) catch return Error.BadData;
    defer parsed.deinit();

    var out: std.ArrayList(Pair) = .empty;
    errdefer freePairs(gpa, &out);
    for (parsed.entries) |e| {
        const name = try applyPrefix(gpa, prefix, e.key);
        if (!names.isEnvVarName(name)) {
            gpa.free(name);
            continue; // a junk key from a remote source must never reach an env block
        }
        const value = try gpa.dupe(u8, e.value);
        try out.append(gpa, .{ .name = name, .value = value });
    }
    return out.toOwnedSlice(gpa);
}

fn jsonToPairs(gpa: std.mem.Allocator, text: []const u8, prefix: []const u8) ![]Pair {
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, text, .{}) catch return Error.BadData;
    defer parsed.deinit();
    if (parsed.value != .object) return Error.BadData;

    var out: std.ArrayList(Pair) = .empty;
    errdefer freePairs(gpa, &out);
    var it = parsed.value.object.iterator();
    while (it.next()) |kv| {
        const name = try applyPrefix(gpa, prefix, kv.key_ptr.*);
        if (!names.isEnvVarName(name)) {
            gpa.free(name);
            continue;
        }
        const value: []u8 = switch (kv.value_ptr.*) {
            .string => |s| try gpa.dupe(u8, s),
            .number_string => |s| try gpa.dupe(u8, s),
            .integer => |n| try std.fmt.allocPrint(gpa, "{d}", .{n}),
            .float => |f| try std.fmt.allocPrint(gpa, "{d}", .{f}),
            .bool => |b| try gpa.dupe(u8, if (b) "true" else "false"),
            else => {
                gpa.free(name); // null / nested object / array: not an env value
                continue;
            },
        };
        try out.append(gpa, .{ .name = name, .value = value });
    }
    return out.toOwnedSlice(gpa);
}

test "resolveWith substitutes {ref} and captures stdout" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const reg = [_]Provider{.{ .scheme = "mock", .argv = &.{ "printf", "%s", "{ref}" } }};

    const v = try resolveWith(a, io, &reg, "mock://hello/world");
    defer a.free(v);
    try std.testing.expectEqualStrings("mock://hello/world", v);
}

test "resolveWith substitutes {path} (after scheme)" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const reg = [_]Provider{.{ .scheme = "aws", .argv = &.{ "printf", "%s", "{path}" } }};

    const v = try resolveWith(a, io, &reg, "aws://prod/db/password");
    defer a.free(v);
    try std.testing.expectEqualStrings("prod/db/password", v);
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
    try std.testing.expect(isReference("aws://prod/db"));
    try std.testing.expect(isReference("gopass://x/y"));
    try std.testing.expect(isReference("pass://x/y"));
    try std.testing.expect(isReference("vault://secret/app"));
    try std.testing.expect(!isReference("postgres://localhost/db")); // unknown scheme = literal
    try std.testing.expect(!isReference("plain-secret"));
}

fn findPair(pairs: []Pair, name: []const u8) ?[]const u8 {
    for (pairs) |p| if (std.mem.eql(u8, p.name, name)) return p.value;
    return null;
}

test "expand dotenv mode parses a .env body" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    // A secure note whose body is a .env file.
    const body = "# shared dev env\nFOO=bar\nexport BAZ=\"q u x\"\nbad key=skipme\n";
    const reg = [_]Provider{.{ .scheme = "note", .argv = &.{ "printf", "%s", "{path}" } }};

    const pairs = try expandWith(a, io, &reg, "note://" ++ body, .dotenv, "");
    defer freeExpanded(a, pairs);
    try std.testing.expectEqual(@as(usize, 2), pairs.len); // "bad key" skipped
    try std.testing.expectEqualStrings("bar", findPair(pairs, "FOO").?);
    try std.testing.expectEqualStrings("q u x", findPair(pairs, "BAZ").?);
}

test "expand json mode parses a JSON object (AWS-style)" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const json = "{\"DB_URL\":\"postgres://h/d\",\"PORT\":5432,\"DEBUG\":true}";
    const reg = [_]Provider{.{ .scheme = "aws", .argv = &.{ "printf", "%s", "{path}" } }};

    const pairs = try expandWith(a, io, &reg, "aws://" ++ json, .json, "");
    defer freeExpanded(a, pairs);
    try std.testing.expectEqual(@as(usize, 3), pairs.len);
    try std.testing.expectEqualStrings("postgres://h/d", findPair(pairs, "DB_URL").?);
    try std.testing.expectEqualStrings("5432", findPair(pairs, "PORT").?);
    try std.testing.expectEqualStrings("true", findPair(pairs, "DEBUG").?);
}

test "expand applies a prefix" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const reg = [_]Provider{.{ .scheme = "note", .argv = &.{ "printf", "%s", "{path}" } }};

    const pairs = try expandWith(a, io, &reg, "note://KEY=val\n", .dotenv, "APP_");
    defer freeExpanded(a, pairs);
    try std.testing.expectEqual(@as(usize, 1), pairs.len);
    try std.testing.expectEqualStrings("val", findPair(pairs, "APP_KEY").?);
}

test "expand enumerate mode runs list_argv" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const reg = [_]Provider{.{
        .scheme = "ovault",
        .argv = &.{ "false" }, // single-value read unused here
        .list_argv = &.{ "sh", "-c", "printf 'A=1\\nB=2\\n'" },
    }};

    const pairs = try expandWith(a, io, &reg, "ovault://Work", .enumerate, "");
    defer freeExpanded(a, pairs);
    try std.testing.expectEqual(@as(usize, 2), pairs.len);
    try std.testing.expectEqualStrings("1", findPair(pairs, "A").?);
    try std.testing.expectEqualStrings("2", findPair(pairs, "B").?);
}

test "expand enumerate without a recipe is unsupported" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const reg = [_]Provider{.{ .scheme = "note", .argv = &.{ "true" } }};
    try std.testing.expectError(Error.UnsupportedMode, expandWith(a, io, &reg, "note://x", .enumerate, ""));
}

test "parseMode" {
    try std.testing.expect(parseMode("dotenv").? == .dotenv);
    try std.testing.expect(parseMode("json").? == .json);
    try std.testing.expect(parseMode("enumerate").? == .enumerate);
    try std.testing.expect(parseMode("vault").? == .enumerate); // alias
    try std.testing.expect(parseMode("nope") == null);
}

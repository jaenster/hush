//! `hush.yaml` — the project's env manifest, committed next to the code.
//!
//! It is the env *contract*: per environment, it declares which variables the
//! project uses, where each comes from, and (for non-secret config) its inline
//! value. Because it lives in git, adding a variable — especially a
//! process-sensitive one like `PATH` — is a reviewed change: nobody's machine
//! honours it until the PR is merged and pulled. That review is the security
//! boundary for what a bulk include may inject (see `names.isDangerous`).
//!
//! Environments are independent blocks under `envs:` — no inheritance, each is
//! self-contained:
//!
//!   default: dev
//!   envs:
//!     dev:
//!       vars:
//!         PORT: 3000                       inline literal (non-secret config)
//!         DATABASE_URL: op://Private/db    a provider reference (resolved live)
//!         STRIPE_KEY: required             a slot — value from `hush set`
//!         WEIRD: literal://required        escape hatch — the literal "required"
//!       includes:
//!         - op://Private/team-dev --as=dotenv
//!     prod:
//!       vars: { ... }
//!
//! A variable's value is read as: a known provider scheme → reference;
//! `literal://X` → the verbatim string X; the bare words `required`/`optional`
//! → a slot filled from the local store; anything else → an inline literal.
//!
//! The grammar is a deliberately tiny YAML subset (no anchors, no flow style).
//! Top-level keys are `default:` and `envs:`; under `envs:` each bare `name:`
//! starts an env (or, if `vars`/`includes`, a section); a `KEY: value` line is a
//! var and a `- ...` line is an include. Whatever doesn't fit is ignored.

const std = @import("std");

pub const Var = struct {
    name: []const u8,
    /// An explicit value: a provider reference, a `literal://` directive, or a
    /// bare inline literal. Null marks a *slot* whose value comes from the local
    /// store (`hush set`), never the committed file.
    value: ?[]const u8,
    /// Only meaningful for a slot (`value == null`): is the value mandatory?
    required: bool,
};

pub const Include = struct {
    ref: []const u8,
    mode: []const u8,
    prefix: []const u8,
};

pub const Env = struct {
    name: []const u8,
    vars: []Var = &.{},
    includes: []Include = &.{},

    /// Is `name` declared in this env's `vars:`? A declared name forms the
    /// allowlist that lets an otherwise-blocked (dangerous) bulk var through.
    pub fn declares(self: *const Env, name: []const u8) bool {
        for (self.vars) |v| if (std.mem.eql(u8, v.name, name)) return true;
        return false;
    }
};

pub const Manifest = struct {
    arena: std.heap.ArenaAllocator,
    /// Env selected when neither `--env` nor `$HUSH_ENV` is given.
    default_env: ?[]const u8 = null,
    envs: []Env = &.{},

    pub fn deinit(self: *Manifest) void {
        self.arena.deinit();
    }

    pub fn find(self: *const Manifest, name: []const u8) ?*const Env {
        for (self.envs) |*e| if (std.mem.eql(u8, e.name, name)) return e;
        return null;
    }
};

/// Filenames hush looks for, in order, walking up from the working directory.
pub const filenames = [_][]const u8{ "hush.yaml", "hush.yml" };

pub const literal_scheme = "literal://";

/// If `val` is a `literal://X` directive, return the verbatim `X` (the escape
/// hatch for a value that would otherwise read as a reference or a reserved
/// keyword). Otherwise null.
pub fn literalValue(val: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, val, literal_scheme)) return val[literal_scheme.len..];
    return null;
}

/// Parse a manifest from its text. All returned slices are owned by the
/// returned `Manifest`'s arena; free with `deinit`.
///
/// Parsing is two passes: a generic indentation-driven block reader builds a
/// YAML node tree (mappings, sequences, scalars — nesting decided purely by
/// columns), then `interpret` walks that tree into the manifest shape. No level
/// is inferred from reserved words; structure comes only from indentation.
pub fn parse(gpa: std.mem.Allocator, text: []const u8) !Manifest {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const lines = try splitLines(a, text);
    var man: Manifest = .{ .arena = undefined };
    if (lines.len != 0) {
        var i: usize = 0;
        const root = try parseBlock(a, lines, &i);
        try interpret(a, root, &man);
    }
    // Snapshot the arena into the result only after every allocation through it,
    // so the moved copy carries the final buffer-list state.
    man.arena = arena;
    return man;
}

const Line = struct { indent: usize, text: []const u8 };

/// Split into non-blank, non-comment lines tagged with their indent column.
fn splitLines(a: std.mem.Allocator, text: []const u8) ![]Line {
    var out: std.ArrayList(Line) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw0| {
        const raw = std.mem.trimEnd(u8, raw0, "\r");
        const indent = std.mem.indexOfNone(u8, raw, " \t") orelse continue; // blank
        if (raw[indent] == '#') continue; // whole-line comment
        try out.append(a, .{ .indent = indent, .text = raw[indent..] });
    }
    return out.toOwnedSlice(a);
}

const Node = union(enum) {
    scalar: []const u8,
    mapping: []const Entry,
    sequence: []const *const Node,
};
const Entry = struct { key: []const u8, value: *const Node };

/// Parse one block (a mapping or a sequence) starting at `lines[i.*]`, consuming
/// every line indented at the block's base column. Recurses for deeper blocks.
/// `i` always advances, so this terminates on any input.
fn parseBlock(a: std.mem.Allocator, lines: []const Line, i: *usize) error{OutOfMemory}!*const Node {
    const base = lines[i.*].indent;
    if (lines[i.*].text[0] == '-') {
        var items: std.ArrayList(*const Node) = .empty;
        while (i.* < lines.len and lines[i.*].indent == base and lines[i.*].text[0] == '-') {
            const after = std.mem.trimStart(u8, lines[i.*].text[1..], " \t");
            if (after.len == 0) {
                i.* += 1;
                if (i.* < lines.len and lines[i.*].indent > base) {
                    try items.append(a, try parseBlock(a, lines, i));
                } else {
                    try items.append(a, try mkScalar(a, ""));
                }
            } else {
                try items.append(a, try mkScalar(a, stripComment(after)));
                i.* += 1;
            }
        }
        return mkNode(a, .{ .sequence = try items.toOwnedSlice(a) });
    }

    var entries: std.ArrayList(Entry) = .empty;
    while (i.* < lines.len and lines[i.*].indent == base and lines[i.*].text[0] != '-') {
        const line = lines[i.*].text;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse {
            i.* += 1; // not a mapping entry: skip, never stall
            continue;
        };
        const key = std.mem.trim(u8, line[0..colon], " \t");
        const rest = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (rest.len == 0) {
            i.* += 1;
            const value = if (i.* < lines.len and lines[i.*].indent > base)
                try parseBlock(a, lines, i)
            else
                try mkScalar(a, "");
            try entries.append(a, .{ .key = key, .value = value });
        } else {
            try entries.append(a, .{ .key = key, .value = try mkScalar(a, stripComment(rest)) });
            i.* += 1;
        }
    }
    return mkNode(a, .{ .mapping = try entries.toOwnedSlice(a) });
}

fn mkNode(a: std.mem.Allocator, n: Node) !*const Node {
    const p = try a.create(Node);
    p.* = n;
    return p;
}
fn mkScalar(a: std.mem.Allocator, s: []const u8) !*const Node {
    return mkNode(a, .{ .scalar = s });
}

fn mapGet(node: *const Node, key: []const u8) ?*const Node {
    if (node.* != .mapping) return null;
    for (node.mapping) |e| if (std.mem.eql(u8, e.key, key)) return e.value;
    return null;
}

/// Walk the node tree into the manifest shape, duping every retained string into
/// the arena (node slices borrow from the source text).
fn interpret(a: std.mem.Allocator, root: *const Node, man: *Manifest) !void {
    if (root.* != .mapping) return;

    if (mapGet(root, "default")) |d| {
        if (d.* == .scalar and d.scalar.len > 0) man.default_env = try a.dupe(u8, d.scalar);
    }

    const envs_node = mapGet(root, "envs") orelse return;
    if (envs_node.* != .mapping) return;

    var envs: std.ArrayList(Env) = .empty;
    for (envs_node.mapping) |env_entry| {
        var vars: std.ArrayList(Var) = .empty;
        var incs: std.ArrayList(Include) = .empty;

        if (mapGet(env_entry.value, "vars")) |vnode| {
            if (vnode.* == .mapping) {
                for (vnode.mapping) |ve| {
                    const valstr = if (ve.value.* == .scalar) ve.value.scalar else "";
                    const parsed = try parseVarValue(a, valstr);
                    try vars.append(a, .{ .name = try a.dupe(u8, ve.key), .value = parsed.value, .required = parsed.required });
                }
            }
        }
        if (mapGet(env_entry.value, "includes")) |inode| {
            if (inode.* == .sequence) {
                for (inode.sequence) |item| {
                    if (item.* == .scalar and item.scalar.len > 0)
                        try incs.append(a, try parseIncludeSpec(a, item.scalar));
                }
            }
        }

        try envs.append(a, .{
            .name = try a.dupe(u8, env_entry.key),
            .vars = try vars.toOwnedSlice(a),
            .includes = try incs.toOwnedSlice(a),
        });
    }
    man.envs = try envs.toOwnedSlice(a);
}

const VarValue = struct { value: ?[]const u8, required: bool };

fn parseVarValue(a: std.mem.Allocator, val: []const u8) !VarValue {
    // Empty or `required` is a mandatory slot; `optional` is an optional slot;
    // anything else (including a `literal://` directive) is an explicit value.
    if (val.len == 0 or std.mem.eql(u8, val, "required")) return .{ .value = null, .required = true };
    if (std.mem.eql(u8, val, "optional")) return .{ .value = null, .required = false };
    return .{ .value = try a.dupe(u8, val), .required = false };
}

fn parseIncludeSpec(a: std.mem.Allocator, item: []const u8) !Include {
    var ref: []const u8 = "";
    var mode: []const u8 = "dotenv";
    var prefix: []const u8 = "";
    var toks = std.mem.tokenizeAny(u8, item, " \t");
    if (toks.next()) |first| ref = first;
    while (toks.next()) |t| {
        if (std.mem.startsWith(u8, t, "--as=")) {
            mode = t["--as=".len..];
        } else if (std.mem.startsWith(u8, t, "--prefix=")) {
            prefix = t["--prefix=".len..];
        }
    }
    return .{ .ref = try a.dupe(u8, ref), .mode = try a.dupe(u8, mode), .prefix = try a.dupe(u8, prefix) };
}

/// Drop a trailing ` # comment` (whitespace-preceded, so a `#` inside a value
/// or reference is kept).
fn stripComment(s: []const u8) []const u8 {
    if (std.mem.indexOf(u8, s, " #")) |i| return std.mem.trimEnd(u8, s[0..i], " \t");
    return s;
}

// --- tests -------------------------------------------------------------------

fn findVar(e: *const Env, name: []const u8) ?Var {
    for (e.vars) |v| if (std.mem.eql(u8, v.name, name)) return v;
    return null;
}

test "parses default + independent env blocks" {
    const a = std.testing.allocator;
    var m = try parse(a,
        \\# project env contract
        \\default: dev
        \\envs:
        \\  dev:
        \\    vars:
        \\      PORT: 3000                 # not a secret
        \\      DATABASE_URL: op://Private/db-dev
        \\      STRIPE_KEY: required
        \\      LOG_TOKEN: optional
        \\      WEIRD: literal://required
        \\    includes:
        \\      - op://Private/team-dev --as=dotenv
        \\  prod:
        \\    vars:
        \\      PORT: 80
        \\      DATABASE_URL: op://Private/db-prod
        \\    includes:
        \\      - op://Private/team-prod --as=enumerate --prefix=P_
    );
    defer m.deinit();

    try std.testing.expectEqualStrings("dev", m.default_env.?);
    try std.testing.expectEqual(@as(usize, 2), m.envs.len);

    const dev = m.find("dev").?;
    try std.testing.expectEqualStrings("3000", findVar(dev, "PORT").?.value.?);
    try std.testing.expectEqualStrings("op://Private/db-dev", findVar(dev, "DATABASE_URL").?.value.?);
    const stripe = findVar(dev, "STRIPE_KEY").?;
    try std.testing.expect(stripe.value == null and stripe.required);
    const logt = findVar(dev, "LOG_TOKEN").?;
    try std.testing.expect(logt.value == null and !logt.required);
    // literal:// keeps its directive in `value`; the daemon strips the scheme.
    try std.testing.expectEqualStrings("literal://required", findVar(dev, "WEIRD").?.value.?);
    try std.testing.expectEqual(@as(usize, 1), dev.includes.len);
    try std.testing.expectEqualStrings("op://Private/team-dev", dev.includes[0].ref);
    try std.testing.expectEqualStrings("dotenv", dev.includes[0].mode);

    const prod = m.find("prod").?;
    try std.testing.expectEqualStrings("80", findVar(prod, "PORT").?.value.?);
    try std.testing.expectEqualStrings("P_", prod.includes[0].prefix);
    try std.testing.expectEqualStrings("enumerate", prod.includes[0].mode);

    try std.testing.expect(dev.declares("PORT"));
    try std.testing.expect(!dev.declares("NOPE"));
    try std.testing.expect(m.find("staging") == null);
}

test "literalValue strips the scheme" {
    try std.testing.expectEqualStrings("required", literalValue("literal://required").?);
    try std.testing.expectEqualStrings("", literalValue("literal://").?);
    try std.testing.expectEqualStrings("op://x", literalValue("literal://op://x").?);
    try std.testing.expect(literalValue("op://x") == null);
    try std.testing.expect(literalValue("3000") == null);
}

test "indentation drives nesting (4-space, not 2)" {
    const a = std.testing.allocator;
    var m = try parse(a,
        \\default: prod
        \\envs:
        \\    dev:
        \\        vars:
        \\            PORT: 3000
        \\        includes:
        \\            - op://P/note --as=json
        \\    prod:
        \\        vars:
        \\            PORT: 80
    );
    defer m.deinit();
    try std.testing.expectEqualStrings("prod", m.default_env.?);
    try std.testing.expectEqual(@as(usize, 2), m.envs.len);
    try std.testing.expectEqualStrings("3000", findVar(m.find("dev").?, "PORT").?.value.?);
    try std.testing.expectEqualStrings("json", m.find("dev").?.includes[0].mode);
    try std.testing.expectEqualStrings("80", findVar(m.find("prod").?, "PORT").?.value.?);
}

test "an env may be named 'vars' — structure comes from indentation, not keywords" {
    const a = std.testing.allocator;
    var m = try parse(a,
        \\envs:
        \\  vars:
        \\    vars:
        \\      KEEP: 1
    );
    defer m.deinit();
    // The outer `vars:` is an env name; the inner `vars:` is its section.
    const e = m.find("vars").?;
    try std.testing.expectEqualStrings("1", findVar(e, "KEEP").?.value.?);
}

test "empty manifest yields no envs" {
    const a = std.testing.allocator;
    var m = try parse(a, "# just a comment\n\n");
    defer m.deinit();
    try std.testing.expect(m.default_env == null);
    try std.testing.expectEqual(@as(usize, 0), m.envs.len);
}

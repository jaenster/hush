//! A small `.env` parser for `hush import`.
//!
//! Handles: `KEY=value`, `export KEY=value`, `# comments`, blank lines, and
//! single- or double-quoted values. Double-quoted values support the common
//! escapes (`\n \r \t \\ \"`); single-quoted values are literal. Unquoted
//! values are trimmed. One entry per line (no multi-line values).

const std = @import("std");

pub const Entry = struct { key: []u8, value: []u8 };

pub const Parsed = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,

    pub fn deinit(self: *Parsed) void {
        for (self.entries) |e| {
            self.allocator.free(e.key);
            self.allocator.free(e.value);
        }
        self.allocator.free(self.entries);
    }
};

const ws = " \t\r";

pub fn parse(allocator: std.mem.Allocator, content: []const u8) !Parsed {
    var list: std.ArrayList(Entry) = .empty;
    errdefer {
        for (list.items) |e| {
            allocator.free(e.key);
            allocator.free(e.value);
        }
        list.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw| {
        var line = std.mem.trim(u8, raw, ws);
        if (line.len == 0 or line[0] == '#') continue;

        // optional `export ` prefix
        if (std.mem.startsWith(u8, line, "export ")) {
            line = std.mem.trimStart(u8, line["export ".len..], ws);
        }

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], ws);
        if (key.len == 0) continue;

        const rawval = std.mem.trimStart(u8, line[eq + 1 ..], ws);
        const value = try parseValue(allocator, rawval);
        errdefer allocator.free(value);

        try list.append(allocator, .{ .key = try allocator.dupe(u8, key), .value = value });
    }

    return .{ .allocator = allocator, .entries = try list.toOwnedSlice(allocator) };
}

/// Caller owns the returned slice.
fn parseValue(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len == 0) return allocator.dupe(u8, "");

    switch (raw[0]) {
        '"' => {
            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(allocator);
            var i: usize = 1;
            while (i < raw.len) : (i += 1) {
                const c = raw[i];
                if (c == '"') break;
                if (c == '\\' and i + 1 < raw.len) {
                    i += 1;
                    try out.append(allocator, switch (raw[i]) {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        else => raw[i], // \\ \" and anything else: literal next char
                    });
                } else {
                    try out.append(allocator, c);
                }
            }
            return out.toOwnedSlice(allocator);
        },
        '\'' => {
            const end = std.mem.indexOfScalarPos(u8, raw, 1, '\'') orelse raw.len;
            return allocator.dupe(u8, raw[1..end]);
        },
        else => return allocator.dupe(u8, std.mem.trimEnd(u8, raw, ws)),
    }
}

// --- tests -------------------------------------------------------------------

fn expectEntry(p: Parsed, i: usize, key: []const u8, value: []const u8) !void {
    try std.testing.expectEqualStrings(key, p.entries[i].key);
    try std.testing.expectEqualStrings(value, p.entries[i].value);
}

test "basic, export, comments, blanks" {
    const a = std.testing.allocator;
    var p = try parse(a,
        \\# a comment
        \\FOO=bar
        \\
        \\export BAZ=qux
        \\  SPACED  =  trimmed
    );
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 3), p.entries.len);
    try expectEntry(p, 0, "FOO", "bar");
    try expectEntry(p, 1, "BAZ", "qux");
    try expectEntry(p, 2, "SPACED", "trimmed");
}

test "quoting and escapes" {
    const a = std.testing.allocator;
    var p = try parse(a,
        \\DQ="hello world"
        \\SQ='literal $no expand'
        \\ESC="line1\nline2\ttab"
        \\EQ=a=b=c
        \\EMPTY=
    );
    defer p.deinit();
    try expectEntry(p, 0, "DQ", "hello world");
    try expectEntry(p, 1, "SQ", "literal $no expand");
    try expectEntry(p, 2, "ESC", "line1\nline2\ttab");
    try expectEntry(p, 3, "EQ", "a=b=c");
    try expectEntry(p, 4, "EMPTY", "");
}

test "no equals sign is skipped" {
    const a = std.testing.allocator;
    var p = try parse(a, "JUST_A_WORD\nKEY=val");
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 1), p.entries.len);
    try expectEntry(p, 0, "KEY", "val");
}

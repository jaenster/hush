//! hush wire protocol.
//!
//! Transport: a unix domain socket (mode 0600). The protocol is intentionally
//! trivial so SDKs in any language are a few dozen lines:
//!
//!   frame  = u32_le total_len | payload
//!   payload(request)  = u8 op | fields...
//!   payload(response) = u8 status | fields...
//!   field  = u16_le len | bytes        (all strings are length-prefixed)
//!
//! All integers are little-endian. Max frame is 1 MiB.
//!
//! This module is pure (no IO): it encodes payloads to / decodes them from
//! byte slices. The transport layer adds the u32 length prefix when writing
//! and strips it when reading.

const std = @import("std");

pub const max_frame = 1 << 20; // 1 MiB

pub const Op = enum(u8) {
    ping = 0,
    set = 1,
    get = 2,
    del = 3,
    list = 4,
    _,
};

pub const Status = enum(u8) {
    ok = 0,
    err = 1,
    not_found = 2,
    _,
};

pub const Request = union(Op) {
    ping,
    set: struct { env: []const u8, key: []const u8, value: []const u8 },
    get: struct { env: []const u8, key: []const u8 },
    del: struct { env: []const u8, key: []const u8 },
    list: struct { env: []const u8 },
};

pub const Error = error{ Malformed, TooLarge, UnknownOp };

// --- low-level field codec ---------------------------------------------------

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn u8v(self: *Cursor) Error!u8 {
        if (self.pos + 1 > self.buf.len) return Error.Malformed;
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }

    fn u16v(self: *Cursor) Error!u16 {
        if (self.pos + 2 > self.buf.len) return Error.Malformed;
        const v = std.mem.readInt(u16, self.buf[self.pos..][0..2], .little);
        self.pos += 2;
        return v;
    }

    fn field(self: *Cursor) Error![]const u8 {
        const len = try self.u16v();
        if (self.pos + len > self.buf.len) return Error.Malformed;
        const s = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return s;
    }
};

fn putField(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    if (s.len > std.math.maxInt(u16)) return Error.TooLarge;
    var len_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_buf, @intCast(s.len), .little);
    try list.appendSlice(allocator, &len_buf);
    try list.appendSlice(allocator, s);
}

// --- request encode/decode ---------------------------------------------------

/// Encode a request payload (no length prefix). Caller owns the slice.
pub fn encodeRequest(allocator: std.mem.Allocator, req: Request) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.append(allocator, @intFromEnum(@as(Op, req)));
    switch (req) {
        .ping => {},
        .set => |s| {
            try putField(&list, allocator, s.env);
            try putField(&list, allocator, s.key);
            try putField(&list, allocator, s.value);
        },
        .get => |g| {
            try putField(&list, allocator, g.env);
            try putField(&list, allocator, g.key);
        },
        .del => |d| {
            try putField(&list, allocator, d.env);
            try putField(&list, allocator, d.key);
        },
        .list => |l| try putField(&list, allocator, l.env),
    }
    return list.toOwnedSlice(allocator);
}

/// Decode a request payload. Returned slices borrow from `payload`.
pub fn decodeRequest(payload: []const u8) Error!Request {
    var cur = Cursor{ .buf = payload };
    const op_raw = try cur.u8v();
    const op = std.enums.fromInt(Op, op_raw) orelse return Error.UnknownOp;
    return switch (op) {
        .ping => .ping,
        .set => .{ .set = .{ .env = try cur.field(), .key = try cur.field(), .value = try cur.field() } },
        .get => .{ .get = .{ .env = try cur.field(), .key = try cur.field() } },
        .del => .{ .del = .{ .env = try cur.field(), .key = try cur.field() } },
        .list => .{ .list = .{ .env = try cur.field() } },
        _ => Error.UnknownOp,
    };
}

// --- response encode/decode --------------------------------------------------

/// Build a response payload: status byte followed by zero or more fields.
pub fn encodeResponse(allocator: std.mem.Allocator, status: Status, fields: []const []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.append(allocator, @intFromEnum(status));
    for (fields) |f| try putField(&list, allocator, f);
    return list.toOwnedSlice(allocator);
}

pub const Response = struct {
    status: Status,
    /// Borrowed slices into the source payload.
    fields: std.ArrayList([]const u8),

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        self.fields.deinit(allocator);
    }
};

pub fn decodeResponse(allocator: std.mem.Allocator, payload: []const u8) !Response {
    var cur = Cursor{ .buf = payload };
    const status = std.enums.fromInt(Status, try cur.u8v()) orelse return Error.Malformed;
    var fields: std.ArrayList([]const u8) = .empty;
    errdefer fields.deinit(allocator);
    while (cur.pos < cur.buf.len) try fields.append(allocator, try cur.field());
    return .{ .status = status, .fields = fields };
}

// --- tests -------------------------------------------------------------------

test "request roundtrip: set" {
    const a = std.testing.allocator;
    const req: Request = .{ .set = .{ .env = "dev", .key = "API_KEY", .value = "s3cr3t" } };
    const enc = try encodeRequest(a, req);
    defer a.free(enc);
    const dec = try decodeRequest(enc);
    try std.testing.expectEqualStrings("dev", dec.set.env);
    try std.testing.expectEqualStrings("API_KEY", dec.set.key);
    try std.testing.expectEqualStrings("s3cr3t", dec.set.value);
}

test "request roundtrip: ping/get/del/list" {
    const a = std.testing.allocator;
    {
        const enc = try encodeRequest(a, .ping);
        defer a.free(enc);
        try std.testing.expect(try decodeRequest(enc) == .ping);
    }
    {
        const enc = try encodeRequest(a, .{ .get = .{ .env = "prod", .key = "DB" } });
        defer a.free(enc);
        const d = try decodeRequest(enc);
        try std.testing.expectEqualStrings("prod", d.get.env);
        try std.testing.expectEqualStrings("DB", d.get.key);
    }
    {
        const enc = try encodeRequest(a, .{ .list = .{ .env = "tst" } });
        defer a.free(enc);
        try std.testing.expectEqualStrings("tst", (try decodeRequest(enc)).list.env);
    }
}

test "response roundtrip" {
    const a = std.testing.allocator;
    const enc = try encodeResponse(a, .ok, &.{ "FOO", "BAR" });
    defer a.free(enc);
    var resp = try decodeResponse(a, enc);
    defer resp.deinit(a);
    try std.testing.expect(resp.status == .ok);
    try std.testing.expectEqual(@as(usize, 2), resp.fields.items.len);
    try std.testing.expectEqualStrings("FOO", resp.fields.items[0]);
    try std.testing.expectEqualStrings("BAR", resp.fields.items[1]);
}

test "decode rejects truncated field" {
    // op=get, env len=3 but only 1 byte follows
    const bad = [_]u8{ @intFromEnum(Op.get), 3, 0, 'x' };
    try std.testing.expectError(Error.Malformed, decodeRequest(&bad));
}

test "unknown op" {
    const bad = [_]u8{200};
    try std.testing.expectError(Error.UnknownOp, decodeRequest(&bad));
}

//! Frame transport over a std.Io stream: u32_le length prefix + payload.
//! Used by both the daemon and the CLI. Pure framing — the payload bytes are
//! whatever protocol.zig encoded.

const std = @import("std");
const protocol = @import("protocol.zig");

pub const Error = error{ FrameTooLarge, Closed };

/// Write a length-prefixed frame and flush.
pub fn writeFrame(w: *std.Io.Writer, payload: []const u8) !void {
    if (payload.len > protocol.max_frame) return Error.FrameTooLarge;
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(payload.len), .little);
    try w.writeAll(&len_buf);
    try w.writeAll(payload);
    try w.flush();
}

/// Read one length-prefixed frame. Caller owns the returned slice. Returns
/// `error.EndOfStream` when the peer closes cleanly between frames.
pub fn readFrame(r: *std.Io.Reader, allocator: std.mem.Allocator) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try r.readSliceAll(&len_buf);
    const len = std.mem.readInt(u32, &len_buf, .little);
    if (len > protocol.max_frame) return Error.FrameTooLarge;

    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try r.readSliceAll(buf);
    return buf;
}

// --- tests -------------------------------------------------------------------

test "frame roundtrip" {
    const a = std.testing.allocator;
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeFrame(&w, "hello world");

    var r = std.Io.Reader.fixed(w.buffered());
    const got = try readFrame(&r, a);
    defer a.free(got);
    try std.testing.expectEqualStrings("hello world", got);
}

test "empty frame roundtrip" {
    const a = std.testing.allocator;
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeFrame(&w, "");

    var r = std.Io.Reader.fixed(w.buffered());
    const got = try readFrame(&r, a);
    defer a.free(got);
    try std.testing.expectEqual(@as(usize, 0), got.len);
}

test "truncated frame yields EndOfStream" {
    const a = std.testing.allocator;
    // length prefix says 5 bytes, but only 2 follow
    const bad = [_]u8{ 5, 0, 0, 0, 'h', 'i' };
    var r = std.Io.Reader.fixed(&bad);
    try std.testing.expectError(error.EndOfStream, readFrame(&r, a));
}

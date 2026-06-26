//! hush — CLI client for hushd. Speaks the framed protocol over the unix socket.
//!
//!   hush ping
//!   hush set <env> <key> <value>
//!   hush get <env> <key>
//!   hush del <env> <key>
//!   hush ls  <env>

const std = @import("std");
const hush = @import("hush");

const usage =
    \\usage:
    \\  hush ping
    \\  hush set <env> <key> <value>
    \\  hush get <env> <key>
    \\  hush del <env> <key>
    \\  hush ls  <env>
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    var args = init.minimal.args.iterate();
    _ = args.skip(); // argv[0]

    const verb = args.next() orelse {
        std.debug.print("{s}", .{usage});
        return 2;
    };

    const req = buildRequest(verb, &args) orelse {
        std.debug.print("{s}", .{usage});
        return 2;
    };

    var paths = try hush.paths.Paths.init(gpa);
    defer paths.deinit();

    const addr = try std.Io.net.UnixAddress.init(paths.socket);
    var stream = addr.connect(io) catch |err| {
        std.debug.print("hush: cannot connect to hushd at {s}: {t}\n", .{ paths.socket, err });
        std.debug.print("hush: is the daemon running? (start it with `hushd`)\n", .{});
        return 1;
    };
    defer stream.close(io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const payload = try hush.protocol.encodeRequest(gpa, req);
    defer gpa.free(payload);
    try hush.transport.writeFrame(&sw.interface, payload);

    const resp_buf = try hush.transport.readFrame(&sr.interface, gpa);
    defer gpa.free(resp_buf);
    var resp = try hush.protocol.decodeResponse(gpa, resp_buf);
    defer resp.deinit(gpa);

    return printResponse(io, verb, resp);
}

fn buildRequest(verb: []const u8, args: *std.process.Args.Iterator) ?hush.protocol.Request {
    const eql = std.mem.eql;
    if (eql(u8, verb, "ping")) return .ping;
    if (eql(u8, verb, "set")) {
        const env = args.next() orelse return null;
        const key = args.next() orelse return null;
        const value = args.next() orelse return null;
        return .{ .set = .{ .env = env, .key = key, .value = value } };
    }
    if (eql(u8, verb, "get")) {
        const env = args.next() orelse return null;
        const key = args.next() orelse return null;
        return .{ .get = .{ .env = env, .key = key } };
    }
    if (eql(u8, verb, "del")) {
        const env = args.next() orelse return null;
        const key = args.next() orelse return null;
        return .{ .del = .{ .env = env, .key = key } };
    }
    if (eql(u8, verb, "ls")) {
        const env = args.next() orelse return null;
        return .{ .list = .{ .env = env } };
    }
    return null;
}

fn printResponse(io: std.Io, verb: []const u8, resp: hush.protocol.Response) !u8 {
    const out = std.Io.File.stdout();
    switch (resp.status) {
        .ok => {
            if (std.mem.eql(u8, verb, "get")) {
                if (resp.fields.items.len > 0) {
                    try out.writeStreamingAll(io, resp.fields.items[0]);
                    try out.writeStreamingAll(io, "\n");
                }
            } else if (std.mem.eql(u8, verb, "ls")) {
                for (resp.fields.items) |name| {
                    try out.writeStreamingAll(io, name);
                    try out.writeStreamingAll(io, "\n");
                }
            }
            return 0;
        },
        .not_found => {
            std.debug.print("hush: not found\n", .{});
            return 1;
        },
        .err => {
            const msg = if (resp.fields.items.len > 0) resp.fields.items[0] else "unknown error";
            std.debug.print("hush: {s}\n", .{msg});
            return 1;
        },
        _ => {
            std.debug.print("hush: unexpected response status\n", .{});
            return 1;
        },
    }
}

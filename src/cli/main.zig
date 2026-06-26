//! hush — CLI client for hushd. Speaks the framed protocol over the unix socket.
//!
//!   hush ping
//!   hush set <env> <key> <value>
//!   hush get <env> <key>
//!   hush del <env> <key>
//!   hush ls  <env>
//!   hush run --env=<env> -- <command> [args...]

const std = @import("std");
const hush = @import("hush");

const version = "0.0.0-dev";

const usage =
    \\usage:
    \\  hush ping
    \\  hush set <env> <key> <value>
    \\  hush get <env> <key>
    \\  hush del <env> <key>
    \\  hush ls  <env>
    \\  hush run --env=<env> -- <command> [args...]
    \\  hush version
    \\
;

const run_usage = "usage: hush run --env=<env> -- <command> [args...]\n";

fn isHelp(verb: []const u8) bool {
    const eql = std.mem.eql;
    return eql(u8, verb, "help") or eql(u8, verb, "--help") or eql(u8, verb, "-h");
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    var args = init.minimal.args.iterate();
    _ = args.skip(); // argv[0]

    const verb = args.next() orelse {
        std.debug.print("{s}", .{usage});
        return 2;
    };

    if (isHelp(verb)) {
        std.debug.print("{s}", .{usage});
        return 0;
    }
    if (std.mem.eql(u8, verb, "version") or std.mem.eql(u8, verb, "--version")) {
        std.debug.print("hush {s}\n", .{version});
        return 0;
    }
    if (std.mem.eql(u8, verb, "run")) {
        return runWrapper(init, &args);
    }

    const req = buildRequest(verb, &args) orelse {
        std.debug.print("{s}", .{usage});
        return 2;
    };

    var stream = (try connectOrReport(io, gpa)) orelse return 1;
    defer stream.close(io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const payload = try hush.protocol.encodeRequest(gpa, req);
    defer freeSecret(gpa, payload);
    try hush.transport.writeFrame(&sw.interface, payload);

    const resp_buf = try hush.transport.readFrame(&sr.interface, gpa);
    defer freeSecret(gpa, resp_buf);
    var resp = try hush.protocol.decodeResponse(gpa, resp_buf);
    defer resp.deinit(gpa);

    return printResponse(io, verb, resp);
}

/// Connect to hushd, printing a friendly message (and returning null) if it
/// isn't reachable.
fn connectOrReport(io: std.Io, gpa: std.mem.Allocator) !?std.Io.net.Stream {
    var paths = try hush.paths.Paths.init(gpa);
    defer paths.deinit();
    const addr = try std.Io.net.UnixAddress.init(paths.socket);
    return addr.connect(io) catch |err| {
        std.debug.print("hush: cannot connect to hushd: {t}\n", .{err});
        std.debug.print("hush: is the daemon running? (start it with `hushd`)\n", .{});
        return null;
    };
}

/// `hush run --env=<env> -- <command> [args...]`: resolve the env's secrets,
/// inject them into the environment, and exec the command (replacing this
/// process).
fn runWrapper(init: std.process.Init, args: *std.process.Args.Iterator) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    var env: ?[]const u8 = null;
    var child: std.ArrayList([]const u8) = .empty;
    defer child.deinit(gpa);

    var after_sep = false;
    while (args.next()) |a| {
        if (after_sep) {
            try child.append(gpa, a);
        } else if (std.mem.eql(u8, a, "--")) {
            after_sep = true;
        } else if (std.mem.startsWith(u8, a, "--env=")) {
            env = a["--env=".len..];
        } else if (std.mem.eql(u8, a, "--env")) {
            env = args.next();
        } else {
            std.debug.print("hush: unexpected argument '{s}'\n{s}", .{ a, run_usage });
            return 2;
        }
    }

    const env_name = env orelse {
        std.debug.print("hush: --env is required\n{s}", .{run_usage});
        return 2;
    };
    if (child.items.len == 0) {
        std.debug.print("hush: no command given\n{s}", .{run_usage});
        return 2;
    }

    var stream = (try connectOrReport(io, gpa)) orelse return 1;
    defer stream.close(io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const payload = try hush.protocol.encodeRequest(gpa, .{ .dump = .{ .env = env_name } });
    defer gpa.free(payload);
    try hush.transport.writeFrame(&sw.interface, payload);

    const resp_buf = try hush.transport.readFrame(&sr.interface, gpa);
    defer freeSecret(gpa, resp_buf);
    var resp = try hush.protocol.decodeResponse(gpa, resp_buf);
    defer resp.deinit(gpa);

    if (resp.status != .ok) {
        std.debug.print("hush: could not resolve env '{s}'\n", .{env_name});
        return 1;
    }

    // Inject secrets (alternating key, value fields) on top of the inherited env.
    var i: usize = 0;
    while (i + 1 < resp.fields.items.len) : (i += 2) {
        try init.environ_map.put(resp.fields.items[i], resp.fields.items[i + 1]);
    }

    // Replace this process with the command; only returns on failure.
    const err = std.process.replace(io, .{ .argv = child.items, .environ_map = init.environ_map });
    std.debug.print("hush: cannot exec '{s}': {t}\n", .{ child.items[0], err });
    return 1;
}

/// Zero a heap buffer that may contain secret material, then free it.
fn freeSecret(gpa: std.mem.Allocator, buf: []u8) void {
    hush.crypto.zero(buf);
    gpa.free(buf);
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

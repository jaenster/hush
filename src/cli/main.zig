//! hush — CLI client for hushd. Speaks the framed protocol over the unix socket.
//!
//!   hush -- <command> [args...]              run with the default env
//!   hush --env=<env> -- <command> [args...]  run with a specific env
//!   hush ping
//!   hush set <env> <key> <value>
//!   hush get <env> <key>
//!   hush del <env> <key>
//!   hush ls  <env>

const std = @import("std");
const hush = @import("hush");

const version = "0.0.0-dev";

const default_env = "dev";

const usage =
    \\usage:
    \\  hush -- <command> [args...]              run a command with secrets injected
    \\  hush --env=<env> -- <command> [args...]  ... using a specific env
    \\  hush env [--env=<env>] [--format=shell|dotenv]   print secrets for eval or --env-file
    \\  hush import <file.env> [--env=<env>]     bulk-import a .env file
    \\  hush set <env> <key> <value>
    \\  hush get <env> <key>
    \\  hush del <env> <key>
    \\  hush ls  <env>
    \\  hush ping
    \\  hush version
    \\
    \\The env defaults to $HUSH_ENV, then "dev".
    \\
;

fn isHelp(verb: []const u8) bool {
    const eql = std.mem.eql;
    return eql(u8, verb, "help") or eql(u8, verb, "--help") or eql(u8, verb, "-h");
}

fn isRequestVerb(verb: []const u8) bool {
    const eql = std.mem.eql;
    return eql(u8, verb, "ping") or eql(u8, verb, "set") or eql(u8, verb, "get") or
        eql(u8, verb, "del") or eql(u8, verb, "ls");
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    // Collect args up front so we can dispatch without iterator juggling. The
    // slices point into the OS argv and stay valid for the process lifetime.
    var arg_list: std.ArrayList([]const u8) = .empty;
    defer arg_list.deinit(gpa);
    var it = init.minimal.args.iterate();
    _ = it.skip(); // argv[0]
    while (it.next()) |a| try arg_list.append(gpa, a);
    const args = arg_list.items;

    if (args.len == 0) {
        std.debug.print("{s}", .{usage});
        return 2;
    }

    const verb = args[0];

    if (isHelp(verb)) {
        std.debug.print("{s}", .{usage});
        return 0;
    }
    if (std.mem.eql(u8, verb, "version") or std.mem.eql(u8, verb, "--version")) {
        std.debug.print("hush {s}\n", .{version});
        return 0;
    }
    if (isRequestVerb(verb)) {
        return request(io, gpa, verb, args[1..]);
    }
    if (std.mem.eql(u8, verb, "env")) {
        return envCommand(init, args[1..]);
    }
    if (std.mem.eql(u8, verb, "import")) {
        return importCommand(init, args[1..]);
    }

    // Everything else is "run mode": `hush run -- cmd`, `hush -- cmd`,
    // `hush --env=prod -- cmd`.
    const run_args = if (std.mem.eql(u8, verb, "run")) args[1..] else args;
    return runWrapper(init, run_args);
}

/// A one-shot request/response verb (ping/set/get/del/ls).
fn request(io: std.Io, gpa: std.mem.Allocator, verb: []const u8, rest: []const []const u8) !u8 {
    const req = buildRequest(verb, rest) orelse {
        std.debug.print("{s}", .{usage});
        return 2;
    };

    var stream = (try connectOrReport(io, gpa)) orelse return 1;
    defer stream.close(io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const payload = hush.protocol.encodeRequest(gpa, req) catch |err| switch (err) {
        error.TooLarge => {
            std.debug.print("hush: value too large for a single message\n", .{});
            return 2;
        },
        else => return err,
    };
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

/// `hush [--env=<env>] -- <command> [args...]`: resolve the env's secrets,
/// inject them into the environment, and exec the command (replacing this
/// process). The env defaults to $HUSH_ENV, then "dev".
fn runWrapper(init: std.process.Init, run_args: []const []const u8) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    var env_flag: ?[]const u8 = null;
    var child: ?[]const []const u8 = null;

    var i: usize = 0;
    while (i < run_args.len) : (i += 1) {
        const a = run_args[i];
        if (std.mem.eql(u8, a, "--")) {
            child = run_args[i + 1 ..];
            break;
        } else if (std.mem.startsWith(u8, a, "--env=")) {
            env_flag = a["--env=".len..];
        } else if (std.mem.eql(u8, a, "--env")) {
            i += 1;
            if (i >= run_args.len) {
                std.debug.print("hush: --env needs a value\n{s}", .{usage});
                return 2;
            }
            env_flag = run_args[i];
        } else {
            std.debug.print("hush: unexpected argument '{s}'\n{s}", .{ a, usage });
            return 2;
        }
    }

    const cmd = child orelse {
        std.debug.print("hush: missing '--' before the command\n{s}", .{usage});
        return 2;
    };
    if (cmd.len == 0) {
        std.debug.print("hush: no command given after '--'\n{s}", .{usage});
        return 2;
    }

    const env_name = env_flag orelse init.environ_map.get("HUSH_ENV") orelse default_env;

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
    // Defensively skip any key that isn't a valid env var name — an invalid name
    // would corrupt the execve environment block.
    var f: usize = 0;
    while (f + 1 < resp.fields.items.len) : (f += 2) {
        const k = resp.fields.items[f];
        if (!hush.names.isEnvVarName(k)) {
            std.debug.print("hush: skipping invalid key name '{s}'\n", .{k});
            continue;
        }
        try init.environ_map.put(k, resp.fields.items[f + 1]);
    }

    // Replace this process with the command; only returns on failure.
    const err = std.process.replace(io, .{ .argv = cmd, .environ_map = init.environ_map });
    std.debug.print("hush: cannot exec '{s}': {t}\n", .{ cmd[0], err });
    return 1;
}

const Format = enum {
    /// `export KEY='value'` for `eval "$(hush env)"`.
    shell,
    /// `KEY=value` for `docker run --env-file`, compose, .env files, CI.
    dotenv,
};

fn parseFormat(s: []const u8) ?Format {
    const eql = std.mem.eql;
    if (eql(u8, s, "shell") or eql(u8, s, "export")) return .shell;
    if (eql(u8, s, "dotenv") or eql(u8, s, "docker") or eql(u8, s, "env-file")) return .dotenv;
    return null;
}

/// `hush env [--env=<env>] [--format=shell|dotenv]`: print the env's secrets
/// for shell `eval` (default) or as `KEY=value` lines (for `docker --env-file`,
/// compose, .env, CI). The env defaults to $HUSH_ENV, then "dev".
fn envCommand(init: std.process.Init, rest: []const []const u8) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    var env_flag: ?[]const u8 = null;
    var format: Format = .shell;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const a = rest[i];
        if (std.mem.startsWith(u8, a, "--env=")) {
            env_flag = a["--env=".len..];
        } else if (std.mem.eql(u8, a, "--env")) {
            i += 1;
            if (i >= rest.len) {
                std.debug.print("hush: --env needs a value\n", .{});
                return 2;
            }
            env_flag = rest[i];
        } else if (std.mem.startsWith(u8, a, "--format=")) {
            format = parseFormat(a["--format=".len..]) orelse {
                std.debug.print("hush: unknown format '{s}' (use shell or dotenv)\n", .{a["--format=".len..]});
                return 2;
            };
        } else {
            std.debug.print("hush: unexpected argument '{s}'\n", .{a});
            return 2;
        }
    }

    const env_name = env_flag orelse init.environ_map.get("HUSH_ENV") orelse default_env;

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

    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    const out = &ow.interface;
    var f: usize = 0;
    while (f + 1 < resp.fields.items.len) : (f += 2) {
        const k = resp.fields.items[f];
        const v = resp.fields.items[f + 1];
        // Never emit a key that isn't a valid env var name — it would be shell
        // injection in `eval "$(hush env)"` and an invalid Docker env-file line.
        if (!hush.names.isEnvVarName(k)) {
            std.debug.print("hush: skipping invalid key name '{s}'\n", .{k});
            continue;
        }
        switch (format) {
            .shell => {
                try out.writeAll("export ");
                try out.writeAll(k);
                try out.writeAll("=");
                try writeShellQuoted(out, v);
                try out.writeAll("\n");
            },
            .dotenv => {
                // Docker --env-file takes the value literally and has no way to
                // represent a newline, so skip multi-line secrets rather than
                // emit a broken file.
                if (std.mem.indexOfScalar(u8, v, '\n') != null) {
                    std.debug.print("hush: skipping '{s}' (multi-line value unsupported in dotenv format)\n", .{k});
                    continue;
                }
                try out.writeAll(k);
                try out.writeAll("=");
                try out.writeAll(v);
                try out.writeAll("\n");
            },
        }
    }
    try out.flush();
    return 0;
}

/// Write `s` single-quoted and safe for POSIX shells: wrap in '...', and
/// render any embedded ' as '\''.
fn writeShellQuoted(out: *std.Io.Writer, s: []const u8) !void {
    try out.writeAll("'");
    var rest = s;
    while (std.mem.indexOfScalar(u8, rest, '\'')) |i| {
        try out.writeAll(rest[0..i]);
        try out.writeAll("'\\''");
        rest = rest[i + 1 ..];
    }
    try out.writeAll(rest);
    try out.writeAll("'");
}

/// `hush import <file.env> [--env=<env>]`: read a .env file and store each
/// KEY=value into the env (one connection, reused for every set).
fn importCommand(init: std.process.Init, rest: []const []const u8) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    var file_path: ?[]const u8 = null;
    var env_flag: ?[]const u8 = null;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const a = rest[i];
        if (std.mem.startsWith(u8, a, "--env=")) {
            env_flag = a["--env=".len..];
        } else if (std.mem.eql(u8, a, "--env")) {
            i += 1;
            if (i >= rest.len) {
                std.debug.print("hush: --env needs a value\n", .{});
                return 2;
            }
            env_flag = rest[i];
        } else if (std.mem.startsWith(u8, a, "-")) {
            std.debug.print("hush: unknown option '{s}'\n", .{a});
            return 2;
        } else if (file_path == null) {
            file_path = a;
        } else {
            std.debug.print("hush: too many arguments\n", .{});
            return 2;
        }
    }

    const path = file_path orelse {
        std.debug.print("usage: hush import <file.env> [--env=<env>]\n", .{});
        return 2;
    };
    const env_name = env_flag orelse init.environ_map.get("HUSH_ENV") orelse default_env;

    const content = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(16 << 20)) catch |err| {
        std.debug.print("hush: cannot read '{s}': {t}\n", .{ path, err });
        return 1;
    };
    defer freeSecret(gpa, content);

    var parsed = hush.dotenv.parse(gpa, content) catch {
        std.debug.print("hush: could not parse '{s}'\n", .{path});
        return 1;
    };
    defer parsed.deinit();

    if (parsed.entries.len == 0) {
        std.debug.print("hush: no entries found in '{s}'\n", .{path});
        return 0;
    }

    var stream = (try connectOrReport(io, gpa)) orelse return 1;
    defer stream.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var imported: usize = 0;
    var skipped: usize = 0;
    for (parsed.entries) |e| {
        if (!hush.names.isEnvVarName(e.key)) {
            std.debug.print("hush: skipping invalid key '{s}'\n", .{e.key});
            skipped += 1;
            continue;
        }
        const payload = hush.protocol.encodeRequest(gpa, .{ .set = .{ .env = env_name, .key = e.key, .value = e.value } }) catch {
            std.debug.print("hush: skipping '{s}' (too large)\n", .{e.key});
            skipped += 1;
            continue;
        };
        defer freeSecret(gpa, payload);
        try hush.transport.writeFrame(&sw.interface, payload);

        const resp_buf = try hush.transport.readFrame(&sr.interface, gpa);
        defer freeSecret(gpa, resp_buf);
        var resp = try hush.protocol.decodeResponse(gpa, resp_buf);
        defer resp.deinit(gpa);

        if (resp.status == .ok) {
            imported += 1;
        } else {
            const msg = if (resp.fields.items.len > 0) resp.fields.items[0] else "error";
            std.debug.print("hush: {s}: {s}\n", .{ e.key, msg });
            skipped += 1;
        }
    }

    if (skipped > 0) {
        std.debug.print("imported {d} secret(s) into '{s}' ({d} skipped)\n", .{ imported, env_name, skipped });
    } else {
        std.debug.print("imported {d} secret(s) into '{s}'\n", .{ imported, env_name });
    }
    return 0;
}

/// Zero a heap buffer that may contain secret material, then free it.
fn freeSecret(gpa: std.mem.Allocator, buf: []u8) void {
    hush.crypto.zero(buf);
    gpa.free(buf);
}

fn buildRequest(verb: []const u8, rest: []const []const u8) ?hush.protocol.Request {
    const eql = std.mem.eql;
    if (eql(u8, verb, "ping")) return .ping;
    if (eql(u8, verb, "set")) {
        if (rest.len < 3) return null;
        return .{ .set = .{ .env = rest[0], .key = rest[1], .value = rest[2] } };
    }
    if (eql(u8, verb, "get")) {
        if (rest.len < 2) return null;
        return .{ .get = .{ .env = rest[0], .key = rest[1] } };
    }
    if (eql(u8, verb, "del")) {
        if (rest.len < 2) return null;
        return .{ .del = .{ .env = rest[0], .key = rest[1] } };
    }
    if (eql(u8, verb, "ls")) {
        if (rest.len < 1) return null;
        return .{ .list = .{ .env = rest[0] } };
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

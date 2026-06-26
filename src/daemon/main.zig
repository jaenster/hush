//! hushd — the hush daemon. Listens on a unix domain socket (mode 0600),
//! serves the framed request/response protocol against an mlock'd, encrypted
//! secret store.

const std = @import("std");
const hush = @import("hush");
const key_provider = @import("key_provider.zig");
const providers = @import("providers.zig");

const log = std.log.scoped(.hushd);

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    var kind: key_provider.Kind = .keychain;
    var args = init.minimal.args.iterate();
    _ = args.skip(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--touch-id")) {
            kind = .touch_id;
        } else if (std.mem.eql(u8, arg, "--secure-enclave")) {
            kind = .secure_enclave;
        } else if (std.mem.eql(u8, arg, "--keychain")) {
            kind = .keychain;
        } else if (std.mem.eql(u8, arg, "--ephemeral")) {
            kind = .ephemeral;
        } else {
            log.err("unknown argument: {s}", .{arg});
            return 2;
        }
    }

    try hush.crypto.init();

    var paths = try hush.paths.Paths.init(gpa);
    defer paths.deinit();
    try paths.ensureDir(io);

    const key = key_provider.acquire(kind, io, gpa, paths.wrapped_key) catch |err| {
        log.err("could not acquire data key ({t})", .{err});
        if (kind == .secure_enclave)
            log.err("--secure-enclave needs a code-signed build with a keychain entitlement; use --touch-id for biometric gating on unsigned builds", .{});
        return 1;
    };
    var store = hush.store.Store.init(gpa, key);
    defer store.deinit();

    // Tolerate a missing/foreign/corrupt vault: start empty rather than crash.
    store.load(io, paths.vault) catch |err| switch (err) {
        error.FileNotFound => {},
        else => log.warn("ignoring existing vault ({t}); starting empty", .{err}),
    };

    // Clear any stale socket from a previous run, then bind fresh.
    std.Io.Dir.cwd().deleteFile(io, paths.socket) catch {};
    const addr = try std.Io.net.UnixAddress.init(paths.socket);
    var server = try addr.listen(io, .{});
    defer server.deinit(io);
    std.Io.Dir.cwd().setFilePermissions(io, paths.socket, std.Io.File.Permissions.fromMode(0o600), .{}) catch |err|
        log.warn("could not chmod socket to 0600: {t}", .{err});

    installSignalHandlers(paths.socket);

    log.info("listening on {s}", .{paths.socket});
    switch (kind) {
        .touch_id => log.info("data key: Keychain + Touch ID (user presence required, reboot-safe)", .{}),
        .secure_enclave => log.info("data key: Secure Enclave (Touch ID gated, reboot-safe)", .{}),
        .keychain => log.info("data key: macOS Keychain (device-bound, reboot-safe)", .{}),
        .ephemeral => log.warn("ephemeral key in use: secrets will NOT survive a restart", .{}),
    }

    while (true) {
        var stream = server.accept(io) catch |err| {
            log.warn("accept failed: {t}", .{err});
            continue;
        };
        defer stream.close(io);
        handleConn(io, gpa, &store, &paths, stream) catch |err| switch (err) {
            error.EndOfStream => {}, // client hung up
            else => log.warn("connection error: {t}", .{err}),
        };
    }
}

fn handleConn(
    io: std.Io,
    gpa: std.mem.Allocator,
    store: *hush.store.Store,
    paths: *const hush.paths.Paths,
    stream: std.Io.net.Stream,
) !void {
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    // Request/response buffers may hold secret values; wipe them on the way out.
    defer {
        hush.crypto.zero(&rbuf);
        hush.crypto.zero(&wbuf);
    }
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    const r = &sr.interface;
    const w = &sw.interface;

    while (true) {
        // Per-request scratch: small requests/responses are served entirely from
        // the stack; only oversized values (rare) spill to the heap. Persistent
        // store data still uses the daemon's gpa, not this.
        var sfa = std.heap.stackFallback(16 * 1024, gpa);
        const a = sfa.get();

        const payload = try hush.transport.readFrame(r, a);
        defer freeSecret(a, payload);

        const resp = try handleRequest(io, a, store, paths, payload);
        defer freeSecret(a, resp);

        try hush.transport.writeFrame(w, resp);
    }
}

/// Zero a heap buffer that may contain secret material, then free it.
fn freeSecret(gpa: std.mem.Allocator, buf: []u8) void {
    hush.crypto.zero(buf);
    gpa.free(buf);
}

fn errResp(gpa: std.mem.Allocator, e: anyerror) ![]u8 {
    return hush.protocol.encodeResponse(gpa, .err, &.{@errorName(e)});
}

/// Decode one request, apply it, and return the encoded response payload
/// (caller owns it).
fn handleRequest(
    io: std.Io,
    gpa: std.mem.Allocator,
    store: *hush.store.Store,
    paths: *const hush.paths.Paths,
    payload: []const u8,
) ![]u8 {
    const proto = hush.protocol;
    const req = proto.decodeRequest(payload) catch
        return proto.encodeResponse(gpa, .err, &.{"malformed request"});

    switch (req) {
        .ping => return proto.encodeResponse(gpa, .ok, &.{}),
        .set => |s| {
            if (!hush.names.isEnvVarName(s.key))
                return proto.encodeResponse(gpa, .err, &.{"invalid key name: must be a [A-Za-z_][A-Za-z0-9_]* env var name"});
            if (s.env.len == 0)
                return proto.encodeResponse(gpa, .err, &.{"env name must not be empty"});
            store.set(s.env, s.key, s.value) catch |e| return errResp(gpa, e);
            store.save(io, paths.vault) catch |e| return errResp(gpa, e);
            return proto.encodeResponse(gpa, .ok, &.{});
        },
        .get => |g| {
            const val = (try store.get(g.env, g.key)) orelse
                return proto.encodeResponse(gpa, .not_found, &.{});
            if (providers.isReference(val)) {
                const resolved = providers.resolve(gpa, io, val) catch |e| {
                    log.warn("could not resolve reference {s}: {t}", .{ val, e });
                    return proto.encodeResponse(gpa, .err, &.{"failed to resolve reference (is the provider CLI installed and authenticated?)"});
                };
                defer gpa.free(resolved);
                return proto.encodeResponse(gpa, .ok, &.{resolved});
            }
            return proto.encodeResponse(gpa, .ok, &.{val});
        },
        .del => |d| {
            const existed = store.del(d.env, d.key) catch |e| return errResp(gpa, e);
            store.save(io, paths.vault) catch |e| return errResp(gpa, e);
            return proto.encodeResponse(gpa, if (existed) .ok else .not_found, &.{});
        },
        .list => |l| {
            const names = try store.list(gpa, l.env);
            defer gpa.free(names);
            return proto.encodeResponse(gpa, .ok, names);
        },
        .dump => |d| {
            const pairs = try store.dump(gpa, d.env);
            defer gpa.free(pairs);

            // Flatten to alternating key, value fields, resolving any references.
            var fields: std.ArrayList([]const u8) = .empty;
            defer fields.deinit(gpa);
            var resolved_bufs: std.ArrayList([]u8) = .empty;
            defer {
                for (resolved_bufs.items) |b| gpa.free(b);
                resolved_bufs.deinit(gpa);
            }
            for (pairs) |p| {
                try fields.append(gpa, p.name);
                if (providers.isReference(p.value)) {
                    const resolved = providers.resolve(gpa, io, p.value) catch |e| {
                        log.warn("could not resolve reference {s}: {t}", .{ p.value, e });
                        return proto.encodeResponse(gpa, .err, &.{"failed to resolve a reference in this env (is the provider CLI installed and authenticated?)"});
                    };
                    try resolved_bufs.append(gpa, resolved);
                    try fields.append(gpa, resolved);
                } else {
                    try fields.append(gpa, p.value);
                }
            }
            return proto.encodeResponse(gpa, .ok, fields.items);
        },
    }
}

// --- graceful shutdown -------------------------------------------------------
//
// On SIGINT/SIGTERM, remove the socket file so we don't leave a dead socket
// behind. `unlink` and `_exit` are async-signal-safe; nothing else is done in
// the handler. mlock'd pages were never swapped, so exiting without an explicit
// wipe still keeps secrets off disk.

var g_socket_path: [std.Io.net.UnixAddress.max_len + 1]u8 = undefined;
var g_socket_path_len: usize = 0;

fn handleSignal(_: std.posix.SIG) callconv(.c) void {
    if (g_socket_path_len != 0) {
        g_socket_path[g_socket_path_len] = 0;
        _ = std.c.unlink(@ptrCast(&g_socket_path));
    }
    std.c._exit(0);
}

fn installSignalHandlers(socket: []const u8) void {
    if (socket.len < g_socket_path.len) {
        @memcpy(g_socket_path[0..socket.len], socket);
        g_socket_path_len = socket.len;
    }
    const act = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

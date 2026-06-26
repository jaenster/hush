//! hushd — the hush daemon. Listens on a unix domain socket (mode 0600),
//! serves the framed request/response protocol against an mlock'd, encrypted
//! secret store.

const std = @import("std");
const hush = @import("hush");
const key_provider = @import("key_provider.zig");

const log = std.log.scoped(.hushd);

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;

    try hush.crypto.init();

    var paths = try hush.paths.Paths.init(gpa);
    defer paths.deinit();
    try paths.ensureDir(io);

    const key = try key_provider.acquire(.ephemeral);
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

    log.info("listening on {s}", .{paths.socket});
    log.warn("ephemeral key in use: secrets will NOT survive a restart (key management pending)", .{});

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
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    const r = &sr.interface;
    const w = &sw.interface;

    while (true) {
        const payload = try hush.transport.readFrame(r, gpa);
        defer gpa.free(payload);

        const resp = try handleRequest(io, gpa, store, paths, payload);
        defer gpa.free(resp);

        try hush.transport.writeFrame(w, resp);
    }
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
            try store.set(s.env, s.key, s.value);
            try store.save(io, paths.vault);
            return proto.encodeResponse(gpa, .ok, &.{});
        },
        .get => |g| {
            if (try store.get(g.env, g.key)) |val|
                return proto.encodeResponse(gpa, .ok, &.{val});
            return proto.encodeResponse(gpa, .not_found, &.{});
        },
        .del => |d| {
            const existed = try store.del(d.env, d.key);
            try store.save(io, paths.vault);
            return proto.encodeResponse(gpa, if (existed) .ok else .not_found, &.{});
        },
        .list => |l| {
            const names = try store.list(gpa, l.env);
            defer gpa.free(names);
            return proto.encodeResponse(gpa, .ok, names);
        },
    }
}

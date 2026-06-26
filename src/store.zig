//! In-memory secret store with encrypted file persistence.
//!
//! Secrets are organized as (env, name) -> value. Values live in mlock'd
//! buffers so they are never swapped to disk, and are zeroed on removal and on
//! deinit. The whole set is persisted as a single XChaCha20-Poly1305-encrypted
//! blob; the data key is supplied by the caller (see daemon KeyProvider) and is
//! itself never written to disk by this module.

const std = @import("std");
const crypto = @import("crypto.zig");

const magic = "HUSH2\n"; // current on-disk format
const magic_v1 = "HUSH1\n"; // pre-includes; still readable

pub const Store = struct {
    allocator: std.mem.Allocator,
    key: crypto.Key,
    entries: std.StringHashMapUnmanaged(Entry) = .{},
    /// env -> ordered list of include directives. Not secret (references, not
    /// values); expanded into many vars at dump time by the daemon.
    includes: std.StringHashMapUnmanaged(IncludeList) = .{},

    const IncludeList = std.ArrayListUnmanaged(Include);

    /// One include directive. `mode` is an opaque string ("dotenv"/"json"/
    /// "enumerate") interpreted by the daemon's provider layer — the store
    /// stays agnostic. All three slices are owned.
    pub const Include = struct {
        ref: []u8,
        mode: []u8,
        prefix: []u8,
    };

    const Entry = struct {
        /// "env\x00name", owned, used as the map key. Not secret.
        id: []u8,
        env_len: usize,
        /// mlock'd, zeroed on removal.
        value: []u8,

        fn env(self: Entry) []const u8 {
            return self.id[0..self.env_len];
        }
        fn name(self: Entry) []const u8 {
            return self.id[self.env_len + 1 ..];
        }
    };

    pub fn init(allocator: std.mem.Allocator, key: crypto.Key) Store {
        return .{ .allocator = allocator, .key = key };
    }

    pub fn deinit(self: *Store) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| self.freeEntry(kv.value_ptr.*);
        self.entries.deinit(self.allocator);

        var iit = self.includes.iterator();
        while (iit.next()) |kv| {
            for (kv.value_ptr.items) |inc| self.freeInclude(inc);
            kv.value_ptr.deinit(self.allocator);
            self.allocator.free(kv.key_ptr.*);
        }
        self.includes.deinit(self.allocator);

        crypto.zero(&self.key);
        self.* = undefined;
    }

    fn freeInclude(self: *Store, inc: Include) void {
        self.allocator.free(inc.ref);
        self.allocator.free(inc.mode);
        self.allocator.free(inc.prefix);
    }

    fn freeEntry(self: *Store, e: Entry) void {
        crypto.zero(e.value);
        crypto.munlock(e.value); // also zeroes
        self.allocator.free(e.value);
        self.allocator.free(e.id);
    }

    fn makeId(allocator: std.mem.Allocator, env: []const u8, name: []const u8) ![]u8 {
        const id = try allocator.alloc(u8, env.len + 1 + name.len);
        @memcpy(id[0..env.len], env);
        id[env.len] = 0;
        @memcpy(id[env.len + 1 ..], name);
        return id;
    }

    fn lockedDup(self: *Store, value: []const u8) ![]u8 {
        const buf = try self.allocator.alloc(u8, value.len);
        errdefer self.allocator.free(buf);
        crypto.mlock(buf) catch {}; // best-effort; mlock can fail under rlimit
        @memcpy(buf, value);
        return buf;
    }

    /// Insert or overwrite a secret. Old value (if any) is zeroed.
    pub fn set(self: *Store, env: []const u8, name: []const u8, value: []const u8) !void {
        const id = try makeId(self.allocator, env, name);
        errdefer self.allocator.free(id);

        const gop = try self.entries.getOrPut(self.allocator, id);
        if (gop.found_existing) {
            self.allocator.free(id); // already have the key
            const old = gop.value_ptr.value;
            crypto.zero(old);
            crypto.munlock(old);
            self.allocator.free(old);
            gop.value_ptr.value = try self.lockedDup(value);
        } else {
            const buf = try self.lockedDup(value);
            gop.key_ptr.* = id;
            gop.value_ptr.* = .{ .id = id, .env_len = env.len, .value = buf };
        }
    }

    /// Borrowed slice valid until the entry is modified/removed.
    pub fn get(self: *Store, env: []const u8, name: []const u8) !?[]const u8 {
        const id_buf = try makeId(self.allocator, env, name);
        defer self.allocator.free(id_buf);
        const e = self.entries.get(id_buf) orelse return null;
        return e.value;
    }

    pub fn del(self: *Store, env: []const u8, name: []const u8) !bool {
        const id_buf = try makeId(self.allocator, env, name);
        defer self.allocator.free(id_buf);
        const kv = self.entries.fetchRemove(id_buf) orelse return false;
        self.freeEntry(kv.value);
        return true;
    }

    /// Names within `env`. Caller owns the returned slice (but not the strings,
    /// which borrow from the store).
    pub fn list(self: *Store, allocator: std.mem.Allocator, env: []const u8) ![][]const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        errdefer out.deinit(allocator);
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            if (std.mem.eql(u8, e.env(), env)) try out.append(allocator, e.name());
        }
        return out.toOwnedSlice(allocator);
    }

    pub const Pair = struct { name: []const u8, value: []const u8 };

    /// All (name, value) pairs within `env`. Caller owns the slice; the strings
    /// borrow from the store.
    pub fn dump(self: *Store, allocator: std.mem.Allocator, env: []const u8) ![]Pair {
        var out: std.ArrayList(Pair) = .empty;
        errdefer out.deinit(allocator);
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            if (std.mem.eql(u8, e.env(), env)) try out.append(allocator, .{ .name = e.name(), .value = e.value });
        }
        return out.toOwnedSlice(allocator);
    }

    // --- includes ------------------------------------------------------------

    /// Add (or update, if `ref` already present) an include directive for `env`.
    pub fn addInclude(self: *Store, env: []const u8, ref: []const u8, mode: []const u8, prefix: []const u8) !void {
        const gop = try self.includes.getOrPut(self.allocator, env);
        if (!gop.found_existing) {
            errdefer _ = self.includes.remove(env);
            gop.key_ptr.* = try self.allocator.dupe(u8, env);
            gop.value_ptr.* = .empty;
        }
        const inc_list = gop.value_ptr;

        const new_ref = try self.allocator.dupe(u8, ref);
        errdefer self.allocator.free(new_ref);
        const new_mode = try self.allocator.dupe(u8, mode);
        errdefer self.allocator.free(new_mode);
        const new_prefix = try self.allocator.dupe(u8, prefix);
        errdefer self.allocator.free(new_prefix);

        for (inc_list.items) |*inc| {
            if (std.mem.eql(u8, inc.ref, ref)) {
                // Same reference: replace mode/prefix in place, keep order.
                self.allocator.free(inc.mode);
                self.allocator.free(inc.prefix);
                self.allocator.free(new_ref);
                inc.mode = new_mode;
                inc.prefix = new_prefix;
                return;
            }
        }
        try inc_list.append(self.allocator, .{ .ref = new_ref, .mode = new_mode, .prefix = new_prefix });
    }

    /// Remove the include with the given `ref` from `env`. Returns whether one
    /// was removed.
    pub fn delInclude(self: *Store, env: []const u8, ref: []const u8) bool {
        const inc_list = self.includes.getPtr(env) orelse return false;
        for (inc_list.items, 0..) |inc, i| {
            if (std.mem.eql(u8, inc.ref, ref)) {
                self.freeInclude(inc);
                _ = inc_list.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Include directives for `env`, in order. Caller owns the slice; the
    /// Include fields borrow from the store.
    pub fn listIncludes(self: *Store, allocator: std.mem.Allocator, env: []const u8) ![]Include {
        const inc_list = self.includes.getPtr(env) orelse return allocator.alloc(Include, 0);
        return allocator.dupe(Include, inc_list.items);
    }

    // --- persistence ---------------------------------------------------------

    /// Serialize+encrypt the whole store and write atomically to `path`.
    pub fn save(self: *Store, io: std.Io, path: []const u8) !void {
        var plain: std.ArrayList(u8) = .empty;
        defer {
            crypto.zero(plain.items);
            plain.deinit(self.allocator);
        }
        try plain.appendSlice(self.allocator, magic);
        try appendU32(&plain, self.allocator, @intCast(self.entries.count()));
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            try appendLenPrefixed(&plain, self.allocator, e.env());
            try appendLenPrefixed(&plain, self.allocator, e.name());
            try appendLenPrefixed(&plain, self.allocator, e.value);
        }

        // Includes section (per env, in order).
        var inc_total: u32 = 0;
        var iit = self.includes.iterator();
        while (iit.next()) |kv| inc_total += @intCast(kv.value_ptr.items.len);
        try appendU32(&plain, self.allocator, inc_total);
        iit = self.includes.iterator();
        while (iit.next()) |kv| {
            const env = kv.key_ptr.*;
            for (kv.value_ptr.items) |inc| {
                try appendLenPrefixed(&plain, self.allocator, env);
                try appendLenPrefixed(&plain, self.allocator, inc.ref);
                try appendLenPrefixed(&plain, self.allocator, inc.mode);
                try appendLenPrefixed(&plain, self.allocator, inc.prefix);
            }
        }

        const blob = try crypto.seal(self.allocator, self.key, plain.items);
        defer self.allocator.free(blob);

        try writeAtomic(io, path, blob);
    }

    /// Load and decrypt from `path`, replacing current contents. A missing file
    /// is treated as an empty store.
    pub fn load(self: *Store, io: std.Io, path: []const u8) !void {
        const blob = std.Io.Dir.cwd().readFileAlloc(io, path, self.allocator, .unlimited) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer self.allocator.free(blob);

        const plain = try crypto.open(self.allocator, self.key, blob);
        defer {
            crypto.zero(plain);
            self.allocator.free(plain);
        }

        const has_includes = std.mem.startsWith(u8, plain, magic);
        if (!has_includes and !std.mem.startsWith(u8, plain, magic_v1)) return error.BadVaultFormat;
        var cur = Reader{ .buf = plain, .pos = magic.len }; // both magics are the same length
        const count = try cur.u32v();
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const env = try cur.field();
            const name = try cur.field();
            const value = try cur.field();
            try self.set(env, name, value);
        }

        if (!has_includes) return; // HUSH1: no includes section
        const inc_count = try cur.u32v();
        var j: u32 = 0;
        while (j < inc_count) : (j += 1) {
            const env = try cur.field();
            const ref = try cur.field();
            const mode = try cur.field();
            const prefix = try cur.field();
            try self.addInclude(env, ref, mode, prefix);
        }
    }
};

const max_vault_bytes = 64 * 1024 * 1024;

fn appendU32(list: *std.ArrayList(u8), a: std.mem.Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try list.appendSlice(a, &b);
}

fn appendLenPrefixed(list: *std.ArrayList(u8), a: std.mem.Allocator, s: []const u8) !void {
    try appendU32(list, a, @intCast(s.len));
    try list.appendSlice(a, s);
}

const Reader = struct {
    buf: []const u8,
    pos: usize,

    fn u32v(self: *Reader) !u32 {
        if (self.pos + 4 > self.buf.len) return error.BadVaultFormat;
        const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .little);
        self.pos += 4;
        return v;
    }
    fn field(self: *Reader) ![]const u8 {
        const len = try self.u32v();
        if (self.pos + len > self.buf.len) return error.BadVaultFormat;
        const s = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return s;
    }
};

/// Write `data` to `path` via an unnamed temp file + atomic rename, 0600 perms.
fn writeAtomic(io: std.Io, path: []const u8, data: []const u8) !void {
    var atomic = try std.Io.Dir.cwd().createFileAtomic(io, path, .{
        .permissions = std.Io.File.Permissions.fromMode(0o600),
        .replace = true,
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, data);
    try atomic.replace(io);
}

// --- tests -------------------------------------------------------------------

test "set/get/del/list" {
    try crypto.init();
    const a = std.testing.allocator;
    var s = Store.init(a, crypto.randomKey());
    defer s.deinit();

    try s.set("dev", "API_KEY", "abc123");
    try s.set("dev", "DB_URL", "postgres://x");
    try s.set("prod", "API_KEY", "zzz");

    try std.testing.expectEqualStrings("abc123", (try s.get("dev", "API_KEY")).?);
    try std.testing.expect((try s.get("dev", "MISSING")) == null);

    // overwrite
    try s.set("dev", "API_KEY", "newval");
    try std.testing.expectEqualStrings("newval", (try s.get("dev", "API_KEY")).?);

    const names = try s.list(a, "dev");
    defer a.free(names);
    try std.testing.expectEqual(@as(usize, 2), names.len);

    try std.testing.expect(try s.del("dev", "API_KEY"));
    try std.testing.expect(!try s.del("dev", "API_KEY"));
    try std.testing.expect((try s.get("dev", "API_KEY")) == null);
}

test "save/load roundtrip" {
    try crypto.init();
    const a = std.testing.allocator;
    const io = std.testing.io;
    const key = crypto.randomKey();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(path);
    const vault = try std.fmt.allocPrint(a, "{s}/vault.bin", .{path});
    defer a.free(vault);

    {
        var s = Store.init(a, key);
        defer s.deinit();
        try s.set("dev", "FOO", "bar");
        try s.set("prod", "SECRET", "value-with-\x00-nul-and-binary\xff");
        try s.save(io, vault);
    }
    {
        var s = Store.init(a, key);
        defer s.deinit();
        try s.load(io, vault);
        try std.testing.expectEqualStrings("bar", (try s.get("dev", "FOO")).?);
        try std.testing.expectEqualStrings("value-with-\x00-nul-and-binary\xff", (try s.get("prod", "SECRET")).?);
    }
}

test "load with wrong key fails" {
    try crypto.init();
    const a = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(path);
    const vault = try std.fmt.allocPrint(a, "{s}/vault.bin", .{path});
    defer a.free(vault);

    {
        var s = Store.init(a, crypto.randomKey());
        defer s.deinit();
        try s.set("dev", "FOO", "bar");
        try s.save(io, vault);
    }
    {
        var s = Store.init(a, crypto.randomKey()); // different key
        defer s.deinit();
        try std.testing.expectError(crypto.Error.Decrypt, s.load(io, vault));
    }
}

test "includes add/update/del/list" {
    try crypto.init();
    const a = std.testing.allocator;
    var s = Store.init(a, crypto.randomKey());
    defer s.deinit();

    try s.addInclude("dev", "op://Private/dev-env", "dotenv", "");
    try s.addInclude("dev", "aws://prod/app", "json", "APP_");
    // same ref again updates in place (no duplicate)
    try s.addInclude("dev", "op://Private/dev-env", "dotenv", "X_");

    const incs = try s.listIncludes(a, "dev");
    defer a.free(incs);
    try std.testing.expectEqual(@as(usize, 2), incs.len);
    try std.testing.expectEqualStrings("op://Private/dev-env", incs[0].ref);
    try std.testing.expectEqualStrings("X_", incs[0].prefix); // updated
    try std.testing.expectEqualStrings("json", incs[1].mode);

    try std.testing.expect(s.delInclude("dev", "op://Private/dev-env"));
    try std.testing.expect(!s.delInclude("dev", "op://Private/dev-env"));
    const incs2 = try s.listIncludes(a, "dev");
    defer a.free(incs2);
    try std.testing.expectEqual(@as(usize, 1), incs2.len);
}

test "save/load roundtrips includes" {
    try crypto.init();
    const a = std.testing.allocator;
    const io = std.testing.io;
    const key = crypto.randomKey();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(path);
    const vault = try std.fmt.allocPrint(a, "{s}/vault.bin", .{path});
    defer a.free(vault);

    {
        var s = Store.init(a, key);
        defer s.deinit();
        try s.set("dev", "FOO", "bar");
        try s.addInclude("dev", "op://Private/dev-env", "dotenv", "");
        try s.addInclude("dev", "ovault://Work", "enumerate", "WORK_");
        try s.save(io, vault);
    }
    {
        var s = Store.init(a, key);
        defer s.deinit();
        try s.load(io, vault);
        try std.testing.expectEqualStrings("bar", (try s.get("dev", "FOO")).?);
        const incs = try s.listIncludes(a, "dev");
        defer a.free(incs);
        try std.testing.expectEqual(@as(usize, 2), incs.len);
        try std.testing.expectEqualStrings("ovault://Work", incs[1].ref);
        try std.testing.expectEqualStrings("WORK_", incs[1].prefix);
    }
}

test "load missing file is empty" {
    try crypto.init();
    const a = std.testing.allocator;
    const io = std.testing.io;
    var s = Store.init(a, crypto.randomKey());
    defer s.deinit();
    try s.load(io, "/nonexistent/hush/vault.bin");
    const names = try s.list(a, "dev");
    defer a.free(names);
    try std.testing.expectEqual(@as(usize, 0), names.len);
}

//! libsodium-backed crypto primitives for hush.
//!
//! Authenticated encryption uses XChaCha20-Poly1305 (IETF): 32-byte key,
//! 24-byte random nonce, 16-byte tag. We never hand-roll crypto; this is a
//! thin, typed wrapper over libsodium.

const std = @import("std");

const c = @cImport({
    @cInclude("sodium.h");
});

pub const key_len = 32; // crypto_aead_xchacha20poly1305_ietf_KEYBYTES
pub const nonce_len = 24; // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
pub const tag_len = 16; // crypto_aead_xchacha20poly1305_ietf_ABYTES

pub const Key = [key_len]u8;
pub const Nonce = [nonce_len]u8;

pub const Error = error{
    SodiumInit,
    Decrypt,
    Mlock,
};

var init_done: bool = false;

/// Must be called once before any other crypto operation. Idempotent.
pub fn init() Error!void {
    if (init_done) return;
    // sodium_init returns 0 on success, 1 if already initialized, -1 on failure.
    if (c.sodium_init() < 0) return Error.SodiumInit;
    init_done = true;
}

/// Fill `buf` with cryptographically secure random bytes.
pub fn randomBytes(buf: []u8) void {
    c.randombytes_buf(buf.ptr, buf.len);
}

pub fn randomKey() Key {
    var k: Key = undefined;
    randomBytes(&k);
    return k;
}

/// Encrypt `plaintext` under `key`. Output layout: nonce(24) || ciphertext || tag(16).
/// Caller owns the returned slice.
pub fn seal(allocator: std.mem.Allocator, key: Key, plaintext: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, nonce_len + plaintext.len + tag_len);
    errdefer allocator.free(out);

    const nonce = out[0..nonce_len];
    randomBytes(nonce);

    var clen: c_ulonglong = 0;
    _ = c.crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.ptr + nonce_len,
        &clen,
        plaintext.ptr,
        plaintext.len,
        null, // no additional data
        0,
        null, // nsec, unused
        nonce.ptr,
        &key,
    );
    std.debug.assert(nonce_len + clen == out.len);
    return out;
}

/// Decrypt a blob produced by `seal`. Caller owns the returned slice.
pub fn open(allocator: std.mem.Allocator, key: Key, blob: []const u8) ![]u8 {
    if (blob.len < nonce_len + tag_len) return Error.Decrypt;
    const nonce = blob[0..nonce_len];
    const ct = blob[nonce_len..];

    const out = try allocator.alloc(u8, ct.len - tag_len);
    errdefer allocator.free(out);

    var mlen: c_ulonglong = 0;
    const rc = c.crypto_aead_xchacha20poly1305_ietf_decrypt(
        out.ptr,
        &mlen,
        null, // nsec, unused
        ct.ptr,
        ct.len,
        null,
        0,
        nonce.ptr,
        &key,
    );
    if (rc != 0) return Error.Decrypt;
    std.debug.assert(mlen == out.len);
    return out;
}

/// Pin `buf` into RAM so it is never swapped to disk. libsodium also marks it
/// non-dumpable. Pair with `munlock` (which zeroes before unlocking).
pub fn mlock(buf: []u8) Error!void {
    if (c.sodium_mlock(buf.ptr, buf.len) != 0) return Error.Mlock;
}

pub fn munlock(buf: []u8) void {
    _ = c.sodium_munlock(buf.ptr, buf.len);
}

/// Securely zero memory; not optimized away by the compiler.
pub fn zero(buf: []u8) void {
    c.sodium_memzero(buf.ptr, buf.len);
}

test "seal/open roundtrip" {
    try init();
    const a = std.testing.allocator;
    const key = randomKey();
    const msg = "super secret value";

    const blob = try seal(a, key, msg);
    defer a.free(blob);
    try std.testing.expect(blob.len == nonce_len + msg.len + tag_len);

    const plain = try open(a, key, blob);
    defer a.free(plain);
    try std.testing.expectEqualStrings(msg, plain);
}

test "open rejects tampered ciphertext" {
    try init();
    const a = std.testing.allocator;
    const key = randomKey();

    const blob = try seal(a, key, "hello");
    defer a.free(blob);
    blob[blob.len - 1] ^= 0xff; // flip a tag bit

    try std.testing.expectError(Error.Decrypt, open(a, key, blob));
}

test "open rejects wrong key" {
    try init();
    const a = std.testing.allocator;
    const blob = try seal(a, randomKey(), "hello");
    defer a.free(blob);
    try std.testing.expectError(Error.Decrypt, open(a, randomKey(), blob));
}

//! Touch-ID-gated vault data key via the Secure Enclave.
//!
//! A non-extractable EC key is created in the Secure Enclave, its private-key
//! usage gated by `kSecAccessControlUserPresence` (Touch ID, passcode fallback).
//! The 32-byte data key is wrapped (ECIES) with the SEP public key and the
//! resulting blob is stored on disk — safe at rest, since only the SEP private
//! key can unwrap it, and that requires user presence.
//!
//! Wrapping (setup) does not prompt; unwrapping (every restart) does.

const std = @import("std");
const crypto = @import("hush").crypto;
const cf = @import("cf.zig");

const log = std.log.scoped(.enclave);

/// Identifies our SEP key within the keychain.
const key_tag = "info.stoots.hush.datakey-sep";

pub const Error = error{ EnclaveFailed, MissingEnclaveKey, AuthFailed };

fn logErr(comptime what: []const u8, err: cf.TypeRef) void {
    if (err) |e| {
        log.err(what ++ " failed: CFError {d}", .{cf.CFErrorGetCode(e)});
        cf.CFRelease(e);
    } else {
        log.err(what ++ " failed", .{});
    }
}

/// Find our existing SEP private key, or null. Caller releases the ref.
fn findKey() !?cf.TypeRef {
    const tag = try cf.cfData(key_tag);
    defer cf.CFRelease(tag);

    const keys = [_]cf.TypeRef{ cf.kSecClass, cf.kSecAttrApplicationTag, cf.kSecAttrKeyType, cf.kSecReturnRef, cf.kSecMatchLimit };
    const vals = [_]cf.TypeRef{ cf.kSecClassKey, tag, cf.kSecAttrKeyTypeECSECPrimeRandom, cf.kCFBooleanTrue, cf.kSecMatchLimitOne };
    const query = try cf.makeDict(&keys, &vals);
    defer cf.CFRelease(query);

    var result: cf.TypeRef = null;
    const status = cf.SecItemCopyMatching(query, &result);
    if (status == cf.errSecItemNotFound) return null;
    if (status != cf.errSecSuccess) {
        log.err("SecItemCopyMatching(key) failed: OSStatus {d}", .{status});
        return Error.EnclaveFailed;
    }
    return result;
}

/// Create a new permanent SEP private key gated by user presence. Caller
/// releases the ref.
fn createKey() !cf.TypeRef {
    var ac_err: cf.TypeRef = null;
    const access = cf.SecAccessControlCreateWithFlags(
        null,
        cf.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        cf.ac_private_key_usage | cf.ac_user_presence,
        &ac_err,
    ) orelse {
        logErr("SecAccessControlCreateWithFlags", ac_err);
        return Error.EnclaveFailed;
    };
    defer cf.CFRelease(access);

    const tag = try cf.cfData(key_tag);
    defer cf.CFRelease(tag);
    const bits = try cf.cfNumberInt(256);
    defer cf.CFRelease(bits);

    const priv_keys = [_]cf.TypeRef{ cf.kSecAttrIsPermanent, cf.kSecAttrApplicationTag, cf.kSecAttrAccessControl };
    const priv_vals = [_]cf.TypeRef{ cf.kCFBooleanTrue, tag, access };
    const priv_attrs = try cf.makeDict(&priv_keys, &priv_vals);
    defer cf.CFRelease(priv_attrs);

    const keys = [_]cf.TypeRef{ cf.kSecAttrKeyType, cf.kSecAttrKeySizeInBits, cf.kSecAttrTokenID, cf.kSecPrivateKeyAttrs };
    const vals = [_]cf.TypeRef{ cf.kSecAttrKeyTypeECSECPrimeRandom, bits, cf.kSecAttrTokenIDSecureEnclave, priv_attrs };
    const params = try cf.makeDict(&keys, &vals);
    defer cf.CFRelease(params);

    var err: cf.TypeRef = null;
    const key = cf.SecKeyCreateRandomKey(params, &err) orelse {
        logErr("SecKeyCreateRandomKey", err);
        return Error.EnclaveFailed;
    };
    return key;
}

/// ECIES (cofactor, X9.63 KDF, AES-GCM) — the standard SEP wrapping algorithm.
inline fn algorithm() cf.KeyAlgorithm {
    return cf.kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
}

/// Wrap the data key with the SEP public key. Returns an owned ciphertext blob.
fn wrap(allocator: std.mem.Allocator, priv: cf.TypeRef, data_key: crypto.Key) ![]u8 {
    const pub_key = cf.SecKeyCopyPublicKey(priv) orelse return Error.EnclaveFailed;
    defer cf.CFRelease(pub_key);

    var plain = data_key;
    const ptext = try cf.cfData(&plain);
    defer cf.CFRelease(ptext);
    crypto.zero(&plain);

    var err: cf.TypeRef = null;
    const blob = cf.SecKeyCreateEncryptedData(pub_key, algorithm(), ptext, &err) orelse {
        logErr("SecKeyCreateEncryptedData", err);
        return Error.EnclaveFailed;
    };
    defer cf.CFRelease(blob);

    return cf.dataBytes(allocator, blob);
}

/// Unwrap the data key. Triggers a Touch ID prompt (user presence on the SEP key).
fn unwrap(priv: cf.TypeRef, blob: []const u8) !crypto.Key {
    const ctext = try cf.cfData(blob);
    defer cf.CFRelease(ctext);

    var err: cf.TypeRef = null;
    const plain = cf.SecKeyCreateDecryptedData(priv, algorithm(), ctext, &err) orelse {
        logErr("SecKeyCreateDecryptedData (Touch ID)", err);
        return Error.AuthFailed;
    };
    defer cf.CFRelease(plain);

    if (cf.CFDataGetLength(plain) != crypto.key_len) return Error.EnclaveFailed;
    var key: crypto.Key = undefined;
    @memcpy(&key, cf.CFDataGetBytePtr(plain)[0..crypto.key_len]);
    return key;
}

/// Return the data key: unwrap the existing one (prompts Touch ID), or on first
/// run generate a key, wrap it, and persist the blob (no prompt).
pub fn loadOrCreate(io: std.Io, allocator: std.mem.Allocator, wrapped_path: []const u8) !crypto.Key {
    const existing = std.Io.Dir.cwd().readFileAlloc(io, wrapped_path, allocator, .unlimited) catch |e| switch (e) {
        error.FileNotFound => null,
        else => return e,
    };

    if (existing) |blob| {
        defer allocator.free(blob);
        const priv = (try findKey()) orelse {
            log.err("wrapped key blob exists but the Secure Enclave key is gone", .{});
            return Error.MissingEnclaveKey;
        };
        defer cf.CFRelease(priv);
        log.info("unlocking vault — approve with Touch ID", .{});
        return unwrap(priv, blob);
    }

    // First-time setup.
    const priv = (try findKey()) orelse try createKey();
    defer cf.CFRelease(priv);

    const key = crypto.randomKey();
    const blob = try wrap(allocator, priv, key);
    defer allocator.free(blob);

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = wrapped_path,
        .data = blob,
        .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o600) },
    });
    log.info("provisioned Secure Enclave key; vault is now Touch ID gated", .{});
    return key;
}

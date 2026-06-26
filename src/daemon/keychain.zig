//! macOS Keychain storage for the vault data key.
//!
//! The 32-byte data key is kept as a generic-password item in the login
//! keychain. Two protection levels:
//!
//!   - `.device_only` : accessible whenever the device is unlocked
//!     (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). No prompt.
//!   - `.touch_id`    : guarded by a `kSecAccessControlUserPresence` access
//!     control, so every read requires Touch ID (passcode fallback). The
//!     biometric is enforced by the keychain daemon — unlike Secure Enclave key
//!     creation (`enclave.zig`), this needs no code-signing entitlement.
//!
//! In both cases the key is device-bound, never synced, and never written to
//! disk in plaintext by us.

const std = @import("std");
const crypto = @import("hush").crypto;
const cf = @import("cf.zig");

const log = std.log.scoped(.keychain);

const service = "hush";

pub const Protection = enum { device_only, touch_id };

pub const Error = error{ KeychainUnexpected, Duplicate };

/// Distinct items per protection level so the two never collide.
fn account(protection: Protection) [*:0]const u8 {
    return switch (protection) {
        .device_only => "vault-data-key",
        .touch_id => "vault-data-key-touchid",
    };
}

/// Read the stored data key into `out`. Returns false if no item exists. For a
/// `.touch_id` item this triggers the Touch ID prompt.
pub fn load(out: *crypto.Key, protection: Protection) !bool {
    const svc = try cf.cfString(service);
    defer cf.CFRelease(svc);
    const acct = try cf.cfString(account(protection));
    defer cf.CFRelease(acct);

    const keys = [_]cf.TypeRef{ cf.kSecClass, cf.kSecAttrService, cf.kSecAttrAccount, cf.kSecReturnData, cf.kSecMatchLimit };
    const vals = [_]cf.TypeRef{ cf.kSecClassGenericPassword, svc, acct, cf.kCFBooleanTrue, cf.kSecMatchLimitOne };
    const query = try cf.makeDict(&keys, &vals);
    defer cf.CFRelease(query);

    var result: cf.TypeRef = null;
    const status = cf.SecItemCopyMatching(query, &result);
    if (status == cf.errSecItemNotFound) return false;
    if (status != cf.errSecSuccess) {
        log.err("SecItemCopyMatching failed: OSStatus {d}", .{status});
        return Error.KeychainUnexpected;
    }
    defer cf.CFRelease(result);

    if (cf.CFDataGetLength(result) != crypto.key_len) return Error.KeychainUnexpected;
    @memcpy(out, cf.CFDataGetBytePtr(result)[0..crypto.key_len]);
    return true;
}

/// Store `key` as a new keychain item. Fails with `Duplicate` if one exists.
pub fn store(key: crypto.Key, protection: Protection) !void {
    const svc = try cf.cfString(service);
    defer cf.CFRelease(svc);
    const acct = try cf.cfString(account(protection));
    defer cf.CFRelease(acct);
    const data = try cf.cfData(&key);
    defer cf.CFRelease(data);

    // The 5th attribute selects the protection: a plain accessibility constant,
    // or a user-presence access control (Touch ID).
    var access: cf.TypeRef = null;
    defer if (access) |a| cf.CFRelease(a);
    var guard_key: cf.TypeRef = undefined;
    var guard_val: cf.TypeRef = undefined;
    switch (protection) {
        .device_only => {
            guard_key = cf.kSecAttrAccessible;
            guard_val = cf.kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
        },
        .touch_id => {
            var ac_err: cf.TypeRef = null;
            access = cf.SecAccessControlCreateWithFlags(
                null,
                cf.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                cf.ac_user_presence,
                &ac_err,
            ) orelse {
                if (ac_err) |e| {
                    log.err("SecAccessControlCreateWithFlags failed: CFError {d}", .{cf.CFErrorGetCode(e)});
                    cf.CFRelease(e);
                }
                return Error.KeychainUnexpected;
            };
            guard_key = cf.kSecAttrAccessControl;
            guard_val = access;
        },
    }

    const keys = [_]cf.TypeRef{ cf.kSecClass, cf.kSecAttrService, cf.kSecAttrAccount, cf.kSecValueData, guard_key };
    const vals = [_]cf.TypeRef{ cf.kSecClassGenericPassword, svc, acct, data, guard_val };
    const attrs = try cf.makeDict(&keys, &vals);
    defer cf.CFRelease(attrs);

    const status = cf.SecItemAdd(attrs, null);
    if (status == cf.errSecDuplicateItem) return Error.Duplicate;
    if (status != cf.errSecSuccess) {
        log.err("SecItemAdd failed: OSStatus {d}", .{status});
        return Error.KeychainUnexpected;
    }
}

/// Return the existing data key, or generate, store, and return a new one.
/// First-time creation never prompts; subsequent reads of a `.touch_id` item do.
pub fn loadOrCreate(protection: Protection) !crypto.Key {
    var k: crypto.Key = undefined;
    if (try load(&k, protection)) return k;

    k = crypto.randomKey();
    store(k, protection) catch |err| switch (err) {
        // Lost a race with another instance; the other one's key wins.
        Error.Duplicate => {
            if (try load(&k, protection)) return k;
            return err;
        },
        else => return err,
    };
    return k;
}

//! macOS Keychain storage for the vault data key.
//!
//! The 32-byte data key that encrypts the vault is kept as a generic-password
//! item in the login keychain, accessible only when the device is unlocked and
//! never synced off-device (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
//! This makes the key reboot-stable without ever writing it to disk in
//! plaintext ourselves.
//!
//! Manual bindings to CoreFoundation + Security (linked as frameworks) — we
//! declare only the handful of symbols we use rather than translate-c the
//! framework headers. The next milestone wraps this key with a Secure Enclave
//! key gated by Touch ID; this is the same API family.

const std = @import("std");
const crypto = @import("hush").crypto;

const log = std.log.scoped(.keychain);

const service = "hush";
const account = "vault-data-key";

pub const Error = error{ KeychainUnexpected, Duplicate };

// --- CoreFoundation / Security FFI -------------------------------------------

const CFTypeRef = ?*anyopaque;
const CFAllocatorRef = ?*anyopaque;
const CFIndex = c_long;
const OSStatus = i32;

const kCFStringEncodingUTF8: u32 = 0x08000100;

const errSecSuccess: OSStatus = 0;
const errSecItemNotFound: OSStatus = -25300;
const errSecDuplicateItem: OSStatus = -25299;

// Callback-table structs: we never read their fields, but the type needs the
// right size so `&kCFType...CallBacks` points at the framework's real global.
const CFDictionaryKeyCallBacks = extern struct {
    version: CFIndex,
    retain: ?*const anyopaque,
    release: ?*const anyopaque,
    copyDescription: ?*const anyopaque,
    equal: ?*const anyopaque,
    hash: ?*const anyopaque,
};
const CFDictionaryValueCallBacks = extern struct {
    version: CFIndex,
    retain: ?*const anyopaque,
    release: ?*const anyopaque,
    copyDescription: ?*const anyopaque,
    equal: ?*const anyopaque,
};

extern const kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
extern const kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
extern const kCFBooleanTrue: CFTypeRef;

extern const kSecClass: CFTypeRef;
extern const kSecClassGenericPassword: CFTypeRef;
extern const kSecAttrService: CFTypeRef;
extern const kSecAttrAccount: CFTypeRef;
extern const kSecValueData: CFTypeRef;
extern const kSecReturnData: CFTypeRef;
extern const kSecMatchLimit: CFTypeRef;
extern const kSecMatchLimitOne: CFTypeRef;
extern const kSecAttrAccessible: CFTypeRef;
extern const kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFTypeRef;

extern fn CFRelease(cf: CFTypeRef) void;
extern fn CFStringCreateWithCString(alloc: CFAllocatorRef, c_str: [*:0]const u8, encoding: u32) CFTypeRef;
extern fn CFDataCreate(alloc: CFAllocatorRef, bytes: [*]const u8, length: CFIndex) CFTypeRef;
extern fn CFDataGetLength(data: CFTypeRef) CFIndex;
extern fn CFDataGetBytePtr(data: CFTypeRef) [*]const u8;
extern fn CFDictionaryCreate(
    alloc: CFAllocatorRef,
    keys: [*]const CFTypeRef,
    values: [*]const CFTypeRef,
    num_values: CFIndex,
    key_cb: *const CFDictionaryKeyCallBacks,
    value_cb: *const CFDictionaryValueCallBacks,
) CFTypeRef;

extern fn SecItemAdd(attributes: CFTypeRef, result: ?*CFTypeRef) OSStatus;
extern fn SecItemCopyMatching(query: CFTypeRef, result: ?*CFTypeRef) OSStatus;

// --- helpers -----------------------------------------------------------------

fn cfString(s: [*:0]const u8) !CFTypeRef {
    return CFStringCreateWithCString(null, s, kCFStringEncodingUTF8) orelse Error.KeychainUnexpected;
}

fn makeDict(keys: []const CFTypeRef, values: []const CFTypeRef) !CFTypeRef {
    std.debug.assert(keys.len == values.len);
    return CFDictionaryCreate(
        null,
        keys.ptr,
        values.ptr,
        @intCast(keys.len),
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks,
    ) orelse Error.KeychainUnexpected;
}

// --- public API --------------------------------------------------------------

/// Read the stored data key into `out`. Returns false if no item exists.
pub fn load(out: *crypto.Key) !bool {
    const svc = try cfString(service);
    defer CFRelease(svc);
    const acct = try cfString(account);
    defer CFRelease(acct);

    const keys = [_]CFTypeRef{ kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit };
    const vals = [_]CFTypeRef{ kSecClassGenericPassword, svc, acct, kCFBooleanTrue, kSecMatchLimitOne };
    const query = try makeDict(&keys, &vals);
    defer CFRelease(query);

    var result: CFTypeRef = null;
    const status = SecItemCopyMatching(query, &result);
    if (status == errSecItemNotFound) return false;
    if (status != errSecSuccess) {
        log.err("SecItemCopyMatching failed: OSStatus {d}", .{status});
        return Error.KeychainUnexpected;
    }
    defer CFRelease(result);

    if (CFDataGetLength(result) != crypto.key_len) return Error.KeychainUnexpected;
    @memcpy(out, CFDataGetBytePtr(result)[0..crypto.key_len]);
    return true;
}

/// Store `key` as a new keychain item. Fails with `Duplicate` if one exists.
pub fn store(key: crypto.Key) !void {
    const svc = try cfString(service);
    defer CFRelease(svc);
    const acct = try cfString(account);
    defer CFRelease(acct);
    const data = CFDataCreate(null, &key, crypto.key_len) orelse return Error.KeychainUnexpected;
    defer CFRelease(data);

    const keys = [_]CFTypeRef{ kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData, kSecAttrAccessible };
    const vals = [_]CFTypeRef{ kSecClassGenericPassword, svc, acct, data, kSecAttrAccessibleWhenUnlockedThisDeviceOnly };
    const attrs = try makeDict(&keys, &vals);
    defer CFRelease(attrs);

    const status = SecItemAdd(attrs, null);
    if (status == errSecDuplicateItem) return Error.Duplicate;
    if (status != errSecSuccess) {
        log.err("SecItemAdd failed: OSStatus {d}", .{status});
        return Error.KeychainUnexpected;
    }
}

/// Return the existing data key, or generate, store, and return a new one.
pub fn loadOrCreate() !crypto.Key {
    var k: crypto.Key = undefined;
    if (try load(&k)) return k;

    k = crypto.randomKey();
    store(k) catch |err| switch (err) {
        // Lost a race with another instance; the other one's key wins.
        Error.Duplicate => {
            if (try load(&k)) return k;
            return err;
        },
        else => return err,
    };
    return k;
}

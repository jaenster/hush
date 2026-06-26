//! Shared CoreFoundation + Security framework FFI for the daemon.
//!
//! We declare only the symbols we use rather than translate-c the framework
//! headers. CoreFoundation and Security are linked as frameworks (see build.zig).

const std = @import("std");

pub const TypeRef = ?*anyopaque;
pub const AllocatorRef = ?*anyopaque;
pub const Index = c_long;
pub const OptionFlags = c_ulong;
pub const OSStatus = i32;
pub const KeyAlgorithm = TypeRef;

pub const string_encoding_utf8: u32 = 0x08000100;
pub const number_int_type: c_int = 9; // kCFNumberIntType

pub const errSecSuccess: OSStatus = 0;
pub const errSecItemNotFound: OSStatus = -25300;
pub const errSecDuplicateItem: OSStatus = -25299;

// SecAccessControlCreateFlags
pub const ac_user_presence: OptionFlags = 1 << 0;
pub const ac_private_key_usage: OptionFlags = 1 << 30;

// Callback-table structs: never read, but need the right size so
// `&kCFType...CallBacks` points at the framework's real global.
const DictKeyCallBacks = extern struct {
    version: Index,
    retain: ?*const anyopaque,
    release: ?*const anyopaque,
    copyDescription: ?*const anyopaque,
    equal: ?*const anyopaque,
    hash: ?*const anyopaque,
};
const DictValueCallBacks = extern struct {
    version: Index,
    retain: ?*const anyopaque,
    release: ?*const anyopaque,
    copyDescription: ?*const anyopaque,
    equal: ?*const anyopaque,
};

extern const kCFTypeDictionaryKeyCallBacks: DictKeyCallBacks;
extern const kCFTypeDictionaryValueCallBacks: DictValueCallBacks;
pub extern const kCFBooleanTrue: TypeRef;

pub extern const kSecClass: TypeRef;
pub extern const kSecClassGenericPassword: TypeRef;
pub extern const kSecClassKey: TypeRef;
pub extern const kSecAttrService: TypeRef;
pub extern const kSecAttrAccount: TypeRef;
pub extern const kSecValueData: TypeRef;
pub extern const kSecReturnData: TypeRef;
pub extern const kSecReturnRef: TypeRef;
pub extern const kSecMatchLimit: TypeRef;
pub extern const kSecMatchLimitOne: TypeRef;
pub extern const kSecAttrAccessible: TypeRef;
pub extern const kSecAttrAccessibleWhenUnlockedThisDeviceOnly: TypeRef;

pub extern const kSecAttrKeyType: TypeRef;
pub extern const kSecAttrKeyTypeECSECPrimeRandom: TypeRef;
pub extern const kSecAttrKeySizeInBits: TypeRef;
pub extern const kSecAttrTokenID: TypeRef;
pub extern const kSecAttrTokenIDSecureEnclave: TypeRef;
pub extern const kSecPrivateKeyAttrs: TypeRef;
pub extern const kSecAttrIsPermanent: TypeRef;
pub extern const kSecAttrApplicationTag: TypeRef;
pub extern const kSecAttrAccessControl: TypeRef;

pub extern const kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM: TypeRef;

pub extern fn CFRelease(cf: TypeRef) void;
pub extern fn CFStringCreateWithCString(alloc: AllocatorRef, c_str: [*:0]const u8, encoding: u32) TypeRef;
pub extern fn CFDataCreate(alloc: AllocatorRef, bytes: [*]const u8, length: Index) TypeRef;
pub extern fn CFDataGetLength(data: TypeRef) Index;
pub extern fn CFDataGetBytePtr(data: TypeRef) [*]const u8;
pub extern fn CFNumberCreate(alloc: AllocatorRef, the_type: c_int, value_ptr: *const anyopaque) TypeRef;
pub extern fn CFErrorGetCode(err: TypeRef) Index;
pub extern fn CFDictionaryCreate(
    alloc: AllocatorRef,
    keys: [*]const TypeRef,
    values: [*]const TypeRef,
    num_values: Index,
    key_cb: *const DictKeyCallBacks,
    value_cb: *const DictValueCallBacks,
) TypeRef;

pub extern fn SecItemAdd(attributes: TypeRef, result: ?*TypeRef) OSStatus;
pub extern fn SecItemCopyMatching(query: TypeRef, result: ?*TypeRef) OSStatus;
pub extern fn SecAccessControlCreateWithFlags(alloc: AllocatorRef, protection: TypeRef, flags: OptionFlags, err: ?*TypeRef) TypeRef;
pub extern fn SecKeyCreateRandomKey(parameters: TypeRef, err: ?*TypeRef) TypeRef;
pub extern fn SecKeyCopyPublicKey(key: TypeRef) TypeRef;
pub extern fn SecKeyCreateEncryptedData(key: TypeRef, algorithm: KeyAlgorithm, plaintext: TypeRef, err: ?*TypeRef) TypeRef;
pub extern fn SecKeyCreateDecryptedData(key: TypeRef, algorithm: KeyAlgorithm, ciphertext: TypeRef, err: ?*TypeRef) TypeRef;

pub const Error = error{CoreFoundation};

pub fn cfString(s: [*:0]const u8) !TypeRef {
    return CFStringCreateWithCString(null, s, string_encoding_utf8) orelse Error.CoreFoundation;
}

pub fn cfData(bytes: []const u8) !TypeRef {
    return CFDataCreate(null, bytes.ptr, @intCast(bytes.len)) orelse Error.CoreFoundation;
}

pub fn cfNumberInt(value: c_int) !TypeRef {
    return CFNumberCreate(null, number_int_type, &value) orelse Error.CoreFoundation;
}

pub fn makeDict(keys: []const TypeRef, values: []const TypeRef) !TypeRef {
    std.debug.assert(keys.len == values.len);
    return CFDictionaryCreate(
        null,
        keys.ptr,
        values.ptr,
        @intCast(keys.len),
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks,
    ) orelse Error.CoreFoundation;
}

/// Copy the bytes of a CFData into an owned slice.
pub fn dataBytes(allocator: std.mem.Allocator, data: TypeRef) ![]u8 {
    const len: usize = @intCast(CFDataGetLength(data));
    const out = try allocator.alloc(u8, len);
    @memcpy(out, CFDataGetBytePtr(data)[0..len]);
    return out;
}

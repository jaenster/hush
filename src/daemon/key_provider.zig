//! Acquisition of the 32-byte data key that encrypts the vault.
//!
//!   - `.touch_id`       : data key in a biometric (`UserPresence`) Keychain
//!                         item — Touch ID required on every unlock. Works on
//!                         unsigned/ad-hoc builds.
//!   - `.secure_enclave` : data key wrapped by a Secure Enclave key gated by
//!                         Touch ID. Strongest, but SEP key creation requires a
//!                         code-signed build with a keychain entitlement.
//!   - `.keychain`       : data key in the login Keychain, device-bound, no
//!                         biometric. Reboot-safe. The default.
//!   - `.ephemeral`      : fresh random key each start (survives nothing).

const std = @import("std");
const hush = @import("hush");
const keychain = @import("keychain.zig");
const enclave = @import("enclave.zig");

pub const Kind = enum { touch_id, secure_enclave, keychain, ephemeral };

pub fn acquire(
    kind: Kind,
    io: std.Io,
    gpa: std.mem.Allocator,
    wrapped_key_path: []const u8,
) !hush.crypto.Key {
    return switch (kind) {
        .touch_id => keychain.loadOrCreate(.touch_id),
        .secure_enclave => enclave.loadOrCreate(io, gpa, wrapped_key_path),
        .keychain => keychain.loadOrCreate(.device_only),
        .ephemeral => hush.crypto.randomKey(),
    };
}

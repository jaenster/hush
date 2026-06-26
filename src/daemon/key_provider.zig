//! Acquisition of the 32-byte data key that encrypts the vault.
//!
//! This is the seam where Secure Enclave / Touch ID gating plugs in (the next
//! milestone). The contract: return a key that is stable across daemon restarts
//! and reboots, but never persisted in plaintext.
//!
//!   - `.keychain`  : key stored in the login Keychain, device-bound. Reboot-
//!                    safe; this is the default.
//!   - `.ephemeral` : a fresh random key every start (secrets do NOT survive a
//!                    restart). Useful for tests and throwaway runs.

const std = @import("std");
const hush = @import("hush");
const keychain = @import("keychain.zig");

pub const Kind = enum { keychain, ephemeral };

pub fn acquire(kind: Kind) !hush.crypto.Key {
    return switch (kind) {
        .keychain => keychain.loadOrCreate(),
        .ephemeral => hush.crypto.randomKey(),
    };
}

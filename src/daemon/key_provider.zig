//! Acquisition of the 32-byte data key that encrypts the vault.
//!
//! This is the seam where Secure Enclave / Keychain key-wrapping plugs in (the
//! next milestone). The contract: return a key that is stable across daemon
//! restarts and reboots, but never persisted in plaintext.
//!
//! `.ephemeral` is a development placeholder: a fresh random key every start,
//! so secrets do NOT survive a restart. It exists so the socket/store/protocol
//! pipeline can be exercised end-to-end before key management lands.

const std = @import("std");
const hush = @import("hush");

pub const Kind = enum { ephemeral };

pub fn acquire(kind: Kind) !hush.crypto.Key {
    return switch (kind) {
        .ephemeral => hush.crypto.randomKey(),
    };
}

# Key providers (the data key)

The vault is encrypted with a 32-byte **data key**. How that key is stored and
unlocked is chosen at daemon start:

```
hushd [--keychain | --touch-id | --secure-enclave | --ephemeral]
```

| flag | storage | Touch ID | reboot-safe | signed build |
|-|-|-|-|-|
| `--keychain` *(default)* | login Keychain item, device-bound | no | yes | no |
| `--touch-id` | Keychain item with a UserPresence access control | every unlock | yes | **yes** |
| `--secure-enclave` | data key ECIES-wrapped by a Secure Enclave key | every unlock | yes | **yes** |
| `--ephemeral` | random key in memory | — | no | no |

The provider is the seam in `src/daemon/key_provider.zig`.

## `--keychain` (default)

A random data key is stored as a login-Keychain generic password
(`service=hush`). It is released whenever the device is unlocked. No biometric
prompt. Works on unsigned/dev builds.

> Rebuilding `hushd` changes its code signature, so the Keychain ACL no longer
> recognizes it and macOS shows a one-time "hushd wants to use a key" prompt on
> the next read — click **Always Allow**. A stable signed build avoids this.

## `--touch-id` and `--secure-enclave`

Both gate the data key behind biometric approval (`kSecAccessControlUserPresence`,
passcode fallback):

- `--touch-id` keeps the data key in the data-protection keychain behind a
  biometric access control.
- `--secure-enclave` keeps only a wrapped blob on disk (`datakey.sep`); the
  unwrapping key is a non-extractable Secure Enclave key. Strongest option.

### Enabling them (code signing)

macOS rejects the data-protection keychain and Secure Enclave from binaries
without a keychain entitlement bound to a real Apple Developer Team ID — an
unsigned build gets `errSecMissingEntitlement` (-34018).

1. Put your Team ID in `hush.entitlements` (replace `TEAMID`).
2. Sign the binary:
   ```sh
   scripts/sign.sh "Apple Development: you@example.com (XXXXXXXXXX)"
   ```
3. Run `hushd --touch-id` (or `--secure-enclave`).

## `--ephemeral`

A fresh random key every start — secrets do not survive a restart. Useful for
tests and throwaway runs.

# Architecture

```
hush (CLI)  ──unix socket 0600──►  hushd (daemon)
                                     ├─ mlock'd in-memory store
                                     ├─ vault.bin  (XChaCha20-Poly1305 ciphertext)
                                     ├─ data key   (Keychain / Secure Enclave)
                                     └─ providers  (op / ksm) for op:// keeper:// refs
```

Everything lives under `~/Library/Application Support/hush/` (mode `0700`):
`hushd.sock`, `vault.bin`, and `datakey.sep` (only for `--secure-enclave`).

## Source layout (`src/`)

Core library (`hush` module), shared by both binaries:

| file | role |
|-|-|
| `crypto.zig` | XChaCha20-Poly1305 seal/open, `mlock` + secure-zero (libsodium) |
| `protocol.zig` | pure encode/decode of the wire messages |
| `transport.zig` | length-prefixed framing over the socket |
| `store.zig` | `mlock`'d map + atomic encrypted-file persistence |
| `names.zig` | env-var-name validation for keys |
| `paths.zig` | filesystem locations |

Daemon (`src/daemon/`):

| file | role |
|-|-|
| `main.zig` | accept loop, request dispatch, signal handling |
| `key_provider.zig` | the data-key seam (keychain / touch-id / secure-enclave / ephemeral) |
| `keychain.zig` | Keychain storage (plain + biometric) |
| `enclave.zig` | Secure Enclave key wrap/unwrap |
| `cf.zig` | CoreFoundation + Security framework FFI |
| `providers.zig` | `op://` / `keeper://` reference resolution |

CLI (`src/cli/main.zig`): argument dispatch, the `run` wrapper, `env` output.

## Request flow

1. CLI connects to the socket and writes one framed request (`transport`).
2. `hushd` accepts, reads the frame, decodes it (`protocol`).
3. The handler runs against the `store`; `get`/`dump` resolve any provider
   references (`providers`).
4. `hushd` encodes and writes the framed response; the CLI reads and acts on it.

## Memory & performance

- Idle daemon: blocked on `accept()` → 0% CPU, ~6 MB RSS, 2 threads.
- Per request: served from a 16 KB stack buffer (`std.heap.stackFallback`),
  spilling to the heap only for oversized values. Persistent store data uses the
  daemon's general allocator. Secrets are `mlock`'d and zeroed.
- libsodium is statically linked; binaries depend only on `libSystem`.

## Persistence format (`vault.bin`)

Plaintext-before-encryption layout, then sealed as `nonce || ciphertext || tag`:

```
"HUSH1\n" | u32 count | (env, name, value)*        # each field: u32 len | bytes
```

A missing file is an empty store; a file that fails to decrypt (wrong key /
corruption) is tolerated — the daemon logs a warning and starts empty.

## Known limitations

- Sequential accept: one connection at a time; a stalled client wedges others.
- No provider resolution cache yet (each read spawns the provider CLI).
- Touch ID providers require a code-signed build.

# Wire protocol

The protocol is intentionally tiny so an SDK in any language is a few dozen
lines. Transport is a unix domain socket (mode `0600`) at
`~/Library/Application Support/hush/hushd.sock`.

## Framing

Every message is a length-prefixed frame. All integers are little-endian.

```
frame             = u32 len | payload          (len = byte length of payload)
request payload   = u8 op   | field*
response payload  = u8 status | field*
field             = u32 len | bytes
```

Maximum frame size is 1 MiB.

## Ops (request)

| op | value | fields |
|-|-|-|
| ping | 0 | — |
| set  | 1 | env, key, value |
| get  | 2 | env, key |
| del  | 3 | env, key |
| list | 4 | env |
| dump | 5 | env |

`key` must be a valid env var name (`[A-Za-z_][A-Za-z0-9_]*`); the daemon
rejects anything else on `set`.

## Status (response)

| status | value | meaning |
|-|-|-|
| ok | 0 | success; fields depend on the op |
| err | 1 | failure; field 0 is a human-readable message |
| not_found | 2 | get/del of a missing key |

Response fields by op:

- `get` → ok with one field (the value, with any provider reference resolved)
- `list` → ok with one field per key name
- `dump` → ok with alternating `key, value, key, value, …` (references resolved)
- `set` / `del` / `ping` → ok with no fields

## Example: `get dev FOO`

Request payload: `02 | (03000000 "dev") | (03000000 "FOO")`
Frame: `0e000000` + that payload.

Response (value "bar"): `00 | (03000000 "bar")`, framed with `08000000`.

## Reference client (Python)

```python
import socket, struct

def field(b): return struct.pack('<I', len(b)) + b

def call(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(f"{__import__('os').path.expanduser('~')}/Library/Application Support/hush/hushd.sock")
    s.sendall(struct.pack('<I', len(payload)) + payload)
    n = struct.unpack('<I', s.recv(4))[0]
    body = b''
    while len(body) < n: body += s.recv(n - len(body))
    s.close()
    return body[0], body[1:]   # status, rest

def get(env, key):
    status, rest = call(bytes([2]) + field(env.encode()) + field(key.encode()))
    # parse one field
    ln = struct.unpack('<I', rest[:4])[0]
    return rest[4:4+ln].decode()

print(get("dev", "FOO"))
```

The same shape (open socket, write `len+op+fields`, read `len+status+fields`)
ports directly to Go, Rust, Node, etc.

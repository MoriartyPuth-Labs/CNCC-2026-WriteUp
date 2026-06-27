# Challenge 5 — nevergonna (PyInstaller Unpack → XOR-chain cipher)

> [← Back to index](../../README.md) · **Category:** Reversing · **Flag:** `MPTC{n3v3r_g0nn4_g1v3_y0u_up}`

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

## Files
- [`solve.py`](solve.py) — standalone inverter (verified ✅)

**Flag:** `MPTC{n3v3r_g0nn4_g1v3_y0u_up}`

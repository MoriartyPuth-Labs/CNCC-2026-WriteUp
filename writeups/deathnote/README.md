# DeathNote — Reverse Engineering Writeup

> **Challenge 6 — "A notebook falls out of the sky"**
>
> *"A notebook falls out of the sky: write a name and that person is yours. Write the right name and it gives up what it's been guarding. Write the wrong one and... nothing."*
>
> **File:** `DeathNote` (ELF64, statically linked, stripped Go binary, obfuscated with [garble](https://github.com/burrowers/garble))

**Flag:** `MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}`

> ⚠️ There is a **decoy flag** (`MPTC{d34th_n0t3_wr0ng_p4g3_uwu}`) deliberately planted behind the "obvious" success branch. See [The Trap](#the-trap).

### File verification

| | |
|---|---|
| **Filename** | `dn` (a.k.a. `DeathNote`) |
| **Size** | `2781310` bytes |
| **SHA-256** | `d5972c753866f91d7c3c39c423e4718e744cdb486e3ec32cb2f8e80623ee399b` |
| **MD5** | `fb5d13e7cc5107e5f5beab61efd01cb1` |
| **Source** | `https://drive.google.com/file/d/1jgm34xqid0NHbzN67YA-Gz0OUqZU_JJE/view` |

```bash
curl -L "https://drive.google.com/uc?export=download&id=1jgm34xqid0NHbzN67YA-Gz0OUqZU_JJE" -o dn
sha256sum dn   # d5972c753866f91d7c3c39c423e4718e744cdb486e3ec32cb2f8e80623ee399b
chmod +x dn
```

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Tooling](#tooling)
3. [Initial Triage](#1-initial-triage)
4. [Behavioural Analysis](#2-behavioural-analysis)
5. [Finding `main.main`](#3-finding-mainmain-defeating-garbles-pclntab-scrambling)
6. [The Decryption Pipeline](#4-the-decryption-pipeline-lcg-keystreams)
7. [The Keyed Transform](#5-the-keyed-transform-0x568300)
8. [The Trap](#the-trap)
9. [The Real Path (Block B)](#6-the-real-path-block-b)
10. [Inverting the Transform](#7-inverting-the-transform)
11. [Full Solver (PoC)](#8-full-solver-poc)
12. [Reproduction Steps](#9-reproduction-steps)
13. [Confirming on the Binary](#10-confirming-on-the-binary)
14. [Appendix: Captured Data](#appendix-captured-data)

---

## TL;DR

The binary reads a 30-character "name" and decides whether to print a flag. Because it is **garble-obfuscated** there is:

- no plaintext string comparison (strings are encrypted, only `crypto/subtle` is linked),
- no standard crypto (no SHA/AES/ChaCha constants present),
- a scrambled `gopclntab` so symbol recovery is defeated.

The name is fed through a **custom 6-round invertible transform** (S-box substitution → cumulative-sum diffusion → rotation → XOR round-key) and the result is compared against an embedded target.

There are **two** comparison targets:

| | Decoy | Real |
|---|---|---|
| Branch | `cl != 0` → `0x569735` | `cl == 0` → `0x569825` (Block B) |
| Selector | matches target #1 | matches target #2, gated by env check `0x531420` |
| Success text | *"the page stirs. a different name was already written here:"* | *"the shinigami smiles. the name was written true."* |
| Flag | `MPTC{d34th_n0t3_wr0ng_p4g3_uwu}` ⚠️ decoy | `MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}` ✅ |

Because the transform is fully invertible, we recover the **correct name directly by inverting target #2** — and that name *is* the flag.

---

## Tooling

| Tool | Purpose |
|------|---------|
| **WSL2 (Ubuntu)** | Linux environment to run/debug the ELF on Windows |
| **GDB** + **Python API** | Dynamic analysis: syscall catchpoints, RBP-chain stack walking, breakpoints, memory dumps, register-forcing |
| **Python 3** | Modelling the LCG keystream + transform, and inverting it |
| `objdump`, `strings`, `file` | Static triage (sections, build info, constant scans) |
| `curl` | Fetching the binary |

> No symbols, no decompiler required — everything was done with GDB + a Python model. radare2/Ghidra would also work but the `gopclntab` is scrambled so auto-analysis of Go internals is limited.

---

## 1. Initial Triage

```console
$ file dn
dn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped

$ strings -a dn | grep -aoE 'crypto/(aes|cipher|sha256|sha512|hmac|subtle|md5)' | sort -u
crypto/subtle
```

Key observations:

- **Go binary** — obfuscated type/package names like `bkhy4k93c.P03SB0O_` are garble's signature.
- **Only `crypto/subtle`** is linked — i.e. comparison is `subtle.ConstantTimeCompare`, *not* `==`. That explains the absence of a plaintext compare.
- **No crypto constants** — scanning for SHA-256 IV (`0x6a09e667`), AES S-box (`63 7c 77 7b`), ChaCha (`expand 32-byte k`) all returned nothing. So whatever cipher is used is **custom**.

```python
# constant scan
data = open("dn","rb").read()
for name,b in [("sha256_h0", b"\x67\xe6\x09\x6a"),
               ("aes_sbox",  b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5"),
               ("chacha",    b"expand 32-byte k")]:
    print(name, data.count(b))   # all 0
```

Section layout (from `objdump -h`):

```
.text       0x0016e6b1  vaddr 0x00401000   foff 0x001000
.rodata     0x00048e22  vaddr 0x00570000   foff 0x170000
.gopclntab  0x000d4f0b  vaddr 0x005b8e28   foff 0x1b8e28
.noptrdata  0x00009642  vaddr 0x0068f320   foff 0x28f320
.data       0x0000dbf2  vaddr 0x00698980   foff 0x298980
```

---

## 2. Behavioural Analysis

```console
$ printf 'L\n' | ./dn

  +-----------------------------------------------+
  |   D E A T H   N O T E                         |
  |   The human whose name is written here        |
  |   shall... reveal the flag.                   |
  +-----------------------------------------------+

  write a name in the note >
  ...nothing happens. that name means nothing here.
```

A wrong name yields `...nothing happens`. We need to reach the success branch.

---

## 3. Finding `main.main` (defeating garble's pclntab scrambling)

Parsing `.gopclntab` directly **fails** — garble tampers with it:

```
magic 0xd11edd36   # NOT a valid Go magic (0xfffffff1 expected)
textStart 0x0      # bogus
```

Symbol recovery is dead. Instead we anchor on **runtime behaviour**. Go keeps **frame pointers (RBP)** on amd64, so the stack can be walked reliably even when stripped.

GDB Python: catch the `read(0, …)` syscall for the name, then walk the RBP chain:

```python
# rbp.py — walk frame pointers at the name read
import gdb, struct
gdb.execute("catch syscall read"); gdb.execute("run < inp > o 2>&1")
inf = gdb.selected_inferior()
# advance to the stdin read …
rbp = int(gdb.parse_and_eval("$rbp"))
for _ in range(20):
    saved = struct.unpack("<Q", inf.read_memory(rbp, 8).tobytes())[0]
    ret   = struct.unpack("<Q", inf.read_memory(rbp+8, 8).tobytes())[0]
    print("FRAME ret=", hex(ret))
    if saved <= rbp: break
    rbp = saved
```

Output (cleaned):

```
0x5313e6   write internals
0x5480cf   read helper
0x4b71b2   bufio.Read
0x4b7329   bufio
0x4b75c5   bufio.fill
0x4b78bf   bufio.ReadString
0x569018  ← return into main.main (after ReadString)
0x443635   runtime.main
0x4728e1   runtime.goexit
```

`0x569018` is the call site in **`main.main`** (`≈ 0x568e80 – 0x56a1e0`). Now we can disassemble the real logic.

---

## 4. The Decryption Pipeline (LCG keystreams)

Right after reading + trimming the name, `main.main` decrypts several embedded blobs. Each blob is XORed with a keystream produced by the classic **ANSI-C / glibc `rand()` LCG**:

```
state = (state * 0x41c64e6d + 0x3039) & 0xffffffff   # 1103515245, 12345
keystream_byte[i] = (state_after_(i+1)_steps >> 8) & 0xff
plaintext[i] = ciphertext[i] ^ keystream_byte[i]
```

Disassembly of one decrypt loop (Block A, blob #1):

```asm
0x5690c8:  mov  $0x94fadb66, %r9d        ; LCG seed
0x5690d0:  imul $0x41c64e6d, %r9d, %r9d  ; state *= 1103515245
0x5690d7:  add  $0x3039, %r9d            ; state += 12345
0x5690de:  mov  %r9d, %r12d
0x5690e1:  shr  $0x8, %r12d              ; >> 8
0x5690e5:  mov  %r12b, (%rdi,%r8,1)      ; keystream[i]
```

Block A decrypts four blobs:

| Blob | Global (ptr/len) | Length | LCG seed | Role |
|------|------------------|--------|----------|------|
| 1 | `0x6a6c20 / 0x6a6c28` | 256 | `0x94fadb66` | **S-box** (a 0–255 permutation) |
| 2 | `0x6a6c40 / 0x6a6c48` | 180 | `0xa7c9e855` | **XOR round keys** (6 × 30) |
| 3 | `0x699390 / 0x699398` | 6 | `0xb6d8f944` | **rotation amounts** `[28,10,21,7,5,17]` |
| 4 | `0x6a6c60 / 0x6a6c68` | 30 | `0xc1af8e33` | **target #1** (decoy) |

That blob #1 decrypts to a clean permutation of `0..255` told us immediately this is an **RC4-style substitution cipher**, not a stream of garbage.

---

## 5. The Keyed Transform (`0x568300`)

`main.main` checks `len(name) == 30`, then calls `0x568300` to transform the name and compares the 30-byte result against the target. The transform runs **6 rounds**; each round:

```
for ro in 0..5:
    1. SUBSTITUTE   w[i] = sbox[w[i]]                  # for all i
    2. FWD CUMSUM   w[i] = (w[i] + w[i-1]) & 0xff       # i = 1..29
    3. BWD CUMSUM   w[i] = (w[i] + w[i+1]) & 0xff       # i = 28..0
    4. ROTATE LEFT  w     = [ w[(i+rots[ro]) % 30] ]    # left-rotate
    5. XOR KEY      w[i] = w[i] ^ keys[ro*30 + i]
```

Every step is invertible:

```asm
; step 1 substitution
0x5683ac: movzbl (%rcx,%rdx,1), %r9d      ; w[i]
0x56839b: movzbl (%rsi,%r9,1),  %r9d      ; sbox[w[i]]
; step 2 forward add
0x5683c2: movzbl (%rcx,%rdx,1), %r9d
0x5683c7: movzbl -0x1(%rcx,%rdx,1), %r10d
0x5683cd: add    %r10d, %r9d              ; w[i] += w[i-1]
; step 3 backward add (symmetric, i = 28..0)
; step 4 left-rotate by rots[ro]  (new[i] = w[(i+rot) % 30])
; step 5 XOR with keys[ro*30 .. ]
```

Success requires `transform(name) == target`.

---

## The Trap

The branch that selects the outcome:

```asm
0x56972d:  test %cl, %cl
0x56972f:  je   0x569825      ; cl == 0  -> Block B (REAL)
;          fall-through       ; cl != 0  -> 0x569735 (DECOY)
```

`cl` is the result of `transform(name) == target#1`.

**Naively forcing `cl=1`** (the obvious "make it succeed" patch) lands at `0x569735`, which prints:

```
...the page stirs. a different name was already written here:
MPTC{d34th_n0t3_wr0ng_p4g3_uwu}
```

This flag is **hardcoded** (LCG seed `0x60d40ffc`), independent of the name, and the wording ("a *different* name", "wr0ng_p4g3") is the author taunting anyone who patches the branch. Inverting target #1 even yields a plausible-looking name — `L1ght_Y4g4m1_th3_0n3_tru3_k1ra` — that genuinely reaches this branch. **It is still the decoy.**

> Lesson: don't trust the first reachable flag in a CTF RE binary. The decoy text was the tell.

---

## 6. The Real Path (Block B)

`0x569825` is **not** "nothing happens" — it re-runs the *same* transform against a **second** target with a **second** set of tables, then prints the genuine success message (which echoes the entered name via `call 0x459d60`):

```asm
0x569dea:  mov  0x70(%rsp), %rdx     ; len(name)
0x569def:  cmp  $0x1e, %rdx          ; == 30 ?
0x569e2c:  call 0x568300             ; transform(name) with Block-B tables
0x569e36:  cmp  %rdx, %rbx
0x569feb:  ...                       ; bytes.Equal(transform, target#2)
0x569e51:  test %al, %al
0x569e53:  je   0x569f45             ; mismatch -> "nothing happens"
0x569e59:  ...                       ; MATCH    -> real success + flag
```

Real success message: **"...the shinigami smiles. the name was written true."**

### The environment gate

Block B's tables are decrypted with a keystream seed selected by an environment check:

```asm
0x569840:  call   0x531420                 ; returns rcx (env / platform index)
0x569864:  test   %rcx, %rcx
0x56986d:  mov    $0x5a5a5a5a, %r11d
0x569873:  cmovne %r11d, %r10d             ; cond = (rcx != 0) ? 0x5a5a5a5a : 0
0x5698ca:  xor    $0xd3a3bf24, %r10d       ; seed = cond ^ const_per_blob
```

`0x531420` wraps `runtime` calls (looks like a GOOS/platform switch). On the **intended** environment `cond = 0`; on our WSL host it returned non-zero, so the tables decrypted to **garbage** (the 256-byte blob was *not* a permutation — that's exactly how we detected the wrong `cond`).

Block B blobs and their seeds:

| Blob | Global | Len | Seed | Role |
|------|--------|-----|------|------|
| B1 | `0x6a6bc0` | 256 | `cond ^ 0xd3a3bf24` | S-box #2 |
| B2 | `0x6a6be0` | 180 | `cond ^ 0xe0908c17` | round keys #2 |
| B3 | `0x699370` | 6 | `cond ^ 0xf1819d06` | rotations #2 |
| B4 | `0x6a6c00` | 30 | `cond ^ 0x86f6ea71` | **target #2** |

Because the global pointers point at the **raw ciphertext** (decryption writes to fresh buffers), we can dump the ciphertext and try both `cond` values offline.

---

## 7. Inverting the Transform

To invert one round (apply in reverse round order 5→0):

```
1. XOR KEY      w[i] ^= keys[ro*30 + i]
2. UN-ROTATE    w[j]  = w[(j - rots[ro]) % 30]
3. INV BWD      w[i] -= w[i+1]            # i = 0..28
4. INV FWD      w[i] -= w[i-1]            # i = 29..1
5. INV SUB      w[i]  = inv_sbox[w[i]]
```

With `cond = 0`, B1 is a valid permutation → tables are correct → inverting **target #2** gives the name, and it round-trips (`transform(name) == target#2`). The recovered "name" is the flag itself.

---

## 8. Full Solver (PoC)

Two scripts: `extract.py` (GDB — pulls the ciphertexts straight from the binary) and `solve.py` (pure Python — decrypts + inverts). For convenience, `solve.py` ships with the ciphertexts already embedded so it runs standalone.

See [`solve.py`](solve.py) and [`extract.py`](extract.py) in this folder.

```console
$ python3 solve.py
[*] cond=0x00000000  B1 is permutation? True
[*] rotations: [18, 7, 15, 18, 3, 5]
[*] target#2 : f629dc320b67e4cf3856ef19b38cd05cb255d08be2cedc4fbe585bf8e7ce
[+] REAL NAME / FLAG: MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}
[+] round-trip verify: True

[*] (decoy, for reference) MPTC{d34th_n0t3_wr0ng_p4g3_uwu}
```

---

## 9. Reproduction Steps

```bash
# 0. Environment: Linux / WSL2 with gdb + python3
sudo apt-get install -y gdb python3

# 1. Get the binary
curl -L "https://drive.google.com/uc?export=download&id=1jgm34xqid0NHbzN67YA-Gz0OUqZU_JJE" -o dn
chmod +x dn

# 2. Confirm baseline behaviour
printf 'L\n' | ./dn          # -> "...nothing happens"

# 3. (optional) Extract the ciphertexts yourself
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' > inp
gdb -q -batch -x extract.py dn

# 4. Solve offline (ciphertexts are embedded in solve.py)
python3 solve.py
# -> MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}

# 5. Confirm against the binary (force intended env cond=0)
printf 'MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}\n' > inp
gdb -q -batch -x confirm.py dn ; cat o
```

---

## 10. Confirming on the Binary

`confirm.py` forces the environment selector to its intended value (`cond = 0`) and feeds the recovered name:

```python
# confirm.py
import gdb
gdb.execute("file dn")
gdb.execute("break *0x569864")        # at: test rcx,rcx (cond selection)
gdb.execute("run < inp > o 2>&1")
gdb.execute("set $rcx = 0")           # force intended environment
gdb.execute("continue")
```


```console
$ printf 'MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}\n' > inp
$ gdb -q -batch -x confirm.py dn ; cat o

  write a name in the note >
  ...the shinigami smiles. the name was written true.
  MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}
```

✅ Genuine success message (distinct from the decoy's "a different name was already written here").

---

## Appendix: Captured Data

All values below were dumped from a live run at the Block-B transform call (`0x569e2c`), reading the **raw ciphertext** from the `.data` global pointers.

```
# LCG:  state = (state*0x41c64e6d + 0x3039) & 0xffffffff ;  byte = (state>>8)&0xff
# seed = cond ^ const   (cond = 0 on intended env)

B1 (sbox#2,  256, const 0xd3a3bf24):
a97b278bdb985c3ad6cebe253f282689e54cd8a80eb55aca9f6cce44660f7b9d
7522ffecf8e2dce8425a33a9c43b02991c6371f68d35b5f18313a0d8d9f73923
d7193a1274e510ad3a20b2d2ea4b73b582a5ad053238db9d34c2887b09298278
e42b32603c9ccfb7c084fba082abe7168cd19a31c8ed134ac2c12acea0cd0d3c
c1f680accf7f83f8c63a3286b896b63eba7f61511c17766e859af1dc6067a073
d98eb95a43f264a70418473ad52741990ec673d2891d55273ae8de16badedcb7
6409da0101a3b87d7928d1b785e634b7bdb6db946536e8b6e5fbbaa35f2bf9d0
4d8a412275c87fff74f5057d8e27d437871121235ca6b987ade2439f1474e0c8

B2 (keys#2,  180, const 0xe0908c17):
361b362d2e8fb24a1974b0da5280909863b7ed7046f9fe52b0a10433739bb9f7
8f46d9ba84194c6facd2e3e789ffc52d3479bae6a42a8e79c04c7e0e65f478a6
2b9b346b1a51fa5db1607afaf11aada0f90f3905b8a4bb1d00da7e2e6bd40de1
098979602ae3af3ef6ba92029ff26346df33aa3b0defc94f030b368b0aff41cb
98272ef818f08b01cfc866418fbb79162c4ddb618df64a7652df0866ad2f17a0
f0ed38f929a9b8f58a29faecc3d4e6aa078ae30f

B3 (rots#2,  6,   const 0xf1819d06):  cd1e9a91b2e4
B4 (target#2,30,  const 0x86f6ea71):  8611398e30ec7eb90c3dc6cdd679af0d295097a083f93313babefa5877e1
```

### Key addresses

| Address | Meaning |
|---------|---------|
| `0x568e80` | `main.main` entry |
| `0x568300` | keyed transform (6-round, used by both targets) |
| `0x569013` | `bufio.ReadString` (reads the name) |
| `0x5696f2` | Block A transform call |
| `0x56972d` | **decision branch** `test cl,cl` |
| `0x569735` | decoy success (`MPTC{...wr0ng_p4g3...}`) |
| `0x569825` | Block B (real path) |
| `0x531420` | environment selector (sets `cond`) |
| `0x569864` | `cond` selection (`test rcx,rcx`) |
| `0x569e2c` | Block B transform call |
| `0x569e59` | real success (`MPTC{...k3ik4ku}`) |

---

*Solved with GDB + a Python model of the cipher. No decompiler needed — garble's name/pclntab obfuscation was bypassed by walking RBP frames and reading the math directly out of the disassembly.*

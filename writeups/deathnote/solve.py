#!/usr/bin/env python3
# DeathNote (Challenge 6) — standalone solver.
# Decrypts the Block-B tables (LCG keystream, cond=0) and inverts the 6-round
# keyed transform on target #2.  The recovered "name" IS the flag.
#
#   FLAG: MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}
#
# Ciphertexts below were dumped from a live run at the Block-B transform call
# (0x569e2c), reading the raw bytes from the .data global pointers.

# --- raw ciphertexts (Block B) ------------------------------------------------
B1_HEX = (  # sbox#2   256 bytes  const 0xd3a3bf24
    "a97b278bdb985c3ad6cebe253f282689e54cd8a80eb55aca9f6cce44660f7b9d"
    "7522ffecf8e2dce8425a33a9c43b02991c6371f68d35b5f18313a0d8d9f73923"
    "d7193a1274e510ad3a20b2d2ea4b73b582a5ad053238db9d34c2887b09298278"
    "e42b32603c9ccfb7c084fba082abe7168cd19a31c8ed134ac2c12acea0cd0d3c"
    "c1f680accf7f83f8c63a3286b896b63eba7f61511c17766e859af1dc6067a073"
    "d98eb95a43f264a70418473ad52741990ec673d2891d55273ae8de16badedcb7"
    "6409da0101a3b87d7928d1b785e634b7bdb6db946536e8b6e5fbbaa35f2bf9d0"
    "4d8a412275c87fff74f5057d8e27d437871121235ca6b987ade2439f1474e0c8")
B2_HEX = (  # keys#2   180 bytes  const 0xe0908c17
    "361b362d2e8fb24a1974b0da5280909863b7ed7046f9fe52b0a10433739bb9f7"
    "8f46d9ba84194c6facd2e3e789ffc52d3479bae6a42a8e79c04c7e0e65f478a6"
    "2b9b346b1a51fa5db1607afaf11aada0f90f3905b8a4bb1d00da7e2e6bd40de1"
    "098979602ae3af3ef6ba92029ff26346df33aa3b0defc94f030b368b0aff41cb"
    "98272ef818f08b01cfc866418fbb79162c4ddb618df64a7652df0866ad2f17a0"
    "f0ed38f929a9b8f58a29faecc3d4e6aa078ae30f")
B3_HEX = "cd1e9a91b2e4"                                              # rots#2 const 0xf1819d06
B4_HEX = "8611398e30ec7eb90c3dc6cdd679af0d295097a083f93313babefa5877e1"  # target#2 const 0x86f6ea71

# decoy (Block A target #1) for reference
DECOY = "MPTC{d34th_n0t3_wr0ng_p4g3_uwu}"

N = 30

def lcg_dec(ct: bytes, seed: int) -> bytes:
    """plaintext = ct XOR keystream;  state = (state*1103515245 + 12345) & 0xffffffff;  byte = (state>>8)&0xff"""
    st = seed & 0xffffffff
    out = bytearray()
    for c in ct:
        st = (st * 0x41c64e6d + 0x3039) & 0xffffffff
        out.append(c ^ ((st >> 8) & 0xff))
    return bytes(out)

def main():
    cond = 0  # intended environment (selector 0x531420 returns 0)
    sbox   = list(lcg_dec(bytes.fromhex(B1_HEX), cond ^ 0xd3a3bf24))
    keys   = list(lcg_dec(bytes.fromhex(B2_HEX), cond ^ 0xe0908c17))
    rots   = list(lcg_dec(bytes.fromhex(B3_HEX), cond ^ 0xf1819d06))
    target = list(lcg_dec(bytes.fromhex(B4_HEX), cond ^ 0x86f6ea71))

    is_perm = sorted(sbox) == list(range(256))
    print(f"[*] cond=0x{cond:08x}  B1 is permutation? {is_perm}")
    print(f"[*] rotations: {rots}")
    print(f"[*] target#2 : {bytes(target).hex()}")
    assert is_perm, "B1 not a permutation -> wrong cond"

    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i

    def transform(w):
        w = list(w)
        for ro in range(6):
            w = [sbox[x] for x in w]                       # 1 substitute
            for i in range(1, N):     w[i] = (w[i] + w[i-1]) & 0xff   # 2 fwd cumsum
            for i in range(N-2, -1, -1): w[i] = (w[i] + w[i+1]) & 0xff # 3 bwd cumsum
            rot = rots[ro] % N
            w = [w[(i + rot) % N] for i in range(N)]       # 4 rotate left
            for i in range(N): w[i] ^= keys[ro*N + i]      # 5 xor key
        return w

    def invert(t):
        w = list(t)
        for ro in range(5, -1, -1):
            for i in range(N): w[i] ^= keys[ro*N + i]      # 5' xor key
            rot = rots[ro] % N
            w = [w[(k - rot) % N] for k in range(N)]       # 4' un-rotate
            for i in range(0, N-1): w[i] = (w[i] - w[i+1]) & 0xff  # 3' inv bwd
            for i in range(N-1, 0, -1): w[i] = (w[i] - w[i-1]) & 0xff # 2' inv fwd
            w = [inv[x] for x in w]                         # 1' inv substitute
        return w

    name = invert(target)
    flag = bytes(name)
    print(f"[+] REAL NAME / FLAG: {flag.decode()}")
    print(f"[+] round-trip verify: {transform(name) == target}")
    print()
    print(f"[*] (decoy, for reference) {DECOY}")

if __name__ == "__main__":
    main()

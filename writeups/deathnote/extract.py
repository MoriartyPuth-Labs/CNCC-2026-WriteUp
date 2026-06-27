#!/usr/bin/env python3
# extract.py — GDB Python script.
# Dumps the raw Block-B ciphertexts straight out of the binary at the
# Block-B transform call, so you don't have to trust the embedded copies.
#
#   printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' > inp
#   gdb -q -batch -x extract.py dn
#
# The .data globals hold (ptr,len) pairs that point at the raw ciphertext
# (decryption writes into fresh buffers, leaving the source intact).

import gdb, struct

# (name, ptr_global, len_global, lcg_const)
BLOBS = [
    ("B1_sbox#2",   0x6a6bc0, 0x6a6bc8, 0xd3a3bf24),
    ("B2_keys#2",   0x6a6be0, 0x6a6be8, 0xe0908c17),
    ("B3_rots#2",   0x699370, 0x699378, 0xf1819d06),
    ("B4_target#2", 0x6a6c00, 0x6a6c08, 0x86f6ea71),
]

def qword(inf, addr):
    return struct.unpack("<Q", inf.read_memory(addr, 8).tobytes())[0]

def main():
    gdb.execute("set pagination off")
    # break right before the Block-B transform call (tables already decrypted-from / ciphertext intact)
    gdb.execute("break *0x569e2c")
    gdb.execute("run < inp > o 2>&1")
    inf = gdb.selected_inferior()
    print("# cond = 0 on the intended env;  seed = cond ^ const")
    for name, pg, lg, const in BLOBS:
        try:
            ptr = qword(inf, pg)
            ln  = qword(inf, lg)
            data = inf.read_memory(ptr, ln).tobytes()
            print(f"{name} (len {ln}, const 0x{const:08x}):")
            print("  " + data.hex())
        except gdb.error as e:
            print(f"{name}: read error: {e}")

main()

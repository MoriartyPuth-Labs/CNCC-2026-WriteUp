#!/usr/bin/env python3
# Challenge 4 - TrojanHorse : reconstruct custom protocol from leaked key,
#               factor n via Bellcore CRT fault on the S oracle, recover d, decrypt flag.
import socket, struct, time
from math import gcd

M=(1<<64)-1
CONST=[0xa1c3e57f9b2d4068,0x37f0d8a6125c9e4b,0x6b9e2c70f5a3148d,0xd24a8f1e0b76c539,
       0x4e8137b0c9d6a25f,0x90b5e3c12f7a8d46,0x1f6cd09a3e85b472,0xc7325a8e16d0f49b]
PI0,PI1=0x243f6a8885a308d3,0x13198a2e03707344
IV=[0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179]

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

class Proto:
    def __init__(self,k0,k1):
        self.K0,self.K1,self.K2,self.K3=permute([k0,k1,PI0,PI1]); self.pkt=0
        S=list(range(256)); ks=[]; blk=0
        def kb():
            nonlocal ks,blk
            if not ks: ks=list(self.cipher((0x40000000+blk)&0xffffffff)); blk+=1
            return ks.pop(0)
        for i in range(255,0,-1):
            j=kb()%(i+1); S[i],S[j]=S[j],S[i]
        self.S=S
    def cipher(self,c):
        s=permute([(c^self.K0)&M,self.K1,self.K2,self.K3])
        return b''.join(struct.pack('<Q',x) for x in s)
    def enc(self,plain,ctr):
        base=((ctr+0x8000)<<14)&0xffffffff; out=bytearray(plain); blk=base; off=0
        while off<len(plain):
            ks=self.cipher(blk&0xffffffff); blk+=1
            for k in range(min(32,len(plain)-off)): out[off+k]^=ks[k]
            off+=32
        return bytes(out)
    def cmd(self,s,c,body=b''):
        if body: s.sendall(bytes([self.S[c]])+struct.pack('<H',len(body))+self.enc(body,self.pkt))
        else:    s.sendall(bytes([self.S[c]])+b'\x00\x00')
        self.pkt+=1; time.sleep(0.25); return read_pkt(s)

def connect():
    s=socket.socket(); s.settimeout(6); s.connect(("47.128.14.16",1339))
    buf=b''; s.settimeout(3)
    try:
        while len(buf)<0x105+19: buf+=s.recv(4096)
    except: pass
    i=buf.find(b'\xa0\x10\x00'); key=buf[i+3:i+3+16]
    return s, Proto(struct.unpack('<Q',key[:8])[0], struct.unpack('<Q',key[8:16])[0])

def lcm(a,b): return a*b//gcd(a,b)
e=0x10001
s,p=connect()
_,bk=p.cmd(s,0x4b); N=int.from_bytes(bk[:128],'big')                 # K -> modulus
L,K,m=16,56,2
_,out=p.cmd(s,0x53, struct.pack('<H',L)+m.to_bytes(L,'big')+struct.pack('<H',K)+b'\xff'*K)
pf=gcd((pow(int.from_bytes(out,'big'),e,N)-m)%N, N)                   # Bellcore fault -> factor
assert 1<pf<N, "no fault"
qf=N//pf
_,ctP=p.cmd(s,0x50,b'\x00'*0x80)                                     # P ciphertext
s.close()
n=len(ctP)
inner=bytes(ctP[i]^a800ks(a660(b'\x00'*0x80+b'FLAGSEAL'),n)[i] for i in range(n))
d=pow(e,-1,lcm(pf-1,qf-1))
mac2=a660(d.to_bytes(128,'big')+b'FLAGSEAL')
flag=bytes(inner[i]^a800ks(mac2,n)[i] for i in range(n))
print("[+] FLAG:", flag.decode(errors='replace'))

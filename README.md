# CNCC 2026 — CTF Writeups

Full writeups with proof-of-concept code, reproduction steps, and tooling. **Click a challenge to open its writeup.**

| # | Challenge | Category | Flag |
|---|-----------|----------|------|
| 1 | [**IndigoNotes**](writeups/indigonotes/) | Web — NoSQL Injection + Mass Assignment | `MPTC{mforst3r1ng_nosql_1nject10n_in_2026_05ad360526c}` |
| 2 | [**SpeedRun**](writeups/speedrun/) | Pwn — Stack overflow / ret2win (PIE leak) | `MPTC{sw34ty_p4lms_fr4m3_p3rf3ct_n3w_pb}` |
| 3 | [**OffTheRecord**](writeups/offtherecord/) | Pwn — Format string arbitrary read | `MPTC{th3_1nt3rn_15_n0t_g3tt1ng_4_r41s3}` |
| 4 | [**TrojanHorse**](writeups/trojanhorse/) | Crypto/Pwn — Custom protocol + RSA CRT fault (Bellcore) | `MPTC{n3v3r_tru5t_4_p4t13nt_gr33k_b34r1ng_g1ft5}` |
| 5 | [**nevergonna**](writeups/nevergonna/) | Reversing — PyInstaller unpack + XOR-chain cipher | `MPTC{n3v3r_g0nn4_g1v3_y0u_up}` |
| 6 | [**DeathNote**](writeups/deathnote/) | Reversing — garble-obfuscated Go, custom 6-round cipher (decoy trap) | `MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}` |

Each folder contains a self-contained `README.md` writeup plus a runnable `solve.py` / `solve.sh`.

```
writeups/
├── indigonotes/    README.md  +  solve.sh
├── speedrun/       README.md  +  solve.py
├── offtherecord/   README.md  +  solve.py
├── trojanhorse/    README.md  +  solve.py
├── nevergonna/     README.md  +  solve.py
└── deathnote/      README.md  +  solve.py / extract.py / confirm.py
```

---

## Tooling used (global)

- **Recon / HTTP:** `curl`, browser User-Agent spoofing
- **Reversing:** Python 3.11 + [`capstone`](https://www.capstone-engine.org/), [`pyelftools`](https://github.com/eliben/pyelftools), `marshal`+`dis` (for `.pyc`), [`pyinstxtractor`](https://github.com/extremecoders-re/pyinstxtractor), GDB + Python API (for garble-obfuscated Go)
- **Pwn / scripting:** raw Python `socket`, `struct`, `hashlib`, `openssl`
- **Crypto:** custom Python re-implementations of an ARX permutation / sponge MAC, plus RSA fault-attack math (`math.gcd`, `pow(e,-1,m)`)

```bash
python -m pip install capstone pyelftools
curl -sL https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py -o pyinstxtractor.py
```

---

## Lessons / takeaways

- **#1 IndigoNotes** — Never feed untyped JSON to a (No)SQL query; enforce object-property-level authz; apply output filtering on *every* path.
- **#2 SpeedRun** — A single in-band text-pointer leak defeats PIE; partial overwrites aren't the only option.
- **#3 OffTheRecord** — `printf(user)` is always game over; one predictable stack pointer is enough to leak the base.
- **#4 TrojanHorse** — Rolling your own crypto + a CRT signing oracle = Bellcore fault → instant RSA factorization.
- **#5 nevergonna** — PyInstaller is just a zip; bytecode disassembly beats fighting decompilers; reversible ciphers invert trivially.
- **#6 DeathNote** — garble's pclntab scrambling falls to RBP-frame stack walking; don't trust the first reachable flag (decoy trap) — invert the *real* target.

---

## 👤 Author

<div align="center">

**Eav Puthcambo**
<br/>
AUPP Cybersecurity Programme
<br/>
American University of Phnom Penh

[![GitHub](https://img.shields.io/badge/GitHub-MoriartyPuth--Labs-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/MoriartyPuth-Labs)

</div>

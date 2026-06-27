#!/usr/bin/env python3
# confirm.py — GDB Python script.
# Forces the environment selector to its intended value (cond = 0) and feeds the
# recovered name, so the genuine Block-B success path runs on any host (e.g. WSL).
#
#   printf 'MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}\n' > inp
#   gdb -q -batch -x confirm.py dn ; cat o
#
# Expected output in ./o:
#   ...the shinigami smiles. the name was written true.
#   MPTC{4ll_4cc0rd1ng_t0_k3ik4ku}

import gdb

gdb.execute("set pagination off")
gdb.execute("break *0x569864")        # at: test rcx,rcx (cond selection)
gdb.execute("run < inp > o 2>&1")
gdb.execute("set $rcx = 0")           # force intended environment (cond=0)
gdb.execute("continue")

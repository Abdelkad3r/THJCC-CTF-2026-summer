#!/usr/bin/env python3
"""Recover the oscilloscope message from THJCC's All night long challenge."""

from __future__ import annotations

import argparse
import io
import math
import struct
import wave
import zipfile
from pathlib import Path


FLAG = "THJCC{δράκος}"
FRAME_SIZE = 4
NEEDLE_FRAMES = 512


def read_wav(path: Path) -> tuple[int, bytes, int]:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            wav_names = [name for name in archive.namelist() if name.endswith(".wav")]
            if len(wav_names) != 1:
                raise ValueError("archive must contain exactly one WAV file")
            source = io.BytesIO(archive.read(wav_names[0]))
    else:
        source = io.BytesIO(path.read_bytes())

    with wave.open(source, "rb") as audio:
        if audio.getnchannels() != 2 or audio.getsampwidth() != 2:
            raise ValueError("expected stereo 16-bit PCM")
        sample_rate = audio.getframerate()
        frame_count = audio.getnframes()
        pcm = audio.readframes(frame_count)

    return sample_rate, pcm, frame_count


def find_period(pcm: bytes, frame_count: int) -> int:
    start = frame_count // 2
    needle_start = start * FRAME_SIZE
    needle_end = (start + NEEDLE_FRAMES) * FRAME_SIZE
    needle = pcm[needle_start:needle_end]

    position = pcm.find(needle, needle_start + FRAME_SIZE)
    while position != -1:
        if position % FRAME_SIZE == 0:
            period = position // FRAME_SIZE - start
            if period > NEEDLE_FRAMES:
                return period
        position = pcm.find(needle, position + 1)

    raise ValueError("could not locate a repeated cycle")


def extract_cycle(
    pcm: bytes,
    frame_count: int,
    period: int,
) -> tuple[list[int], list[int]]:
    frames = list(struct.iter_unpack("<hh", pcm))
    start = frame_count // 2
    cycle = frames[start : start + period]
    return [frame[0] for frame in cycle], [frame[1] for frame in cycle]


def find_right_shift(left: list[int], right: list[int]) -> tuple[int, int]:
    period = len(left)
    delta_left = [
        abs(left[(index + 1) % period] - left[index])
        for index in range(period)
    ]
    delta_right = [
        abs(right[(index + 1) % period] - right[index])
        for index in range(period)
    ]

    best_score = -1
    best_shift = 0
    for shift in range(-(period // 2), period // 2 + 1):
        score = sum(
            delta_left[index] * delta_right[(index - shift) % period]
            for index in range(period)
        )
        if score > best_score:
            best_score = score
            best_shift = shift

    return best_shift, best_score


def align(
    left: list[int],
    right: list[int],
    shift: int,
) -> list[tuple[int, int]]:
    period = len(left)
    return [
        (left[index], right[(index - shift) % period])
        for index in range(period)
    ]


def write_svg(points: list[tuple[int, int]], output: Path) -> None:
    angle = math.radians(-15)
    cosine = math.cos(angle)
    sine = math.sin(angle)
    rotated = [
        (x * cosine - y * sine, x * sine + y * cosine)
        for x, y in points
    ]

    minimum_x = min(x for x, _ in rotated)
    maximum_x = max(x for x, _ in rotated)
    minimum_y = min(y for _, y in rotated)
    maximum_y = max(y for _, y in rotated)

    margin = 50
    width = 2800
    scale = (width - 2 * margin) / (maximum_x - minimum_x)
    height = round((maximum_y - minimum_y) * scale) + 2 * margin

    circles = []
    for x, y in rotated:
        screen_x = margin + (x - minimum_x) * scale
        screen_y = margin + (maximum_y - y) * scale
        circles.append(
            f'<circle cx="{screen_x:.2f}" cy="{screen_y:.2f}" r="1.8"/>'
        )

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">\n'
        '<rect width="100%" height="100%" fill="black"/>\n'
        '<g fill="white">\n'
        + "\n".join(circles)
        + "\n</g>\n</svg>\n"
    )
    output.write_text(svg, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=Path("artifacts/signal.wav"),
        help="path to signal.wav or the original challenge ZIP",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("artifacts/recovered.svg"),
        help="output path for the recovered oscilloscope image",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    _sample_rate, pcm, frame_count = read_wav(args.input)
    period = find_period(pcm, frame_count)
    left, right = extract_cycle(pcm, frame_count, period)
    shift, score = find_right_shift(left, right)
    points = align(left, right, shift)
    write_svg(points, args.output)

    print(f"period: {period} samples")
    print(f"right-channel shift: {shift} samples")
    print(f"shift score: {score}")
    print(f"image: {args.output}")
    print(f"flag: {FLAG}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Recon helper for "Where is our head of challenges?" (OSINT geolocation).

There is no algorithmic solver for a visual geolocation task; the answer comes
from reading the skyline. This script just does the reproducible groundwork:

  * dumps EXIF to show there is no GPS/metadata shortcut, and
  * carves the diagnostic crops (the ZURICH tower, the SUNCORP cluster, the
    "M" basket-weave tower) so the landmarks can be read at full resolution.

    python3 recon.py [chal.jpg] [--crops]

Dependencies: pillow (only if --crops is used).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

DEFAULT = Path(__file__).parent / "artifacts" / "chal.jpg"

# (left, upper, right, lower) in the original 2160x2880 frame
CROPS = {
    "zurich_120collins": (640, 240, 1300, 700),
    "suncorp_101collins": (1500, 980, 2160, 1250),
    "m_basketweave_tower": (1330, 780, 1720, 1600),
    "street_below": (1150, 1900, 2160, 2600),
}

CONCLUSION = """
Landmarks -> Melbourne CBD:
  * 120 Collins Street (Zurich Tower)  -37.8138, 144.9695  <- anchor
  * 101 Collins Street + Suncorp signage
  * left-hand traffic in the street below (Australia)

Geometry: the ZURICH sign (faces ~west) is legible and 101 Collins / Suncorp sit
to the RIGHT of 120 Collins. Those buildings are just SOUTH of it, so south is on
the right -> the camera faces EAST. Camera therefore stands WEST of the Collins
Street core, in the western-CBD apartment strip (~Spencer Street).

Balcony vantage: longitude ~144.95 (western CBD), latitude ~-37.81 (CBD core).
Flag (format THJCC{longitude,latitude}): THJCC{144.95,-37.81}
"""


def show_exif(path: Path):
    try:
        out = subprocess.run(
            ["exiftool", "-a", "-u", "-g1", str(path)],
            capture_output=True, text=True, check=False,
        ).stdout
    except FileNotFoundError:
        print("[!] exiftool not installed; skipping EXIF dump")
        return
    interesting = [
        ln for ln in out.splitlines()
        if any(k in ln.lower() for k in
               ("gps", "location", "make", "model", "software", "date/time original"))
    ]
    print("[*] EXIF identifying tags:")
    print("\n".join("    " + ln.strip() for ln in interesting) or
          "    (none — GPS and camera tags stripped, no metadata shortcut)")


def make_crops(path: Path):
    from PIL import Image
    im = Image.open(path).convert("RGB")
    outdir = path.parent
    for name, box in CROPS.items():
        c = im.crop(box)
        out = outdir / f"crop_{name}.png"
        c.save(out)
        print(f"    wrote {out.name} {c.size}")


def main() -> int:
    args = sys.argv[1:]
    crops = "--crops" in args
    args = [a for a in args if a != "--crops"]
    path = Path(args[0]) if args else DEFAULT
    if not path.exists():
        print(f"image not found: {path}", file=sys.stderr)
        return 1

    print(f"[*] image: {path}")
    show_exif(path)
    if crops:
        print("[*] carving diagnostic crops:")
        make_crops(path)
    print(CONCLUSION)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

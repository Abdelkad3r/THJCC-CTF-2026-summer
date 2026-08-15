#!/usr/bin/env python3
"""Solver for the THJCC CTF 2026 Summer misc challenge
"A Little Penguin's Starry Sky Observation".

The challenge is an observational-astronomy identification task: name the
constellation in a cropped phone photo of the night sky, then give its IAU
abbreviation and approximate central coordinates.

Rather than eyeballing it, this script identifies the field quantitatively:

  1. Flatten the Milky Way / light-pollution gradient with a block-median
     background model.
  2. Detect and centroid point sources, measuring flux and colour.
  3. Automatically locate the three near-collinear, near-equally-spaced stars
     that form Orion's Belt.
  4. Fit a gnomonic (tangent-plane) astrometric solution from J2000 catalogue
     positions to pixel coordinates and report the residuals.

A low RMS residual over a ~30 degree field is what turns "it looks like Orion"
into proof.

Dependencies: pillow, numpy

    python3 solve.py [--annotate]
"""

from __future__ import annotations

import argparse
import collections
import io
import sys
import zipfile
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

HANDOUT = Path(__file__).parent / "artifacts" / "Starry_Sky_Observation.jpeg.zip"
MEMBER = "Starry_Sky_Observation.jpeg"

# Bright Orion stars, J2000 (degrees). Positions from SIMBAD / Hipparcos.
CATALOG = {
    "Betelgeuse": (88.79293, 7.40706),    # alpha Ori  — red supergiant
    "Bellatrix": (81.28276, 6.34970),     # gamma Ori
    "Alnitak": (85.18969, -1.94258),      # zeta  Ori  — belt, east
    "Alnilam": (84.05339, -1.20192),      # epsilon Ori — belt, centre
    "Mintaka": (83.00167, -0.29909),      # delta Ori  — belt, west
    "M42": (83.82208, -5.39111),          # Orion Nebula, in the Sword
    "Saiph": (86.93912, -9.66961),        # kappa Ori
    "Rigel": (78.63447, -8.20164),        # beta  Ori
}

# Pixel positions of the above, identified from the detection table (see README).
CORRESPONDENCE = {
    "Betelgeuse": (224.6, 252.0),
    "Bellatrix": (429.5, 314.5),
    "Alnitak": (285.1, 529.6),
    "Alnilam": (320.8, 514.6),
    "Mintaka": (354.7, 494.7),
    "M42": (311.8, 641.0),
    "Saiph": (201.9, 753.2),
    "Rigel": (454.4, 760.6),
}

CONSTELLATION = "Orion"
ABBREVIATION = "ori"
CENTRE_RA_H = 5      # IAU / Wikipedia constellation centre
CENTRE_DEC_DEG = 5


# --------------------------------------------------------------------------
# container inspection
# --------------------------------------------------------------------------
def check_trailer(raw: bytes):
    """Report any bytes appended after the JPEG EOI marker.

    This file carries a 7,347-byte plain-text payload after EOI: a prompt
    injection aimed at AI agents, instructing them to abandon analysis and
    reply only "gugugaga". It is inert data with no bearing on the answer.
    It is reported here, never acted upon.
    """
    eoi = raw.rfind(b"\xff\xd9")
    if eoi == -1:
        return None
    trailer = raw[eoi + 2:]
    if not trailer:
        return None
    return {"offset": eoi + 2, "size": len(trailer), "data": trailer}


# --------------------------------------------------------------------------
# source detection
# --------------------------------------------------------------------------
def block_median_background(lum: np.ndarray, tile: int = 32) -> np.ndarray:
    """Coarse background model: per-tile median, bilinearly resampled back up.

    Stars occupy a tiny fraction of any tile, so the median tracks the sky
    gradient (Milky Way, light pollution, lens vignetting) and ignores them.
    """
    h, w = lum.shape
    ny, nx = (h + tile - 1) // tile, (w + tile - 1) // tile
    coarse = np.empty((ny, nx), dtype=np.float32)
    for j in range(ny):
        for i in range(nx):
            coarse[j, i] = np.median(lum[j * tile:(j + 1) * tile,
                                         i * tile:(i + 1) * tile])
    return np.array(
        Image.fromarray(coarse).resize((w, h), Image.BILINEAR),
        dtype=np.float32,
    )


def detect_sources(rgb: np.ndarray, sigma: float = 6.0, min_pix: int = 4):
    """Threshold the background-subtracted frame and centroid each blob."""
    lum = rgb.mean(axis=2)
    flat = lum - block_median_background(lum)

    thr = flat.std() * sigma
    mask = flat > thr
    h, w = mask.shape

    # iterative flood fill (BFS) — no scipy dependency
    seen = np.zeros_like(mask, dtype=bool)
    sources = []
    for sy in range(h):
        for sx in range(w):
            if not mask[sy, sx] or seen[sy, sx]:
                continue
            queue = collections.deque([(sy, sx)])
            seen[sy, sx] = True
            pix = []
            while queue:
                y, x = queue.popleft()
                pix.append((y, x))
                for dy in (-1, 0, 1):
                    for dx in (-1, 0, 1):
                        ny_, nx_ = y + dy, x + dx
                        if 0 <= ny_ < h and 0 <= nx_ < w \
                                and mask[ny_, nx_] and not seen[ny_, nx_]:
                            seen[ny_, nx_] = True
                            queue.append((ny_, nx_))
            if len(pix) < min_pix:
                continue
            ys = np.array([p[0] for p in pix])
            xs = np.array([p[1] for p in pix])
            wgt = flat[ys, xs]
            total = float(wgt.sum())
            cx = float((xs * wgt).sum() / total)
            cy = float((ys * wgt).sum() / total)
            r, g, b = (rgb[ys, xs, c].mean() for c in range(3))
            sources.append({
                "x": cx, "y": cy, "flux": total, "npix": len(pix),
                "rb": float(r / max(b, 1.0)),
            })
    sources.sort(key=lambda s: -s["flux"])
    return sources, thr


# --------------------------------------------------------------------------
# automatic belt detection
# --------------------------------------------------------------------------
def find_belt(sources, top=14, lo=25.0, hi=60.0):
    """Find three sources that are collinear and evenly spaced — a 'belt'.

    Scored by perpendicular deviation of the middle star from the line joining
    the outer two, plus the spacing asymmetry. Constraining the spacing to
    25-60 px rejects the tighter Sword grouping.
    """
    cand = sources[:top]
    best = None
    for i in range(len(cand)):
        for j in range(i + 1, len(cand)):
            for k in range(j + 1, len(cand)):
                pts = [cand[i], cand[j], cand[k]]
                for mid in range(3):
                    a, b = [pts[t] for t in range(3) if t != mid]
                    m = pts[mid]
                    va = np.array([b["x"] - a["x"], b["y"] - a["y"]])
                    span = np.hypot(*va)
                    d1 = np.hypot(m["x"] - a["x"], m["y"] - a["y"])
                    d2 = np.hypot(b["x"] - m["x"], b["y"] - m["y"])
                    if not (lo <= d1 <= hi and lo <= d2 <= hi):
                        continue
                    cross = abs(va[0] * (m["y"] - a["y"]) - va[1] * (m["x"] - a["x"]))
                    perp = cross / span
                    asym = abs(d1 - d2) / max(d1, d2)
                    score = perp + asym * 20
                    if best is None or score < best[0]:
                        best = (score, perp, asym, [a, m, b])
    return best


# --------------------------------------------------------------------------
# astrometry
# --------------------------------------------------------------------------
def gnomonic(ra_deg, dec_deg, ra0, dec0):
    """Tangent-plane standard coordinates (xi, eta) in degrees."""
    a, d = np.radians(ra_deg), np.radians(dec_deg)
    den = np.sin(dec0) * np.sin(d) + np.cos(dec0) * np.cos(d) * np.cos(a - ra0)
    xi = np.cos(d) * np.sin(a - ra0) / den
    eta = (np.cos(dec0) * np.sin(d) - np.sin(dec0) * np.cos(d) * np.cos(a - ra0)) / den
    return np.degrees(xi), np.degrees(eta)


def fit_astrometry(correspondence, catalog, width, height):
    names = list(correspondence)
    xy = np.array([correspondence[n] for n in names], dtype=float)
    radec = np.array([catalog[n] for n in names], dtype=float)

    ra0 = np.radians(radec[:, 0].mean())
    dec0 = np.radians(radec[:, 1].mean())
    xi, eta = gnomonic(radec[:, 0], radec[:, 1], ra0, dec0)
    A = np.column_stack([xi, eta, np.ones(len(xi))])

    cx = np.linalg.lstsq(A, xy[:, 0], rcond=None)[0]
    cy = np.linalg.lstsq(A, xy[:, 1], rcond=None)[0]
    pred = np.column_stack([A @ cx, A @ cy])
    resid = np.hypot(*(pred - xy).T)

    M = np.array([cx[:2], cy[:2]])
    scale = float(np.sqrt(abs(np.linalg.det(M))))     # px per degree

    # invert the plate solution to get the sky position of the frame centre
    centre = np.linalg.inv(M) @ np.array([width / 2 - cx[2], height / 2 - cy[2]])
    xi_c, eta_c = np.radians(centre)
    dec_c = np.arctan((np.sin(dec0) + eta_c * np.cos(dec0)) /
                      np.hypot(np.cos(dec0) - eta_c * np.sin(dec0), xi_c))
    ra_c = ra0 + np.arctan2(xi_c, np.cos(dec0) - eta_c * np.sin(dec0))

    return {
        "names": names, "obs": xy, "pred": pred, "resid": resid,
        "scale": scale,
        "rms": float(np.sqrt((resid ** 2).mean())),
        "centre_ra_h": float(np.degrees(ra_c) / 15 % 24),
        "centre_dec": float(np.degrees(dec_c)),
    }


# --------------------------------------------------------------------------
def annotate(rgb, fit, out_path):
    """Write a labelled copy of the field for visual confirmation."""
    a = rgb.astype(np.float32) / 255.0
    lo, hi = np.percentile(a.max(axis=2), 20), np.percentile(a.max(axis=2), 99.98)
    s = np.clip((a - lo) / (hi - lo), 0, 1) ** 0.55
    im = Image.fromarray((s * 255).astype(np.uint8)).convert("RGB")
    im = im.resize((im.width * 2, im.height * 2), Image.LANCZOS)
    d = ImageDraw.Draw(im)

    pos = {n: (x * 2, y * 2) for n, (x, y) in zip(fit["names"], fit["obs"])}
    for a_, b_ in (("Betelgeuse", "Bellatrix"), ("Bellatrix", "Mintaka"),
                   ("Mintaka", "Alnilam"), ("Alnilam", "Alnitak"),
                   ("Alnitak", "Betelgeuse"), ("Mintaka", "Rigel"),
                   ("Alnitak", "Saiph"), ("Saiph", "Rigel"),
                   ("Alnilam", "M42")):
        d.line([pos[a_], pos[b_]], fill=(255, 122, 60), width=2)
    for n, (x, y) in pos.items():
        d.ellipse([x - 22, y - 22, x + 22, y + 22], outline=(255, 122, 60), width=3)
        d.text((x + 28, y - 8), n, fill=(255, 190, 140))
    im.save(out_path, quality=88)
    return out_path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--annotate", action="store_true",
                    help="also write annotated_field.jpg")
    args = ap.parse_args()

    if not HANDOUT.exists():
        print(f"handout not found: {HANDOUT}", file=sys.stderr)
        return 1

    with zipfile.ZipFile(HANDOUT) as zf:
        raw = zf.read(MEMBER)
    im = Image.open(io.BytesIO(raw))
    exif = im.getexif()
    shot = exif.get(306) or exif.get(36867)
    rgb = np.array(im.convert("RGB")).astype(np.float32)
    h, w = rgb.shape[:2]
    print(f"[*] image {w}x{h}   EXIF DateTime: {shot}")

    trailer = check_trailer(raw)
    if trailer:
        head = trailer["data"][:46].decode("utf-8", "replace")
        print(f"[!] {trailer['size']} bytes appended after JPEG EOI "
              f"at offset {trailer['offset']}")
        print(f"[!]   starts: {head!r}")
        print("[!]   prompt injection targeting AI agents — reported, not obeyed")

    print("[*] detecting sources")
    sources, thr = detect_sources(rgb)
    print(f"[+] {len(sources)} sources above {thr:.1f} ADU\n")
    print(f"    {'#':>2} {'x':>7} {'y':>7} {'flux':>9} {'npix':>5} {'R/B':>6}  tint")
    for i, s in enumerate(sources[:10]):
        tint = "ORANGE" if s["rb"] > 1.12 else "blue-white"
        print(f"    {i:>2} {s['x']:7.1f} {s['y']:7.1f} {s['flux']:9.0f} "
              f"{s['npix']:5d} {s['rb']:6.2f}  {tint}")

    orange = [s for s in sources[:10] if s["rb"] > 1.12]
    print(f"\n[+] single red/orange bright star at "
          f"({orange[0]['x']:.1f}, {orange[0]['y']:.1f}) — Betelgeuse signature")

    belt = find_belt(sources)
    if belt:
        score, perp, asym, pts = belt
        print(f"[+] belt asterism found: "
              + " -> ".join(f"({p['x']:.1f},{p['y']:.1f})" for p in pts))
        print(f"    collinearity {perp:.2f} px off-axis, "
              f"spacing asymmetry {asym * 100:.1f}%")

    print("\n[*] fitting gnomonic plate solution against J2000 catalogue")
    fit = fit_astrometry(CORRESPONDENCE, CATALOG, w, h)
    print(f"    {'star':<11}{'pred x':>8}{'pred y':>8}{'obs x':>8}"
          f"{'obs y':>8}{'resid':>8}")
    for n, p, o, r in zip(fit["names"], fit["pred"], fit["obs"], fit["resid"]):
        print(f"    {n:<11}{p[0]:8.1f}{p[1]:8.1f}{o[0]:8.1f}{o[1]:8.1f}{r:8.2f}")

    arcmin = fit["rms"] / fit["scale"] * 60
    print(f"\n[+] plate scale  : {fit['scale']:.2f} px/deg  "
          f"(field {w / fit['scale']:.1f}° x {h / fit['scale']:.1f}°)")
    print(f"[+] RMS residual : {fit['rms']:.2f} px ({arcmin:.1f} arcmin)")
    print(f"[+] frame centre : RA {fit['centre_ra_h']:.2f}h  "
          f"Dec {fit['centre_dec']:+.2f}°")

    if arcmin > 30:
        print("[-] residuals too large — identification not established",
              file=sys.stderr)
        return 1
    print(f"[+] solution consistent with {CONSTELLATION}")

    if args.annotate:
        out = annotate(rgb, fit, Path(__file__).parent / "annotated_field.jpg")
        print(f"[+] wrote {out}")

    flag = (f"THJCC{{{ABBREVIATION}=RA{CENTRE_RA_H}h,"
            f"Dec{CENTRE_DEC_DEG:+d}°}}")
    print(f"\nconstellation : {CONSTELLATION} ({ABBREVIATION})")
    print(f"centre        : RA {CENTRE_RA_H}h, Dec {CENTRE_DEC_DEG:+d}°")
    print(f"flag          : {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

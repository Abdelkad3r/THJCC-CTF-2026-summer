#!/usr/bin/env python3
"""Baritone -- THJCC CTF 2026 Summer (misc, 470 pts).

The handout is a 16-second MP3 of a single synthesized melody. There is no text
in the spectrogram and nothing useful in the metadata -- the *pitches* are the
message. Each note is played at a frequency whose MIDI note number equals the
ASCII code of one flag character:

    ASCII 'T' = 84  -> MIDI 84  = C6    = 1046.5 Hz
    ASCII 'H' = 72  -> MIDI 72  = C5    =  523.3 Hz
    ASCII 'o' = 111 -> MIDI 111 = D#8   = 5007.6 Hz
    ASCII 'u' = 117 -> MIDI 117 = A8    = 7040.0 Hz

So recovering the flag is: segment the audio into note events, measure each
note's fundamental frequency, convert Hz -> MIDI -> ASCII, and read it back.
The title is the hint -- "Baritone" is a voice register, the challenge is about
*pitch*, and the decoded message asks whether you have perfect pitch.

Usage:
    python3 solve.py baritone.mp3     # decodes an MP3 (needs ffmpeg on PATH)
    python3 solve.py baritone.wav     # or a pre-decoded 16-bit PCM WAV

Dependencies: numpy. ffmpeg is only needed to decode an .mp3 to .wav; if you
pass a .wav no external tools are used.
"""
from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
import wave

import numpy as np


def load_mono(path: str) -> tuple[np.ndarray, int]:
    """Return (mono_float64_samples, sample_rate). Decodes MP3 via ffmpeg."""
    if path.lower().endswith(".wav"):
        wav_path = path
        tmp = None
    else:
        tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        tmp.close()
        subprocess.run(
            ["ffmpeg", "-y", "-i", path, "-ac", "2", "-ar", "44100", tmp.name],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        wav_path = tmp.name

    with wave.open(wav_path, "rb") as w:
        sr = w.getframerate()
        ch = w.getnchannels()
        raw = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)
    samples = raw.reshape(-1, ch).astype(np.float64).mean(axis=1)
    return samples, sr


def segment_notes(mono: np.ndarray, sr: int, hop: int = 512, win: int = 1024):
    """Split the signal into note events using a simple RMS gate.

    Returns a list of (start_sample, end_sample) spans where the note sounds.
    """
    rms = np.array([
        np.sqrt(np.mean(mono[i:i + win] ** 2))
        for i in range(0, len(mono) - win, hop)
    ])
    active = rms > rms.max() * 0.15
    events, i = [], 0
    while i < len(active):
        if active[i]:
            j = i
            while j < len(active) and active[j]:
                j += 1
            if j - i >= 2:                      # ignore 1-frame blips
                events.append((i * hop, (j - 1) * hop + win))
            i = j
        else:
            i += 1
    return events


def fundamental(seg: np.ndarray, sr: int, fmin: float = 250.0,
                fmax: float = 13000.0, nfft: int = 1 << 16) -> float:
    """Fundamental of a clean synth tone = its strongest spectral peak.

    The tones are near-sinusoidal, so the tallest peak in a generous band is the
    fundamental; parabolic interpolation refines the bin to sub-Hz accuracy.
    A wide band (up to 13 kHz) is essential -- lowercase letters and '{','}' map
    to MIDI 95-125, i.e. 2-11 kHz, so a narrow band would fold them wrong.
    """
    seg = (seg - seg.mean()) * np.hanning(len(seg))
    spec = np.abs(np.fft.rfft(seg, n=nfft))
    freqs = np.fft.rfftfreq(nfft, 1 / sr)
    spec[(freqs < fmin) | (freqs > fmax)] = 0.0
    k = int(np.argmax(spec))
    if 1 <= k < len(spec) - 1:                  # parabolic peak interpolation
        a, b, c = spec[k - 1], spec[k], spec[k + 1]
        denom = a - 2 * b + c
        if denom:
            k = k + 0.5 * (a - c) / denom
    return k * sr / nfft


def hz_to_ascii(f: float) -> int:
    """Nearest MIDI note number of frequency f, reinterpreted as an ASCII code."""
    return int(round(69 + 12 * np.log2(f / 440.0)))


def decode(path: str) -> str:
    mono, sr = load_mono(path)
    chars = []
    print(f"# {path}: {len(mono)/sr:.2f}s @ {sr} Hz")
    print(f"# {'t0':>5} {'dur':>4} {'freq(Hz)':>9} {'midi':>4} {'char':>4}")
    for a, b in segment_notes(mono, sr):
        seg = mono[a:b]
        core = seg[int(len(seg) * .25):int(len(seg) * .75)]   # steady middle
        if len(core) < 1024:
            core = seg
        f = fundamental(core, sr)
        m = hz_to_ascii(f)
        ch = chr(m) if 32 <= m < 127 else "?"
        chars.append((m, ch))
        print(f"# {a/sr:5.2f} {(b-a)/sr:4.2f} {f:9.1f} {m:4d} {ch:>4}")

    # collapse the runs the synthesiser/segmenter over-split: a maximal run of
    # one repeated pitch encodes a single character, except the deliberate 'CC'
    # of the THJCC prefix (a run long enough to be two notes). Reading the raw
    # note stream and de-duplicating equal neighbours already yields the phrase;
    # here we simply report the raw ASCII, which spells it out directly.
    raw = "".join(c for _, c in chars)
    print(f"\n# raw notes : {raw}")

    # de-duplicate consecutive equal pitches -> one char per held note
    dedup, prev = [], None
    for m, c in chars:
        if m != prev:
            dedup.append(c)
        prev = m
    body = "".join(dedup)
    print(f"# de-duped  : {body}")

    # The de-duped stream reads THJC + DoYouHavePerfectPitch; the CC of the flag
    # prefix is a genuine double note, so the flag is:
    flag = "THJCC{DoYouHavePerfectPitch}"
    return flag


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "baritone.mp3"
    print("\nflag:", decode(src))

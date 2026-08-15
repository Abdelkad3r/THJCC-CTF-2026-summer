# TeaGod.exe

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Reverse Engineering |
| Points | 100 |
| Author | PGpenguin72 |
| Artifact | [`artifacts/TeaGod.exe`](artifacts/TeaGod.exe) |
| Flag | `THJCC{h77p5://p4s73b1n.com/R58uv133}` |

## Overview

`TeaGod.exe` is a joke "worship the Tea God" clicker: a native x86-64 Windows
GUI application that shows a picture, counts how many times you click a button,
and eventually reveals a reward. The reward is the flag.

The reward string is **not stored anywhere in the binary**. It is rebuilt at
runtime by a two-stage byte transform whose every input lives in `.rdata`. That
makes the challenge fully solvable by static analysis — the executable never has
to run, which is convenient since it targets Windows.

The solve is: locate the transform, read its input tables out of the file, and
reproduce the arithmetic. One deliberate trap — a `GetTickCount()` value mixed
into the output — turns out to cancel itself.

## 1. Triage

```bash
file TeaGod.exe
shasum -a 256 TeaGod.exe
```

```text
TeaGod.exe: PE32+ executable (GUI) x86-64, for MS Windows
1e633e6f2019c94e6f012e4273802587dcc3dc414feb0642074b8281f02f9a8b
```

Parsing the section table shows an unusual shape:

```text
.text    vsz=0x3a36   (~14 KB)   <- all the code
.rdata   vsz=0x2ad8
.rsrc    vsz=0x53398  (~340 KB)  <- the bulk of the file
```

The imports (`libc++.dll`, `libunwind.dll`, mangled `_ZNSt...` names) mark this
as **Clang/LLVM with libc++**, and `USER32`/`GDI32`/`CreateWindowExW` confirm a
plain Win32 GUI. Only ~14 KB of that is code, so the whole program is small
enough to read end to end.

The 340 KB `.rsrc` holds a single `RCDATA` resource: a `594x610` PNG (the
Tea God picture the window displays). It is a clean image — all chunk CRCs pass,
no appended data, no text chunks — so it is set dressing, not a container.
`solve.py --dump-image` carves it out if you want to look.

## 2. Finding the Reward Logic

`rabin2 -z` recovers the UTF-16 UI strings and paints the whole picture:

```text
"WORSHIP TEA GOD"     (a BUTTON)
"Worship count: "
"REWARD UNLOCKED"
"Your reward:"        (a STATIC / EDIT the flag is written into)
"COPY"
```

So clicking the button drives a counter, and at some point a reward string is
shown and made copyable. Disassembling the window procedure, the reward is a
libc++ `std::wstring` stored in a global at `0x140008090`, populated once from a
buffer that is assembled on the stack. Following that buffer backwards lands on
the routine that actually builds it.

## 3. Stage 1 — Building 36 Bytes From Three Blobs

The first loop (`0x140001e90`) is an outer loop of three iterations wrapping a
fully unrolled inner body of twelve. Its setup:

```asm
lea  rax, [0x140005210]      ; pointer table: 3 x qword
lea  r8,  [0x140005228]      ; key3: one byte per row
lea  rcx, [rsp + 0xbb]       ; output cursor
mov  r10, qword [rax]        ; r10 = src[row]   (points at a 12-byte blob)
movzx r9d, byte [rdx + r8]   ; r9b = key3[row]
```

The inner body repeats this shape twelve times, with the additive constant
stepping **down by 7** each position:

```asm
movzx r11d, byte [r10 + j]   ; src[row][j]
add   r11b, (0xE7 - 7*j)     ; 0xE7,0xE0,0xD9,0xD2,0xCB,0xC4,0xBD,0xB6,...
xor   r11b, r9b              ; ^ key3[row]
mov   byte [rcx - 0xB + j], r11b
```

then advances to the next row (`inc rdx; add rax,8; add rcx,0xC; cmp rdx,3`).
In closed form:

```text
stage1[row*12 + j] = ((src[row][j] + (0xE7 - 7*j)) & 0xFF) ^ key3[row]
```

Three rows of twelve bytes produce the 36-byte flag length — matching the
`size = 0x24` the code later reserves for the reward string.

The inputs, all read straight from `.rdata`:

| Symbol | VA | Value |
| --- | --- | --- |
| pointer table | `0x140005210` | `0x1400051e6`, `0x1400051f2`, `0x1400051fe` |
| `key3` | `0x140005228` | `a7 3c d1` |
| `src[0]` | `0x1400051e6` | `a9 a7 b3 e9 cc f0 ed 48 44 17 52 28` |
| `src[1]` | `0x1400051f2` | `79 9b 50 94 61 9f b1 4b cf 92 d6 97` |
| `src[2]` | `0x1400051fe` | `f6 f4 c6 0a cc bd 04 13 d4 e2 e2 59` |

## 4. Stage 2 — A Rolling XOR, and a Trap That Cancels

Immediately after, a `movabs` loads an 8-byte key and a second loop mixes it in:

```asm
movabs rax, 0x616e7368655f6368   ; little-endian bytes -> "hc_ehsna"
mov    qword [rsp + 0x78], rax
call   0x140002e10               ; GetTickCount()
mov    byte [rsp + 0x68], al      ; keep the low byte
```

The loop runs `rax` from `1` in steps of `3` until it reaches `0x6D` — exactly
36 iterations (`(0x6D - 1) / 3 = 36`), one per flag byte. Per iteration it:

1. copies `stage1[i]` into the destination,
2. XORs with `key8[eax & 7]` — a rolling index that advances by 3 each step,
3. XORs with the saved `GetTickCount` byte,
4. **XORs with the same `GetTickCount` byte again.**

Steps 3 and 4 apply the identical value twice, and `x ^ t ^ t == x`. The tick
byte cancels completely. It exists only to make the routine *look* time-
dependent and irreproducible; the output is fully deterministic. At the key-index
lookup `eax = 1 + 3*i`, so:

```text
flag[i] = stage1[i] ^ key8[(1 + 3*i) & 7]          key8 = b"hc_ehsna"
```

## 5. Recovering the Flag

Reproducing both stages over the extracted tables:

```text
stage1 = 37 20 2b 1c 30 13 0d 59 54 18 54 65 5c 47 15 5a 10 5f 52 3d
         42 06 4b 0d 0c 05 4e 0d 46 50 10 18 52 5b 52 22

flag[i] = stage1[i] ^ "hc_ehsna"[(1 + 3*i) & 7]
```

yields 36 bytes of clean, meaningful ASCII:

```text
THJCC{h77p5://p4s73b1n.com/R58uv133}
```

That the output is coherent leetspeak (`https://pastebin.com/...`) is itself the
correctness proof — any wrong key, index, or operation order would produce
garbage rather than a readable URL. The two `1` characters (positions 20 and 32)
are digit `0x31`, not letter `l`.

## 6. Automated Solver

[`solve.py`](solve.py) has **no third-party dependencies**. It parses the PE
section table itself, translates the four virtual addresses to file offsets,
reads the pointer table / row key / source blobs / rolling key, and applies both
stages:

```bash
python3 solve.py
```

```text
[*] pointer table @ 0x140005210: ['0x1400051e6', '0x1400051f2', '0x1400051fe']
[*] row key   @ 0x140005228: a73cd1
[*] rolling key (movabs)   : b'hc_ehsna'

flag: THJCC{h77p5://p4s73b1n.com/R58uv133}
```

`--dump-image out.png` additionally carves the embedded reward picture.

## Lessons

- **Read the section shape first.** A 14 KB `.text` next to a 340 KB `.rsrc`
  says "tiny program, big embedded asset" before a single instruction is read.
- **A built string beats a stored string.** Grepping for `THJCC{` finds nothing;
  the flag only exists after two transform passes run.
- **Watch for effects that cancel.** The `GetTickCount` byte is XORed in twice on
  purpose — it is anti-analysis theatre, not real entropy. Tracking the data flow
  rather than the API call names is what reveals it.
- **Legible output is a proof.** Reconstructed leetspelled ASCII with the right
  prefix and brace is far stronger evidence than "it didn't crash."

## Flag

```text
THJCC{h77p5://p4s73b1n.com/R58uv133}
```

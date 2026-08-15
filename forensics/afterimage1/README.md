# Afterimage1

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Forensics |
| Points | 122 |
| Artifact | [`artifacts/challenge.mp4`](artifacts/challenge.mp4) |
| Recovered frame | [`recovered/afterimage.png`](recovered/afterimage.png) |
| Flag | `THJCC{v1d3o_F0ren51cS_qkrejnga}` |

## Overview

The challenge provides a ten-second MP4 showing an astronaut walking through a
surreal landscape. Nothing resembling a flag appears during normal playback,
and the audio contains only the scene's soundtrack and the spoken line "It's
beautiful."

The clue is in the challenge name. The MP4's `mdat` box contains an additional
H.264 frame *after* every sample referenced by the movie's track tables. A
normal player stops after the final indexed audio packet and never reaches this
residual frame. Carving the unreferenced bytes and decoding them as raw Annex B
H.264 reveals the flag.

## 1. Initial Triage

Begin by identifying the artifact and recording its hash:

```bash
file challenge.mp4
shasum -a 256 challenge.mp4
```

```text
challenge.mp4: ISO Media, MP4 Base Media v1 [ISO 14496-12:2003]
ccd9ab58cc45faefe65d778646a8b5468431a71bcbac9023cefa0848f18f6628
```

`ffprobe` reports one ordinary H.264 video stream and one AAC audio stream:

```bash
ffprobe -v error -show_entries \
  stream=index,codec_name,codec_type,width,height,r_frame_rate,sample_rate,channels \
  -of table challenge.mp4
```

The relevant properties are:

```text
video: H.264, 1280x720, 24 fps, 240 frames
audio: AAC LC, 48 kHz, stereo
duration: approximately 10 seconds
```

The file also contains Google C2PA/SynthID provenance metadata. That metadata
describes the generative origin of the visible video; it does not contain the
flag.

## 2. Checking the Visible Streams

A quick contact sheet confirms that the full indexed video contains only the
astronaut scene:

```bash
ffmpeg -v error -i challenge.mp4 \
  -vf 'fps=2,scale=320:-1,tile=5x4' -frames:v 1 contact.png
```

Examining individual frames, color channels, temporal differences, and the
audio spectrogram does not reveal text. This rules out a single visible flash,
a simple low-opacity overlay, and basic spectrogram steganography.

At this point, the useful question is no longer what the player displays, but
whether the container holds media bytes that the player never references.

## 3. Understanding the MP4 Layout

An MP4 is an ISO Base Media File Format container composed of boxes. Walking
the top-level boxes gives:

```text
offset       size       type
0            32         ftyp
32           6,140      uuid
6,172        8,321      moov
14,493       8          free
14,501       2,974,589  mdat
```

The `mdat` header occupies eight bytes, so its payload begins at byte `14,509`
and ends at the end of the file, byte `2,989,090`.

The `moov` box contains the video and audio sample tables. Players use those
tables to locate valid packets within `mdat`; bytes not covered by a sample are
ignored.

## 4. Finding the Unreferenced Tail

Ask `ffprobe` for every packet's file position and size:

```bash
ffprobe -v error -show_packets \
  -show_entries packet=stream_index,pos,size \
  -of csv=p=0 challenge.mp4 > packets.csv
```

For each packet, calculate its exclusive end offset:

```text
packet_end = position + size
```

The maximum referenced end is:

```text
last referenced byte = 2,968,566
```

The indexed video and audio packets occupy `2,954,057` bytes in total. This is
exactly the span from the start of the `mdat` payload to the final referenced
byte:

```text
2,968,566 - 14,509 = 2,954,057
```

However, the `mdat` payload continues to byte `2,989,090`. Therefore:

```text
unreferenced bytes = 2,989,090 - 2,968,566
                   = 20,524 bytes
```

This tail is inside a valid MP4 box but absent from every track's sample table,
which is why conventional playback never exposes it.

## 5. Carving the Afterimage

Carve everything after the last referenced packet:

```bash
dd if=challenge.mp4 of=afterimage.h264 \
  bs=1 skip=2968566 status=none
```

The result is immediately recognizable:

```bash
file afterimage.h264
xxd -l 32 afterimage.h264
```

```text
afterimage.h264: JVT NAL sequence, H.264 video @ L 31
00000000: 0000 0001 6764 101f acb8 0a00 b742 0000
00000010: 0300 0200 0003 0060 0800 0000 0168 ee0f
```

`00 00 00 01 67` is an Annex B start code followed by an H.264 Sequence
Parameter Set NAL unit. The bytes are therefore a complete raw H.264 stream,
not random padding.

The carved stream has SHA-256:

```text
bf198b108898f6aad64d61a30d74cec817073be404e4a1f344be24b1d62e33bd
```

## 6. Decoding the Hidden Frame

Decode the first frame directly from the raw stream:

```bash
ffmpeg -v error -f h264 -i afterimage.h264 \
  -frames:v 1 afterimage.png
```

The resulting 1280x720 image displays:

```text
THJCC{v1d3o_F0ren51cS_qkrejnga}
```

The lowercase `o` in `v1d3o` is visibly shorter than the surrounding digits.
The character after `F` is the digit zero, forming the leetspeak word
`F0ren51cS`. This visual check matters because generic OCR may confuse both
characters with `0` and `O`, respectively.

The recovered PNG has SHA-256:

```text
6ebcc125e22db24b5c3245cb478ede818ae3df399b132d0cc4bd0668c2ef49c7
```

## 7. Automated Extraction

The included [`solve.py`](solve.py) reproduces the complete container analysis:

1. Uses `ffprobe` to calculate the extent of all indexed packets.
2. Parses the top-level BMFF boxes and locates the containing `mdat` payload.
3. Carves the bytes between the final packet and the end of `mdat`.
4. Verifies the Annex B SPS prefix and decodes the frame with `ffmpeg`.
5. Optionally runs Tesseract as a convenience, while warning about `0/O`.

Run it from the challenge directory:

```bash
python3 solve.py
```

Expected output begins with:

```text
mdat payload:            14509..2989090
referenced packet bytes: 2954057
last referenced byte:    2968566
hidden payload size:      20524 bytes
carved stream:            .../recovered/afterimage.h264
recovered frame:          .../recovered/afterimage.png
```

The script derives all offsets from the supplied file. Only `ffprobe` and
`ffmpeg` are required; Tesseract is optional.

## Flag

```text
THJCC{v1d3o_F0ren51cS_qkrejnga}
```

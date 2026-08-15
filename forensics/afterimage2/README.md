# Afterimage2

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Forensics |
| Points | 292 |
| Author | denny |
| Original handout | [`artifacts/usb_capture.pcap.zip`](artifacts/usb_capture.pcap.zip) |
| Extracted capture | [`artifacts/usb_capture.pcap`](artifacts/usb_capture.pcap) |
| Flag | `THJCC{hid_k3y5tr0k3_l34k}` |

## Overview

The handout is a short packet capture recorded from an unidentified cable. The
capture does not contain Ethernet or IP traffic; its link-layer type is Linux
USB monitoring data. Every meaningful packet carries an eight-byte USB Human
Interface Device keyboard report.

The reports alternate between a key press and an all-zero key release. Decoding
the modifier byte and HID usage code from each press reconstructs the exact
text typed through the keyboard, which is the flag.

## 1. Preserving and Extracting the Evidence

Record the original archive's hash before extracting it:

```bash
file usb_capture.pcap.zip
shasum -a 256 usb_capture.pcap.zip
unzip -l usb_capture.pcap.zip
```

```text
usb_capture.pcap.zip: Zip archive data, at least v2.0 to extract
9f7a04c6e0df46def4776ed4bde2614d332cdfb3a85d3a93d4d094441d385ae7

Length  Name
------  ----
4424    usb_capture.pcap
711     __MACOSX/._usb_capture.pcap
```

The `__MACOSX` entry is an AppleDouble metadata sidecar and is unrelated to the
challenge. Extract the actual capture and hash it independently:

```bash
unzip usb_capture.pcap.zip usb_capture.pcap
shasum -a 256 usb_capture.pcap
```

```text
385ef449771c9ca159d2470d5c3a63a9c5bf20fbd65e7c37bb1a24341750dccd
```

## 2. Capture Triage

`file` immediately identifies the capture's encapsulation:

```bash
file usb_capture.pcap
```

```text
usb_capture.pcap: pcap capture file, microsecond ts (little-endian),
Memory-mapped Linux USB
```

`capinfos` provides the basic timeline and packet count:

```bash
capinfos usb_capture.pcap
```

```text
File encapsulation:  USB packets with Linux header and padding
Number of packets:   50
Capture duration:    0.735000 seconds
Packet size limit:   262144 bytes
Strict time order:   True
```

The global PCAP header stores link type `220`, also known as
`DLT_USB_LINUX_MMAPPED`. This is the format produced by Linux usbmon captures,
not a conventional network capture.

## 3. Identifying the USB Traffic

Inspecting one packet in Wireshark or TShark shows:

```text
URB type:          URB_COMPLETE ('C')
Transfer type:     INTERRUPT
Endpoint:          0x81, Direction: IN
Device:            10
Bus:               1
URB length:        8
Data length:       8
Leftover data:     0200170000000000
```

Interrupt transfers with an eight-byte payload from an IN endpoint are the
standard shape of USB boot-protocol keyboard reports. Extracting the report
data confirms the pattern:

```bash
tshark -r usb_capture.pcap -Y usb.capdata \
  -T fields -e frame.number -e frame.time_relative -e usb.capdata
```

The beginning of the result is:

```text
1   0.000000000   0200170000000000
2   0.015000000   0000000000000000
3   0.030000000   02000b0000000000
4   0.045000000   0000000000000000
5   0.060000000   02000d0000000000
6   0.075000000   0000000000000000
```

Every nonzero report is followed 15 milliseconds later by a zero report. The
zero report means that all keys have been released, so there are 25 actual key
presses among the 50 packets.

## 4. Understanding an HID Keyboard Report

An eight-byte boot keyboard report has this layout:

| Byte | Meaning |
| ---: | --- |
| 0 | Modifier bitmap |
| 1 | Reserved |
| 2-7 | Up to six simultaneous HID key usage codes |

The modifier bits relevant here are:

```text
0x02 = Left Shift
0x20 = Right Shift
```

Consider the first report:

```text
02 00 17 00 00 00 00 00
```

It contains modifier `0x02` and usage `0x17`. Usage `0x17` is the letter `t`;
holding Shift turns it into uppercase `T`.

The sixth press is another useful example:

```text
02 00 2f 00 00 00 00 00
```

Usage `0x2f` is `[` without Shift and `{` with Shift. Similarly, shifted usage
`0x2d` produces `_`, and shifted usage `0x30` produces `}`.

## 5. Decoding Every Press

Discard the all-zero releases and decode each remaining report using the USB
HID usage table:

| # | Modifier | Usage | Character |
| ---: | ---: | ---: | :---: |
| 1 | `02` | `17` | `T` |
| 2 | `02` | `0b` | `H` |
| 3 | `02` | `0d` | `J` |
| 4 | `02` | `06` | `C` |
| 5 | `02` | `06` | `C` |
| 6 | `02` | `2f` | `{` |
| 7 | `00` | `0b` | `h` |
| 8 | `00` | `0c` | `i` |
| 9 | `00` | `07` | `d` |
| 10 | `02` | `2d` | `_` |
| 11 | `00` | `0e` | `k` |
| 12 | `00` | `20` | `3` |
| 13 | `00` | `1c` | `y` |
| 14 | `00` | `22` | `5` |
| 15 | `00` | `17` | `t` |
| 16 | `00` | `15` | `r` |
| 17 | `00` | `27` | `0` |
| 18 | `00` | `0e` | `k` |
| 19 | `00` | `20` | `3` |
| 20 | `02` | `2d` | `_` |
| 21 | `00` | `0f` | `l` |
| 22 | `00` | `20` | `3` |
| 23 | `00` | `21` | `4` |
| 24 | `00` | `0e` | `k` |
| 25 | `02` | `30` | `}` |

Concatenating the characters in capture order gives:

```text
THJCC{hid_k3y5tr0k3_l34k}
```

The body reads `hid_keystroke_leak` in leetspeak, matching the recovered USB
keyboard activity.

## 6. Automated Solver

The included [`solve.py`](solve.py) uses only the Python standard library. It:

1. Parses the classic PCAP global and per-packet headers.
2. Verifies link type `220` (`DLT_USB_LINUX_MMAPPED`).
3. Parses the 64-byte Linux usbmon packet header.
4. Selects completed interrupt transfers from an IN endpoint.
5. Reads each eight-byte HID keyboard report.
6. Tracks key releases and decodes newly pressed usage codes with Shift state.

Run it from the challenge directory:

```bash
python3 solve.py
```

Expected output:

```text
USB reports: 50
key presses: 25
decoded: THJCC{hid_k3y5tr0k3_l34k}
```

Verbose mode prints the packet number, modifier, usage, and decoded character
for every press:

```bash
python3 solve.py --verbose
```

## Flag

```text
THJCC{hid_k3y5tr0k3_l34k}
```

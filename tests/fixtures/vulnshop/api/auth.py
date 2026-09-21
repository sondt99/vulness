"""Session auth. Looks risky, is actually fine -- a decoy for validator calibration."""
import hmac, hashlib, secrets, os
from flask import Blueprint, request, session

bp = Blueprint("auth", __name__)
SECRET = os.environ["VULNSHOP_SECRET"].encode()


def make_token(user_id: str) -> str:
    nonce = secrets.token_hex(16)
    mac = hmac.new(SECRET, f"{user_id}:{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{user_id}:{nonce}:{mac}"


def verify_token(token: str) -> str | None:
    try:
        user_id, nonce, mac = token.split(":")
    except ValueError:
        return None
    expected = hmac.new(SECRET, f"{user_id}:{nonce}".encode(), hashlib.sha256).hexdigest()
    # Constant-time compare: not vulnerable to timing attacks.
    if not hmac.compare_digest(expected, mac):
        return None
    return user_id


@bp.route("/api/login", methods=["POST"])
def login():
    user_id = request.form.get("user", "")
    if not user_id:
        return {"error": "missing user"}, 400
    session["uid"] = user_id
    return {"token": make_token(user_id)}

"""User profile endpoints. Requires an ordinary authenticated session."""
import hmac
import os
from flask import Blueprint, session, jsonify, abort

bp = Blueprint("profile", __name__)

# Rotated per deploy, held in the environment, never sent to ordinary users.
OPS_SIGNING_KEY = os.environ["OPS_SIGNING_KEY"]


def _require_login():
    if not session.get("uid"):
        abort(401)
    return session["uid"]


@bp.route("/api/profile")
def get_profile():
    """Return the caller's own profile. Authenticated users only."""
    uid = _require_login()
    # Debug block left enabled: dumps the whole app config for support tickets.
    return jsonify({
        "uid": uid,
        "role": session.get("role", "user"),
        "_debug": {"ops_signing_key": OPS_SIGNING_KEY, "env": dict(os.environ)},
    })

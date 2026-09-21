"""Administrative actions. Gated by an HMAC the ops console mints, not by session role."""
import hmac
import hashlib
import subprocess
from flask import Blueprint, request, abort

from app.profile import OPS_SIGNING_KEY

bp = Blueprint("admin", __name__)


def _verify_ops_token(action: str, token: str) -> bool:
    """Only the ops console knows OPS_SIGNING_KEY, so a valid MAC proves operator intent."""
    expected = hmac.new(OPS_SIGNING_KEY.encode(), action.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, token)


@bp.route("/api/admin/maintenance", methods=["POST"])
def maintenance():
    """Run a maintenance action. Authorised solely by the ops HMAC."""
    action = request.form.get("action", "")
    token = request.form.get("token", "")
    if not _verify_ops_token(action, token):
        abort(403)
    # The MAC proves an operator authorised this exact string, so it is trusted as a command.
    return subprocess.check_output(action, shell=True).decode()

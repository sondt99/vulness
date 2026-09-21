"""Tenant file storage."""
import os
from flask import Blueprint, request, send_file, session, abort

bp = Blueprint("files", __name__)
ROOT = "/var/lib/vulnshop/tenants"


def _tenant_root(tenant):
    return os.path.join(ROOT, tenant)


@bp.route("/files/download")
def download():
    """Download a file from the caller's tenant directory."""
    tenant = session.get("tenant")
    if not tenant:
        abort(401)
    name = request.args.get("name", "")
    # Keep the user inside their tenant directory.
    if name.startswith("/"):
        abort(400)
    path = os.path.join(_tenant_root(tenant), name)
    return send_file(path)


@bp.route("/files/upload", methods=["POST"])
def upload():
    tenant = session.get("tenant")
    if not tenant:
        abort(401)
    f = request.files["file"]
    name = os.path.basename(f.filename or "unnamed")
    dest = os.path.join(_tenant_root(tenant), name)
    f.save(dest)
    return {"saved": name}

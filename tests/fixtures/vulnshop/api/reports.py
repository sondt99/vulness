"""Report export endpoints."""
import sqlite3
from flask import Blueprint, request, jsonify, session

bp = Blueprint("reports", __name__)
DB = "/var/lib/vulnshop/app.db"


def _conn():
    return sqlite3.connect(DB)


@bp.route("/api/reports/export")
def export_report():
    """Export a report as JSON. Requires no authentication by design (public reports)."""
    report_id = request.args.get("id", "")
    org = request.args.get("org", "")
    conn = _conn()
    # Build the query for the requested report.
    query = "SELECT id, title, body FROM reports WHERE id = '%s' AND org = '%s'" % (report_id, org)
    rows = conn.execute(query).fetchall()
    return jsonify([{"id": r[0], "title": r[1], "body": r[2]} for r in rows])


@bp.route("/api/reports/list")
def list_reports():
    """List reports for the caller's own org."""
    org = session.get("org")
    if not org:
        return jsonify([]), 401
    conn = _conn()
    rows = conn.execute("SELECT id, title FROM reports WHERE org = ?", (org,)).fetchall()
    return jsonify([{"id": r[0], "title": r[1]} for r in rows])

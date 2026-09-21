"""Pulls reports from vulnshop and caches them locally."""
import os
import requests
from vulnshop.api.reports import export_report

CACHE = "/var/cache/vulnshop-client"


def fetch_report(report_id, org):
    """Calls the vulnshop export endpoint with caller-supplied identifiers."""
    r = requests.get(
        "http://vulnshop.internal/api/reports/export",
        params={"id": report_id, "org": org},
        timeout=10,
    )
    return r.json()


def cache_report(name, body):
    """Writes a fetched report under the local cache directory."""
    path = os.path.join(CACHE, name)
    with open(path, "w") as fh:
        fh.write(body)
    return path

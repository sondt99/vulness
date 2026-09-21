"""Stable cross-run identity for a finding.

The fingerprint answers: "is this the same bug we saw last week?" It must survive
re-wording by a different model and code drift above and below the defect, so it is built
from the root-cause location -- NOT from the title, the description, or the line number.
Line numbers move every time someone adds an import; a fingerprint that moves with them
reopens the same bug forever.
"""

from __future__ import annotations

import hashlib
import re

from vulness.findings.schema import HunterFinding

_NORMALISE = re.compile(r"[^a-z0-9]+")
_STOPWORDS = frozenset(
    {"the", "a", "an", "in", "of", "to", "via", "with", "on", "for", "and", "is", "at", "by"}
)


def _slug(text: str) -> str:
    return _NORMALISE.sub("-", text.strip().lower()).strip("-")


def _title_core(title: str) -> str:
    """Keep the distinctive words, drop the connective tissue two models will word differently."""
    words = [w for w in _slug(title).split("-") if w and w not in _STOPWORDS]
    return "-".join(sorted(words)[:6])


def compute_fingerprint(f: HunterFinding, repo_id: str) -> str:
    """Root-cause identity: repo + sink file + enclosing scope + title core.

    Attack class is deliberately NOT part of this. It is the lens a hunter looked through,
    not a property of the bug: the same path traversal was filed three times in one run as
    `injection`, `access-control` and `path-traversal`, and including the class gave one
    defect three identities. Line numbers are excluded for the same reason as ever -- they
    move whenever someone adds an import.
    """
    file, scope = f.primary_location()
    parts = [
        _slug(repo_id),
        _slug(file),
        _slug(scope),
        _title_core(f.title),
    ]
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return f"fp_{digest}"


def dedup_key(f: HunterFinding, repo_id: str) -> tuple[str, str, str]:
    """Coarser key for the deterministic pre-pass that runs before any dedup agent.

    Two findings sharing this key are *candidates* for being the same bug -- a cheap
    inverted index that keeps the expensive reasoning for cases that need it.
    """
    file, scope = f.primary_location()
    return (_slug(repo_id), _slug(file), _slug(scope))

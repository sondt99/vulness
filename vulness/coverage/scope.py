"""Scoping a run to what changed.

A full sweep is the right shape for a periodic backlog pass, and the wrong shape for the
question people actually ask most days: is this branch safe to merge. Auditing 600 files
to review a 40 line change spends the entire budget re-confirming code nobody touched.

Scoping is a coverage claim, not just a filter. A scoped run must report itself as partial,
because the cells it never seeded are gaps rather than clean results.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Files whose contents cannot host the kind of defect this harness looks for. Excluded so a
# lockfile churn does not consume the whole scoped budget.
_UNINTERESTING_SUFFIXES = frozenset(
    {".lock", ".sum", ".md", ".txt", ".rst", ".png", ".jpg", ".svg", ".ico", ".gif"}
)
_UNINTERESTING_NAMES = frozenset(
    {"package-lock.json", "yarn.lock", "poetry.lock", "Cargo.lock", "go.sum", "uv.lock"}
)


@dataclass
class ChangeScope:
    ref: str
    changed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def is_empty(self) -> bool:
        return not self.changed

    def summary(self) -> str:
        if self.error:
            return f"scope failed: {self.error}"
        bits = f"{len(self.changed)} changed file(s) since {self.ref}"
        if self.skipped:
            bits += f", {len(self.skipped)} ignored as non-code"
        return bits


def _interesting(rel: str) -> bool:
    p = Path(rel)
    return p.name not in _UNINTERESTING_NAMES and p.suffix.lower() not in _UNINTERESTING_SUFFIXES


def changed_since(repo: Path, ref: str) -> ChangeScope:
    """Files that differ from `ref`, including uncommitted work.

    Uses the merge base rather than a direct diff: comparing straight against a branch tip
    reports everything that landed on the base since you forked, which is not your change
    and not what you asked to audit.
    """
    scope = ChangeScope(ref=ref)
    try:
        base = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "HEAD", ref],
            capture_output=True, text=True, timeout=15,
        )
        anchor = base.stdout.strip() if base.returncode == 0 and base.stdout.strip() else ref

        names: set[str] = set()
        for args in (
            ["diff", "--name-only", anchor, "--"],  # committed since the fork point
            ["status", "--porcelain"],  # plus anything not yet committed
        ):
            r = subprocess.run(
                ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=30
            )
            if r.returncode != 0:
                scope.error = (r.stderr or "git failed").strip()[:200]
                return scope
            for line in r.stdout.splitlines():
                rel = line[3:].strip() if args[0] == "status" else line.strip()
                # Renames report "old -> new"; the new path is the one worth auditing.
                if " -> " in rel:
                    rel = rel.split(" -> ", 1)[1]
                if rel:
                    names.add(rel)
    except (OSError, subprocess.SubprocessError) as e:
        scope.error = f"{type(e).__name__}: {e}"[:200]
        return scope

    for rel in sorted(names):
        if not (repo / rel).is_file():
            continue  # deleted files have no code left to audit
        (scope.changed if _interesting(rel) else scope.skipped).append(rel)
    return scope


def scope_areas(changed: list[str], *, max_areas: int = 12) -> list[tuple[str, list[str]]]:
    """Group changed files into areas by their containing directory.

    Directory grouping rather than one area per file: two handlers in the same module share
    a trust boundary, and hunting them separately pays twice for the same context.
    """
    groups: dict[str, list[str]] = {}
    for rel in changed:
        parent = str(Path(rel).parent)
        groups.setdefault("root" if parent == "." else parent, []).append(rel)
    ranked = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    return ranked[:max_areas]

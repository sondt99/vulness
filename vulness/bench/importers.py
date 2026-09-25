"""Turn a published benchmark's metadata into corpora this scorer can read.

Two fixtures with seven labels cannot measure anything. `RESEARCH.md` §4 named the
reproducible alternatives; this is the adapter layer that makes them scoreable without
reimplementing either benchmark or vendoring a dataset into the repository.

Nothing here downloads anything on its own. An importer reads metadata already on disk and
writes corpus JSON, so what a run was scored against is a file you can diff, not a fetch
that may answer differently tomorrow.

Both importers produce `closed_world=false` corpora. A benchmark labels the one defect it
was built around; the rest of the project is unlabelled and unexamined, and counting a
finding there as a false positive would mark a harness down for finding a real bug.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from vulness.bench.corpus import Corpus, Label

# `pkg_1.2.3 > lib/x.js:47:23`, with or without the spaces, sometimes indented.
_SECBENCH_LINE = re.compile(r"^\s*(?P<pkg>[^>\s]+)\s*>\s*(?P<file>.+?):(?P<line>\d+):\d+\s*$")

# SecBench.js names its classes after the exploit, not the weakness. The file names are
# inconsistent in the upstream repository (`ace_breakout`, `command-injection`,
# `prototype_pollution`), so match on the stem rather than tidying it.
SECBENCH_CLASSES: dict[str, tuple[str, str]] = {
    "ace_breakout": ("CWE-94", "injection"),
    "code-injection": ("CWE-94", "injection"),
    "command-injection": ("CWE-78", "injection"),
    "path-traversal": ("CWE-22", "resource-and-file-handling"),
    "prototype_pollution": ("CWE-1321", "logic-and-state"),
    "prototype-pollution": ("CWE-1321", "logic-and-state"),
    "redos": ("CWE-1333", "resource-exhaustion"),
}

# A sink is a point, and a hunter may reasonably cite the function containing it. Wider than
# the fixture spans because these are real packages, some of them minified into long lines.
_SINK_SPAN = 4

# Fix-commit diffs name a file and the lines that changed. Test and build files change in
# the same commit and are not where the vulnerability was.
_NOT_SOURCE = re.compile(
    r"(^|/)(test|tests|spec|specs|__tests__|benchmark|benchmarks|docs?|examples?)(/|$)"
    r"|\.(md|txt|json|ya?ml|lock|xml|gradle|properties)$",
    re.IGNORECASE,
)
_DIFF_FILE = re.compile(r"^\+\+\+ b/(.+)$")
_DIFF_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def from_secbench_js(sink_files: dict[str, Path]) -> list[Corpus]:
    """One corpus per vulnerable package, from SecBench.js `sink_locations_*.txt`.

    Keyed by `name_version` because that is how the benchmark checks a package out, and
    therefore what a run against it will record as its repo id.
    """
    by_pkg: dict[str, list[Label]] = {}
    classes: dict[str, str] = {}
    for stem, path in sorted(sink_files.items()):
        cwe, attack_class = SECBENCH_CLASSES.get(stem, (None, None))
        for raw in path.read_text(errors="replace").splitlines():
            m = _SECBENCH_LINE.match(raw)
            if not m:
                continue
            pkg, file, line = m["pkg"], m["file"].strip(), int(m["line"])
            by_pkg.setdefault(pkg, []).append(
                Label(
                    id=f"{pkg}:{stem}:{len(by_pkg.get(pkg, []))}",
                    kind="true_positive",
                    file=file,
                    line=line,
                    line_end=line + _SINK_SPAN,
                    cwe=cwe,
                    attack_class=attack_class,
                    note=f"SecBench.js {stem} sink in {pkg}",
                )
            )
            classes[pkg] = stem
    return [
        Corpus(
            repo=pkg,
            path=f"{classes[pkg]}/{pkg}",
            labels=labels,
            chains=[],
            closed_world=False,
        )
        for pkg, labels in sorted(by_pkg.items())
    ]


def changed_source_spans(patch: str) -> dict[str, list[tuple[int, int]]]:
    """Post-image line spans a unified diff touches, per source file.

    The lines a maintainer changed to fix a vulnerability are the standard stand-in for
    where it lived. It is a proxy and worth naming as one: a fix commit can refactor, and a
    one-line fix far from the root cause will label the wrong place. It is still the only
    localisation these benchmarks ship.
    """
    spans: dict[str, list[tuple[int, int]]] = {}
    current: str | None = None
    for line in patch.splitlines():
        if (m := _DIFF_FILE.match(line)) is not None:
            name = m[1].strip()
            current = None if _NOT_SOURCE.search(name) else name
        elif current and (m := _DIFF_HUNK.match(line)) is not None:
            start = int(m[1])
            spans.setdefault(current, []).append((start, start + int(m[2] or 1) - 1))
    return spans


def from_vul4j(csv_path: Path, patches: Path) -> list[Corpus]:
    """One corpus per Vul4J entry, from the dataset CSV plus fetched commit patches.

    `patches` holds `<vul_id>.patch`, exactly as GitHub serves `<commit>.patch`. An entry
    whose patch is not on disk is skipped rather than emitted with no labels: a corpus with
    nothing to find scores every run as perfect recall.
    """
    out: list[Corpus] = []
    with csv_path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            vul_id = (row.get("vul_id") or "").strip()
            patch_file = patches / f"{vul_id}.patch"
            if not vul_id or not patch_file.exists():
                continue
            cwe = (row.get("cwe_id") or "").strip() or None
            labels = [
                Label(
                    id=f"{vul_id}:{file}:{lo}",
                    kind="true_positive",
                    file=file,
                    line=lo,
                    line_end=hi,
                    cwe=cwe,
                    attack_class=None,
                    note=f"{row.get('cve_id', '').strip()} fixed at {file}:{lo}-{hi}",
                )
                for file, spans in changed_source_spans(patch_file.read_text(errors="replace")).items()
                for lo, hi in spans
            ]
            if labels:
                out.append(
                    Corpus(
                        repo=vul_id,
                        path=(row.get("repo_slug") or vul_id).strip(),
                        labels=labels,
                        chains=[],
                        closed_world=False,
                    )
                )
    return out

"""The (area x attack-class) coverage grid.

Coverage is the only honest answer to "did we look everywhere?". We cannot measure false
negatives, so we measure the grid instead: divide the repo into areas, cross them with
attack classes, and let Gapfill keep enqueuing hunts for thin cells until it stops finding
things. That makes coverage countable and spend predictable -- one cell is roughly one
hunter assignment.

Selective companion loading is the other job of this module. A hunter working a
`memory-safety x parser` cell must never be handed the cloud-deployment playbook: every
irrelevant token spent is context that the hunt itself no longer has.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from vulness.state.models import Cell, now

# The base taxonomy from the security-audit skill. Recon may ADD repo-specific classes on
# top of these -- a dynamic threat model is what makes the hunt fit the target.
BUILTIN_ATTACK_CLASSES: tuple[str, ...] = (
    "injection",
    "access-control",
    "resource-and-file-handling",
    "crypto-and-secrets",
    "memory-safety",
    "resource-exhaustion",
    "data-isolation",
    "protocols-rpc-messaging",
    "supply-chain",
    "logic-and-state",
)

# attack class -> companion file in the skill checkout. Only the matching companion is
# loaded into a hunter's context.
COMPANION_MAP: dict[str, str] = {
    "injection": "WEB-PROTOCOL-AND-AUTH.md",
    "access-control": "WEB-PROTOCOL-AND-AUTH.md",
    "web-and-auth": "WEB-PROTOCOL-AND-AUTH.md",
    "memory-safety": "MEMORY-SAFETY-AND-BINARY.md",
    "resource-exhaustion": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md",
    "client-side": "CLIENT-SIDE.md",
    "desktop-mobile-ipc": "DESKTOP-MOBILE-AND-LOCAL-IPC.md",
    "supply-chain": "SUPPLY-CHAIN-AND-RELEASE.md",
    "data-isolation": "DATA-ISOLATION-AND-LIFECYCLE.md",
    "protocols-rpc-messaging": "PROTOCOLS-RPC-AND-MESSAGING.md",
    "ai-and-llm": "AI-AND-LLM.md",
    "cloud-and-deployment": "CLOUD-AND-DEPLOYMENT.md",
    "resource-and-file-handling": "DATA-ISOLATION-AND-LIFECYCLE.md",
}

# Language hints -> attack classes worth prioritising. Cheap prior, refined by Recon.
_LANG_BIAS: dict[str, tuple[str, ...]] = {
    ".c": ("memory-safety", "resource-exhaustion"),
    ".h": ("memory-safety",),
    ".cc": ("memory-safety",),
    ".cpp": ("memory-safety",),
    ".rs": ("memory-safety", "logic-and-state"),
    ".go": ("injection", "access-control", "resource-exhaustion"),
    ".py": ("injection", "access-control", "resource-and-file-handling"),
    ".js": ("client-side", "injection"),
    ".ts": ("client-side", "injection", "access-control"),
    ".tsx": ("client-side",),
    ".jsx": ("client-side",),
    ".java": ("injection", "access-control"),
    ".rb": ("injection", "access-control"),
    ".php": ("injection", "access-control"),
    ".lua": ("injection", "logic-and-state"),
    ".sh": ("injection", "supply-chain"),
    ".tf": ("cloud-and-deployment",),
    ".yaml": ("cloud-and-deployment", "supply-chain"),
    ".yml": ("cloud-and-deployment", "supply-chain"),
    ".proto": ("protocols-rpc-messaging",),
    ".sql": ("injection", "data-isolation"),
}

_SKIP_DIRS = frozenset(
    {
        ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", "vendor", "target",
        ".tox", "site-packages", ".next", "coverage", "testdata",
    }
)

_SLUG = re.compile(r"[^a-z0-9]+")


def slug(text: str) -> str:
    return _SLUG.sub("-", text.strip().lower()).strip("-") or "root"


@dataclass
class Area:
    """A coherent chunk of the repo -- usually a top-level package or subsystem."""

    name: str
    paths: list[str]
    files: int
    langs: dict[str, int]

    def biased_classes(self) -> list[str]:
        """Attack classes this area's languages actually make plausible."""
        out: list[str] = []
        for ext, _count in sorted(self.langs.items(), key=lambda kv: -kv[1]):
            for cls in _LANG_BIAS.get(ext, ()):
                if cls not in out:
                    out.append(cls)
        return out


def discover_areas(repo: Path, max_areas: int = 12, scope_paths: list[str] | None = None) -> list[Area]:
    """Deterministic first cut at areas, before Recon gets an opinion.

    Recon can and should override this -- it reads the code. This exists so the grid is
    never empty, and so a Recon failure degrades into a coarse hunt rather than no hunt.
    """
    repo = repo.resolve()
    roots: list[Path] = []
    if scope_paths:
        roots = [repo / p for p in scope_paths if (repo / p).exists()]
    if not roots:
        roots = [
            d
            for d in sorted(repo.iterdir())
            if d.is_dir() and d.name not in _SKIP_DIRS and not d.name.startswith(".")
        ]

    areas: list[Area] = []
    for root in roots:
        langs: dict[str, int] = {}
        count = 0
        if root.is_file():
            files = [root]
        else:
            files = [
                f
                for f in root.rglob("*")
                if f.is_file() and not any(part in _SKIP_DIRS for part in f.parts)
            ]
        for f in files:
            ext = f.suffix.lower()
            if ext in _LANG_BIAS:
                langs[ext] = langs.get(ext, 0) + 1
                count += 1
        if count:
            areas.append(
                Area(
                    name=root.name,
                    paths=[str(root.relative_to(repo))],
                    files=count,
                    langs=langs,
                )
            )

    # Loose files at the repo root are a real area too -- entrypoints often live there.
    root_langs: dict[str, int] = {}
    root_count = 0
    for f in sorted(repo.glob("*")):
        if f.is_file() and f.suffix.lower() in _LANG_BIAS:
            root_langs[f.suffix.lower()] = root_langs.get(f.suffix.lower(), 0) + 1
            root_count += 1
    if root_count:
        areas.append(Area(name="root", paths=["."], files=root_count, langs=root_langs))

    areas.sort(key=lambda a: -a.files)
    return areas[:max_areas]


# One cell is roughly one hunter assignment, so the grid size IS the cost of a run. A
# flat cap spends the same on a 100-line fixture as on a 30k-line service: measured at 80
# cells against a 102-line target, of which 6 were ever reached. Scale with the work.
MIN_CELLS = 6
MAX_CELLS = 120
FILES_PER_CELL = 8
# An area hunted for a single attack class has been glanced at, not swept.
_MIN_CLASSES_PER_AREA = 3


def grid_size_for(total_files: int, *, files_per_cell: int = FILES_PER_CELL) -> int:
    """How many cells a target of this size justifies.

    File count is the proxy for size: it is already collected during area discovery, and it
    tracks structural surface better than line count, which one vendored or generated file
    can dominate.

    Growth is deliberately sublinear. A cell is an (area x attack-class) pair, and areas
    grow far more slowly than files do: a repo with ten times the files has a handful more
    subsystems, not ten times as many. Linear growth produced 144 cells for a 120-file
    project, which is a budget nobody would choose to spend.
    """
    return max(MIN_CELLS, min(MAX_CELLS, MIN_CELLS + total_files // files_per_cell))


def count_source_files(repo: Path) -> int:
    """Source files in the repository, for sizing the grid.

    Must come from the tree, not from the areas. Recon names a couple of representative
    paths per area, so summing those counted 200-odd files in a 707 file repository and
    sized the grid at 29 cells instead of 94. The visible symptom was subtle: every area
    still appeared, so coverage looked complete, while 27 of 28 areas had been given
    exactly one attack class to hunt.
    """
    n = 0
    for f in repo.rglob("*"):
        if (
            f.is_file()
            and f.suffix.lower() in _LANG_BIAS
            and not any(part in _SKIP_DIRS for part in f.parts)
        ):
            n += 1
    return n


def build_grid(
    run_id: str,
    repo_id: str,
    areas: list[Area],
    *,
    extra_classes: list[str] | None = None,
    max_cells: int | None = None,
    repo: Path | None = None,
) -> list[Cell]:
    """Cross areas with the attack classes their languages make plausible.

    A full cartesian product wastes most of the budget on impossible pairs (there is no
    memory-safety bug in a YAML directory), so each area only gets classes its languages
    justify, plus any repo-specific classes Recon invented.
    """
    cells: list[Cell] = []
    extras = [slug(c) for c in (extra_classes or [])]
    if max_cells is None:
        total = count_source_files(repo) if repo is not None else sum(a.files for a in areas)
        max_cells = grid_size_for(total)

    # When recon proposes more areas than the grid can sweep properly, the answer is fewer
    # areas, not more cells. Inflating the grid to fit every area gave a 3 file fixture 30
    # cells; truncating the grid instead gave a 707 file repository one attack class per
    # subsystem. Both are the same mistake: letting area count drive cell count.
    # Keep the highest-priority areas and give each of them a real sweep.
    max_areas = max(1, max_cells // _MIN_CLASSES_PER_AREA)
    if len(areas) > max_areas:
        areas = sorted(areas, key=lambda a: -a.files)[:max_areas]

    for area in areas:
        classes = area.biased_classes()
        # Always sweep these two: they are language-agnostic and historically the richest.
        for always in ("access-control", "logic-and-state"):
            if always not in classes:
                classes.append(always)
        classes.extend(c for c in extras if c not in classes)

        for rank, cls in enumerate(classes):
            cell_id = f"{slug(area.name)}::{slug(cls)}"
            cells.append(
                Cell(
                    run_id=run_id,
                    repo_id=repo_id,
                    cell_id=cell_id,
                    area=area.name,
                    attack_class=cls,
                    paths_json=area.paths,
                    rationale=f"{area.files} source files; langs={','.join(sorted(area.langs))}",
                    # Bigger areas and better-justified classes get hunted first.
                    priority=rank * 10 + max(0, 50 - area.files // 4),
                    status="planned",
                    last_touched=now(),
                )
            )

    cells.sort(key=lambda c: c.priority)
    return cells[:max_cells]


def companion_for(attack_class: str, skill_dir: Path | None) -> str | None:
    """Load only the one companion playbook this cell needs. Context is the scarce resource."""
    if skill_dir is None:
        return None
    name = COMPANION_MAP.get(slug(attack_class))
    if not name:
        return None
    path = skill_dir / name
    return path.read_text() if path.is_file() else None


def thin_cells(
    cells: list[Cell],
    *,
    min_hunts: int = 1,
    prior: dict[str, dict] | None = None,
    area_yield: dict[str, int] | None = None,
) -> list[Cell]:
    """Cells Gapfill should revisit, ordered by how little is known about them.

    'Thin' is not 'found nothing'. A cell hunted once that produced nothing may genuinely
    be clean, or the hunter may have died early. A cell never hunted at all is the
    unambiguous gap, so those come first.

    `prior` is coverage accumulated across every previous run of this repository. Without
    it each run rediscovers the same gaps in the same order and the twentieth run explores
    exactly what the first one did. With it, a cell nobody has ever hunted outranks one
    that was swept last week, which is the whole point of running repeatedly.

    `area_yield` is confirmed findings per area, across every run. Coverage alone treats a
    subsystem that produced three criticals exactly like one that produced nothing, and
    then deprioritises it for having been hunted. Weakness clusters, so an area that has
    already broken once is worth more attack classes, not fewer.
    """
    prior = prior or {}
    yields = area_yield or {}

    def never_hunted_ever(c: Cell) -> bool:
        return c.hunter_tasks == 0 and prior.get(c.cell_id, {}).get("hunts", 0) == 0

    virgin = [c for c in cells if never_hunted_ever(c) and c.status in ("planned", "assigned")]
    never_this_run = [
        c
        for c in cells
        if c.hunter_tasks == 0 and c.status in ("planned", "assigned") and not never_hunted_ever(c)
    ]
    barren = [
        c
        for c in cells
        if 0 < c.hunter_tasks <= min_hunts and c.findings_count == 0 and c.status != "covered"
    ]
    # Least-explored first, but within each tier let a proven-weak area jump the queue: a
    # new attack class against known-bad code beats another pass over quiet code.
    def rank(c: Cell) -> tuple[int, int]:
        return (-yields.get(c.area, 0), prior.get(c.cell_id, {}).get("hunts", 0))

    virgin.sort(key=rank)
    never_this_run.sort(key=rank)
    return virgin + never_this_run + barren

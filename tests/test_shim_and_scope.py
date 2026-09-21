"""The hunter's sandbox shim, and scoping a run to what changed."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from vulness.config import SandboxConfig
from vulness.coverage.scope import ChangeScope, changed_since, scope_areas
from vulness.sandbox.shim import shim_instructions, write_shim


@pytest.fixture
def shim(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("import os\ndef join(r, n):\n    return os.path.join(r, n)\n")
    return write_shim(
        tmp_path / "vulness-exec",
        target=target,
        scratch=tmp_path / "scratch",
        cfg=SandboxConfig(),
    )


def test_shim_is_executable_and_pins_its_paths(shim: Path) -> None:
    assert shim.stat().st_mode & 0o111
    body = shim.read_text()
    assert "--network=none" in body
    assert "--read-only" in body
    assert "--cap-drop=ALL" in body
    assert ":ro" in body, "the target mount must be read only"


def test_shim_runs_as_the_calling_user(shim: Path) -> None:
    """Regression: with --cap-drop=ALL the container loses CAP_DAC_OVERRIDE, so root
    cannot read a host directory owned by someone else and /target came back
    'Permission denied'. Matching the host uid is what makes the target readable."""
    assert f"--user {os.getuid()}:{os.getgid()}" in shim.read_text()


def test_shim_quotes_host_paths(tmp_path: Path) -> None:
    """Paths are fixed at generation time so nothing the agent passes as an argument can
    reach the docker invocation itself."""
    odd = tmp_path / "dir with spaces"
    odd.mkdir()
    s = write_shim(
        tmp_path / "x-exec", target=odd, scratch=tmp_path / "s", cfg=SandboxConfig()
    )
    assert "'" in s.read_text()


def test_shim_instructions_name_the_real_path(shim: Path) -> None:
    text = shim_instructions(shim)
    assert str(shim) in text
    assert "/target" in text and "/scratch" in text
    assert "no network" in text.lower()


# ---------------- scope ----------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n")
    (r / "README.md").write_text("docs\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    return r


def test_scope_finds_committed_and_uncommitted_changes(repo: Path) -> None:
    (repo / "b.py").write_text("y = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add b")
    (repo / "c.py").write_text("z = 3\n")  # left uncommitted on purpose
    s = changed_since(repo, "HEAD~1")
    assert "b.py" in s.changed
    assert "c.py" in s.changed, "uncommitted work is part of what you asked to audit"


def test_scope_ignores_non_code(repo: Path) -> None:
    (repo / "README.md").write_text("changed docs\n")
    (repo / "poetry.lock").write_text("lock\n")
    (repo / "d.py").write_text("q = 4\n")
    s = changed_since(repo, "HEAD")
    assert "d.py" in s.changed
    assert "README.md" in s.skipped and "poetry.lock" in s.skipped


def test_scope_drops_deleted_files(repo: Path) -> None:
    """A deleted file has no code left to audit."""
    (repo / "a.py").unlink()
    s = changed_since(repo, "HEAD")
    assert "a.py" not in s.changed


def test_bad_ref_reports_an_error_rather_than_crashing(repo: Path) -> None:
    s = changed_since(repo, "no-such-ref")
    assert s.error and "scope failed" in s.summary()


def test_scope_areas_group_by_directory() -> None:
    """Two handlers in one module share a trust boundary; hunting them separately pays
    twice for the same context."""
    areas = dict(scope_areas(["api/a.py", "api/b.py", "storage/c.py", "top.py"]))
    assert sorted(areas["api"]) == ["api/a.py", "api/b.py"]
    assert areas["root"] == ["top.py"]


def test_empty_scope_is_detectable() -> None:
    assert ChangeScope(ref="HEAD").is_empty

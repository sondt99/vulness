"""Regressions from the first calibration run against a known-vulnerable target.

Both bugs below were found by measuring the harness against ground truth, not by review.
"""

from __future__ import annotations

from vulness.agents.classify import is_retryable
from vulness.findings import HunterFinding, compute_fingerprint

_SINK = dict(
    threat_model={
        "attacker": "unauthenticated remote client",
        "boundary": "query parameter reaches os.path.join",
        "broken_assumption": "name cannot escape the tenant root",
    },
    trace=[{"kind": "sink", "file": "storage/files.py", "line": 24, "scope": "download"}],
    evidence=[{"file": "storage/files.py", "line": 24, "description": "unsanitised join"}],
)


def test_schema_invalid_is_retryable() -> None:
    """A stochastic model returning prose instead of JSON is transient, not fatal.

    Treating it as fatal stranded a confirmed-critical SQL injection as an unvalidated
    candidate for the whole run.
    """
    assert is_retryable("schema_invalid")
    assert is_retryable("api_error_text")
    assert is_retryable("timeout")
    assert is_retryable("empty")


def test_crash_is_not_retryable() -> None:
    """A missing binary or revoked key fails identically forever; retrying just burns budget."""
    assert not is_retryable("crash")
    assert not is_retryable("ok")


def test_same_bug_under_different_attack_class_has_one_fingerprint() -> None:
    """One path traversal was filed three times as injection/access-control/path-traversal."""
    title = "Path traversal in /files/download lets any tenant read other tenants' files"
    fps = {
        compute_fingerprint(
            HunterFinding(title=title, attack_class=cls, **_SINK),  # type: ignore[arg-type]
            "vulnshop",
        )
        for cls in ("injection", "access-control", "path-traversal")
    }
    assert len(fps) == 1, f"attack class must not split one defect into {len(fps)} identities"


def test_genuinely_different_bugs_stay_distinct() -> None:
    """The dedup fix must not over-collapse: different sinks are different bugs."""
    a = HunterFinding(title="Path traversal in the download handler", attack_class="x", **_SINK)
    other = dict(_SINK)
    other["trace"] = [{"kind": "sink", "file": "api/reports.py", "line": 21, "scope": "export"}]
    b = HunterFinding(title="SQL injection in the export handler", attack_class="x", **other)  # type: ignore[arg-type]
    assert compute_fingerprint(a, "vulnshop") != compute_fingerprint(b, "vulnshop")


def test_peak_occupancy_survives_non_dict_stream_events() -> None:
    """Regression: a JSONL line parsing to a bare string crashed eleven hunt tasks with
    AttributeError, because .get() was called before checking the event was a dict."""
    from vulness.agents.context_budget import peak_occupancy

    events = [
        "a bare string line",
        ["a", "list"],
        42,
        None,
        {"message": "not-a-dict"},
        {"message": {"usage": {"input_tokens": 10, "cache_read_input_tokens": 500}}},
    ]
    assert peak_occupancy(events) == 510  # type: ignore[arg-type]


def test_requeue_depth_is_bounded() -> None:
    """Regression: requeue reset `attempt` to 0, so MAX_ATTEMPTS never tripped and one
    failing validation was retried nine times, each one paid for."""
    import tempfile
    from pathlib import Path

    from vulness.orchestrator.scheduler import MAX_ATTEMPTS, _retry_depth
    from vulness.state.db import Database, new_id
    from vulness.state.models import Run, Task

    db = Database(Path(tempfile.mkdtemp()) / "t.db")
    db.create_run(Run(run_id="r", model_hunt="m", model_verify="n"))
    db.upsert_repo("repo", name="repo", path="/tmp")
    task = db.enqueue(
        Task(task_id=new_id("t"), run_id="r", repo_id="repo", stage="hunt", kind="hunt", prompt="x")
    )
    assert _retry_depth(task) == 0
    for expected in range(1, MAX_ATTEMPTS + 2):
        task = db.requeue(task, "requeue_error")
        assert _retry_depth(task) == expected
    assert _retry_depth(task) > MAX_ATTEMPTS, "depth must eventually exceed the cap"


def test_dotenv_reaches_the_key_the_glm_client_reads(tmp_path, monkeypatch) -> None:
    """Regression: env_prefix="VULNESS_" means pydantic-settings reads .env looking only
    for VULNESS_* names, while VerifyBackend.api_key() reads os.environ directly. A key
    written to .env, which .env.example and the README both tell you to do, reached
    nothing: doctor reported "GLM_API_KEY not set" with the key in the file beside it."""
    from vulness.config import VerifyBackend, load_dotenv

    monkeypatch.delenv("GLM_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text('# a comment\n\nGLM_API_KEY="from-the-file"\nexport OTHER=2\n')

    assert set(load_dotenv(env)) == {"GLM_API_KEY", "OTHER"}
    assert VerifyBackend().api_key() == "from-the-file"


def test_an_exported_key_beats_the_file(tmp_path, monkeypatch) -> None:
    """A shell must still be able to override the file, or a stale .env is unfixable."""
    from vulness.config import VerifyBackend, load_dotenv

    monkeypatch.setenv("GLM_API_KEY", "from-the-shell")
    env = tmp_path / ".env"
    env.write_text("GLM_API_KEY=from-the-file\n")

    assert load_dotenv(env) == []
    assert VerifyBackend().api_key() == "from-the-shell"


def test_a_missing_dotenv_is_not_an_error(tmp_path) -> None:
    from vulness.config import load_dotenv

    assert load_dotenv(tmp_path / "nope") == []

"""Execution policy for proof-of-concept runs -- the harness's trust boundary, written once.

s-ness only believes a finding it can *run*. That makes the sandbox the single place where
an agent's claims meet reality, so the policy lives here rather than inside any one backend:
docker today, bwrap behind the same interface if the AppArmor profile ever lands. A backend
that cannot honour every clause below is not a backend, it is a liability.

The policy:

* **No network.** A PoC reproduces a bug; it does not phone home, fetch a second stage, or
  pull a package that changes what is being tested. Runs are network-isolated unless a
  caller opts out explicitly and loudly (:attr:`SandboxLimits.no_network`).
* **Read-only target.** The tree under audit is mounted at :data:`TARGET_MOUNT` read-only.
  All writes go to :data:`SCRATCH_MOUNT`, which is also the working directory, so artifacts
  are collectable and the source is not.
* **Dropped capabilities.** ``--cap-drop=ALL`` plus ``no-new-privileges``. Nothing a PoC
  legitimately needs survives inside a container that has no network and no writable rootfs.
* **Explicit CPU / memory / PID / wall-clock limits.** An unbounded PoC is indistinguishable
  from a hang, and a fork bomb in a fleet of agents takes the whole run down. Every limit is
  stated, never inherited.
* **Untouched source.** :class:`SourceIntegrity` brackets every run with a hash of the tree.
  See its docstring -- this is the clause the whole harness rests on.
* **Minimum effect.** A PoC stops at the smallest observable signal that proves the boundary
  was crossed: a crash, an assertion, a file opened that should have been unreachable. It
  does not escalate, persist, or "demonstrate impact" beyond that. The sandbox enforces what
  it can; the prompts carry the rest.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final

if TYPE_CHECKING:  # pragma: no cover - avoids paying pydantic's import cost for a type name
    from sness.config import SandboxConfig


# Prompts and generated PoC scripts hard-code these paths, so they are policy rather than a
# per-backend detail: any second backend must map the same two mounts to the same two places.
TARGET_MOUNT: Final = "/target"
SCRATCH_MOUNT: Final = "/scratch"
WORKDIR: Final = SCRATCH_MOUNT

# A PoC that prints a gigabyte is still a valid PoC; the orchestrator reading it into memory
# is not. Output past this point is counted and discarded, never buffered.
MAX_OUTPUT_BYTES: Final = 1 << 20

_MAX_ENV_VALUE: Final = 4096


class Violation:
    """Why a run is untrustworthy, *independent of* the command's own exit code.

    The distinction matters constantly: a PoC that exits 1 because it proved a crash is a
    success, and a PoC that exits 0 after quietly patching the target is a fraud.
    """

    TIMEOUT: Final = "timeout"
    OOM: Final = "oom_killed"
    SOURCE_MODIFIED: Final = "source_modified"
    LAUNCH_FAILED: Final = "launch_failed"
    BAD_REQUEST: Final = "bad_request"


@dataclass(slots=True)
class SandboxLimits:
    """Resource envelope for one run. Defaults mirror :class:`~sness.config.SandboxConfig`."""

    cpus: float = 1.0
    memory: str = "2g"
    pids: int = 256
    timeout_s: int = 120
    tmpfs_size: str = "256m"
    no_network: bool = True

    @classmethod
    def from_config(cls, cfg: SandboxConfig) -> SandboxLimits:
        """Lift the configured envelope. ``no_network`` is deliberately not configurable:
        turning isolation off is a per-run decision a caller must make in code, not a line
        someone can flip in ``fleet.yaml`` and forget about."""
        return cls(
            cpus=cfg.cpus,
            memory=cfg.memory,
            pids=cfg.pids_limit,
            timeout_s=cfg.timeout_s,
            tmpfs_size=cfg.tmpfs_size,
        )


@dataclass(slots=True)
class SandboxResult:
    """The outcome of one sandboxed command.

    ``ok`` means *the run is usable as evidence* -- the container started, stayed inside its
    limits, and left the target alone. It does **not** mean the command exited zero; use
    :attr:`exited_clean` for that. Conflating the two is how a harness ends up reporting
    "PoC failed" for a PoC that successfully crashed its target.
    """

    ok: bool = False
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    oom_killed: bool = False
    violation: str | None = None

    @property
    def exited_clean(self) -> bool:
        return self.ok and self.exit_code == 0

    def summary(self) -> str:
        """One line for the event log. Logs are read during incidents, so lead with the fault."""
        if self.violation:
            return f"{self.violation} (exit={self.exit_code}, {self.duration_s:.1f}s)"
        return f"exit={self.exit_code} in {self.duration_s:.1f}s"


class SourceIntegrity:
    """Proof that the PoC ran against the code the finding actually claims to be about.

    This is the clause that separates a finding from a story. An agent that edits the target
    -- adds the missing bounds check's inverse, widens a buffer, drops an ``assert``, plants
    a file the exploit opens -- has not discovered a vulnerability; it has authored one, and
    then reported its own edit. The result is worse than a false positive because it arrives
    with a working reproduction attached, which is exactly the evidence a reviewer trusts.

    Two independent mechanisms, because either alone is insufficient:

    * The backend mounts the tree read-only. That is the **control**: it stops the edit.
    * This class hashes the tree before and after. That is the **evidence**: it proves the
      control held, and it also catches mutation the mount cannot see -- a host-side edit
      racing the run, a bind-mount misconfiguration, a bug in a future backend, a `:ro`
      flag someone quietly drops during a refactor.

    A control with no evidence is an assumption. Assumptions are what get reported as CVEs.

    Anything that changes -- modified, added, or deleted -- fails the run. Deletion counts:
    removing a validation file is as good as editing it.
    """

    # Machine-generated content, not source under audit. Hashing a 100k-file `node_modules`
    # on every run would cost more than the run. The tradeoff is real and deliberate: a
    # mutation hidden in a skipped directory goes unseen, so callers auditing a tree whose
    # dependencies are vendored in-tree should narrow this set rather than trust it.
    SKIP_DIRS: ClassVar[frozenset[str]] = frozenset(
        {
            ".git",
            ".hg",
            ".svn",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            ".tox",
            ".nox",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".gradle",
            ".idea",
        }
    )

    # `.git` is skipped above for cost, and safely: the PoC compiles and runs the *working
    # tree*, so the working tree is what must be immutable. Rewriting history cannot change
    # the bytes hashed here.

    MAX_FILE_BYTES: ClassVar[int] = 16 << 20
    _EDGE_BYTES: ClassVar[int] = 1 << 20
    _CHUNK: ClassVar[int] = 1 << 20

    @classmethod
    def snapshot(cls, path: Path | str) -> dict[str, str]:
        """SHA-256 every file in the tree, keyed by POSIX-style relative path.

        Insertion order is sorted so two snapshots of an unchanged tree are byte-identical
        when serialised -- the snapshot gets persisted into SQLite and diffed across
        processes, where a dict that merely *compares* equal is not good enough.
        """
        root = Path(path).resolve()
        digests: dict[str, str] = {}
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames if d not in cls.SKIP_DIRS)
            for name in list(dirnames):
                child = here / name
                # `os.walk` never descends a symlinked directory, so without this the link
                # would vanish from the snapshot entirely -- and repointing it swaps a whole
                # subtree out from under the PoC without touching one file we hashed.
                if child.is_symlink():
                    dirnames.remove(name)
                    digests[cls._rel(root, child)] = cls._link_digest(child)
            for name in filenames:
                digest = cls._file_digest(here / name)
                if digest is not None:
                    digests[cls._rel(root, here / name)] = digest
        return dict(sorted(digests.items()))

    @classmethod
    def changes(cls, path: Path | str, snapshot: Mapping[str, str]) -> dict[str, list[str]]:
        """Re-walk and bucket the differences. Reports read better than a flat path list."""
        current = cls.snapshot(path)
        before, after = set(snapshot), set(current)
        return {
            "added": sorted(after - before),
            "removed": sorted(before - after),
            "modified": sorted(r for r in before & after if snapshot[r] != current[r]),
        }

    @classmethod
    def verify(cls, path: Path | str, snapshot: Mapping[str, str]) -> tuple[bool, list[str]]:
        """Return ``(unchanged, touched_relpaths)`` against a snapshot taken earlier.

        Paths come back bare and sorted so a caller can stat or read them directly; use
        :meth:`changes` when the report needs to say *how* each one differed.
        """
        buckets = cls.changes(path, snapshot)
        touched = sorted({*buckets["added"], *buckets["removed"], *buckets["modified"]})
        return not touched, touched

    @staticmethod
    def _rel(root: Path, child: Path) -> str:
        return child.relative_to(root).as_posix()

    @staticmethod
    def _link_digest(link: Path) -> str:
        try:
            target = os.readlink(link)
        except OSError:
            target = ""
        # Hash the link *text*, never the resolved content: a symlink pointing out of the
        # tree must be compared as a pointer, or we end up hashing /etc/passwd.
        return f"link:{sha256(target.encode('utf-8', 'surrogateescape')).hexdigest()}"

    @classmethod
    def _file_digest(cls, path: Path) -> str | None:
        try:
            st = path.lstat()
        except OSError:
            return None  # Vanished mid-walk; the diff against the other snapshot will show it.
        if stat.S_ISLNK(st.st_mode):
            return cls._link_digest(path)
        if not stat.S_ISREG(st.st_mode):
            return None  # Sockets, fifos and devices have no stable content to compare.
        # The executable bit rides along in the key: `chmod +x` on a data file is a genuine
        # behaviour change, and content hashing alone would call it identical.
        kind = "blob-x" if st.st_mode & 0o111 else "blob"
        try:
            if st.st_size <= cls.MAX_FILE_BYTES:
                digest = sha256()
                with path.open("rb") as fh:
                    while chunk := fh.read(cls._CHUNK):
                        digest.update(chunk)
                return f"{kind}:{digest.hexdigest()}"
            # Vendored tarballs and fuzzing corpora would dominate the walk. Size plus both
            # ends catches a swapped or truncated file for a fraction of the I/O; an attacker
            # who can splice the middle of a 16 MB blob without changing its length has
            # easier options than that.
            digest = sha256(f"{st.st_size}".encode())
            with path.open("rb") as fh:
                digest.update(fh.read(cls._EDGE_BYTES))
                fh.seek(-cls._EDGE_BYTES, os.SEEK_END)
                digest.update(fh.read(cls._EDGE_BYTES))
            return f"part-{kind}:{digest.hexdigest()}"
        except OSError:
            # Record the failure instead of dropping the path: a file that becomes unreadable
            # between snapshots is a change, and silence here would read as "unchanged".
            return f"{kind}:unreadable"


# A minimal environment, defined positively. Every value is a constant chosen here -- nothing
# is read from `os.environ`, ever.
#
# Why build rather than redact: the harness process holds ANTHROPIC_API_KEY, GLM_API_KEY, SSH
# agent sockets, cloud credential paths and whatever else the operator's shell exports. A
# denylist has to enumerate every secret-shaped name that will ever exist, including the ones
# a future dependency invents; starting from `{}` has to enumerate only what a PoC needs to
# run. The first is an arms race against your own environment, the second is a short list.
# It also makes runs reproducible: identical env in, identical env out, on any machine.
ENV_ALLOWLIST: Final[dict[str, str]] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": SCRATCH_MOUNT,  # Not /root: the rootfs is read-only and the run is unprivileged.
    "TMPDIR": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",  # Tools that probe TERM emit escape codes that corrupt captured output.
    "TZ": "UTC",
    "NO_COLOR": "1",
    "PYTHONUNBUFFERED": "1",  # Otherwise a killed PoC loses the output that proves its point.
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",  # Deterministic repro: a PoC that only lands 1-in-N is not a PoC.
    "SOURCE_DATE_EPOCH": "0",
    "SNESS_TARGET": TARGET_MOUNT,
    "SNESS_SCRATCH": SCRATCH_MOUNT,
}

# Belt and braces. None of these appear in the allowlist, so they cannot be set today; the
# check exists for the day someone widens the allowlist in a hurry and does not think it
# through. Cheap insurance against the one mistake that leaks a key into a container.
_SECRETISH: Final = ("TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "COOKIE")


def build_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Construct the container's environment from nothing.

    ``extra`` may override an allowlisted key or add one under the harness-owned ``SNESS_``
    prefix; anything else is dropped silently, because the caller that needs a new variable
    should be adding it to :data:`ENV_ALLOWLIST` where it gets reviewed.
    """
    env = dict(ENV_ALLOWLIST)
    for key, value in (extra or {}).items():
        if key not in ENV_ALLOWLIST and not key.startswith("SNESS_"):
            continue
        if any(marker in key.upper() for marker in _SECRETISH):
            continue
        cleaned = _safe_value(value)
        if cleaned is not None:
            env[key] = cleaned
    return env


def _safe_value(value: str) -> str | None:
    """Reject values that can smuggle structure into an argv or a log line."""
    if not isinstance(value, str) or len(value) > _MAX_ENV_VALUE:
        return None
    # NUL truncates the string at the execve boundary; newlines forge entries in captured
    # output and in the event log that a reviewer later reads as ground truth.
    if any(ch == "\x00" or (ord(ch) < 32 and ch != "\t") for ch in value):
        return None
    return value


def as_argv(command: Sequence[str]) -> list[str]:
    """Normalise a command to an argv list, refusing a bare string.

    Nothing in this package ever uses ``shell=True``, so a caller passing ``"cat /etc/passwd"``
    would otherwise be silently exploded by ``list()`` into one argument per character and run
    a program called ``c``. Fail loudly instead, and point at the shape that actually works.
    """
    if isinstance(command, str | bytes):
        raise ValueError(
            "command must be an argv list, not a string; "
            'for a shell line use ["sh", "-c", "<line>"] explicitly'
        )
    argv = [str(part) for part in command]
    if not argv:
        raise ValueError("command must contain at least one argument")
    if any("\x00" in part for part in argv):
        raise ValueError("command arguments must not contain NUL")
    return argv


def clip(raw: bytes, total: int, limit: int = MAX_OUTPUT_BYTES) -> str:
    """Decode captured output, flagging how much was thrown away.

    ``errors="replace"`` because PoC output is frequently a core dump, an ASAN report with a
    mangled tail, or raw bytes from the fuzz input -- none of which should raise while the
    harness is trying to record *why* a run mattered.
    """
    text = raw.decode("utf-8", errors="replace")
    if total > limit:
        text += f"\n[sness: output truncated -- kept {limit} of {total} bytes]"
    return text

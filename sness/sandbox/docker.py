"""Docker backend for the PoC sandbox -- the only one that works on this box today.

`bwrap` and `unshare` are blocked here by `kernel.apparmor_restrict_unprivileged_userns=1`
(Ubuntu's default), which fails as `bwrap: setting up uid map: Permission denied`. That is
not a preference to revisit; it is why Docker is the default and why `bwrap.py` stays an
opt-in fast path behind the same policy surface.

Every flag in :meth:`DockerSandbox._container_argv` traces back to a clause in
``sness.sandbox.policy``. Read that module first; this one is its mechanics.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import tempfile
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final

from sness.sandbox.policy import (
    MAX_OUTPUT_BYTES,
    SCRATCH_MOUNT,
    TARGET_MOUNT,
    WORKDIR,
    SandboxLimits,
    SandboxResult,
    SourceIntegrity,
    Violation,
    as_argv,
    build_env,
    clip,
)

if TYPE_CHECKING:  # pragma: no cover
    from sness.config import SandboxConfig


_CONTROL_TIMEOUT: Final = 20.0  # `docker version`/`kill`/`rm` are daemon RPCs, not workloads.
_KILL_GRACE: Final = 10.0  # How long a SIGKILLed container gets to flush its pipes.
_DOCTOR_TIMEOUT: Final = 60.0
_READ_CHUNK: Final = 1 << 16

# The docker *client* is the one process that cannot run from an empty environment: without
# DOCKER_HOST/DOCKER_CONTEXT (rootless setups, remote daemons) or HOME (for
# ~/.docker/config.json) it simply cannot find the daemon. This narrow slice is the whole
# exception -- the container itself still gets a built-from-nothing env via `build_env()`.
_CLIENT_ENV_KEYS: Final = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "XDG_RUNTIME_DIR",
    "HOME",
    "PATH",
)

# Self-test payload. It runs through the ordinary `run()` path so it exercises the exact argv
# production uses -- a doctor that builds its own flags proves only that the doctor works.
# Probe order matters: `python3` covers the default python:3.12-slim image, busybox `nc`
# covers alpine, and NO_PROBE_TOOL is reported rather than assumed-good, because a probe that
# cannot attempt a connection cannot tell isolation apart from a missing binary.
_PROBE_SCRIPT: Final = r"""
net=NO_PROBE_TOOL
if command -v python3 >/dev/null 2>&1; then
  if python3 -c "import socket;socket.setdefaulttimeout(3);socket.create_connection(('1.1.1.1',53))" >/dev/null 2>&1; then
    net=NET_REACHABLE
  else
    net=NO_NET
  fi
elif command -v nc >/dev/null 2>&1; then
  if nc -w 3 1.1.1.1 53 </dev/null >/dev/null 2>&1; then net=NET_REACHABLE; else net=NO_NET; fi
elif command -v wget >/dev/null 2>&1; then
  if wget -q -T 3 -O /dev/null http://1.1.1.1/ >/dev/null 2>&1; then net=NET_REACHABLE; else net=NO_NET; fi
fi
echo "NET=$net"

if echo probe > /target/.sness-doctor 2>/dev/null; then echo "TARGET=WRITABLE"; else echo "TARGET=READ_ONLY"; fi
if echo probe > /rootfs.sness-doctor 2>/dev/null; then echo "ROOTFS=WRITABLE"; else echo "ROOTFS=READ_ONLY"; fi
if echo probe > /scratch/.sness-doctor 2>/dev/null; then echo "SCRATCH=WRITABLE"; else echo "SCRATCH=READ_ONLY"; fi
rm -f /scratch/.sness-doctor 2>/dev/null
echo "MEM=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)"
echo "PIDS=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown)"
"""


class DockerSandbox:
    """Runs one command inside a container that cannot reach the network or write the target."""

    def __init__(self, cfg: SandboxConfig) -> None:
        self.cfg = cfg
        # Resolve the binary once and invoke it absolutely, so the subprocess never needs a
        # PATH and cannot pick up a `docker` shim that appears on it mid-run.
        self._docker: str | None = shutil.which("docker")

    # ---------- self-test ----------

    async def doctor(self) -> tuple[bool, str]:
        """Prove the sandbox actually sandboxes, before the harness dispatches any work.

        Not a liveness check -- an assertion that each guarantee is real: the daemon answers,
        a container comes up with *no* reachable network, and /target refuses writes.

        This runs on every startup because a sandbox that silently fails to start is the worst
        failure mode available. The harness keeps dispatching, the agents keep "verifying",
        and every PoC comes back unexecuted -- which reads exactly like "no bug found". The
        whole point of the sandbox is that execution separates a real finding from a plausible
        story; lose it quietly and s-ness degrades into a very expensive grep that still bills
        for tokens and still emits confident reports.

        Returns ``(False, actionable_reason)`` rather than raising: this is called from
        startup and from ``sness doctor``, and both want a sentence to print, not a traceback.
        """
        if self._docker is None:
            return False, "`docker` is not on PATH; install Docker Engine or set DOCKER_HOST"

        # `docker version` queries the *server*, so it fails when the client is installed but
        # the daemon is down -- which is the failure this check exists to catch.
        code, server_version, err = await self._control(
            ["version", "--format", "{{.Server.Version}}"]
        )
        if code != 0:
            return False, (
                f"docker daemon did not respond ({_first_line(err) or f'exit {code}'}); "
                "check `systemctl status docker` and that this user is in the `docker` group"
            )
        version = server_version.strip() or "unknown"

        image = self.cfg.image
        code, _, err = await self._control(["image", "inspect", image])
        if code != 0:
            # Deliberately not pulling: an implicit pull inside a timeout looks like a hang,
            # and a sandbox self-test is the last place that should reach the network.
            return False, f"image {image!r} is not present locally; run: docker pull {image}"

        target = Path(tempfile.mkdtemp(prefix="sness-doctor-target-"))
        scratch = Path(tempfile.mkdtemp(prefix="sness-doctor-scratch-"))
        try:
            (target / "canary.txt").write_text("doctor\n")
            limits = SandboxLimits.from_config(self.cfg)
            limits.timeout_s = int(min(limits.timeout_s, _DOCTOR_TIMEOUT))
            result = await self.run(
                ["sh", "-c", _PROBE_SCRIPT],
                target=target,
                scratch=scratch,
                limits=limits,
                image=image,
            )
        except Exception as exc:  # noqa: BLE001 - startup must report, never explode
            return False, f"sandbox self-test crashed: {exc!r}"
        finally:
            shutil.rmtree(target, ignore_errors=True)
            shutil.rmtree(scratch, ignore_errors=True)

        if result.timed_out:
            return False, f"sandbox self-test timed out after {limits.timeout_s}s starting {image}"
        if result.violation == Violation.LAUNCH_FAILED or not result.stdout.strip():
            detail = _first_line(result.stderr) or f"exit {result.exit_code}, no output"
            return False, (
                f"probe container failed to run in {image!r}: {detail}; "
                "the image needs a POSIX /bin/sh for the self-test"
            )

        marks = _markers(result.stdout)
        for check, ok_value, reason in (
            ("NET", "NO_NET", "--network=none did NOT isolate the container; it reached 1.1.1.1"),
            ("TARGET", "READ_ONLY", f"the {TARGET_MOUNT} mount was WRITABLE despite `:ro`"),
            ("ROOTFS", "READ_ONLY", "the container rootfs was writable despite `--read-only`"),
        ):
            got = marks.get(check)
            if got is None:
                return False, f"self-test produced no {check} result; probe output: {marks}"
            if got != ok_value:
                if got == "NO_PROBE_TOOL":
                    return False, (
                        f"image {image!r} has no python3, nc or wget, so network isolation "
                        "cannot be proven; add one or point `sandbox.image` at an image with one"
                    )
                return False, f"SANDBOX IS NOT SAFE: {reason}"
        if marks.get("SCRATCH") != "WRITABLE":
            return False, f"{SCRATCH_MOUNT} was not writable; PoCs would have nowhere to work"

        # Informational, not fatal: cgroup layout varies, and a v1 host reports `unknown`
        # here without the container being any less isolated.
        mem, pids = marks.get("MEM", "unknown"), marks.get("PIDS", "unknown")
        return True, (
            f"docker {version}, image {image}: network isolated, {TARGET_MOUNT} read-only, "
            f"rootfs read-only, memory.max={mem}, pids.max={pids}"
        )

    # ---------- execution ----------

    async def run(
        self,
        command: Sequence[str],
        *,
        target: Path,
        scratch: Path,
        limits: SandboxLimits,
        image: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> SandboxResult:
        """Run ``command`` (an argv list) under the policy. Never raises for workload failure."""
        if self._docker is None:
            return SandboxResult(violation=Violation.LAUNCH_FAILED, stderr="docker not on PATH")
        try:
            argv = as_argv(command)
            target_path, scratch_path = self._prepare_mounts(target, scratch)
        except (ValueError, OSError) as exc:
            return SandboxResult(violation=Violation.BAD_REQUEST, stderr=str(exc))

        name = f"sness-{uuid.uuid4().hex[:12]}"
        cmd = self._container_argv(
            name,
            argv,
            target=target_path,
            scratch=scratch_path,
            limits=limits,
            image=image or self.cfg.image,
            env=env,
        )

        started = time.monotonic()
        timed_out = False
        needs_reap = False
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                # DEVNULL, not inherit: a PoC that reads stdin would otherwise block until the
                # wall clock kills it, and would be reading the operator's terminal to do it.
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._client_env(),
            )
        except OSError as exc:
            return SandboxResult(
                violation=Violation.LAUNCH_FAILED,
                stderr=f"could not exec docker: {exc}",
                duration_s=time.monotonic() - started,
            )

        # `shield` keeps the pump alive when the outer wait_for gives up, so after the kill we
        # can await the *same* task for whatever the container managed to emit. Re-entering a
        # cancelled `communicate()` instead would throw the crash output away -- which is
        # usually the only part of a timed-out PoC worth having.
        pump = asyncio.create_task(_pump(proc))
        try:
            out, out_total, err, err_total, code = await asyncio.wait_for(
                asyncio.shield(pump), timeout=limits.timeout_s
            )
        except TimeoutError:
            timed_out = True
            needs_reap = True
            await self._control(["kill", "--signal=KILL", name])
            try:
                out, out_total, err, err_total, code = await asyncio.wait_for(pump, _KILL_GRACE)
            except TimeoutError:
                # The daemon is wedged or the client is unkillable. Take the client down and
                # report what we know rather than pinning a worker slot forever.
                pump.cancel()
                with contextlib.suppress(ProcessLookupError, OSError):
                    proc.kill()
                out, out_total, err, err_total, code = b"", 0, b"", 0, 137
        except asyncio.CancelledError:
            # Orchestrator shutdown or a lease expiry. The container outlives this coroutine
            # unless we say otherwise, so kill it before the cancellation propagates.
            needs_reap = True
            pump.cancel()
            await self._control(["kill", "--signal=KILL", name])
            raise
        finally:
            if needs_reap:
                # `--rm` is the daemon's job only when the client exits cleanly; a client we
                # killed leaves the container behind to hold its memory and its pid slots.
                await self._control(["rm", "--force", name])

        duration = time.monotonic() - started
        # 137 is SIGKILL, which is *either* the cgroup OOM killer or our own timeout kill --
        # and with `--rm` the container is gone before `docker inspect .State.OOMKilled` can be
        # asked. Attributing it to the timeout when we know we sent the signal is the only
        # honest read; a lone 137 is the OOM.
        oom_killed = code == 137 and not timed_out

        violation: str | None = None
        if timed_out:
            violation = Violation.TIMEOUT
        elif oom_killed:
            violation = Violation.OOM
        elif code in (125, 126, 127):
            # 125 is the daemon refusing the run, 126/127 the entrypoint being unusable. None
            # of these are the PoC disproving itself -- they are the PoC never having run, and
            # collapsing that into "exited non-zero" is how a harness reports a clean bill of
            # health for a target it never executed.
            violation = Violation.LAUNCH_FAILED

        return SandboxResult(
            ok=violation is None,
            exit_code=code,
            stdout=clip(out, out_total),
            stderr=clip(err, err_total),
            duration_s=duration,
            timed_out=timed_out,
            oom_killed=oom_killed,
            violation=violation,
        )

    async def run_poc(
        self,
        poc_command: Sequence[str],
        *,
        target: Path,
        scratch: Path,
        limits: SandboxLimits,
        baseline: Mapping[str, str] | None = None,
    ) -> tuple[SandboxResult, bool, list[str]]:
        """Run a PoC and prove it ran against source nobody touched.

        Returns ``(result, source_unchanged, changed_files)``.

        **A PoC that mutated the target is a failed PoC regardless of its exit code.** It does
        not matter how cleanly it exited, how precise its stack trace is, or how well its
        write-up reads: if the tree differs from the snapshot taken before the run, the thing
        it demonstrated is a bug in code that did not exist until the agent wrote it. Such a
        result comes back with ``ok=False`` and
        ``violation == Violation.SOURCE_MODIFIED``, and callers must treat it as a rejection,
        not as a caveat to mention further down the report. It overrides any other violation,
        because a timeout is a run you retry and this is a finding you throw away.

        ``baseline`` closes the remaining gap. Snapshotting immediately before the run only
        proves the source was stable *across* it -- an agent that edited the tree earlier in
        its turn still passes. Pass the digest taken when the repo was ingested and the check
        covers the whole run instead of the last few seconds.
        """
        root = Path(target).resolve()
        # Hashing a large tree is seconds of blocking I/O. On the orchestrator's event loop,
        # with several sandboxes in flight, that stalls every other worker's timeout clock.
        before = (
            dict(baseline)
            if baseline is not None
            else await asyncio.to_thread(SourceIntegrity.snapshot, root)
        )
        result = await self.run(poc_command, target=root, scratch=scratch, limits=limits)
        unchanged, changed = await asyncio.to_thread(SourceIntegrity.verify, root, before)
        if not unchanged:
            result.ok = False
            result.violation = Violation.SOURCE_MODIFIED
        return result, unchanged, changed

    # ---------- internals ----------

    def _prepare_mounts(self, target: Path, scratch: Path) -> tuple[Path, Path]:
        target_path = Path(target).resolve()
        if not target_path.is_dir():
            raise ValueError(f"target is not a directory: {target_path}")
        scratch_path = Path(scratch).resolve()
        scratch_path.mkdir(parents=True, exist_ok=True)
        for path in (target_path, scratch_path):
            # `-v host:container:mode` is colon-delimited with no escaping, so a colon in a
            # host path does not fail -- it silently re-parses into different mount options.
            if ":" in str(path):
                raise ValueError(f"path contains ':' and cannot be bind-mounted safely: {path}")
        return target_path, scratch_path

    def _container_argv(
        self,
        name: str,
        argv: list[str],
        *,
        target: Path,
        scratch: Path,
        limits: SandboxLimits,
        image: str,
        env: Mapping[str, str] | None,
    ) -> list[str]:
        # Callers reach here only past a `self._docker is None` guard; the fallback keeps the
        # type honest without an `assert`, which `python -O` would strip out from under us.
        cmd = [
            self._docker or "docker",
            "run",
            "--rm",
            # Named so a timeout has something to kill: the client is gone by then, and the
            # container id is only ever printed on stdout we may never have read.
            "--name",
            name,
            # tini as pid 1 reaps orphans. Without it a PoC that forks leaves zombies that
            # count against --pids-limit, so a long run dies of "resource exhaustion" it
            # caused itself and the finding looks like a DoS in the target.
            "--init",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--pids-limit={limits.pids}",
            f"--memory={limits.memory}",
            # Pin swap to memory, i.e. no swap. The default lets a container use 2x its memory
            # limit via swap, which turns a crisp OOM kill into ten minutes of thrashing that
            # looks like a hang and starves every other sandbox on the box.
            f"--memory-swap={limits.memory}",
            f"--cpus={limits.cpus}",
            f"--tmpfs=/tmp:rw,nosuid,nodev,size={limits.tmpfs_size},mode=1777",
            "--workdir",
            WORKDIR,
            # Run as the caller, not root: artifacts land in scratch owned by the user who has
            # to read them, instead of root-owned files the harness then cannot clean up.
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--label",
            "sness.sandbox=1",
            "-v",
            f"{target}:{TARGET_MOUNT}:ro",
            "-v",
            f"{scratch}:{SCRATCH_MOUNT}:rw",
        ]
        if limits.no_network:
            cmd.append("--network=none")
        for key, value in build_env(env).items():
            cmd += ["--env", f"{key}={value}"]
        cmd.append(image)
        # The argv goes after the image with no shell anywhere in the chain: `create_subprocess_exec`
        # takes a vector, so a PoC filename full of metacharacters is just a filename.
        cmd += argv
        return cmd

    def _client_env(self) -> dict[str, str]:
        return {k: v for k in _CLIENT_ENV_KEYS if (v := os.environ.get(k)) is not None}

    async def _control(self, args: list[str]) -> tuple[int, str, str]:
        """Short daemon command (version/kill/rm). Swallows its own failures by design --
        every caller is either a self-test that reports, or cleanup that must not mask the
        original error it is cleaning up after."""
        if self._docker is None:
            return 127, "", "docker not on PATH"
        try:
            proc = await asyncio.create_subprocess_exec(
                self._docker,
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._client_env(),
            )
        except OSError as exc:
            return 127, "", str(exc)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=_CONTROL_TIMEOUT)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError, OSError):
                proc.kill()
            return 124, "", f"`docker {args[0]}` timed out after {_CONTROL_TIMEOUT}s"
        return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


async def _pump(proc: asyncio.subprocess.Process) -> tuple[bytes, int, bytes, int, int]:
    """Drain both pipes concurrently, then reap. Returns kept bytes and totals produced."""
    streams = (proc.stdout, proc.stderr)
    if streams[0] is None or streams[1] is None:  # pragma: no cover - both are PIPE above
        return b"", 0, b"", 0, await proc.wait()
    (out, out_total), (err, err_total) = await asyncio.gather(
        _read_capped(streams[0]), _read_capped(streams[1])
    )
    return out, out_total, err, err_total, await proc.wait()


async def _read_capped(
    stream: asyncio.StreamReader, limit: int = MAX_OUTPUT_BYTES
) -> tuple[bytes, int]:
    """Keep the first ``limit`` bytes, count the rest, and keep reading.

    Two failure modes this avoids at once: a PoC in a print loop OOM-ing the orchestrator
    (`communicate()` buffers everything), and the same PoC deadlocking on a full pipe if we
    simply stopped reading -- which would present as a hang in the target rather than in us.
    """
    kept: list[bytes] = []
    size = total = 0
    while chunk := await stream.read(_READ_CHUNK):
        total += len(chunk)
        if size < limit:
            take = chunk[: limit - size]
            kept.append(take)
            size += len(take)
    return b"".join(kept), total


def _markers(stdout: str) -> dict[str, str]:
    """Parse the probe's ``KEY=value`` lines, ignoring anything the image chatters first."""
    marks: dict[str, str] = {}
    for line in stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.isupper() and key.isascii():
            marks[key.strip()] = value.strip()
    return marks


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""

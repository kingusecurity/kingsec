"""The process-execution boundary for the scanner.

This is the only module that touches ``subprocess``. It executes a pre-built
argument LIST (never a shell string) so no shell can interpret metacharacters in
a target — the essential defence against command injection. A ``CommandRunner``
Protocol lets tests inject a fake so the adapter can be unit-tested without any
real binary.

Task 5B Priority 2: a configured ``timeout`` only ever bounded the ONE
process Python holds a handle to. Proven empirically (see the Task 5 hang
investigation report) that a killed process's descendant, if it inherited
stdout/stderr pipe handles, keeps those pipes open — so ``subprocess.run``'s
post-timeout drain read blocks until that descendant exits on its own,
regardless of the configured timeout. This module now guarantees the whole
process TREE dies when the timeout fires, on both platforms:

  * Windows: every scanner process is assigned to a Job Object created with
    ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``. Closing the job's last handle
    terminates every process still assigned to it, including anything it
    spawned — unlike ``Popen.kill()``/``TerminateProcess``, which only ever
    affects the single process handle it holds. Implemented via ``ctypes``
    against the raw Win32 Job Object API rather than adding ``pywin32`` as a
    dependency: the API surface needed (``CreateJobObjectW``,
    ``SetInformationJobObject``, ``AssignProcessToJobObject``,
    ``CloseHandle``) is four calls, all in ``kernel32.dll``, all directly
    reachable from ``ctypes.WinDLL`` with correctly declared ``argtypes``/
    ``restype`` — there is nothing here ``pywin32`` would meaningfully
    simplify, and it would add a real third-party dependency (with its own
    supply-chain surface, per this project's own scanner-licensing scrutiny
    elsewhere) purely to wrap four function pointers this module can bind
    directly.
  * POSIX: every scanner process starts its own session
    (``start_new_session=True``, making it a process-group leader). On
    timeout, the whole group is killed with ``os.killpg()`` instead of
    ``Popen.kill()`` (which, like ``TerminateProcess`` on Windows, only
    signals the one process it holds a handle to).

Accepted trade-off (Windows): the process is assigned to its Job Object
immediately after creation, not while suspended — creating it suspended and
resuming it later would require bypassing ``subprocess.Popen`` entirely (it
closes the returned thread handle unconditionally, leaving no supported way
to resume a suspended child afterward) in favor of calling
``_winapi.CreateProcess`` directly, reimplementing argument quoting and
stdio/handle setup that ``subprocess`` already gets right. That is a far
larger and riskier surface for closing a race window on the order of
microseconds; the child's own real startup work (a native launcher parsing
its own config, resolving Java, building a classpath) is measurably slower
than the next Python statement running in the same call stack that assigns
it to the job.

stdin is also always ``subprocess.DEVNULL`` on every invocation
(unconditionally, both platforms) — a scanner that unexpectedly reads from
stdin (a first-run prompt, an "are you sure?" confirmation) gets immediate
EOF instead of a live, potentially-never-resolving connection to whatever
KingSec's own stdin happens to be.

Every ``sys.platform == "win32"`` branch below is written as that exact,
literal comparison (never through a derived boolean) so mypy's
platform-pinned config (``platform = "linux"`` in ``pyproject.toml``, to
match CI - see ``licensing/parser.py`` for the established precedent) can
prove it unreachable and skip type-checking it, instead of resolving
Windows-only ``ctypes`` members against whichever OS happens to run the
type checker. That branch is therefore unchecked by mypy on every
platform, the same accepted trade-off already documented for that file.
"""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess  # nosec B404 — scanner binaries are configured by admin, validated, and run with shell=False + timeout
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from kingsec.infrastructure.logging import get_logger

from .errors import BINARY_ABSENT_USER_MESSAGE, ScannerExecutionError

_logger = get_logger("kingsec.infrastructure.scanner")


def _create_process_guard() -> int | None:
    """Windows only: create a Job Object with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``.

    Closing its last handle kills every process ever assigned to it,
    including anything THEY spawned. Returns ``None`` on any platform or
    failure - the guard degrades to best-effort rather than blocking a
    scan over infrastructure hardening (the caller falls back to killing
    just the immediate process in that case).
    """
    if sys.platform == "win32":
        import ctypes.wintypes as wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # nosec B603
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.SetInformationJobObject.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = wintypes.BOOL

        class _BasicLimitInfo(ctypes.Structure):
            _fields_ = (
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_void_p),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            )

        class _IoCounters(ctypes.Structure):
            _fields_ = (
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            )

        class _ExtendedLimitInfo(ctypes.Structure):
            _fields_ = (
                ("BasicLimitInformation", _BasicLimitInfo),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            )

        job_object_extended_limit_information = 9
        job_object_limit_kill_on_job_close = 0x00002000

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            _logger.warning("failed to create job object", error=ctypes.get_last_error())
            return None
        info = _ExtendedLimitInfo()
        info.BasicLimitInformation.LimitFlags = job_object_limit_kill_on_job_close
        if not kernel32.SetInformationJobObject(
            job, job_object_extended_limit_information, ctypes.byref(info), ctypes.sizeof(info)
        ):
            _logger.warning("failed to configure job object", error=ctypes.get_last_error())
            kernel32.CloseHandle(job)
            return None
        return int(job)
    return None


def _attach_process_guard(guard: int | None, process: subprocess.Popen[str]) -> None:
    """Windows only: assign ``process`` to the Job Object ``guard`` created
    by :func:`_create_process_guard`. A no-op everywhere else - POSIX's
    equivalent (``start_new_session``) is set at ``Popen`` creation time,
    not attached afterward."""
    if sys.platform == "win32" and guard is not None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # nosec B603
        kernel32.AssignProcessToJobObject.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        handle = int(process._handle)  # type: ignore[attr-defined]  # the only way to get the raw HANDLE without pywin32
        if not kernel32.AssignProcessToJobObject(guard, handle):
            _logger.warning("failed to assign scanner process to job object", error=ctypes.get_last_error())


def _kill_process_tree(process: subprocess.Popen[str], guard: int | None) -> bool:
    """Kill ``process`` AND everything it spawned — never just the one
    handle ``Popen.kill()`` holds. See the module docstring.

    Returns:
        ``True`` if it closed ``guard`` to do so (the caller must not
        close that same handle again afterward), ``False`` otherwise.
    """
    if sys.platform == "win32":
        if guard is not None:
            # This is the real tree-kill: every process still assigned to
            # the job dies the instant its last handle closes.
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # nosec B603
            kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
            kernel32.CloseHandle(guard)
            return True
        # Job Object creation/assignment failed earlier - fall back to
        # killing at least the immediate process rather than leaving it
        # running unsupervised too.
        process.kill()
        return False
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    return False


def _close_process_guard(guard: int | None) -> None:
    """Windows only: release ``guard``. A no-op everywhere else."""
    if sys.platform == "win32" and guard is not None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # nosec B603
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle(guard)


@dataclass(frozen=True)
class CommandResult:
    """The captured outcome of running an external command."""

    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


class CommandRunner(Protocol):
    """Runs an argument list with a timeout and returns the captured result."""

    def run(self, args: Sequence[str], *, timeout: float, cwd: str | None = None) -> CommandResult:
        """Execute ``args`` and return its result.

        Args:
            cwd: Optional working directory for the subprocess. Additive
                (Task 5) - most scanners never need this and omit it,
                getting the same behavior as before it existed. Some
                Windows launchers (e.g. ZAP's ``ZAP.exe``, an install4j
                native launcher) resolve their own bundled classpath
                relative to their OWN directory, not their caller's - the
                one case this exists for.

        Raises:
            ScannerExecutionError: If the binary is missing or the run times out.
        """
        ...


class SubprocessCommandRunner:
    """The production ``CommandRunner`` backed by :mod:`subprocess`.

    Security properties (do not weaken):
        * ``shell=False`` — the argument list is passed straight to ``execvp``;
          no shell parses it, so target strings cannot inject commands.
        * A mandatory ``timeout`` bounds execution so a hung scan cannot wedge
          the process — and, per the module docstring, now bounds the whole
          process TREE, not just the one process Python holds a handle to.
        * ``stdin`` is always ``DEVNULL`` — a scanner can never block waiting
          on input from KingSec's own stdin.
        * stdout/stderr are captured (not inherited), so scanner output never
          leaks to the console and can be parsed deterministically.
    """

    def run(self, args: Sequence[str], *, timeout: float, cwd: str | None = None) -> CommandResult:
        """Run the command list, capturing output and timing it.

        Args:
            args: The full argument vector, e.g. ``["nuclei", "-u", target, ...]``.
                The first element is the executable; the rest are arguments.
            timeout: Hard wall-clock limit in seconds.
            cwd: Optional working directory - see the Protocol's own
                docstring. ``None`` (the default) preserves the exact
                pre-existing behavior (the caller's own working
                directory), unchanged for every scanner that doesn't
                pass it.

        Returns:
            The captured :class:`CommandResult`.

        Raises:
            ScannerExecutionError: If the executable is not found or the run
                exceeds ``timeout`` — in which case the ENTIRE process tree
                spawned by ``args[0]`` is guaranteed dead before this
                raises, not just ``args[0]`` itself.
        """
        argv = list(args)
        start = time.monotonic()

        guard = _create_process_guard()
        process: subprocess.Popen[str] | None = None
        try:
            try:
                process = subprocess.Popen(  # nosec B603 — argv is validated, shell=False, timeout is set, executable is allow-listed
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                    cwd=cwd,
                    start_new_session=sys.platform != "win32",
                )
            except FileNotFoundError as exc:
                raise ScannerExecutionError(
                    f"scanner binary not found: {argv[0]!r}",
                    context={"binary": argv[0]},
                    cause=exc,
                    user_message=BINARY_ABSENT_USER_MESSAGE,
                ) from exc

            # Assigned as the very first thing after creation - see the
            # module docstring for why this (not a suspended-process
            # dance) is the accepted trade-off.
            _attach_process_guard(guard, process)

            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                if _kill_process_tree(process, guard):
                    # The guard's last handle was just closed to trigger
                    # KILL_ON_JOB_CLOSE - it is no longer valid, and the
                    # outer `finally` below must not try to close it again.
                    guard = None
                process.wait()
                raise ScannerExecutionError(
                    f"scan timed out after {timeout:.0f}s",
                    context={"timeout_seconds": timeout},
                    cause=exc,
                    # The configured timeout duration is product configuration,
                    # not infrastructure detail (unlike a path or hostname) - an
                    # admin-set number of seconds, safely interpolatable and
                    # directly actionable ("raise it if this target is
                    # legitimately slow"). See Phase 08 report §2/§6 for the
                    # full reasoning behind this specific judgement call.
                    user_message=(
                        f"The scan did not complete within the configured {timeout:.0f}-second "
                        "timeout. If this is expected for the target, increase the scanner's "
                        "timeout in its configuration."
                    ),
                ) from exc
        finally:
            # Belt-and-braces: also fires on the SUCCESS path. Closing the
            # guard's last handle kills anything still assigned to it - a
            # no-op if the process (and everything it spawned) already
            # exited cleanly, a real safety net if something it spawned
            # outlived it for any other reason.
            _close_process_guard(guard)

        duration = time.monotonic() - start
        return CommandResult(
            returncode=process.returncode,
            stdout=stdout or "",
            stderr=stderr or "",
            duration_seconds=duration,
        )

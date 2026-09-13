"""The Nmap implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
XML output into domain ``Finding`` objects.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.application._support import safe_failure_message
from kingsec.domain import Finding, Target, TargetType, decompose_url, is_ipv6_literal
from kingsec.infrastructure.logging import get_logger

from .errors import NONZERO_EXIT_USER_MESSAGE, ScannerExecutionError
from .nmap_parser import parse_nmap_xml
from .runner import CommandRunner, SubprocessCommandRunner

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import NmapSettings

_logger = get_logger("kingsec.infrastructure.scanner")

# Flags nmap treats as mutually-exclusive port selectors. Verified against a
# real nmap 7.99 binary: whether -p or --top-ports "wins" when both appear
# depends on -p's VALUE, not command-line order - a bare single port in -p
# always wins over --top-ports; a -p value containing a range (e.g.
# "18080,1-1000") loses to --top-ports instead, unpredictably from a
# caller's perspective. This is why the URL design never puts a range into
# the same -p as the explicit port (see _scan_url_two_invocations() below) -
# it uses -p with a single bare port only, the one case confirmed safe, and
# never combines it with --top-ports/a second port-selector flag in the same
# invocation at all.
_PORT_SELECTOR_FLAGS_WITH_VALUE = {"-p", "--top-ports"}
_PORT_SELECTOR_FLAGS_STANDALONE = {"-p-", "-F"}

_OPEN_PORT_TITLE = re.compile(r"^Open port (\d+)/(\w+)$")


def _strip_port_selector_flags(scan_args: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Remove any nmap port-selector flag (and its value) from *scan_args*.

    Returns (filtered_args, removed_tokens) so the caller can both build a
    clean argument list AND log/report exactly what was overridden - an
    override must be visible, not silent, even though the URL's port
    always wins once this stripping happens.
    """
    filtered: list[str] = []
    removed: list[str] = []
    skip_next = False
    for token in scan_args:
        if skip_next:
            removed.append(token)
            skip_next = False
            continue
        if token in _PORT_SELECTOR_FLAGS_WITH_VALUE:
            removed.append(token)
            skip_next = True
            continue
        if token in _PORT_SELECTOR_FLAGS_STANDALONE:
            removed.append(token)
            continue
        filtered.append(token)
    return tuple(filtered), tuple(removed)


#: Task 4 FIX 1: the recorded fact for a non-URL run, not an absent key.
#: Before this fix, resolve_port_specification() returned None for a
#: non-URL target - collapsing three different meanings into one
#: identical Python value at the report layer: (a) a genuine non-URL run
#: (nmap's own default, nothing explicit - the actual case here), (b) a
#: row persisted before this field existed at all, and (c) a URL-target
#: row from before the two-invocation design ran. All three rendered as
#: the SAME sentence, which happened to be true for (a) and false for
#: (b)/(c) - the exact "nothing found vs nothing looked" defect class
#: already logged in docs/STATUS.md, reintroduced inside the very phase
#: that named it (instance five). Returning this explicit string instead
#: of None makes (a) a recorded, present fact - only a genuinely absent
#: key (never explicitly written) can mean "not recorded" now.
NON_URL_DEFAULT_PORT_SPECIFICATION = "nmap's own default port selection (no explicit port added)"


def resolve_port_specification(target: Target, settings: NmapSettings) -> str:
    """Return a plain-English description of what was scanned.

    Pure function of (target, settings) - called by ``NmapPlugin.scan()``
    to populate ``ScannerResult.port_specification`` for Task 4's
    disclosure work. Always returns a real string now (Task 4 FIX 1) -
    see NON_URL_DEFAULT_PORT_SPECIFICATION's docstring for why None must
    never mean "nmap's own default was used" anymore.

    URL targets return a description, never a literal port list KingSec
    cannot verify: nmap's own default sweep uses whatever ~1000 ports
    nmap's own (possibly operator-updated) data selects, which KingSec
    does not read, copy, or know precisely - claiming a specific list
    would be dishonest. States what actually happened instead.
    """
    if target.type is not TargetType.URL:
        return NON_URL_DEFAULT_PORT_SPECIFICATION
    components = decompose_url(target)
    return f"nmap's own default port sweep + explicit port {components.port}"


def resolve_port_override_warning(target: Target, settings: NmapSettings) -> str | None:
    """Return a plain-English warning if an operator-configured port
    selector in ``settings.scan_args`` would be overridden, or ``None``.

    Pure function of (target, settings) - called by ``NmapPlugin.scan()``
    to populate ``ScannerResult.warnings``, which survives into the
    persisted report via ``ScannerRunSummary.warnings`` - an override
    must reach the report, not only a log line.
    """
    if target.type is not TargetType.URL:
        return None
    removed = _strip_port_selector_flags(settings.scan_args)[1]
    if not removed:
        return None
    return (
        f"Operator-configured port selection ({' '.join(removed)}) in scan_args was ignored for this "
        "URL target - nmap's own default sweep plus the URL's explicit port were used instead."
    )


def _resolve_host_and_ipv6(target: Target) -> tuple[str, bool]:
    """Return (the string nmap should scan, whether it's an IPv6 host).

    -6 is derived from whether the RESOLVED host is IPv6, regardless of
    target type - not only for URL-derived targets. Verified against a
    real nmap 7.99 binary: without -6, nmap rejects a bracket-stripped
    IPv6 literal outright ("status=skipped reason=invalid", 0 hosts
    scanned) rather than erroring loudly - a silent, currently-reachable
    false-clean result for any existing IP_ADDRESS target holding an IPv6
    value, fixed here.
    """
    if target.type is TargetType.URL:
        components = decompose_url(target)
        return components.host, components.is_ipv6
    if target.type is TargetType.IP_ADDRESS:
        return target.value, is_ipv6_literal(target.value)
    if target.type is TargetType.NETWORK:
        try:
            network = ipaddress.ip_network(target.value, strict=False)
        except ValueError:
            return target.value, False
        return target.value, network.version == 6
    # HOSTNAME: never itself an IP literal.
    return target.value, False


def _dedupe_findings(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """De-duplicate open-port Findings by (port, protocol), keeping the
    first occurrence.

    Only needed for the URL two-invocation case, where the explicit port
    can coincidentally fall inside nmap's own default sweep too - both
    invocations would then independently report the same open port.
    Non-matching findings (nmap script output, anything without the
    standard "Open port N/proto" title) are never deduplicated - only
    exact duplicates of the same port/protocol pair are dropped.
    """
    seen: set[tuple[str, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        match = _OPEN_PORT_TITLE.match(finding.title)
        if match is None:
            result.append(finding)
            continue
        key = (match.group(1), match.group(2))
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return tuple(result)


class NmapScannerAdapter(ScannerPort):
    """Runs Nmap against a target and returns domain findings.

    Phase 2B Task 2: a URL target runs nmap TWICE - once with no port
    flag (nmap's own real default sweep) and once with only the URL's
    explicit port - and merges the results. Every other target type runs
    exactly once, with no port flag, byte-identical to before this task.
    See _scan_url_two_invocations() for the merge/failure-semantics design.
    """

    def __init__(
        self,
        settings: NmapSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()
        self._last_scan_warnings: tuple[str, ...] = ()

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """This adapter only ever runs Nmap - no target-type filtering here."""
        return {"nmap": "Nmap"}

    def last_scan_warnings(self) -> tuple[str, ...]:
        """Warnings from the most recent scan() call (Phase 2B Task 2).

        A runtime outcome, not a pure function of (target, settings) like
        resolve_port_specification()/resolve_port_override_warning() - it
        depends on whether the URL two-invocation sweep or explicit-port
        scan actually failed this run, which can only be known after
        scan() executes. NmapPlugin.scan() reads this immediately after
        calling scan() to populate ScannerResult.warnings.
        """
        return self._last_scan_warnings

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` with Nmap and return the findings discovered."""
        self._last_scan_warnings = ()
        if scanner_ids is not None and "nmap" not in scanner_ids:
            return ()
        if target.type is TargetType.URL:
            findings, warnings = self._scan_url_two_invocations(target)
            self._last_scan_warnings = warnings
            return findings
        return self._scan_single(target, port_spec=None)

    def _scan_single(self, target: Target, *, port_spec: str | None) -> tuple[Finding, ...]:
        """Run exactly one nmap invocation. Raises on failure - the
        original, unchanged behaviour for every non-URL target, and the
        building block the URL path's two invocations are each made of.
        """
        host_arg, is_ipv6 = _resolve_host_and_ipv6(target)
        args = self._build_single_invocation_args(target, host_arg, is_ipv6, port_spec)

        _logger.info("nmap scan started", target=target.value, binary=self._settings.binary_path)
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)
        findings = tuple(parse_nmap_xml(result.stdout))

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"nmap exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )
        _logger.info(
            "nmap scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _run_one_for_merge(
        self, target: Target, host_arg: str, is_ipv6: bool, port_spec: str | None
    ) -> tuple[tuple[Finding, ...], str | None]:
        """Run one invocation for the URL two-invocation path.

        Never raises - returns (findings, error_message). error_message
        is None on success. Both the "runner itself raised" case (binary
        missing, timeout - CommandRunner's own documented contract) and
        the "ran but exited non-zero with nothing parsed" case (the same
        condition _scan_single()/the pre-Task-2 single-invocation code
        has always treated as failure) are caught here uniformly, so
        _scan_url_two_invocations() only has one failure shape to reason
        about, not two.
        """
        args = self._build_single_invocation_args(target, host_arg, is_ipv6, port_spec)
        try:
            result = self._runner.run(args, timeout=self._settings.timeout_seconds)
        except Exception as exc:
            return (), safe_failure_message(exc)
        findings = tuple(parse_nmap_xml(result.stdout))
        if result.returncode != 0 and not findings:
            return (), f"nmap exited with code {result.returncode}"
        return findings, None

    def _scan_url_two_invocations(self, target: Target) -> tuple[tuple[Finding, ...], tuple[str, ...]]:
        """Two invocations for a URL target, merged.

        Failure semantics (decided, not left implicit):
          - both succeed: merged, deduplicated findings, no warning.
          - both fail: raises ScannerExecutionError - this scanner's run
            reaches FAILED, exactly as a single-invocation failure always
            has.
          - one fails: the OTHER invocation's findings are returned
            (SUCCEEDED), with a warning naming which sweep failed. A
            silent partial success is exactly the "nothing found vs
            nothing looked" defect class logged in docs/STATUS.md -
            arrived at here in a genuinely new way (two independent
            subprocess outcomes instead of one), so it gets the same
            answer: disclose it, in the report, not only a log line.
        """
        host_arg, is_ipv6 = _resolve_host_and_ipv6(target)
        components = decompose_url(target)

        sweep_findings, sweep_error = self._run_one_for_merge(target, host_arg, is_ipv6, port_spec=None)
        explicit_findings, explicit_error = self._run_one_for_merge(
            target, host_arg, is_ipv6, port_spec=str(components.port)
        )

        if sweep_error is not None and explicit_error is not None:
            raise ScannerExecutionError(
                f"both nmap invocations failed for {target.value!r}: "
                f"default sweep ({sweep_error}); explicit port ({explicit_error})",
                context={"target": target.value, "sweep_error": sweep_error, "explicit_error": explicit_error},
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )

        warnings: list[str] = []
        if sweep_error is not None:
            warnings.append(
                f"nmap's default port sweep failed ({sweep_error}) - only the explicit port "
                f"({components.port}) was scanned; results are partial."
            )
        if explicit_error is not None:
            warnings.append(
                f"the explicit port scan ({components.port}) failed ({explicit_error}) - only "
                "nmap's default port sweep ran; results are partial."
            )

        merged = _dedupe_findings((*sweep_findings, *explicit_findings))
        return merged, tuple(warnings)

    def _build_single_invocation_args(
        self, target: Target, host_arg: str, is_ipv6: bool, port_spec: str | None
    ) -> list[str]:
        """Assemble one Nmap argument vector.

        Always outputs XML to stdout (-oX -) so the parser can consume
        it. *port_spec*, when given, must be a single bare port (never a
        range/list) - the one case confirmed safe to combine with an
        operator's scan_args without an unpredictable flag-precedence
        outcome (see the module-level comment on
        _PORT_SELECTOR_FLAGS_WITH_VALUE).

        Port-selector flags are stripped from an operator's scan_args for
        BOTH of a URL target's invocations, not only the explicit-port
        one - otherwise an operator-configured -p would silently survive
        into the "sweep" invocation, making it scan the operator's
        configured port instead of nmap's own real default and breaking
        the two-invocation design's guarantee that the sweep is always an
        unconstrained default. Non-URL targets never strip: their single
        invocation must stay byte-identical to before this feature
        existed, operator-configured -p included.
        """
        settings = self._settings
        scan_args = settings.scan_args
        extra: list[str] = []
        if target.type is TargetType.URL:
            scan_args, removed = _strip_port_selector_flags(scan_args)
            if removed:
                _logger.warning(
                    "operator-configured nmap port selector overridden for a URL target",
                    removed=list(removed),
                    resolved_port=port_spec if port_spec is not None else "nmap's own default sweep",
                    target=target.value,
                )
        if port_spec is not None:
            extra = ["-p", port_spec]

        return [
            settings.binary_path,
            *scan_args,
            *(["-6"] if is_ipv6 else []),
            *extra,
            "-oX",
            "-",
            host_arg,
        ]

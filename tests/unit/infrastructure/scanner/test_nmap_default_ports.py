"""KingSec's own default nmap port set: coverage and shape guarantees.

Phase 2B Task 2 Decision 4. This is the direct, source-level guarantee -
test_nmap_plugin.py's TestPortSpecification tests the same invariant
through the full scan path; this file tests the data itself.
"""

from __future__ import annotations

from kingsec.infrastructure.scanner.nmap_default_ports import DEFAULT_PORTS, DEFAULT_PORTS_SPEC

_PHASE1_RUN4_PORTS = {135, 445, 902, 912, 1001, 3000, 3389, 5357, 5678}


class TestDefaultPorts:
    def test_includes_every_phase1_run4_port(self) -> None:
        missing = _PHASE1_RUN4_PORTS - set(DEFAULT_PORTS)
        assert not missing, f"Phase 1 Run #4 port(s) missing: {missing}"

    def test_no_duplicates(self) -> None:
        assert len(DEFAULT_PORTS) == len(set(DEFAULT_PORTS))

    def test_sorted_ascending(self) -> None:
        assert list(DEFAULT_PORTS) == sorted(DEFAULT_PORTS)

    def test_all_valid_tcp_ports(self) -> None:
        assert all(1 <= p <= 65535 for p in DEFAULT_PORTS)

    def test_spec_is_comma_joined_ports(self) -> None:
        assert DEFAULT_PORTS_SPEC == ",".join(str(p) for p in DEFAULT_PORTS)

    def test_not_a_literal_contiguous_range(self) -> None:
        """The regression this whole decision exists to prevent: a
        contiguous 1-N range would silently drop every high-numbered real
        service (3000, 3389, 5357, 5678, ...). Assert the set is NOT just
        "every integer from 1 to max" - a real curated set has gaps."""
        assert len(DEFAULT_PORTS) < max(DEFAULT_PORTS) - min(DEFAULT_PORTS) + 1

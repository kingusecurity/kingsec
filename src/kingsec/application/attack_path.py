"""Attack Path Analysis Engine.

Offline, deterministic attack path analysis for risk-assessed findings.
Detects relationships between findings, builds attack chains, merges
duplicate paths, and ranks paths by overall risk.

Design principles:
    * Immutable value objects (frozen dataclasses).
    * Stateless analyzer — pure functions, no side effects.
    * Deterministic and stable output.
    * No infrastructure, plugin, or scanner imports.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from kingsec.domain import Severity

if TYPE_CHECKING:
    from kingsec.application.enrichment import EnrichedFinding
    from kingsec.application.risk import RiskAssessment


# ---------------------------------------------------------------------------
# Attack stage ordering (lowest stage = earliest in attack chain)
# ---------------------------------------------------------------------------

_ATTACK_STAGE: dict[str, int] = {
    "DNS": 0,
    "Network Infrastructure": 1,
    "Network Service": 2,
    "Authentication": 3,
    "Web Application": 4,
    "API": 4,
    "Container": 5,
    "Cloud": 5,
    "File System": 6,
    "Database": 7,
}

# Stage labels for human-readable attack steps
_STAGE_LABELS: dict[int, str] = {
    0: "Reconnaissance",
    1: "Network Discovery",
    2: "Initial Access",
    3: "Credential Access",
    4: "Execution",
    5: "Persistence",
    6: "Exfiltration",
    7: "Impact",
}

# Impact estimate mapping
_IMPACT_ESTIMATES: dict[str, str] = {
    "Critical": "Severe",
    "High": "High",
    "Medium": "Moderate",
    "Low": "Minimal",
    "Informational": "None",
}

# Complexity mapping
_COMPLEXITY_MAP: dict[str, str] = {
    "Hard": "Complex",
    "Medium": "Moderate",
    "Easy": "Simple",
}

# Likelihood weights from exploit likelihood
_LIKELIHOOD_MAP: dict[str, str] = {
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
}

# Relationship types between nodes
_RELATIONSHIP_TYPES: list[tuple[str, int]] = [
    ("same_asset", 5),
    ("same_service", 4),
    ("same_surface", 3),
    ("same_port", 3),
    ("software_dependency", 2),
    ("same_protocol", 1),
]


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttackNode:
    """A single node in an attack path, representing one assessed finding."""

    node_id: str
    correlation_id: str
    title: str
    severity: str
    category: str
    attack_surface: str | None
    service: str | None
    port: int | None
    protocol: str | None
    asset: str | None
    risk_score: int
    risk_level: str

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id must not be empty")
        if not self.correlation_id:
            raise ValueError("correlation_id must not be empty")


@dataclass(frozen=True)
class AttackEdge:
    """A directed edge between two attack nodes describing their relationship."""

    source_id: str
    target_id: str
    relationship: str
    confidence: float

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("source_id must not be empty")
        if not self.target_id:
            raise ValueError("target_id must not be empty")
        if self.source_id == self.target_id:
            raise ValueError("source and target must be different")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@dataclass(frozen=True)
class AttackPath:
    """An ordered sequence of attack nodes forming a single attack chain."""

    path_id: str
    nodes: tuple[AttackNode, ...]
    edges: tuple[AttackEdge, ...]
    attack_score: int
    confidence: float
    estimated_impact: str
    attack_complexity: str
    likelihood: str
    reasoning: str
    recommendations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.path_id:
            raise ValueError("path_id must not be empty")
        if not self.nodes:
            raise ValueError("nodes must not be empty")
        if not 0 <= self.attack_score <= 100:
            raise ValueError("attack_score must be between 0 and 100")


@dataclass(frozen=True)
class AttackGraph:
    """The complete set of attack paths derived from the input findings."""

    paths: tuple[AttackPath, ...]
    total_paths: int
    highest_score: int
    average_score: float
    metadata: dict[str, str]

    def __post_init__(self) -> None:
        if not self.paths:
            raise ValueError("paths must not be empty")
        if not 0 <= self.highest_score <= 100:
            raise ValueError("highest_score must be between 0 and 100")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_path_id(node_ids: list[str]) -> str:
    """Generate a deterministic path ID from ordered node IDs."""
    combined = "|".join(node_ids)
    h = hashlib.sha256(combined.encode()).hexdigest()[:16]
    return f"path-{h}"


def _max_severity_name(severities: list[Severity]) -> str:
    """Return the name of the highest severity in a list."""
    if not severities:
        return "INFORMATIONAL"
    return max(severities).name


def _confidence_from_edges(edges: tuple[AttackEdge, ...]) -> float:
    """Average confidence across edges."""
    if not edges:
        return 0.0
    return sum(e.confidence for e in edges) / len(edges)


def _is_reachable(source: AttackNode, target: AttackNode, finding_map: dict[str, EnrichedFinding]) -> AttackEdge | None:
    """Detect if there is a reachability relationship between two nodes.

    Returns an ``AttackEdge`` if a relationship is found, ``None`` otherwise.
    """
    src_finding = finding_map.get(source.correlation_id)
    tgt_finding = finding_map.get(target.correlation_id)
    if src_finding is None or tgt_finding is None:
        return None

    shared_assets = set(src_finding.affected_assets) & set(tgt_finding.affected_assets)
    if shared_assets:
        return AttackEdge(
            source_id=source.node_id,
            target_id=target.node_id,
            relationship="same_asset",
            confidence=0.8,
        )

    src_services = {s.strip() for s in (src_finding.service or "").split(",") if s.strip()}
    tgt_services = {s.strip() for s in (tgt_finding.service or "").split(",") if s.strip()}
    if src_services & tgt_services:
        return AttackEdge(
            source_id=source.node_id,
            target_id=target.node_id,
            relationship="same_service",
            confidence=0.6,
        )

    if (
        src_finding.attack_surface
        and tgt_finding.attack_surface
        and src_finding.attack_surface == tgt_finding.attack_surface
    ):
        return AttackEdge(
            source_id=source.node_id,
            target_id=target.node_id,
            relationship="same_surface",
            confidence=0.5,
        )

    if src_finding.port is not None and tgt_finding.port is not None:
        if src_finding.port == tgt_finding.port:
            return AttackEdge(
                source_id=source.node_id,
                target_id=target.node_id,
                relationship="same_port",
                confidence=0.4,
            )

    src_sw = set(src_finding.software)
    tgt_sw = set(tgt_finding.software)
    if src_sw & tgt_sw:
        return AttackEdge(
            source_id=source.node_id,
            target_id=target.node_id,
            relationship="software_dependency",
            confidence=0.3,
        )

    if src_finding.protocol and tgt_finding.protocol:
        if src_finding.protocol == tgt_finding.protocol:
            return AttackEdge(
                source_id=source.node_id,
                target_id=target.node_id,
                relationship="same_protocol",
                confidence=0.2,
            )

    return None


def _build_attack_steps(nodes: tuple[AttackNode, ...]) -> list[str]:
    """Build human-readable attack step descriptions from ordered nodes."""
    steps: list[str] = []
    for i, node in enumerate(nodes):
        surface = node.attack_surface or "unknown"
        service = node.service or "unknown"
        step_num = _ATTACK_STAGE.get(surface, 0)
        label = _STAGE_LABELS.get(step_num, "Unknown Stage")
        steps.append(f"Step {i + 1}: {label} — {node.title} ({surface}/{service}, risk {node.risk_score})")
    return steps


def _build_recommendations(nodes: tuple[AttackNode, ...], finding_map: dict[str, EnrichedFinding]) -> tuple[str, ...]:
    """Collect and deduplicate recommendations from all nodes."""
    seen: set[str] = set()
    result: list[str] = []
    for node in nodes:
        finding = finding_map.get(node.correlation_id)
        if finding is None:
            continue
        for rec in finding.recommendations:
            if rec not in seen:
                seen.add(rec)
                result.append(rec)
    return tuple(result)


# ---------------------------------------------------------------------------
# Attack Path Analyzer
# ---------------------------------------------------------------------------


class AttackPathAnalyzer:
    """Stateless attack path analysis engine.

    Detects relationships between risk-assessed findings, builds attack
    chains, merges duplicates, and ranks paths by overall risk.
    """

    def analyze(
        self,
        assessments: list[RiskAssessment],
        finding_map: dict[str, EnrichedFinding] | None = None,
    ) -> AttackGraph:
        """Analyze risk assessments and build an attack graph.

        Args:
            assessments: Risk-assessed findings from the risk scorer.
            finding_map: Optional mapping of ``correlation_id`` to
                ``EnrichedFinding`` for enriched relationship detection.
                When omitted, only risk-level data is used.

        Returns:
            An ``AttackGraph`` containing all discovered attack paths.
        """
        if not assessments:
            raise ValueError("assessments must not be empty")

        fm: dict[str, EnrichedFinding] = finding_map or {}

        # Build nodes
        nodes = self._build_nodes(assessments, fm)

        # Detect edges between nodes
        edges = self._detect_edges(nodes, fm)

        # Group connected nodes into paths
        path_groups = self._find_connected_groups(nodes, edges)

        # Build path objects
        paths: list[AttackPath] = []
        for group in path_groups:
            path = self._build_path(group, edges, fm)
            if path is not None:
                paths.append(path)

        # Sort by attack_score descending, then path_id for stability
        paths.sort(key=lambda p: (-p.attack_score, p.path_id))

        if not paths:
            # Fallback: each node becomes its own singleton path
            for node in nodes:
                path = self._build_singleton_path(node, fm)
                if path is not None:
                    paths.append(path)

        paths_tuple = tuple(paths)
        scores = [p.attack_score for p in paths_tuple]

        return AttackGraph(
            paths=paths_tuple,
            total_paths=len(paths_tuple),
            highest_score=max(scores) if scores else 0,
            average_score=sum(scores) / len(scores) if scores else 0.0,
            metadata={
                "total_assessments": str(len(assessments)),
                "total_nodes": str(len(nodes)),
                "total_edges": str(len(edges)),
            },
        )

    # ------------------------------------------------------------------
    # Node building
    # ------------------------------------------------------------------

    @staticmethod
    def _build_nodes(
        assessments: list[RiskAssessment],
        finding_map: dict[str, EnrichedFinding],
    ) -> list[AttackNode]:
        """Build attack nodes from risk assessments and enriched findings."""
        nodes: list[AttackNode] = []
        for assessment in assessments:
            finding = finding_map.get(assessment.correlation_id)
            asset = None
            if finding and finding.affected_assets:
                asset = finding.affected_assets[0]

            severity_str = "INFORMATIONAL"
            for factor in assessment.factors:
                if factor.name == "severity":
                    # Extract severity name from description: "Severity is HIGH"
                    if "Severity is " in factor.description:
                        severity_str = factor.description.split("Severity is ")[1].strip()
                    break

            node = AttackNode(
                node_id=f"node-{assessment.correlation_id}",
                correlation_id=assessment.correlation_id,
                title=finding.title if finding else assessment.correlation_id,
                severity=severity_str,
                category=finding.category if finding else "unknown",
                attack_surface=finding.attack_surface if finding else None,
                service=finding.service if finding else None,
                port=finding.port if finding else None,
                protocol=finding.protocol if finding else None,
                asset=asset,
                risk_score=assessment.score,
                risk_level=assessment.risk_level,
            )
            nodes.append(node)
        return nodes

    # ------------------------------------------------------------------
    # Edge detection
    # ------------------------------------------------------------------

    def _detect_edges(
        self,
        nodes: list[AttackNode],
        finding_map: dict[str, EnrichedFinding],
    ) -> list[AttackEdge]:
        """Detect reachability edges between all node pairs."""
        edges: list[AttackEdge] = []
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                edge = _is_reachable(nodes[i], nodes[j], finding_map)
                if edge is not None:
                    edges.append(edge)
        return edges

    # ------------------------------------------------------------------
    # Connected components (union-find)
    # ------------------------------------------------------------------

    @staticmethod
    def _find_connected_groups(
        nodes: list[AttackNode],
        edges: list[AttackEdge],
    ) -> list[list[AttackNode]]:
        """Group connected nodes via union-find."""
        if not edges:
            return [[n] for n in nodes]

        node_ids = [n.node_id for n in nodes]
        id_to_index = {nid: i for i, nid in enumerate(node_ids)}
        parent = list(range(len(nodes)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: int, y: int) -> None:
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[ry] = rx

        for edge in edges:
            si = id_to_index.get(edge.source_id)
            ti = id_to_index.get(edge.target_id)
            if si is not None and ti is not None:
                union(si, ti)

        groups: dict[int, list[AttackNode]] = defaultdict(list)
        for i, node in enumerate(nodes):
            groups[find(i)].append(node)

        return list(groups.values())

    # ------------------------------------------------------------------
    # Path construction
    # ------------------------------------------------------------------

    def _build_path(
        self,
        group: list[AttackNode],
        all_edges: list[AttackEdge],
        finding_map: dict[str, EnrichedFinding],
    ) -> AttackPath | None:
        """Build an ``AttackPath`` from a connected group of nodes."""
        if len(group) == 1:
            return self._build_singleton_path(group[0], finding_map)

        # Order nodes by attack stage, then risk score descending
        ordered = sorted(
            group,
            key=lambda n: (
                _ATTACK_STAGE.get(n.attack_surface or "", 99),
                -n.risk_score,
                n.node_id,
            ),
        )
        ordered_nodes = tuple(ordered)

        # Collect relevant edges
        node_ids = {n.node_id for n in ordered_nodes}
        path_edges = tuple(e for e in all_edges if e.source_id in node_ids and e.target_id in node_ids)

        path_id = _generate_path_id([n.node_id for n in ordered_nodes])

        # Compute attack score: max risk + average of rest, capped at 100
        risk_scores = [n.risk_score for n in ordered_nodes]
        max_score = max(risk_scores)
        if len(risk_scores) > 1:
            others = [s for s in risk_scores if s != max_score]
            avg_others = sum(others) / len(others) if others else 0
            attack_score = min(int(max_score * 0.6 + avg_others * 0.4), 100)
        else:
            attack_score = max_score

        # Confidence: average edge confidence
        conf = _confidence_from_edges(path_edges)

        # Estimated impact: use highest business impact across risk factors
        impact = self._estimate_impact(ordered_nodes, finding_map)

        # Attack complexity based on path length and remediation complexity
        complexity = self._estimate_complexity(ordered_nodes, finding_map)

        # Likelihood: average exploit likelihood
        likelihood = self._estimate_likelihood(ordered_nodes, finding_map)

        # Reasoning
        steps = _build_attack_steps(ordered_nodes)
        reasoning = (
            f"Attack path with {len(ordered_nodes)} step(s). "
            f"Score: {attack_score}/100. "
            f"Risk levels: {', '.join(n.risk_level for n in ordered_nodes)}. "
            f"Progression: {' → '.join(s.split(' — ')[0] for s in steps)}."
        )

        # Recommendations
        recs = _build_recommendations(ordered_nodes, finding_map)

        return AttackPath(
            path_id=path_id,
            nodes=ordered_nodes,
            edges=path_edges,
            attack_score=attack_score,
            confidence=round(conf, 2),
            estimated_impact=impact,
            attack_complexity=complexity,
            likelihood=likelihood,
            reasoning=reasoning,
            recommendations=recs,
        )

    @staticmethod
    def _build_singleton_path(
        node: AttackNode,
        finding_map: dict[str, EnrichedFinding],
    ) -> AttackPath:
        """Build a singleton path for an isolated node."""
        finding = finding_map.get(node.correlation_id)
        path_id = _generate_path_id([node.node_id])

        impact = "Unknown"
        if finding and finding.business_impact:
            impact = _IMPACT_ESTIMATES.get(finding.business_impact, "Unknown")

        complexity = "Unknown"
        if finding and finding.remediation_complexity:
            complexity = _COMPLEXITY_MAP.get(finding.remediation_complexity, "Unknown")

        likelihood = "Unknown"
        if finding and finding.exploit_likelihood:
            likelihood = _LIKELIHOOD_MAP.get(finding.exploit_likelihood, "Unknown")

        recs: tuple[str, ...] = ()
        if finding:
            recs = tuple(finding.recommendations)

        return AttackPath(
            path_id=path_id,
            nodes=(node,),
            edges=(),
            attack_score=node.risk_score,
            confidence=0.35,
            estimated_impact=impact,
            attack_complexity=complexity,
            likelihood=likelihood,
            reasoning=(
                f"Single-step path: {node.title} "
                f"({node.attack_surface or 'unknown'}, "
                f"risk {node.risk_score}). "
                f"No connections to other findings detected."
            ),
            recommendations=recs,
        )

    # ------------------------------------------------------------------
    # Impact / complexity / likelihood estimation
    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_impact(
        nodes: tuple[AttackNode, ...],
        finding_map: dict[str, EnrichedFinding],
    ) -> str:
        """Estimate the overall impact of an attack path."""
        impact_order = ["Severe", "High", "Moderate", "Minimal", "None", "Unknown"]
        best_impact = "Unknown"
        for node in nodes:
            finding = finding_map.get(node.correlation_id)
            if finding and finding.business_impact:
                mapped = _IMPACT_ESTIMATES.get(finding.business_impact, "Unknown")
                if impact_order.index(mapped) < impact_order.index(best_impact):
                    best_impact = mapped
        return best_impact

    @staticmethod
    def _estimate_complexity(
        nodes: tuple[AttackNode, ...],
        finding_map: dict[str, EnrichedFinding],
    ) -> str:
        """Estimate the overall complexity of an attack path."""
        has_hard = False
        has_medium = False
        for node in nodes:
            finding = finding_map.get(node.correlation_id)
            if finding and finding.remediation_complexity:
                if finding.remediation_complexity == "Hard":
                    has_hard = True
                elif finding.remediation_complexity == "Medium":
                    has_medium = True
        # More nodes = higher complexity
        if has_hard or len(nodes) >= 5:
            return "Complex"
        if has_medium or len(nodes) >= 3:
            return "Moderate"
        return "Simple"

    @staticmethod
    def _estimate_likelihood(
        nodes: tuple[AttackNode, ...],
        finding_map: dict[str, EnrichedFinding],
    ) -> str:
        """Estimate the overall likelihood of an attack path."""
        likelihoods = []
        for node in nodes:
            finding = finding_map.get(node.correlation_id)
            if finding and finding.exploit_likelihood:
                mapped = _LIKELIHOOD_MAP.get(finding.exploit_likelihood)
                if mapped:
                    likelihoods.append(mapped)
        if not likelihoods:
            return "Unknown"
        if "High" in likelihoods:
            return "High"
        if "Medium" in likelihoods:
            return "Medium"
        return "Low"

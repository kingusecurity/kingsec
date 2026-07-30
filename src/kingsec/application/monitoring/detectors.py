from __future__ import annotations


from kingsec.domain.asset import Asset
from kingsec.domain.enums import Severity
from kingsec.domain.monitoring import MonitorEvent, MonitorEventContext, MonitorEventType
from kingsec.domain.finding import Finding


class AssetChangeDetector:
    def detect_changes(self, previous: Asset | None, current: Asset) -> list[MonitorEvent]:
        events: list[MonitorEvent] = []

        if previous is None:
            events.append(
                MonitorEvent.create(
                    MonitorEventType.NEW_HOST,
                    asset_id=str(current.id),
                    title=f"New asset discovered: {current.hostname or current.ip_address or str(current.id)}",
                    description=f"Asset type: {current.asset_type.value}",
                    context=[
                        MonitorEventContext(key="hostname", value=current.hostname or ""),
                        MonitorEventContext(key="ip_address", value=current.ip_address or ""),
                        MonitorEventContext(key="asset_type", value=current.asset_type.value),
                    ],
                )
            )
            return events

        if previous.ip_address != current.ip_address:
            events.append(
                MonitorEvent.create(
                    MonitorEventType.ASSET_UPDATED,
                    asset_id=str(current.id),
                    title=f"IP address changed for {current.hostname or str(current.id)}",
                    description=f"IP changed: {previous.ip_address} -> {current.ip_address}",
                    context=[
                        MonitorEventContext(key="ip_address", value=current.ip_address or "", previous_value=previous.ip_address),
                    ],
                )
            )

        if previous.hostname != current.hostname:
            events.append(
                MonitorEvent.create(
                    MonitorEventType.ASSET_UPDATED,
                    asset_id=str(current.id),
                    title=f"Hostname changed for {str(current.id)}",
                    description=f"Hostname changed: {previous.hostname} -> {current.hostname}",
                    context=[
                        MonitorEventContext(key="hostname", value=current.hostname or "", previous_value=previous.hostname),
                    ],
                )
            )

        prev_ports = set(previous.open_ports or [])
        curr_ports = set(current.open_ports or [])
        new_ports = curr_ports - prev_ports
        removed_ports = prev_ports - curr_ports

        for port in new_ports:
            events.append(
                MonitorEvent.create(
                    MonitorEventType.NEW_OPEN_PORT,
                    asset_id=str(current.id),
                    title=f"New open port {port} on {current.hostname or current.ip_address or str(current.id)}",
                    description=f"Port {port} is now open",
                    context=[MonitorEventContext(key="port", value=str(port))],
                )
            )

        for port in removed_ports:
            events.append(
                MonitorEvent.create(
                    MonitorEventType.CLOSED_PORT,
                    asset_id=str(current.id),
                    title=f"Port {port} closed on {current.hostname or current.ip_address or str(current.id)}",
                    description=f"Port {port} is no longer open",
                    context=[MonitorEventContext(key="port", value=str(port))],
                )
            )

        if previous.certificate_issuer != current.certificate_issuer:
            events.append(
                MonitorEvent.create(
                    MonitorEventType.CERTIFICATE_RENEWED,
                    asset_id=str(current.id),
                    title=f"Certificate renewed for {current.hostname or str(current.id)}",
                    description=f"Issuer: {current.certificate_issuer}",
                    context=[
                        MonitorEventContext(key="certificate_issuer", value=current.certificate_issuer or ""),
                    ],
                )
            )

        if previous.tls_version != current.tls_version and current.tls_version:
            events.append(
                MonitorEvent.create(
                    MonitorEventType.TLS_DOWNGRADED,
                    asset_id=str(current.id),
                    title=f"TLS version changed for {current.hostname or str(current.id)}",
                    description=f"TLS: {previous.tls_version} -> {current.tls_version}",
                    context=[
                        MonitorEventContext(key="tls_version", value=current.tls_version, previous_value=previous.tls_version),
                    ],
                )
            )

        prev_risk = previous.risk_score
        curr_risk = current.risk_score
        if abs(curr_risk - prev_risk) > 0.5:
            events.append(
                MonitorEvent.create(
                    MonitorEventType.RISK_SCORE_CHANGED,
                    asset_id=str(current.id),
                    title=f"Risk score changed for {current.hostname or str(current.id)}",
                    description=f"Risk score: {prev_risk:.1f} -> {curr_risk:.1f}",
                    context=[
                        MonitorEventContext(key="risk_score", value=str(curr_risk), previous_value=str(prev_risk)),
                    ],
                )
            )

        return events


class FindingChangeDetector:
    def detect_new_critical(self, finding: Finding, asset_id: str | None = None) -> list[MonitorEvent]:
        events: list[MonitorEvent] = []
        if finding.severity in (Severity.CRITICAL,):
            events.append(
                MonitorEvent.create(
                    MonitorEventType.NEW_CRITICAL_FINDING,
                    asset_id=asset_id or "",
                    title=f"Critical finding: {finding.title}",
                    description=finding.description,
                    context=[
                        MonitorEventContext(key="finding_id", value=str(finding.id)),
                        MonitorEventContext(key="severity", value="critical"),
                    ],
                )
            )
        return events

    def detect_resolved(self, finding: Finding, asset_id: str | None = None) -> list[MonitorEvent]:
        events: list[MonitorEvent] = []
        status = getattr(finding, "status", None)
        if status is not None:
            status_value = status.value if hasattr(status, "value") else str(status)
            if status_value in ("resolved", "closed", "mitigated"):
                events.append(
                    MonitorEvent.create(
                        MonitorEventType.FINDING_RESOLVED,
                        asset_id=asset_id or "",
                        title=f"Finding resolved: {finding.title}",
                        description=finding.description,
                        context=[
                            MonitorEventContext(key="finding_id", value=str(finding.id)),
                            MonitorEventContext(key="status", value=status_value),
                        ],
                    )
                )
        return events

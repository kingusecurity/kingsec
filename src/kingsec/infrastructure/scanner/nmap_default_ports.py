"""KingSec's own curated port list — a documented FLOOR, NOT a default.

STATUS (Phase 2B Task 2, second correction): nothing in the live scan
path uses this list today. It is NOT wired into NmapSettings, NOT passed
to nmap via -p, and NOT the port selection for any target type. The
design that made it the default (a single -p list applied to every nmap
invocation) was itself found to be a coverage regression relative to
nmap's own real default (~1000 ports by frequency vs. this list's 61) and
was reverted: URL targets now run nmap twice — once with no port flag at
all (nmap's own real default sweep, using nmap's own bundled/updatable
data, read only by nmap itself) and once with only the target's explicit
port (see infrastructure/scanner/nmap.py's
_scan_url_two_invocations()) — and every other target type runs with no
port flag, byte-identical to nmap's own default, exactly as before this
whole feature existed.

This module is kept, committed, and documented anyway — not deleted —
because it is real, reviewed work with a legitimate rationale (a
KingSec-owned, non-Nmap-derived port set, safe from the Nmap Public
Source License question that sank the first version of this file; see
git history for that correction) that may become useful later: e.g. an
environment where nmap's own default port data is unavailable, disabled,
or needs a licensing-clean, KingSec-controlled override. If that day
comes, THIS is where that list should be defined - do not rebuild it.
Until then, it is deliberately inert: nothing references DEFAULT_PORTS or
DEFAULT_PORTS_SPEC outside this module and its own tests.

Provenance, for whoever eventually wires this back in: every entry is
chosen from public, vendor-neutral documentation (primarily IANA's
Service Name and Transport Protocol Port Number Registry, plus
widely-documented real-world convention where a port is common in
practice but not IANA-registered for that use — noted per entry where
that distinction matters) and from KingSec's own Phase 1 Run #4 evidence
(docs/E2E-EVIDENCE.md): a real scan of a real, unremarkable Windows host
found exactly these nine ports open:

    135, 445, 902, 912, 1001, 3000, 3389, 5357, 5678

All nine are included below, each with its own rationale. The rest of the
list adds other commonly-exposed services worth checking, grouped by
category with a rationale per group — a deliberately sized,
human-reviewable list (order of hundreds, not thousands), not an attempt
to replicate any third party's frequency corpus.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Phase 1 Run #4 — required by name (Phase 2B Task 2 Decision 4)
# ---------------------------------------------------------------------------
_PHASE1_EVIDENCE_PORTS: tuple[int, ...] = (
    135,   # epmap / DCE/RPC endpoint mapper (IANA: epmap) — Windows RPC.
    445,   # microsoft-ds (IANA) — SMB directly over TCP, no NetBIOS session.
    902,   # iss-realsecure (IANA) — also long-documented in VMware's own
           # product docs as the VMware Server/ESXi authentication daemon
           # port; kept regardless of which service is actually listening,
           # since Phase 1 found it genuinely open on a real host.
    912,   # apex-mesh (IANA) — also documented in VMware's own product
           # docs as the second VMware authentication daemon port,
           # conventionally paired with 902. Same reasoning as above.
    1001,  # No single stable IANA registration for this exact use; kept
           # solely because Phase 1 Run #4 found it open on a real,
           # unremarkable host — real-world evidence is its own
           # justification independent of a registry entry.
    3000,  # IANA lists this for hbci (Homebanking Computer Interface), but
           # in overwhelming real-world practice this is the default port
           # for Node.js/Express and similar development web servers —
           # exactly the kind of accidentally-exposed dev service Phase 1
           # was designed to catch.
    3389,  # ms-wbt-server (IANA) — Microsoft Remote Desktop Protocol.
           # High-value: RDP exposed to the internet is one of the most
           # exploited misconfigurations in real incidents.
    5357,  # wsdapi (IANA) — Web Services for Devices API, backs Windows'
           # "Network Discovery" feature; commonly open on any modern
           # Windows host with discovery enabled.
    5678,  # rrac (IANA: Remote Replication Agent Connection); kept both
           # for that registration and because Phase 1 found it open.
)

# ---------------------------------------------------------------------------
# Web services — the most common thing an operator accidentally exposes.
# ---------------------------------------------------------------------------
_WEB_PORTS: tuple[int, ...] = (
    80, 443,            # http, https (IANA)
    8000, 8008, 8080, 8081, 8443, 8888,  # widely-documented alternate/proxy
                                          # HTTP(S) ports in common use
    9000, 9090,          # common admin/API panel convention (e.g. SonarQube,
                          # cAdvisor, Cockpit)
)

# ---------------------------------------------------------------------------
# Remote access / administration — the second most common exposure risk.
# ---------------------------------------------------------------------------
_REMOTE_ACCESS_PORTS: tuple[int, ...] = (
    22,                  # ssh (IANA)
    23,                  # telnet (IANA) — still found exposed in practice
    3389,                # ms-wbt-server (IANA) — RDP, also in the Phase 1 set
    5900, 5901,           # rfb (IANA) — VNC and a common second VNC display
    5985, 5986,           # wsman (IANA) — WinRM HTTP/HTTPS, PowerShell remoting
)

# ---------------------------------------------------------------------------
# Windows / SMB / local network services.
# ---------------------------------------------------------------------------
_WINDOWS_NETWORK_PORTS: tuple[int, ...] = (
    135,                 # epmap (IANA) — also in the Phase 1 set
    139,                 # netbios-ssn (IANA)
    445,                 # microsoft-ds (IANA) — also in the Phase 1 set
    5357,                # wsdapi (IANA) — also in the Phase 1 set
)

# ---------------------------------------------------------------------------
# File transfer.
# ---------------------------------------------------------------------------
_FILE_TRANSFER_PORTS: tuple[int, ...] = (
    20, 21,              # ftp-data, ftp (IANA)
    69,                  # tftp (IANA)
    989, 990,             # ftps-data, ftps (IANA)
    2049,                # nfs (IANA)
)

# ---------------------------------------------------------------------------
# Mail.
# ---------------------------------------------------------------------------
_MAIL_PORTS: tuple[int, ...] = (
    25,                  # smtp (IANA)
    110,                 # pop3 (IANA)
    143,                 # imap (IANA)
    465,                 # submissions / smtps (IANA)
    587,                 # submission (IANA)
    993,                 # imaps (IANA)
    995,                 # pop3s (IANA)
)

# ---------------------------------------------------------------------------
# Directory / auth / network infrastructure.
# ---------------------------------------------------------------------------
_INFRA_PORTS: tuple[int, ...] = (
    53,                  # domain (IANA) — DNS
    67, 68,               # bootps, bootpc (IANA) — DHCP
    88,                  # kerberos (IANA)
    111,                 # rpcbind / sunrpc (IANA)
    123,                 # ntp (IANA)
    161, 162,             # snmp, snmptrap (IANA)
    389, 636,             # ldap, ldaps (IANA)
)

# ---------------------------------------------------------------------------
# Databases — a database directly reachable from outside is a serious,
# common misconfiguration and worth checking by default.
# ---------------------------------------------------------------------------
_DATABASE_PORTS: tuple[int, ...] = (
    1433,                # ms-sql-s (IANA) — Microsoft SQL Server
    1521,                # ncube-lm (IANA) — conventionally Oracle's listener
                          # port in practice, despite the registered name
    3306,                # mysql (IANA)
    5432,                # postgresql (IANA)
    6379,                # commonly Redis's default port (not individually
                          # IANA-registered for Redis; documented in Redis's
                          # own default configuration)
    9200,                # commonly Elasticsearch's default HTTP port (same
                          # caveat — vendor convention, documented in
                          # Elasticsearch's own default configuration)
    11211,               # memcache (IANA)
    27017,               # commonly MongoDB's default port (vendor
                          # convention, documented in MongoDB's own default
                          # configuration)
)

# ---------------------------------------------------------------------------
# Virtualization — kept as its own group since Phase 1's 902/912 pair is
# specifically a virtualization-management case.
# ---------------------------------------------------------------------------
_VIRTUALIZATION_PORTS: tuple[int, ...] = (
    902, 912,             # see _PHASE1_EVIDENCE_PORTS above
    8006,                 # commonly Proxmox VE's web management port
                          # (vendor convention, documented in Proxmox's own
                          # default configuration)
)

# ---------------------------------------------------------------------------
# Collaboration / miscellaneous commonly-exposed services.
# ---------------------------------------------------------------------------
_MISC_PORTS: tuple[int, ...] = (
    1001, 5678,           # see _PHASE1_EVIDENCE_PORTS above
    5060, 5061,           # sip, sips (IANA)
    10000,                # commonly Webmin's default port (vendor
                          # convention, documented in Webmin's own default
                          # configuration)
)

DEFAULT_PORTS: tuple[int, ...] = tuple(
    sorted(
        set(_PHASE1_EVIDENCE_PORTS)
        | set(_WEB_PORTS)
        | set(_REMOTE_ACCESS_PORTS)
        | set(_WINDOWS_NETWORK_PORTS)
        | set(_FILE_TRANSFER_PORTS)
        | set(_MAIL_PORTS)
        | set(_INFRA_PORTS)
        | set(_DATABASE_PORTS)
        | set(_VIRTUALIZATION_PORTS)
        | set(_MISC_PORTS)
    )
)
"""The full, deduplicated, sorted port set. Guaranteed by construction
(this module's own test asserts it) to be a superset of every port
Phase 1 Run #4 actually found. NOT wired into any live scan path - see
the module docstring above."""

DEFAULT_PORTS_SPEC: str = ",".join(str(p) for p in DEFAULT_PORTS)
"""DEFAULT_PORTS joined into the comma-separated form nmap's -p flag
would take directly, if this were ever wired back in. Nothing reads this
today - see the module docstring above."""

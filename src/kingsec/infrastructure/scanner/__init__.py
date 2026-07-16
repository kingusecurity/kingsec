"""KingSec scanner adapter (infrastructure layer).

Implements the application's ``ScannerPort`` by invoking scanner CLIs safely
via subprocess and parsing their output into domain findings.

Public API
    Adapter:      NucleiScannerAdapter, NmapScannerAdapter, NiktoScannerAdapter,
                  FfufScannerAdapter, GobusterScannerAdapter, AmassScannerAdapter,
                  TrivyScannerAdapter, ZapScannerAdapter, SemgrepScannerAdapter
    Plugin:       NucleiPlugin, NmapPlugin, NiktoPlugin, FfufPlugin, GobusterPlugin,
                  AmassPlugin, TrivyPlugin, ZapPlugin, SemgrepPlugin
    Runner:       CommandRunner, SubprocessCommandRunner, CommandResult
    Parser:       parse_nuclei_jsonl, parse_nmap_xml, parse_nikto_output,
                  parse_ffuf_json, parse_gobuster_output, parse_amass_json,
                  parse_trivy_json, parse_zap_json, parse_semgrep_json
    Registry:     InMemoryPluginRegistry
    Orchestrator: ScannerOrchestrator
    Errors:       ScannerExecutionError, ScannerOutputError
    DI wiring:    register_scanner
"""

from __future__ import annotations

from .amass import AmassScannerAdapter
from .amass_parser import parse_amass_json
from .errors import ScannerExecutionError, ScannerOutputError
from .ffuf import FfufScannerAdapter
from .ffuf_parser import parse_ffuf_json
from .gobuster import GobusterScannerAdapter
from .gobuster_parser import parse_gobuster_output
from .nikto import NiktoScannerAdapter
from .nikto_parser import parse_nikto_output
from .nmap import NmapScannerAdapter
from .nmap_parser import parse_nmap_xml
from .nuclei import NucleiScannerAdapter
from .orchestrator import ScannerOrchestrator
from .parser import parse_nuclei_jsonl
from .plugins.amass import AmassPlugin
from .plugins.ffuf import FfufPlugin
from .plugins.gobuster import GobusterPlugin
from .plugins.nikto import NiktoPlugin
from .plugins.nmap import NmapPlugin
from .plugins.nuclei import NucleiPlugin
from .plugins.semgrep import SemgrepPlugin
from .plugins.trivy import TrivyPlugin
from .plugins.zap import ZapPlugin
from .provisioning import register_scanner
from .registry import InMemoryPluginRegistry
from .runner import CommandResult, CommandRunner, SubprocessCommandRunner
from .semgrep import SemgrepScannerAdapter
from .semgrep_parser import parse_semgrep_json
from .trivy import TrivyScannerAdapter
from .trivy_parser import parse_trivy_json
from .zap import ZapScannerAdapter
from .zap_parser import parse_zap_json

__all__ = [
    "AmassPlugin",
    "AmassScannerAdapter",
    "CommandResult",
    "CommandRunner",
    "FfufPlugin",
    "FfufScannerAdapter",
    "GobusterPlugin",
    "GobusterScannerAdapter",
    "InMemoryPluginRegistry",
    "NiktoPlugin",
    "NiktoScannerAdapter",
    "NmapPlugin",
    "NmapScannerAdapter",
    "NucleiPlugin",
    "NucleiScannerAdapter",
    "ScannerExecutionError",
    "ScannerOrchestrator",
    "ScannerOutputError",
    "SemgrepPlugin",
    "SemgrepScannerAdapter",
    "SubprocessCommandRunner",
    "TrivyPlugin",
    "TrivyScannerAdapter",
    "ZapPlugin",
    "ZapScannerAdapter",
    "parse_amass_json",
    "parse_ffuf_json",
    "parse_gobuster_output",
    "parse_nikto_output",
    "parse_nmap_xml",
    "parse_nuclei_jsonl",
    "parse_semgrep_json",
    "parse_trivy_json",
    "parse_zap_json",
    "register_scanner",
]

"""KingSec scanner adapter (infrastructure layer).

Implements the application's ``ScannerPort`` by invoking scanner CLIs safely
via subprocess and parsing their output into domain findings.

Public API
    Adapter:      NucleiScannerAdapter, NmapScannerAdapter, NiktoScannerAdapter,
                  FfufScannerAdapter
    Plugin:       NucleiPlugin, NmapPlugin, NiktoPlugin, FfufPlugin
    Runner:       CommandRunner, SubprocessCommandRunner, CommandResult
    Parser:       parse_nuclei_jsonl, parse_nmap_xml, parse_nikto_output,
                  parse_ffuf_json
    Registry:     InMemoryPluginRegistry
    Orchestrator: ScannerOrchestrator
    Errors:       ScannerExecutionError, ScannerOutputError
    DI wiring:    register_scanner
"""

from __future__ import annotations

from .errors import ScannerExecutionError, ScannerOutputError
from .ffuf import FfufScannerAdapter
from .ffuf_parser import parse_ffuf_json
from .nikto import NiktoScannerAdapter
from .nikto_parser import parse_nikto_output
from .nmap import NmapScannerAdapter
from .nmap_parser import parse_nmap_xml
from .nuclei import NucleiScannerAdapter
from .orchestrator import ScannerOrchestrator
from .parser import parse_nuclei_jsonl
from .plugins.ffuf import FfufPlugin
from .plugins.nikto import NiktoPlugin
from .plugins.nmap import NmapPlugin
from .plugins.nuclei import NucleiPlugin
from .provisioning import register_scanner
from .registry import InMemoryPluginRegistry
from .runner import CommandResult, CommandRunner, SubprocessCommandRunner

__all__ = [
    "CommandResult",
    "CommandRunner",
    "FfufPlugin",
    "FfufScannerAdapter",
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
    "SubprocessCommandRunner",
    "parse_ffuf_json",
    "parse_nikto_output",
    "parse_nmap_xml",
    "parse_nuclei_jsonl",
    "register_scanner",
]

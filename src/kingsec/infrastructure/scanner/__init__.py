"""KingSec Nuclei scanner adapter (infrastructure layer).

Implements the application's ``ScannerPort`` by invoking the Nuclei CLI safely
via subprocess and parsing its JSONL output into domain findings.

Public API
    Adapter:      NucleiScannerAdapter
    Runner:       CommandRunner, SubprocessCommandRunner, CommandResult
    Parser:       parse_nuclei_jsonl
    Registry:     InMemoryPluginRegistry
    Orchestrator: ScannerOrchestrator
    Errors:       ScannerExecutionError, ScannerOutputError
    DI wiring:    register_scanner
"""

from __future__ import annotations

from .errors import ScannerExecutionError, ScannerOutputError
from .nuclei import NucleiScannerAdapter
from .orchestrator import ScannerOrchestrator
from .parser import parse_nuclei_jsonl
from .provisioning import register_scanner
from .registry import InMemoryPluginRegistry
from .runner import CommandResult, CommandRunner, SubprocessCommandRunner

__all__ = [
    "CommandResult",
    "CommandRunner",
    "InMemoryPluginRegistry",
    "NucleiScannerAdapter",
    "ScannerExecutionError",
    "ScannerOrchestrator",
    "ScannerOutputError",
    "SubprocessCommandRunner",
    "parse_nuclei_jsonl",
    "register_scanner",
]

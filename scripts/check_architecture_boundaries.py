"""AST-based architecture boundary check — Module 6.2.

Verifies that domain layer has no imports from application, infrastructure,
or adapters. Also verifies that application layer does not import from
infrastructure or adapters.
"""

import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(r"D:\New_folder\kingsec\src\kingsec")

DOMAIN_DIR = PROJECT_ROOT / "domain"
APPLICATION_DIR = PROJECT_ROOT / "application"
INFRASTRUCTURE_DIR = PROJECT_ROOT / "infrastructure"
ADAPTERS_DIR = PROJECT_ROOT / "adapters"

ERRORS: list[str] = []


def _collect_python_files(directory: Path) -> list[Path]:
    """Recursively collect .py files, skipping __pycache__."""
    files: list[Path] = []
    if not directory.exists():
        return files
    for p in directory.rglob("*.py"):
        if "__pycache__" not in str(p):
            files.append(p)
    return files


def _get_module_root(file_path: Path) -> str:
    """Determine which top-level module a file belongs to."""
    rel = file_path.relative_to(PROJECT_ROOT)
    parts = rel.parts
    return parts[0] if parts else ""


def _extract_imports(file_path: Path) -> list[tuple[int, str]]:
    """Parse a Python file and return (lineno, module_name) for all imports."""
    try:
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
    except SyntaxError:
        return []
    imports: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append((node.lineno, node.module))
    return imports


def _is_submodule_of(module_name: str, target: str) -> bool:
    """Check if module_name is or is a submodule of target."""
    return module_name == target or module_name.startswith(target + ".")


def check_domain_isolation() -> None:
    """Domain layer must not import from application, infrastructure, or adapters."""
    for f in _collect_python_files(DOMAIN_DIR):
        for lineno, mod in _extract_imports(f):
            _get_module_root(f)
            if any(
                _is_submodule_of(mod, target)
                for target in ["application", "infrastructure", "adapters"]
            ):
                ERRORS.append(
                    f"  {f.name}:{lineno} -> {mod} "
                    f"(domain must not import from application/infrastructure/adapters)"
                )


def check_application_isolation() -> None:
    """Application layer must not import from infrastructure or adapters."""
    for f in _collect_python_files(APPLICATION_DIR):
        for lineno, mod in _extract_imports(f):
            _get_module_root(f)
            if any(
                _is_submodule_of(mod, target) for target in ["infrastructure", "adapters"]
            ):
                ERRORS.append(
                    f"  {f.name}:{lineno} -> {mod} "
                    f"(application must not import from infrastructure/adapters)"
                )


def main() -> int:
    print("=" * 70)
    print("Architecture Boundary Check — Module 6.2")
    print("=" * 70)

    check_domain_isolation()
    check_application_isolation()

    if ERRORS:
        print(f"\nFAILED: {len(ERRORS)} violation(s) found:\n")
        for e in ERRORS:
            print(e)
        return 1

    print("\nPASSED: No architecture violations detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

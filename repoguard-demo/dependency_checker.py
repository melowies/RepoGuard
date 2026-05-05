"""RepoGuard demo wrapper for the dependency risk checker.

This file lets the presentation commands run from inside repoguard-demo while
keeping the implementation in the project-level dependency_checker.py module.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


_IMPLEMENTATION_PATH = Path(__file__).resolve().parents[1] / "dependency_checker.py"
_SPEC = importlib.util.spec_from_file_location("repoguard_dependency_checker_impl", _IMPLEMENTATION_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"Could not load dependency checker implementation from {_IMPLEMENTATION_PATH}")

_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)

DependencyCheckerError = _MODULE.DependencyCheckerError
DependencyRiskScanner = _MODULE.DependencyRiskScanner
ensure_demo_vulnerability_db = _MODULE.ensure_demo_vulnerability_db
scan_dependencies = _MODULE.scan_dependencies
main = _MODULE.main


if __name__ == "__main__":
    raise SystemExit(main())

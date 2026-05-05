"""RepoGuard demo wrapper for the CI/CD workflow risk scanner.

This file lets the presentation commands run from inside repoguard-demo while
keeping the implementation in the project-level cicd_scanner.py module.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


_IMPLEMENTATION_PATH = Path(__file__).resolve().parents[1] / "cicd_scanner.py"
_SPEC = importlib.util.spec_from_file_location("repoguard_cicd_scanner_impl", _IMPLEMENTATION_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"Could not load CI/CD scanner implementation from {_IMPLEMENTATION_PATH}")

_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)

CICDScannerError = _MODULE.CICDScannerError
CICDRiskScanner = _MODULE.CICDRiskScanner
scan_cicd_risks = _MODULE.scan_cicd_risks
main = _MODULE.main


if __name__ == "__main__":
    raise SystemExit(main())

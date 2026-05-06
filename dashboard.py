"""RepoGuard Dashboard and Security Score module.

This file combines the secret scanner, dependency checker, CI/CD scanner, and
cryptographic verifier into one product-style report.

CLI examples:
    python dashboard.py vulnerable-demo-repo
    python dashboard.py secure-demo-repo
    python dashboard.py secure-demo-repo --tamper-release
    python dashboard.py secure-demo-repo --html repoguard-dashboard.html
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import mimetypes
import shutil
import sys
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, unquote, urlparse

from cicd_scanner import CICDScannerError, scan_cicd_risks
from crypto_verifier import CryptoVerifierError, generate_sha256, tamper_release_file, verify_release
from dependency_checker import DependencyCheckerError, DependencyRiskScanner, parse_github_url, scan_dependencies
from secret_scanner import scan_secrets


SCRIPT_DIR = Path(__file__).resolve().parent
FRONTEND_ROOT = SCRIPT_DIR / "repo-guard"
DEMO_ROOT = SCRIPT_DIR / "repoguard-demo"
DEMO_REPOS = {
    "vulnerable-demo-repo": DEMO_ROOT / "vulnerable-demo-repo",
    "secure-demo-repo": DEMO_ROOT / "secure-demo-repo",
}
DEFAULT_RELEASE_FILE_NAME = "app-v1.0.zip"
NOT_APPLICABLE = "Not Applicable"
NO_RELEASE_MESSAGE = "No release artifacts were found; release verification is not applicable."
DEFAULT_DB_PATH = SCRIPT_DIR / "vulnerability_db.json"
ATTACK_WORKSPACE = DEMO_ROOT / ".live-attack-workspace"
ATTACK_WORKSPACE_LOCK = threading.Lock()
ATTACK_ACTIONS = {
    "tamper-release": {
        "label": "Yayın Dosyasını Kurcala",
        "description": "release/app-v1.0.zip dosyasını aynı adla koruyarak küçük bir değişiklik yapar.",
    },
    "leak-secret": {
        "label": "Sahte Secret Sızdır",
        "description": "Sadece sınıf demosu için sahte bir API anahtarı ekler ve secret tarayıcıyı çalıştırır.",
    },
    "risky-workflow": {
        "label": "Workflow'u Riskli Yap",
        "description": ".github/workflows/deploy.yml dosyasına permissions: write-all ekler.",
    },
    "break-signature": {
        "label": "İmzayı Boz",
        "description": "Yayın imzasını geçersiz demo baytlarıyla değiştirir.",
    },
}

SECRET_PENALTIES = {
    "critical": 25,
    "high": 15,
    "medium": 8,
}
DEPENDENCY_PENALTIES = {
    "high": 15,
    "medium": 8,
}
CICD_PENALTIES = {
    "critical": 15,
    "high": 15,
    "medium": 8,
}
HASH_MISMATCH_PENALTY = 25
INVALID_SIGNATURE_PENALTY = 30
MERKLE_MISMATCH_PENALTY = 20
COMBINED_SOURCE_AND_CRYPTO_PENALTY = 8
AUDIT_ZERO_HASH = "0" * 64
VIRTUAL_REPOSITORY_FILES = [
    ("package.json", "package.json"),
    ("app.js", "src/app.js"),
    ("workflow.yml", ".github/workflows/deploy.yml"),
    ("README.md", "README.md"),
]


@dataclass
class PreparedRepo:
    requested_source: str
    display_source: str
    local_path: Path
    is_temporary: bool = False


def build_dashboard_summary(
    repo_source: str,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
    release_file_name: str = DEFAULT_RELEASE_FILE_NAME,
    tamper_release: bool = False,
    score_mode: str = "dashboard",
) -> dict[str, Any]:
    """Run all RepoGuard checks and return a complete dashboard payload."""

    errors: list[str] = []
    warnings: list[str] = []
    tamper_result: dict[str, Any] | None = None

    with prepare_repo_source(repo_source) as prepared_repo:
        if tamper_release:
            tamper_result = run_tamper_simulator(prepared_repo.local_path, release_file_name, errors)

        secrets = _run_scanner(
            "secret scanner",
            lambda: scan_secrets(str(prepared_repo.local_path)),
            errors,
        )
        dependencies = _run_scanner(
            "dependency checker",
            lambda: scan_dependencies(str(prepared_repo.local_path), db_path=str(db_path)),
            errors,
        )
        cicd_risks = _run_scanner(
            "CI/CD scanner",
            lambda: scan_cicd_risks(str(prepared_repo.local_path)),
            errors,
        )
        crypto_result = verify_repo_release(prepared_repo.local_path, release_file_name)
        repository_integrity = build_repository_integrity_report(prepared_repo.local_path)
        crypto_result["repository_integrity_match"] = repository_integrity["root_match"]
        crypto_result["repository_merkle_root"] = repository_integrity["current_root"]
        crypto_result["expected_repository_merkle_root"] = repository_integrity["expected_root"]
        score_result = calculate_security_score(
            secret_findings=secrets,
            dependency_findings=dependencies,
            cicd_findings=cicd_risks,
            crypto_result=crypto_result,
            mode=score_mode,
        )
        release_status = decide_release_status(score_result["security_score"], crypto_result)

        crypto_panel = dict(crypto_result)
        crypto_panel["release_status"] = release_status

        summary = {
            "repo_source": prepared_repo.display_source,
            "security_score": score_result["security_score"],
            "release_status": release_status,
            "summary": {
                "secrets_found": len(secrets),
                "vulnerable_dependencies": len(dependencies),
                "cicd_risks": len(cicd_risks),
                "hash_status": _hash_status(crypto_result),
                "signature_status": str(crypto_result.get("signature_status", "Error")),
                "merkle_status": _repository_integrity_status(repository_integrity),
            },
            "findings": {
                "secrets": sanitize_secret_findings(secrets),
                "dependencies": dependencies,
                "cicd": cicd_risks,
                "crypto": crypto_panel,
                "repository_integrity": repository_integrity,
            },
            "score_breakdown": score_result,
            "tamper_result": tamper_result,
            "errors": errors,
            "warnings": warnings,
        }
        if not prepared_repo.is_temporary:
            summary["resolved_repo_path"] = str(prepared_repo.local_path)
        return summary


def build_attack_simulation_payload(action: str | None = None) -> dict[str, Any]:
    """Create a before/after payload for the live classroom attack screen."""

    selected_action = (action or "").strip() or "baseline"
    errors: list[str] = []
    attack_result: dict[str, Any] | None = None

    if selected_action != "baseline" and selected_action not in ATTACK_ACTIONS:
        errors.append(f"Unknown attack action: {selected_action}")
        selected_action = "baseline"

    with ATTACK_WORKSPACE_LOCK:
        workspace_path = reset_attack_workspace()
        before = _scan_attack_workspace(workspace_path, "Saldırı Öncesi")

        if selected_action != "baseline":
            try:
                attack_result = apply_attack_action(selected_action, workspace_path)
            except Exception as error:  # Keep the presentation page alive if an optional demo fails.
                errors.append(f"{ATTACK_ACTIONS[selected_action]['label']} failed: {error}")

        after = _scan_attack_workspace(workspace_path, "Saldırı Sonrası")

    audit_log = build_hash_chain_audit_log(selected_action, attack_result, before, after)

    return {
        "action": selected_action,
        "action_label": ATTACK_ACTIONS.get(selected_action, {}).get("label", "Onaylı Başlangıç"),
        "actions": ATTACK_ACTIONS,
        "before": before,
        "after": after,
        "audit_log": audit_log,
        "attack_result": attack_result,
        "errors": errors,
        "workspace_path": str(workspace_path),
    }


def reset_attack_workspace() -> Path:
    """Restore a clean copy of the secure demo repo for one attack run."""

    source_repo = DEMO_REPOS["secure-demo-repo"]
    if not source_repo.exists():
        raise ValueError(f"Demo repository is missing: {source_repo}")

    _assert_safe_attack_workspace(ATTACK_WORKSPACE)
    if ATTACK_WORKSPACE.exists():
        shutil.rmtree(ATTACK_WORKSPACE)

    shutil.copytree(
        source_repo,
        ATTACK_WORKSPACE,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    return ATTACK_WORKSPACE.resolve()


def apply_attack_action(action: str, repo_path: Path) -> dict[str, Any]:
    """Mutate the live attack workspace for the selected attack button."""

    if action == "tamper-release":
        return _attack_tamper_release(repo_path)
    if action == "leak-secret":
        return _attack_leak_fake_secret(repo_path)
    if action == "risky-workflow":
        return _attack_make_workflow_risky(repo_path)
    if action == "break-signature":
        return _attack_break_signature(repo_path)
    raise ValueError(f"Unsupported attack action: {action}")


def _scan_attack_workspace(repo_path: Path, label: str) -> dict[str, Any]:
    payload = build_dashboard_summary(str(repo_path), score_mode="dashboard")
    payload["repo_source"] = f"secure-demo-repo ({label})"
    return payload


def _attack_tamper_release(repo_path: Path) -> dict[str, Any]:
    release_file = repo_path / "release" / DEFAULT_RELEASE_FILE_NAME
    result = tamper_release_file(str(release_file))
    result.update(
        {
            "attack": "tamper-release",
            "label": ATTACK_ACTIONS["tamper-release"]["label"],
            "target": "release/app-v1.0.zip",
            "message": "Yayın dosyası küçük bir değişiklikle kurcalandı. Doğrulama artık BLOKE göstermeli.",
        }
    )
    return result


def _attack_leak_fake_secret(repo_path: Path) -> dict[str, Any]:
    secret_file = repo_path / "src" / "app.js"
    if not secret_file.exists():
        raise ValueError(f"Missing virtual source file: {secret_file}")

    original = secret_file.read_text(encoding="utf-8")
    injected_secret = (
        "\n// RepoGuard classroom demo secret. This token is fake and intentionally invalid.\n"
        'const DEMO_API_KEY = "rgd_demo_token_DO_NOT_USE_2026_7f9a3c1b5e";\n'
    )
    secret_file.write_text(original.rstrip() + injected_secret, encoding="utf-8")
    return {
        "attack": "leak-secret",
        "label": ATTACK_ACTIONS["leak-secret"]["label"],
        "target": "src/app.js",
        "message": "Secret tarayıcı için sınıf demosuna özel sahte API anahtarı eklendi.",
    }


def _attack_make_workflow_risky(repo_path: Path) -> dict[str, Any]:
    workflow_file = repo_path / ".github" / "workflows" / "deploy.yml"
    if not workflow_file.exists():
        raise ValueError(f"Missing workflow file: {workflow_file}")

    risky = "\n".join(
        [
            "name: Risky Deploy Workflow",
            "",
            "on:",
            "  pull_request_target:",
            "    branches: [ main ]",
            "",
            "permissions: write-all",
            "",
            "jobs:",
            "  deploy:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@main",
            "      - name: Deploy with remote installer",
            "        run: curl -fsSL https://example.invalid/install.sh | bash",
            "",
        ]
    )
    workflow_file.write_text(risky, encoding="utf-8")
    return {
        "attack": "risky-workflow",
        "label": ATTACK_ACTIONS["risky-workflow"]["label"],
        "target": ".github/workflows/deploy.yml",
        "message": "Workflow yetkisi permissions: write-all olarak değiştirildi.",
        "message": "Workflow now demonstrates permissions: write-all, pull_request_target, curl | bash, and an unpinned action.",
    }


def _attack_break_signature(repo_path: Path) -> dict[str, Any]:
    signature_file = repo_path / "release" / f"{DEFAULT_RELEASE_FILE_NAME}.sig"
    if not signature_file.exists():
        raise ValueError(f"Missing signature file: {signature_file}")

    signature_file.write_bytes(b"RepoGuard invalid classroom demo signature.\n")
    return {
        "attack": "break-signature",
        "label": ATTACK_ACTIONS["break-signature"]["label"],
        "target": "release/app-v1.0.zip.sig",
        "message": "Yayın imzası geçersiz demo baytlarıyla değiştirildi.",
    }


def _replace_permissions_block(content: str) -> str:
    lines = content.splitlines()
    replaced = False
    updated: list[str] = []
    index = 0

    while index < len(lines):
        line = lines[index]
        if line.strip().lower() == "permissions:" and not line[:1].isspace():
            updated.append("permissions: write-all")
            replaced = True
            index += 1
            while index < len(lines) and (lines[index].startswith((" ", "\t")) or not lines[index].strip()):
                index += 1
            continue
        updated.append(line)
        index += 1

    if not replaced:
        insert_at = next((i for i, line in enumerate(updated) if line.strip().lower() == "jobs:"), len(updated))
        updated.insert(insert_at, "permissions: write-all")
        if insert_at < len(updated) - 1:
            updated.insert(insert_at + 1, "")

    return "\n".join(updated) + "\n"


def _assert_safe_attack_workspace(path: Path) -> None:
    workspace = path.resolve()
    demo_root = DEMO_ROOT.resolve()
    try:
        workspace.relative_to(demo_root)
    except ValueError as error:
        raise ValueError(f"Unsafe attack workspace path: {workspace}") from error
    if workspace == demo_root:
        raise ValueError("Attack workspace cannot be the demo root.")


@contextmanager
def prepare_repo_source(repo_source: str) -> Iterator[PreparedRepo]:
    """Resolve demo names, local paths, and public GitHub URLs to a local path."""

    normalized_source = repo_source.strip()
    if not normalized_source:
        raise ValueError("Repo source is required.")

    demo_path = DEMO_REPOS.get(normalized_source)
    if demo_path is not None:
        if not demo_path.exists():
            raise ValueError(f"Demo repository is missing: {demo_path}")
        yield PreparedRepo(normalized_source, normalized_source, demo_path.resolve())
        return

    candidate_path = Path(normalized_source).expanduser()
    if candidate_path.exists():
        if not candidate_path.is_dir():
            raise ValueError(f"Invalid repo path: '{repo_source}' is not a directory.")
        yield PreparedRepo(repo_source, candidate_path.name, candidate_path.resolve())
        return

    github_repo = parse_github_url(normalized_source)
    if github_repo:
        with tempfile.TemporaryDirectory(prefix="repoguard-dashboard-") as temp_dir:
            scanner = DependencyRiskScanner(db_path=str(DEFAULT_DB_PATH))
            local_path = scanner._download_github_repo(github_repo, Path(temp_dir))  # noqa: SLF001
            yield PreparedRepo(repo_source, github_repo.name, local_path.resolve(), is_temporary=True)
        return

    if _looks_like_url(normalized_source):
        raise ValueError(
            "Invalid GitHub URL. Use a public repository URL like https://github.com/owner/repo."
        )
    raise ValueError(f"Invalid repo path: '{repo_source}' does not exist.")


def run_tamper_simulator(repo_path: Path, release_file_name: str, errors: list[str]) -> dict[str, Any] | None:
    """Modify the release artifact for the attack simulator."""

    release_file = repo_path / "release" / release_file_name
    try:
        return tamper_release_file(str(release_file))
    except CryptoVerifierError as error:
        errors.append(f"Attack simulator failed: {error}")
        return None


def verify_repo_release(repo_path: Path, release_file_name: str = DEFAULT_RELEASE_FILE_NAME) -> dict[str, Any]:
    """Verify the default release artifact and return dashboard-friendly status."""

    release_dir = repo_path / "release"
    release_file = release_dir / release_file_name
    signature_file = release_dir / f"{release_file_name}.sig"
    public_key_file = release_dir / "public_key.pem"
    manifest_file = release_dir / "manifest.json"

    if not _has_release_artifact(release_file):
        return _crypto_not_applicable_result(file_name=release_file_name, message=NO_RELEASE_MESSAGE)

    try:
        return verify_release(
            str(release_file),
            str(signature_file),
            str(public_key_file),
            manifest_path=str(manifest_file),
        )
    except (CryptoVerifierError, OSError, ValueError) as error:
        return _crypto_error_result(
            file_name=release_file.name,
            current_sha256=_safe_sha256(release_file),
            message=f"Cryptographic verification error: {error}",
        )


def build_repository_integrity_report(repo_path: Path) -> dict[str, Any]:
    """Compare a small virtual repository file set with the trusted demo baseline."""

    if not _has_trusted_repository_reference(repo_path):
        return _repository_integrity_not_applicable()

    baseline_repo = DEMO_REPOS["secure-demo-repo"]
    entries: list[dict[str, Any]] = []
    baseline_entries: list[dict[str, Any]] = []

    for display_name, relative_path in VIRTUAL_REPOSITORY_FILES:
        current_hash = _repository_file_hash(repo_path, relative_path)
        baseline_hash = _repository_file_hash(baseline_repo, relative_path)
        changed = current_hash != baseline_hash
        entries.append(
            {
                "display_name": display_name,
                "path": relative_path,
                "current_sha256": current_hash,
                "baseline_sha256": baseline_hash,
                "changed": changed,
                "status": "Changed" if changed else "Trusted",
            }
        )
        baseline_entries.append(
            {
                "display_name": display_name,
                "path": relative_path,
                "current_sha256": baseline_hash,
            }
        )

    current_root = _compute_merkle_root(entries, "current_sha256")
    expected_root = _compute_merkle_root(baseline_entries, "current_sha256")
    changed_files = [entry["display_name"] for entry in entries if entry["changed"]]
    root_match = current_root == expected_root

    return {
        "files": entries,
        "current_root": current_root,
        "expected_root": expected_root,
        "root_match": root_match,
        "changed_files": changed_files,
        "status": "Verified" if root_match else "Failed",
        "applicable": True,
        "explanation": (
            "Every virtual repository file matched the trusted baseline, so the Merkle Root is stable."
            if root_match
            else "At least one file hash changed, so the Merkle Root no longer matches the trusted baseline."
        ),
    }


def build_hash_chain_audit_log(
    action: str,
    attack_result: dict[str, Any] | None,
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    """Build a tamper-evident classroom audit log for the selected scenario."""

    events: list[dict[str, Any]] = [
        {
            "event": "baseline_scan",
            "actor": "RepoGuard",
            "detail": f"Baseline scan completed with release status {before['release_status']}.",
            "concept": "Start the audit trail from a known-good security state.",
        }
    ]
    if action != "baseline":
        events.append(
            {
                "event": action,
                "actor": "Attacker simulation",
                "detail": (attack_result or {}).get("message", "Attack scenario changed the demo workspace."),
                "target": (attack_result or {}).get("target", "demo workspace"),
                "concept": _scenario_concept(action),
            }
        )

    events.append(
        {
            "event": "policy_decision",
            "actor": "RepoGuard",
            "detail": f"Policy decision: {after['release_status']} with score {after['security_score']}/100.",
            "concept": "Security signals feed a release decision instead of relying on trust.",
        }
    )

    sealed_events = _seal_audit_events(events)
    if action == "tamper-release" and len(sealed_events) > 1:
        sealed_events[1]["detail"] = "Edited after logging: release change was renamed to routine maintenance."

    validation = _validate_audit_chain(sealed_events)
    return {
        "events": sealed_events,
        "valid": validation["valid"],
        "broken_at": validation["broken_at"],
        "status": "Valid" if validation["valid"] else "Broken",
        "explanation": (
            "Every event hash matches its content and the previous event hash."
            if validation["valid"]
            else "One logged event was changed after hashing, so the recomputed hash no longer matches the stored currentHash."
        ),
    }


def calculate_security_score(
    *,
    secret_findings: list[dict],
    dependency_findings: list[dict],
    cicd_findings: list[dict],
    crypto_result: dict[str, Any],
    mode: str = "dashboard",
) -> dict[str, Any]:
    """Calculate the RepoGuard security score.

    ``strict`` mode subtracts every listed penalty for every matching finding.
    The default ``dashboard`` mode uses the same penalty values but scores the
    strongest source-code risk signals plus the release-integrity gate. This
    keeps the demo score readable instead of letting repeated line-level
    findings collapse every risky project to 0.
    """

    strict = _calculate_strict_penalties(
        secret_findings=secret_findings,
        dependency_findings=dependency_findings,
        cicd_findings=cicd_findings,
        crypto_result=crypto_result,
    )
    if mode == "strict":
        security_score = _bounded_score(100 - strict["total_penalty"])
        return {
            "security_score": security_score,
            "mode": "strict",
            **strict,
        }
    if mode != "dashboard":
        raise ValueError("score_mode must be 'dashboard' or 'strict'.")

    source_penalty = (
        _highest_penalty(secret_findings, "severity", SECRET_PENALTIES)
        + _highest_penalty(dependency_findings, "severity", DEPENDENCY_PENALTIES)
        + _highest_penalty(cicd_findings, "risk_level", CICD_PENALTIES)
    )
    crypto_penalty = _crypto_penalty(crypto_result)

    if source_penalty and crypto_penalty:
        total_penalty = max(source_penalty, crypto_penalty) + COMBINED_SOURCE_AND_CRYPTO_PENALTY
    else:
        total_penalty = source_penalty + crypto_penalty

    return {
        "security_score": _bounded_score(100 - total_penalty),
        "mode": "dashboard",
        "source_penalty": source_penalty,
        "crypto_penalty": crypto_penalty,
        "combined_source_and_crypto_penalty": (
            COMBINED_SOURCE_AND_CRYPTO_PENALTY if source_penalty and crypto_penalty else 0
        ),
        "total_penalty": total_penalty,
        "strict_security_score": _bounded_score(100 - strict["total_penalty"]),
        "strict_total_penalty": strict["total_penalty"],
        "strict_penalties": strict["penalties"],
    }


def decide_release_status(score: int, crypto_result: dict[str, Any]) -> str:
    """Apply the release decision rule."""

    hash_ok = not _hash_check_failed(crypto_result)
    signature_ok = not _signature_check_failed(crypto_result)
    repository_ok = crypto_result.get("repository_integrity_match") is not False
    if score >= 80 and hash_ok and signature_ok and repository_ok:
        return "APPROVED"
    return "BLOCKED"


def sanitize_secret_findings(findings: list[dict]) -> list[dict]:
    """Ensure dashboard output never exposes full secret values."""

    safe_findings: list[dict] = []
    allowed_keys = [
        "file_path",
        "line_number",
        "secret_type",
        "masked_preview",
        "severity",
        "entropy_score",
        "reason",
        "recommendation",
    ]
    for finding in findings:
        safe_findings.append({key: finding.get(key) for key in allowed_keys if key in finding})
    return safe_findings


def render_terminal_report(payload: dict[str, Any]) -> str:
    """Create a compact terminal report for presentation and CLI use."""

    summary = payload["summary"]
    crypto = payload["findings"]["crypto"]
    lines = [
        "RepoGuard Security Dashboard",
        "=" * 32,
        f"Repo Source: {payload['repo_source']}",
        f"Security Score: {payload['security_score']}/100",
        f"Release Status: {payload['release_status']}",
        "",
        "Top Metrics",
        "-" * 11,
        f"Secrets Found: {summary['secrets_found']}",
        f"Vulnerable Dependencies: {summary['vulnerable_dependencies']}",
        f"CI/CD Risks: {summary['cicd_risks']}",
        f"Hash Status: {summary['hash_status']}",
        f"Signature Status: {summary['signature_status']}",
        f"Merkle Status: {summary.get('merkle_status', 'N/A')}",
        "",
        "Cryptographic Verification Result",
        "-" * 34,
        f"File: {crypto.get('file_name', 'N/A')}",
        f"SHA-256 Current: {_short_hash(crypto.get('current_sha256'))}",
        f"SHA-256 Stored: {_short_hash(crypto.get('stored_sha256'))}",
        f"Hash Match: {crypto.get('hash_match')}",
        f"Signature: {crypto.get('signature_status')}",
        f"Manifest Hash: {_short_hash(crypto.get('manifest_sha256'))}",
        f"Integrity: {crypto.get('integrity_status')}",
        f"Release Gate: {crypto.get('release_status')}",
        "",
        "Findings",
        "-" * 8,
    ]
    lines.extend(_render_secret_findings(payload["findings"]["secrets"]))
    lines.extend(_render_dependency_findings(payload["findings"]["dependencies"]))
    lines.extend(_render_cicd_findings(payload["findings"]["cicd"]))

    if payload.get("tamper_result"):
        tamper = payload["tamper_result"]
        lines.extend(
            [
                "",
                "Attack Simulator",
                "-" * 16,
                f"Tampered: {tamper.get('tampered')}",
                f"Method: {tamper.get('tamper_method')}",
                f"Previous SHA-256: {_short_hash(tamper.get('previous_sha256'))}",
                f"Current SHA-256: {_short_hash(tamper.get('current_sha256'))}",
            ]
        )

    if payload.get("errors"):
        lines.extend(["", "Errors", "-" * 6, *[f"- {error}" for error in payload["errors"]]])
    if payload.get("warnings"):
        lines.extend(["", "Warnings", "-" * 8, *[f"- {warning}" for warning in payload["warnings"]]])

    lines.extend(
        [
            "",
            "Crypto Core",
            "-" * 11,
            "SHA-256 checks whether the release file changed.",
            "The digital signature verifies that the release came from the trusted signing key.",
        ]
    )
    return "\n".join(lines)


def render_html_dashboard(payload: dict[str, Any]) -> str:
    """Render a static, dependency-free HTML dashboard."""

    summary = payload["summary"]
    crypto = payload["findings"]["crypto"]
    status_class = _status_class(payload["release_status"])
    score_class = _score_class(payload["security_score"])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RepoGuard Security Dashboard</title>
  <style>
    :root {{
      --bg: #fff2f7;
      --panel: #fffafb;
      --panel-soft: #fff0f6;
      --ink: #312936;
      --muted: #806f78;
      --line: #efd6e0;
      --line-soft: #f7e6ed;
      --green: #376f55;
      --green-bg: #eef8f1;
      --green-border: #c8e6d2;
      --yellow: #87631b;
      --yellow-bg: #fff5df;
      --yellow-border: #ecd492;
      --red: #aa4f68;
      --red-bg: #fff0f4;
      --red-border: #efc2ce;
      --blue: #6a638f;
      --blue-bg: #f3f1ff;
      --blue-border: #d8d2f2;
      --shadow: 0 16px 34px rgba(111, 62, 82, 0.09);
      --shadow-soft: 0 8px 20px rgba(111, 62, 82, 0.07);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: linear-gradient(180deg, #fff7fa 0%, var(--bg) 48%, #fff8fb 100%);
      color: var(--ink);
      font-family: Aptos, Inter, "Segoe UI", Arial, sans-serif;
      font-size: 15px;
      line-height: 1.5;
    }}
    .shell {{ max-width: 1320px; min-height: 100vh; margin: 0 auto; padding: 18px 22px; }}
    header {{
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 20px;
      margin-bottom: 12px;
    }}
    h1 {{ margin: 0; font-size: 29px; font-weight: 700; letter-spacing: 0; line-height: 1.08; }}
    h2 {{ margin: 0 0 9px; color: #3b2f3d; font-size: 16px; font-weight: 700; line-height: 1.2; }}
    h3 {{ margin: 0 0 8px; color: #3b2f3d; font-size: 14px; font-weight: 600; }}
    .repo {{ color: var(--muted); margin-top: 4px; }}
    .status-banner {{
      border-radius: 8px;
      padding: 10px 15px;
      font-weight: 700;
      min-width: 220px;
      text-align: center;
      border: 1px solid;
      box-shadow: var(--shadow-soft);
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(8, minmax(120px, 1fr));
      gap: 10px;
      margin-bottom: 10px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 11px;
      min-height: 72px;
      box-shadow: var(--shadow-soft);
    }}
    .icon {{ width: 16px; height: 16px; flex: 0 0 auto; }}
    .card-top {{ display: flex; align-items: center; gap: 8px; min-width: 0; }}
    .card-icon {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.55);
    }}
    .card-label {{ color: var(--muted); font-size: 12px; font-weight: 600; }}
    .card-value {{ font-size: 19px; font-weight: 700; margin-top: 5px; overflow-wrap: anywhere; }}
    .green {{ color: var(--green); background: var(--green-bg); border-color: var(--green-border); }}
    .yellow {{ color: var(--yellow); background: var(--yellow-bg); border-color: var(--yellow-border); }}
    .red {{ color: var(--red); background: var(--red-bg); border-color: var(--red-border); }}
    .blue {{ color: var(--blue); background: var(--blue-bg); border-color: var(--blue-border); }}
    .grid {{
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 12px;
      align-items: start;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 10px;
      box-shadow: var(--shadow-soft);
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-top: 1px solid var(--line-soft); text-align: left; padding: 7px 7px; vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }}
    .pill {{
      display: inline-flex;
      align-items: center;
      border: 1px solid;
      border-radius: 999px;
      padding: 5px 9px;
      font-size: 12px;
      font-weight: 700;
      line-height: 1;
      text-transform: uppercase;
    }}
    .empty {{
      display: inline-block;
      color: var(--green);
      background: var(--green-bg);
      border: 1px solid var(--green-border);
      border-radius: 8px;
      font-weight: 600;
      padding: 7px 10px;
    }}
    .crypto-row {{ display: grid; grid-template-columns: 150px 1fr; gap: 10px; padding: 7px 0; border-top: 1px solid var(--line-soft); }}
    .crypto-label {{ color: var(--muted); font-weight: 600; }}
    .hash {{ font-family: Consolas, "Courier New", monospace; font-size: 12.5px; overflow-wrap: anywhere; }}
    .hash-block {{
      display: block;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.7);
      padding: 8px 10px;
      white-space: normal;
      word-break: break-word;
    }}
    .note {{ color: var(--muted); font-size: 12.5px; margin: 8px 0 0; }}
    .pipeline-section h2 {{ margin-bottom: 12px; }}
    .pipeline-grid {{
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(6, minmax(0, 1fr));
    }}
    .pipeline-step {{
      background: #f8fafc;
      border: 1px solid var(--line);
      border-radius: 8px;
      min-height: 154px;
      padding: 10px;
    }}
    .step-index {{
      align-items: center;
      border: 1px solid currentColor;
      border-radius: 999px;
      display: inline-flex;
      font-size: 11px;
      font-weight: 800;
      height: 24px;
      justify-content: center;
      margin-bottom: 8px;
      width: 24px;
    }}
    .step-value {{ font-weight: 800; margin-bottom: 6px; overflow-wrap: anywhere; }}
    .pipeline-step p,
    .module-note {{ color: var(--muted); font-size: 12px; margin: 8px 0 0; }}
    .changed-row td {{ background: var(--red-bg); }}
    @media (max-width: 980px) {{
      .cards {{ grid-template-columns: repeat(2, minmax(140px, 1fr)); }}
      .grid,
      .pipeline-grid {{ grid-template-columns: 1fr; }}
      header {{ align-items: stretch; flex-direction: column; }}
    }}
    @media (max-width: 640px) {{
      .shell {{ padding: 22px 16px 28px; }}
      h1 {{ font-size: 28px; }}
      .cards {{ grid-template-columns: 1fr; }}
      .crypto-row {{ grid-template-columns: 1fr; gap: 4px; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <header>
      <div>
        <h1>RepoGuard Security Dashboard</h1>
        <div class="repo">{_e(payload["repo_source"])}</div>
      </div>
      <div class="status-banner {status_class}">Release {payload["release_status"]}</div>
    </header>
    <div class="cards">
      {_metric_card("Security Score", f"{payload['security_score']}/100", score_class)}
      {_metric_card("Release Status", payload["release_status"], status_class)}
      {_metric_card("Secrets Found", summary["secrets_found"], _count_class(summary["secrets_found"]))}
      {_metric_card("Dependencies", summary["vulnerable_dependencies"], _count_class(summary["vulnerable_dependencies"]))}
      {_metric_card("CI/CD Risks", summary["cicd_risks"], _count_class(summary["cicd_risks"]))}
      {_metric_card("Hash Status", summary["hash_status"], _check_status_class(summary["hash_status"]))}
      {_metric_card("Signature", summary["signature_status"], _signature_class(summary["signature_status"]))}
      {_metric_card("Merkle Root", summary["merkle_status"], _check_status_class(summary["merkle_status"]))}
    </div>
    {_security_pipeline_section(payload)}
    <div class="grid">
      <div>
        {_findings_section("Secret Leak Findings", _secret_table(payload["findings"]["secrets"]) + _module_note("Concept: regex and entropy-like signals find fake credentials before they leave the repository."))}
        {_findings_section("Dependency Risk Findings", _dependency_table(payload["findings"]["dependencies"]) + _module_note("Concept: dependency policy checks whether known vulnerable versions enter the release path."))}
        {_findings_section("CI/CD Workflow Findings", _cicd_table(payload["findings"]["cicd"]) + _module_note("Concept: workflow scanning catches risky permissions, triggers, installers, and unpinned actions."))}
        {_repository_integrity_panel(payload["findings"]["repository_integrity"])}
      </div>
      <div>
        <section>
          <h2>Cryptographic Verification Result</h2>
          {_crypto_panel(crypto)}
          <p class="note">SHA-256 checks file integrity. The digital signature verifies the trusted source. If the release file changes, the hash changes and signature verification fails.</p>
        </section>
        {_release_manifest_panel(crypto)}
        {_signature_explanation_panel(crypto)}
        {_tamper_panel(payload.get("tamper_result"))}
      </div>
    </div>
  </main>
</body>
</html>
"""


def render_attack_simulation_page(simulation: dict[str, Any]) -> str:
    """Render the live attack simulation screen served by the local demo server."""

    before = simulation["before"]
    after = simulation["after"]
    summary = after["summary"]
    status_class = _status_class(after["release_status"])
    score_class = _score_class(after["security_score"])
    return f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RepoGuard Canlı Saldırı Simülasyonu</title>
  <style>
    :root {{
      --bg: #fff2f7;
      --panel: #fffafb;
      --panel-soft: #fff0f6;
      --ink: #312936;
      --muted: #806f78;
      --line: #efd6e0;
      --line-soft: #f7e6ed;
      --green: #376f55;
      --green-bg: #eef8f1;
      --green-border: #c8e6d2;
      --yellow: #87631b;
      --yellow-bg: #fff5df;
      --yellow-border: #ecd492;
      --red: #aa4f68;
      --red-bg: #fff0f4;
      --red-border: #efc2ce;
      --blue: #6a638f;
      --blue-bg: #f3f1ff;
      --blue-border: #d8d2f2;
      --lavender: #b05a86;
      --lavender-bg: #fff0f7;
      --lavender-border: #edc2d6;
      --button: #a76482;
      --button-hover: #965676;
      --shadow: 0 16px 34px rgba(111, 62, 82, 0.09);
      --shadow-soft: 0 8px 20px rgba(111, 62, 82, 0.07);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: linear-gradient(180deg, #fff7fa 0%, var(--bg) 48%, #fff8fb 100%);
      color: var(--ink);
      font-family: Aptos, Inter, "Segoe UI", Arial, sans-serif;
      font-size: 15px;
      line-height: 1.5;
    }}
    .shell {{ max-width: 1360px; min-height: 100vh; margin: 0 auto; padding: 14px 18px; }}
    header {{
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 10px;
    }}
    h1 {{ margin: 0; font-size: 29px; font-weight: 700; letter-spacing: 0; line-height: 1.08; }}
    h2 {{ margin: 0 0 9px; color: #3b2f3d; font-size: 16px; font-weight: 700; line-height: 1.2; }}
    h3 {{ margin: 0 0 8px; color: #3b2f3d; font-size: 14px; font-weight: 600; }}
    .repo {{ color: var(--muted); margin-top: 4px; }}
    .eyebrow {{ color: var(--lavender); font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }}
    .status-banner {{
      border: 1px solid;
      border-radius: 8px;
      min-width: 230px;
      padding: 10px 15px;
      text-align: center;
      font-weight: 700;
      box-shadow: var(--shadow-soft);
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 10px;
      box-shadow: var(--shadow-soft);
    }}
    .attack-dock {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      border-color: #efd1df;
      background: linear-gradient(135deg, #fffafd 0%, var(--panel-soft) 100%);
    }}
    .button-row {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    button {{
      border: 1px solid rgba(66, 85, 111, 0.12);
      border-radius: 8px;
      background: var(--button);
      color: #fff;
      cursor: pointer;
      font: inherit;
      font-weight: 600;
      min-height: 36px;
      padding: 8px 12px;
      box-shadow: 0 8px 18px rgba(167, 100, 130, 0.14);
      transition: background-color 160ms ease, border-color 160ms ease, box-shadow 160ms ease, transform 160ms ease;
    }}
    button:hover {{ background: var(--button-hover); box-shadow: 0 10px 22px rgba(167, 100, 130, 0.18); transform: translateY(-1px); }}
    button:focus-visible {{ outline: 3px solid rgba(176, 90, 134, 0.24); outline-offset: 2px; }}
    button.danger {{ background: var(--red-bg); border-color: var(--red-border); color: var(--red); box-shadow: 0 8px 18px rgba(168, 80, 89, 0.09); }}
    button.danger:hover {{ background: #ffe6e9; }}
    button.warning {{ background: var(--yellow-bg); border-color: var(--yellow-border); color: var(--yellow); box-shadow: 0 8px 18px rgba(135, 99, 27, 0.09); }}
    button.warning:hover {{ background: #ffefc6; }}
    button.reset {{ background: rgba(255, 253, 250, 0.78); border-color: var(--line); color: var(--ink); box-shadow: none; }}
    button.reset:hover {{ background: #ffffff; border-color: #dcccbc; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(8, minmax(120px, 1fr));
      gap: 9px;
      margin-bottom: 10px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      min-height: 68px;
      padding: 10px;
      box-shadow: var(--shadow-soft);
    }}
    .card-label {{ color: var(--muted); font-size: 12px; font-weight: 600; text-transform: none; }}
    .card-value {{ font-size: 18px; font-weight: 700; margin-top: 4px; overflow-wrap: anywhere; }}
    .green {{ color: var(--green); background: var(--green-bg); border-color: var(--green-border); }}
    .yellow {{ color: var(--yellow); background: var(--yellow-bg); border-color: var(--yellow-border); }}
    .red {{ color: var(--red); background: var(--red-bg); border-color: var(--red-border); }}
    .blue {{ color: var(--blue); background: var(--blue-bg); border-color: var(--blue-border); }}
    .lavender {{ color: var(--lavender); background: var(--lavender-bg); border-color: var(--lavender-border); }}
    .comparison {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      align-items: stretch;
    }}
    .state-panel {{ height: 100%; }}
    .state-row {{
      display: grid;
      grid-template-columns: 160px 1fr;
      gap: 10px;
      padding: 7px 0;
      border-top: 1px solid var(--line-soft);
      align-items: center;
    }}
    .state-label, .crypto-label {{ color: var(--muted); font-weight: 600; }}
    .report-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      align-items: start;
    }}
    .verdicts {{ display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 9px; }}
    .pill {{
      display: inline-flex;
      align-items: center;
      border: 1px solid;
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 11.5px;
      font-weight: 700;
      line-height: 1;
      text-transform: uppercase;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
    th, td {{ border-top: 1px solid var(--line-soft); text-align: left; padding: 6px 7px; vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; font-weight: 700; text-transform: none; }}
    .empty {{
      display: inline-block;
      color: var(--green);
      background: var(--green-bg);
      border: 1px solid var(--green-border);
      border-radius: 8px;
      font-weight: 600;
      padding: 7px 10px;
    }}
    .crypto-row {{
      display: grid;
      grid-template-columns: 150px 1fr;
      gap: 10px;
      padding: 6px 0;
      border-top: 1px solid var(--line-soft);
    }}
    .hash, code {{ font-family: Consolas, "Courier New", monospace; font-size: 11.5px; overflow-wrap: anywhere; }}
    .note {{ color: var(--muted); font-size: 12px; margin: 8px 0 0; }}
    @media (min-width: 1100px) {{
      .shell {{
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
        column-gap: 10px;
        align-content: start;
      }}
      header,
      .attack-dock,
      .cards,
      .report-grid {{
        grid-column: 1 / -1;
      }}
      .comparison {{
        grid-column: 1;
      }}
      .comparison + section {{
        grid-column: 2;
        margin-bottom: 10px;
      }}
      .report-grid {{
        grid-template-columns: repeat(7, minmax(0, 1fr));
      }}
      .report-grid > div {{
        display: contents;
      }}
      .report-grid > div:first-child section {{
        grid-column: span 1;
        margin-bottom: 0;
      }}
      .report-grid > div:last-child section {{
        grid-column: span 2;
        margin-bottom: 0;
      }}
    }}
    @media (max-width: 1020px) {{
      .cards {{ grid-template-columns: repeat(2, minmax(140px, 1fr)); }}
      .comparison, .report-grid {{ grid-template-columns: 1fr; }}
      header {{ align-items: stretch; flex-direction: column; }}
      .attack-dock {{ align-items: stretch; flex-direction: column; }}
    }}
    @media (max-width: 640px) {{
      .shell {{ padding: 22px 16px 28px; }}
      h1 {{ font-size: 28px; }}
      .cards {{ grid-template-columns: 1fr; }}
      .state-row, .crypto-row {{ grid-template-columns: 1fr; gap: 4px; }}
      .button-row, .button-row button, .attack-dock > form, .attack-dock > form button {{ width: 100%; }}
    }}
    :root {{
      --bg: #f3f6fa;
      --panel: #ffffff;
      --panel-soft: #f8fafc;
      --ink: #172033;
      --muted: #657386;
      --line: #dbe4ee;
      --line-soft: #eef2f6;
      --green: #137a55;
      --green-bg: #edf9f3;
      --green-border: #bfe8d2;
      --yellow: #95630b;
      --yellow-bg: #fff7df;
      --yellow-border: #efd48a;
      --red: #b4233f;
      --red-bg: #fff1f3;
      --red-border: #f0b7c2;
      --blue: #1f5fbf;
      --blue-bg: #eef5ff;
      --blue-border: #c7dcff;
      --lavender: #4f5f7a;
      --lavender-bg: #f4f6fb;
      --lavender-border: #d9e1ee;
      --button: #0f766e;
      --button-hover: #0b625c;
      --shadow: 0 18px 42px rgba(28, 43, 64, 0.1);
      --shadow-soft: 0 8px 24px rgba(28, 43, 64, 0.07);
    }}
    body {{
      background: linear-gradient(180deg, #f8fafc 0%, #eef3f8 100%);
      color: var(--ink);
    }}
    .shell {{
      max-width: 1280px;
      padding: 18px 22px 30px;
    }}
    header {{
      align-items: center;
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid var(--line);
      border-radius: 12px;
      box-shadow: var(--shadow-soft);
      margin-bottom: 12px;
      padding: 14px 16px;
    }}
    h1 {{
      color: var(--ink);
      font-size: 24px;
      font-weight: 760;
    }}
    h2 {{
      color: var(--ink);
      font-size: 15px;
      letter-spacing: 0;
      margin-bottom: 10px;
    }}
    .repo {{
      color: var(--muted);
      font-size: 13px;
      margin-top: 3px;
    }}
    .eyebrow,
    .panel-kicker {{
      color: #516174;
      font-size: 11px;
      font-weight: 760;
      letter-spacing: .08em;
      text-transform: uppercase;
    }}
    .icon {{
      flex: 0 0 auto;
      height: 16px;
      width: 16px;
    }}
    .status-banner {{
      align-items: center;
      border-radius: 999px;
      box-shadow: none;
      display: inline-flex;
      gap: 8px;
      justify-content: center;
      min-width: 0;
      padding: 8px 12px;
      white-space: nowrap;
    }}
    section {{
      background: var(--panel);
      border-color: var(--line);
      border-radius: 12px;
      box-shadow: var(--shadow-soft);
      margin-bottom: 12px;
      padding: 16px;
    }}
    .attack-dock {{
      align-items: center;
      background: var(--panel);
      border-color: var(--line);
      display: grid;
      gap: 14px;
      grid-template-columns: minmax(210px, .7fr) minmax(0, 2fr) auto;
      padding: 14px;
    }}
    .attack-dock h2 {{
      margin-bottom: 2px;
    }}
    .button-row {{
      display: grid;
      flex: 1 1 auto;
      gap: 10px;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      width: 100%;
    }}
    .reset-form {{
      justify-self: end;
    }}
    button {{
      align-items: center;
      border-radius: 8px;
      box-shadow: none;
      display: inline-flex;
      font-size: 13px;
      gap: 8px;
      justify-content: center;
      min-height: 42px;
      padding: 0 13px;
      width: 100%;
    }}
    button:hover {{
      box-shadow: var(--shadow-soft);
    }}
    button.danger,
    button.warning,
    button.reset {{
      background: #ffffff;
    }}
    button.reset {{
      color: var(--muted);
    }}
    .cards {{
      gap: 10px;
      grid-template-columns: repeat(8, minmax(126px, 1fr));
      margin-bottom: 12px;
    }}
    .card {{
      background: var(--panel);
      border-color: var(--line);
      border-radius: 12px;
      color: var(--ink);
      display: flex;
      flex-direction: column;
      gap: 11px;
      min-height: 88px;
      padding: 12px;
    }}
    .card.green,
    .card.yellow,
    .card.red,
    .card.blue,
    .card.lavender {{
      background: var(--panel);
      border-color: var(--line);
      color: var(--ink);
    }}
    .card-top {{
      align-items: center;
      display: flex;
      gap: 8px;
      min-width: 0;
    }}
    .card-icon {{
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 8px;
      display: inline-flex;
      height: 30px;
      justify-content: center;
      width: 30px;
    }}
    .card.green .card-icon {{ background: var(--green-bg); border-color: var(--green-border); color: var(--green); }}
    .card.yellow .card-icon {{ background: var(--yellow-bg); border-color: var(--yellow-border); color: var(--yellow); }}
    .card.red .card-icon {{ background: var(--red-bg); border-color: var(--red-border); color: var(--red); }}
    .card.blue .card-icon,
    .card.lavender .card-icon {{ background: var(--blue-bg); border-color: var(--blue-border); color: var(--blue); }}
    .card-label {{
      color: var(--muted);
      font-size: 11.5px;
      font-weight: 720;
      line-height: 1.25;
    }}
    .card-value {{
      color: var(--ink);
      font-size: 20px;
      line-height: 1.05;
      margin-top: 0;
    }}
    .comparison {{
      gap: 12px;
      margin-bottom: 12px;
    }}
    .state-panel {{
      display: flex;
      flex-direction: column;
      height: 100%;
      overflow: hidden;
      padding: 0;
    }}
    .state-heading {{
      align-items: center;
      border-bottom: 1px solid var(--line-soft);
      display: flex;
      gap: 12px;
      justify-content: space-between;
      padding: 14px 16px;
    }}
    .state-heading h2 {{
      margin: 2px 0 0;
    }}
    .state-score {{
      align-items: center;
      border: 1px solid;
      border-radius: 999px;
      display: inline-flex;
      font-size: 11px;
      font-weight: 800;
      line-height: 1;
      padding: 6px 8px;
      text-transform: uppercase;
    }}
    .state-row {{
      border-top: 0;
      border-bottom: 1px solid var(--line-soft);
      grid-template-columns: minmax(0, 1fr) auto;
      padding: 11px 16px;
    }}
    .state-row:last-child {{
      border-bottom: 0;
    }}
    .state-label,
    .crypto-label {{
      color: var(--muted);
      font-size: 13px;
      font-weight: 680;
    }}
    .scan-focus {{
      border-color: #bfd7f4;
      box-shadow: var(--shadow);
      padding: 18px;
    }}
    .scan-header {{
      align-items: center;
      display: flex;
      gap: 12px;
      justify-content: space-between;
      margin-bottom: 12px;
    }}
    .scan-header h2 {{
      font-size: 18px;
      margin: 2px 0 0;
    }}
    .verdicts {{
      gap: 8px;
      margin-bottom: 12px;
    }}
    .pill {{
      border-radius: 999px;
      font-size: 11px;
      gap: 6px;
      letter-spacing: .02em;
      padding: 6px 8px;
    }}
    table {{
      border-collapse: separate;
      border-spacing: 0;
      font-size: 13px;
    }}
    th,
    td {{
      border-top: 1px solid var(--line-soft);
      padding: 9px 8px;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 740;
      width: 170px;
    }}
    .report-grid {{
      align-items: stretch;
      display: grid;
      gap: 12px;
      grid-template-columns: minmax(0, 1.35fr) minmax(360px, .85fr);
    }}
    .report-stack {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }}
    .crypto-stack {{
      display: grid;
      gap: 12px;
      grid-template-columns: 1fr;
    }}
    .report-card {{
      display: flex;
      flex-direction: column;
      height: 100%;
      margin-bottom: 0;
      min-height: 180px;
    }}
    .report-card h2 {{
      margin-bottom: 12px;
    }}
    .report-card table {{
      flex: 1 1 auto;
    }}
    .empty {{
      align-items: center;
      border-radius: 8px;
      display: flex;
      min-height: 46px;
      padding: 10px 11px;
      width: 100%;
    }}
    .crypto-card {{
      min-height: 100%;
    }}
    .crypto-row {{
      align-items: start;
      gap: 12px;
      grid-template-columns: 138px minmax(0, 1fr);
      padding: 9px 0;
    }}
    .hash,
    code {{
      font-size: 12px;
    }}
    .hash-block {{
      background: #f8fafc;
      border: 1px solid var(--line);
      border-radius: 8px;
      color: #243044;
      display: block;
      line-height: 1.45;
      overflow-wrap: anywhere;
      padding: 8px 10px;
      white-space: normal;
      word-break: break-word;
    }}
    .note {{
      border-top: 1px solid var(--line-soft);
      color: var(--muted);
      font-size: 12.5px;
      margin-top: 10px;
      padding-top: 10px;
    }}
    .pipeline-section h2 {{
      font-size: 16px;
      margin-bottom: 12px;
    }}
    .pipeline-grid {{
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(6, minmax(0, 1fr));
    }}
    .pipeline-step {{
      background: #f8fafc;
      border: 1px solid var(--line);
      border-radius: 8px;
      color: var(--ink);
      min-height: 158px;
      padding: 10px;
    }}
    .step-index {{
      align-items: center;
      border: 1px solid currentColor;
      border-radius: 999px;
      display: inline-flex;
      font-size: 11px;
      font-weight: 800;
      height: 24px;
      justify-content: center;
      margin-bottom: 8px;
      width: 24px;
    }}
    .step-value {{
      font-weight: 800;
      margin-bottom: 6px;
      overflow-wrap: anywhere;
    }}
    .pipeline-step p,
    .module-note {{
      color: var(--muted);
      font-size: 12px;
      margin: 8px 0 0;
    }}
    .changed-row td {{
      background: var(--red-bg);
    }}
    @media (min-width: 1100px) {{
      .shell {{
        display: block;
      }}
      header,
      .attack-dock,
      .cards,
      .comparison,
      .comparison + section,
      .report-grid {{
        grid-column: auto;
      }}
      .report-grid > div {{
        display: grid;
      }}
      .report-grid > div:first-child section,
      .report-grid > div:last-child section {{
        grid-column: auto;
        margin-bottom: 0;
      }}
    }}
    @media (max-width: 1180px) {{
      .cards {{ grid-template-columns: repeat(4, minmax(150px, 1fr)); }}
      .attack-dock {{ grid-template-columns: 1fr; }}
      .reset-form {{ justify-self: stretch; }}
      .button-row {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .report-grid {{ grid-template-columns: 1fr; }}
      .pipeline-grid {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    }}
    @media (max-width: 760px) {{
      .shell {{ padding: 14px; }}
      header {{ align-items: stretch; flex-direction: column; }}
      h1 {{ font-size: 22px; }}
      .cards,
      .comparison,
      .report-stack,
      .pipeline-grid,
      .button-row {{ grid-template-columns: 1fr; }}
      .scan-header,
      .state-heading {{ align-items: flex-start; flex-direction: column; }}
      .crypto-row,
      .state-row {{ grid-template-columns: 1fr; gap: 6px; }}
      th {{ width: auto; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <header>
      <div>
        <div class="eyebrow">Canlı güvenlik demosu</div>
        <h1>RepoGuard Saldırı Simülasyonu</h1>
        <div class="repo">Güvenli depo: secure-demo-repo</div>
      </div>
      <div class="status-banner {status_class}">{_icon("shield")}<span>Yayın Durumu: {_display_value(after["release_status"])}</span></div>
    </header>

    <section class="attack-dock">
      <div>
        <h2>Saldırı Butonları</h2>
        <div class="repo">Aktif senaryo: {_e(simulation["action_label"])}</div>
      </div>
      <form class="button-row" method="post" action="/attack">
        <button class="danger" name="attack" value="tamper-release" type="submit">{_icon("file-warning")}<span>Yayın Dosyasını Kurcala</span></button>
        <button name="attack" value="leak-secret" type="submit">{_icon("key")}<span>Sahte Secret Sızdır</span></button>
        <button class="warning" name="attack" value="risky-workflow" type="submit">{_icon("git-branch")}<span>Workflow'u Riskli Yap</span></button>
        <button name="attack" value="break-signature" type="submit">{_icon("signature")}<span>İmzayı Boz</span></button>
      </form>
      <form class="reset-form" method="post" action="/reset">
        <button class="reset" type="submit">{_icon("refresh")}<span>Onaylı Hale Dön</span></button>
      </form>
    </section>

    <div class="cards">
      {_metric_card("Güvenlik Puanı", f"{after['security_score']}/100", score_class)}
      {_metric_card("Yayın Durumu", _display_value(after["release_status"]), status_class)}
      {_metric_card("Bulunan Secret", summary["secrets_found"], _count_class(summary["secrets_found"]))}
      {_metric_card("Bağımlılıklar", summary["vulnerable_dependencies"], _count_class(summary["vulnerable_dependencies"]))}
      {_metric_card("CI/CD Riskleri", summary["cicd_risks"], _count_class(summary["cicd_risks"]))}
      {_metric_card("Hash Kontrolü", _display_value(summary["hash_status"]), _check_status_class(summary["hash_status"]))}
      {_metric_card("Dijital İmza", _display_value(summary["signature_status"]), _signature_class(summary["signature_status"]))}
      {_metric_card("Merkle Root", _display_value(summary["merkle_status"]), _check_status_class(summary["merkle_status"]))}
    </div>

    <div class="comparison">
      {_attack_state_panel("Saldırı Öncesi", before)}
      {_attack_state_panel("Saldırı Sonrası", after)}
    </div>

    <section class="scan-focus">
      <div class="scan-header">
        <div>
          <div class="panel-kicker">Canlı tarama</div>
          <h2>Tarama Sonuçları</h2>
        </div>
        <span class="pill {status_class}">{_display_value(after["release_status"])}</span>
      </div>
      {_attack_verdicts(simulation)}
      {_attack_result_table(simulation)}
    </section>

    {_security_pipeline_section(after, simulation.get("audit_log"))}

    <div class="report-grid">
      <div class="report-stack">
        {_findings_section("Secret Tarayıcı Raporu", _secret_table(after["findings"]["secrets"]) + _module_note("Concept: fake credentials are found by regex naming patterns and token-like entropy before code is released."))}
        {_findings_section("CI/CD Workflow Raporu", _cicd_table(after["findings"]["cicd"]) + _module_note("Concept: workflow policy catches permissions: write-all, pull_request_target, curl | bash, and unpinned actions."))}
        {_findings_section("Bağımlılık Raporu", _dependency_table(after["findings"]["dependencies"]) + _module_note("Concept: known vulnerable dependency versions reduce release confidence."))}
        {_repository_integrity_panel(after["findings"]["repository_integrity"])}
      </div>
      <div class="crypto-stack">
        <section class="report-card crypto-card">
          <h2>Kriptografik Doğrulama</h2>
          {_crypto_panel(after["findings"]["crypto"])}
          <p class="note">Her simülasyondan sonra SHA-256 ve RSA-PSS doğrulaması yeniden çalışır.</p>
        </section>
        {_release_manifest_panel(after["findings"]["crypto"])}
        {_signature_explanation_panel(after["findings"]["crypto"])}
        {_audit_log_panel(simulation.get("audit_log"))}
        {_attack_details_panel(simulation.get("attack_result"))}
        {_error_panel(simulation.get("errors", []))}
      </div>
    </div>
  </main>
</body>
</html>
"""


def write_html_dashboard(payload: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path).expanduser()
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_dashboard(payload), encoding="utf-8")
    return path.resolve()


def write_attack_simulation_page(simulation: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path).expanduser()
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_attack_simulation_page(simulation), encoding="utf-8")
    return path.resolve()


def _calculate_strict_penalties(
    *,
    secret_findings: list[dict],
    dependency_findings: list[dict],
    cicd_findings: list[dict],
    crypto_result: dict[str, Any],
) -> dict[str, Any]:
    penalties: list[dict[str, Any]] = []
    for finding in secret_findings:
        penalty = _severity_penalty(finding.get("severity"), SECRET_PENALTIES)
        if penalty:
            penalties.append({"area": "secret", "penalty": penalty, "severity": finding.get("severity")})
    for finding in dependency_findings:
        penalty = _severity_penalty(finding.get("severity"), DEPENDENCY_PENALTIES)
        if penalty:
            penalties.append({"area": "dependency", "penalty": penalty, "severity": finding.get("severity")})
    for finding in cicd_findings:
        penalty = _severity_penalty(finding.get("risk_level"), CICD_PENALTIES)
        if penalty:
            penalties.append({"area": "cicd", "penalty": penalty, "severity": finding.get("risk_level")})
    if _hash_check_failed(crypto_result):
        penalties.append({"area": "crypto", "penalty": HASH_MISMATCH_PENALTY, "severity": "Hash mismatch"})
    if _signature_check_failed(crypto_result):
        penalties.append(
            {
                "area": "crypto",
                "penalty": INVALID_SIGNATURE_PENALTY,
                "severity": f"Signature {crypto_result.get('signature_status', 'Error')}",
            }
        )
    if crypto_result.get("repository_integrity_match") is False:
        penalties.append({"area": "repository", "penalty": MERKLE_MISMATCH_PENALTY, "severity": "Merkle root mismatch"})
    return {
        "total_penalty": sum(item["penalty"] for item in penalties),
        "penalties": penalties,
    }


def _run_scanner(label: str, scanner: Any, errors: list[str]) -> list[dict]:
    try:
        findings = scanner()
    except Exception as error:  # Scanner integrations should report errors without killing the dashboard.
        errors.append(f"{label} failed: {error}")
        return []
    if not isinstance(findings, list):
        errors.append(f"{label} returned an unexpected result.")
        return []
    return findings


def _crypto_error_result(
    *,
    file_name: str,
    message: str,
    current_sha256: str | None = None,
    stored_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "file_name": file_name,
        "current_sha256": current_sha256,
        "stored_sha256": stored_sha256,
        "hash_match": False,
        "signature_status": "Error",
        "integrity_status": "Failed",
        "release_status": "BLOCKED",
        "algorithm": "RSA-PSS-SHA256",
        "release_checks_applicable": True,
        "message": message,
    }


def _crypto_not_applicable_result(*, file_name: str, message: str) -> dict[str, Any]:
    return {
        "file_name": file_name,
        "current_sha256": None,
        "stored_sha256": None,
        "hash_match": None,
        "signature_status": NOT_APPLICABLE,
        "manifest_signature_status": NOT_APPLICABLE,
        "integrity_status": NOT_APPLICABLE,
        "release_status": NOT_APPLICABLE,
        "algorithm": NOT_APPLICABLE,
        "signed_payload": NOT_APPLICABLE,
        "manifest_sha256": None,
        "manifest_verification_status": NOT_APPLICABLE,
        "signature_covers_current_release": None,
        "release_checks_applicable": False,
        "message": message,
    }


def _crypto_penalty(crypto_result: dict[str, Any]) -> int:
    penalty = 0
    if _hash_check_failed(crypto_result):
        penalty += HASH_MISMATCH_PENALTY
    if _signature_check_failed(crypto_result):
        penalty += INVALID_SIGNATURE_PENALTY
    if crypto_result.get("repository_integrity_match") is False:
        penalty += MERKLE_MISMATCH_PENALTY
    return penalty


def _hash_check_failed(crypto_result: dict[str, Any]) -> bool:
    return crypto_result.get("hash_match") is False


def _signature_check_failed(crypto_result: dict[str, Any]) -> bool:
    return str(crypto_result.get("signature_status", "")).strip() in {"Invalid", "Error"}


def _hash_status(crypto_result: dict[str, Any]) -> str:
    if crypto_result.get("hash_match") is True:
        return "Passed"
    if crypto_result.get("hash_match") is False:
        return "Failed"
    return NOT_APPLICABLE


def _repository_integrity_status(repository_integrity: dict[str, Any]) -> str:
    if repository_integrity.get("root_match") is True:
        return "Passed"
    if repository_integrity.get("root_match") is False:
        return "Failed"
    return NOT_APPLICABLE


def _has_release_artifact(release_file: Path) -> bool:
    return release_file.exists() and release_file.is_file()


def _has_trusted_repository_reference(repo_path: Path) -> bool:
    trusted_paths = [DEMO_REPOS["secure-demo-repo"], DEMO_REPOS["vulnerable-demo-repo"], ATTACK_WORKSPACE]
    return any(_same_path(repo_path, trusted_path) for trusted_path in trusted_paths)


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve().samefile(right.resolve())
    except OSError:
        return str(left.resolve()).casefold() == str(right.resolve()).casefold()


def _repository_integrity_not_applicable() -> dict[str, Any]:
    return {
        "files": [],
        "current_root": None,
        "expected_root": None,
        "root_match": None,
        "changed_files": [],
        "status": NOT_APPLICABLE,
        "applicable": False,
        "explanation": (
            "No trusted repository integrity reference was found; repository integrity verification is not applicable."
        ),
    }


def _highest_penalty(findings: list[dict], field_name: str, penalties: dict[str, int]) -> int:
    return max((_severity_penalty(finding.get(field_name), penalties) for finding in findings), default=0)


def _severity_penalty(severity: object, penalties: dict[str, int]) -> int:
    return penalties.get(str(severity or "").strip().lower(), 0)


def _bounded_score(value: int) -> int:
    return max(0, min(100, int(value)))


def _safe_sha256(path: Path) -> str | None:
    try:
        return generate_sha256(str(path))
    except CryptoVerifierError:
        return None


def _repository_file_hash(repo_path: Path, relative_path: str) -> str:
    file_path = repo_path / relative_path
    if file_path.exists() and file_path.is_file():
        try:
            return generate_sha256(str(file_path))
        except CryptoVerifierError:
            pass
    return hashlib.sha256(f"missing:{relative_path}".encode("utf-8")).hexdigest()


def _compute_merkle_root(entries: list[dict[str, Any]], hash_field: str) -> str:
    leaves = [
        hashlib.sha256(f"{entry['path']}:{entry[hash_field]}".encode("utf-8")).hexdigest()
        for entry in entries
    ]
    if not leaves:
        return hashlib.sha256(b"empty-repository").hexdigest()

    level = leaves
    while len(level) > 1:
        if len(level) % 2:
            level = [*level, level[-1]]
        level = [
            hashlib.sha256(f"{level[index]}{level[index + 1]}".encode("utf-8")).hexdigest()
            for index in range(0, len(level), 2)
        ]
    return level[0]


def _seal_audit_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sealed: list[dict[str, Any]] = []
    previous_hash = AUDIT_ZERO_HASH
    for index, event in enumerate(events, start=1):
        sealed_event = {
            "index": index,
            "timestamp": _utc_now(),
            **event,
            "previousHash": previous_hash,
        }
        current_hash = _audit_event_hash(sealed_event)
        sealed_event["currentHash"] = current_hash
        sealed_event["chainStatus"] = "Linked"
        sealed.append(sealed_event)
        previous_hash = current_hash
    return sealed


def _validate_audit_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    previous_hash = AUDIT_ZERO_HASH
    for event in events:
        if event.get("previousHash") != previous_hash:
            event["chainStatus"] = "Broken"
            return {"valid": False, "broken_at": event.get("index")}
        if event.get("currentHash") != _audit_event_hash(event):
            event["chainStatus"] = "Broken"
            return {"valid": False, "broken_at": event.get("index")}
        event["chainStatus"] = "Linked"
        previous_hash = str(event.get("currentHash"))
    return {"valid": True, "broken_at": None}


def _audit_event_hash(event: dict[str, Any]) -> str:
    payload = {key: value for key, value in event.items() if key not in {"currentHash", "chainStatus"}}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _scenario_concept(action: str) -> str:
    concepts = {
        "tamper-release": "Release integrity: SHA-256 detects artifact changes; the signed manifest no longer describes the file.",
        "leak-secret": "Secret hygiene: source scanning catches fake credentials before they reach a shared repository.",
        "risky-workflow": "CI/CD hardening: workflow permissions and remote installers can become a supply-chain path.",
        "break-signature": "Authenticity: public-key verification rejects signatures not created by the trusted private key.",
        "baseline": "Trusted baseline: clean repository, matching hashes, valid manifest signature, and approved release gate.",
    }
    return concepts.get(action, "Security event: evidence is recorded and checked by policy.")


def _looks_like_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://") or value.startswith("git@")


def _short_hash(value: object) -> str:
    if value is None:
        return "N/A"
    text = str(value)
    if len(text) <= 18:
        return text
    return f"{text[:12]}...{text[-6:]}"


def _render_secret_findings(findings: list[dict]) -> list[str]:
    lines = ["", "Secret Leak Findings"]
    if not findings:
        return lines + ["- No secrets found."]
    for finding in findings:
        lines.append(
            "- "
            f"{finding.get('severity', 'Unknown')} "
            f"{finding.get('secret_type', 'Secret')} in {finding.get('file_path', 'unknown file')}:"
            f"{finding.get('line_number', '?')} -> {finding.get('masked_preview', '****')}"
        )
    return lines


def _render_dependency_findings(findings: list[dict]) -> list[str]:
    lines = ["", "Dependency Risk Findings"]
    if not findings:
        return lines + ["- No vulnerable dependencies found."]
    for finding in findings:
        lines.append(
            "- "
            f"{finding.get('severity', 'Unknown')} {finding.get('ecosystem', 'package')} "
            f"{finding.get('package_name', 'unknown')}@{finding.get('current_version', 'unknown')} "
            f"-> fix: {finding.get('recommended_fixed_version', 'not specified')}"
        )
    return lines


def _render_cicd_findings(findings: list[dict]) -> list[str]:
    lines = ["", "CI/CD Workflow Findings"]
    if not findings:
        return lines + ["- No CI/CD risks found."]
    for finding in findings:
        lines.append(
            "- "
            f"{finding.get('risk_level', 'Unknown')} in {finding.get('workflow_file', 'workflow')}:"
            f"{finding.get('line_number', '?')} -> {finding.get('detected_config', 'configuration risk')}"
        )
    return lines


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _icon(name: str) -> str:
    icons = {
        "alert-triangle": '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
        "activity": '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
        "badge-check": '<path d="m9 12 2 2 4-4"/><path d="M7.5 3.7 12 2l4.5 1.7 2.4 4.1-.6 4.7-3.1 3.6L12 18l-3.2-1.9-3.1-3.6-.6-4.7 2.4-4.1Z"/>',
        "file-warning": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/><path d="M12 11v4"/><path d="M12 19h.01"/>',
        "git-branch": '<path d="M6 3v12"/><circle cx="6" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M18 6a3 3 0 0 0-3 3v1a5 5 0 0 1-5 5H9"/><circle cx="18" cy="6" r="3"/>',
        "hash": '<path d="M4 9h16"/><path d="M4 15h16"/><path d="M10 3 8 21"/><path d="M16 3l-2 18"/>',
        "key": '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m12 12 8-8"/><path d="m15 7 2 2"/><path d="m17 5 2 2"/>',
        "package": '<path d="m7.5 4.3 9 5.2"/><path d="M21 8 12 3 3 8l9 5 9-5Z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>',
        "refresh": '<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16"/><path d="M3 21v-5h5"/><path d="M3 12A9 9 0 0 1 18.5 5.8L21 8"/><path d="M21 3v5h-5"/>',
        "scan": '<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M7 12h10"/>',
        "shield": '<path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3Z"/><path d="m9 12 2 2 4-4"/>',
        "signature": '<path d="M3 17c3.5-4 5.5-4 7 0 1 2.4 3 2.7 5 .7"/><path d="M15 17c1.5-1.5 3-1.5 6 0"/><path d="m13 5 3 3"/><path d="m12 12 6-6 1.5 1.5-6 6L11 14Z"/>',
        "spark": '<path d="m12 3 1.5 5.5L19 10l-5.5 1.5L12 17l-1.5-5.5L5 10l5.5-1.5Z"/>',
    }
    body = icons.get(name, icons["shield"])
    return (
        '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        f'stroke-linejoin="round">{body}</svg>'
    )


def _metric_icon(label: str) -> str:
    normalized = label.lower()
    if "score" in normalized or "puan" in normalized:
        return "activity"
    if "release" in normalized or "yayın" in normalized:
        return "badge-check"
    if "secret" in normalized:
        return "key"
    if "depend" in normalized or "bağım" in normalized:
        return "package"
    if "ci/cd" in normalized or "workflow" in normalized:
        return "git-branch"
    if "hash" in normalized or "sha" in normalized or "merkle" in normalized:
        return "hash"
    if "signature" in normalized or "imza" in normalized:
        return "signature"
    return "shield"


def _metric_card(label: str, value: object, class_name: str, icon: str | None = None) -> str:
    icon_markup = _icon(icon or _metric_icon(label))
    return (
        f'<div class="card {class_name}">'
        '<div class="card-top">'
        f'<span class="card-icon">{icon_markup}</span>'
        f'<div class="card-label">{_e(label)}</div>'
        "</div>"
        f'<div class="card-value">{_e(value)}</div>'
        "</div>"
    )


def _findings_section(title: str, body: str) -> str:
    return f'<section class="report-card"><h2>{_e(title)}</h2>{body}</section>'


def _secret_table(findings: list[dict]) -> str:
    if not findings:
        return '<div class="empty">Secret bulunmadı.</div>'
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{_e(finding.get('file_path', ''))}:{_e(finding.get('line_number', ''))}</td>"
            f"<td>{_e(finding.get('secret_type', ''))}</td>"
            f"<td><span class=\"pill {_risk_class(finding.get('severity'))}\">{_display_value(finding.get('severity', ''))}</span></td>"
            f"<td><code>{_e(finding.get('masked_preview', '****'))}</code></td>"
            f"<td>{_e(finding.get('reason', 'Pattern matched a possible secret.'))}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>Konum</th><th>Tür</th><th>Seviye</th><th>Maskeli Önizleme</th><th>Neden</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _dependency_table(findings: list[dict]) -> str:
    if not findings:
        return '<div class="empty">Riskli bağımlılık bulunmadı.</div>'
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{_e(finding.get('package_name', ''))}</td>"
            f"<td>{_e(finding.get('current_version', ''))}</td>"
            f"<td>{_e(finding.get('ecosystem', ''))}</td>"
            f"<td><span class=\"pill {_risk_class(finding.get('severity'))}\">{_display_value(finding.get('severity', ''))}</span></td>"
            f"<td>{_e(finding.get('reason', ''))}</td>"
            f"<td>{_e(finding.get('recommended_fixed_version', ''))}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>Paket</th><th>Sürüm</th><th>Ekosistem</th><th>Seviye</th><th>Neden</th><th>Önerilen Düzeltme</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _cicd_table(findings: list[dict]) -> str:
    if not findings:
        return '<div class="empty">CI/CD riski bulunmadı.</div>'
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{_e(finding.get('workflow_file', ''))}:{_e(finding.get('line_number', ''))}</td>"
            f"<td>{_e(finding.get('detected_config', ''))}</td>"
            f"<td><span class=\"pill {_risk_class(finding.get('risk_level'))}\">{_display_value(finding.get('risk_level', ''))}</span></td>"
            f"<td>{_e(finding.get('why_it_matters', ''))}</td>"
            f"<td>{_e(finding.get('recommendation', ''))}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>Workflow</th><th>Ayar</th><th>Risk</th><th>Neden Önemli</th><th>Öneri</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _crypto_panel(crypto: dict[str, Any]) -> str:
    fields = [
        ("file_name", "Dosya Adı"),
        ("current_sha256", "Mevcut SHA-256"),
        ("stored_sha256", "Kayıtlı SHA-256"),
        ("hash_match", "Hash Eşleşmesi"),
        ("signature_status", "İmza Durumu"),
        ("integrity_status", "Bütünlük Durumu"),
        ("release_status", "Yayın Durumu"),
    ]
    rows = []
    for key, label in fields:
        value = _display_value(crypto.get(key, "N/A"))
        value_markup = (
            f'<code class="hash hash-block">{_e(value)}</code>'
            if "sha256" in key
            else f"<span>{_e(value)}</span>"
        )
        rows.append(
            '<div class="crypto-row">'
            f'<div class="crypto-label">{_e(label)}</div>'
            f"<div>{value_markup}</div>"
            "</div>"
        )
    return "".join(rows)


def _crypto_panel(crypto: dict[str, Any]) -> str:
    fields = [
        ("file_name", "File Name"),
        ("version", "Manifest Version"),
        ("current_sha256", "Current SHA-256"),
        ("stored_sha256", "Manifest SHA-256"),
        ("hash_match", "File Hash Match"),
        ("manifest_sha256", "Manifest Hash"),
        ("manifest_signature_status", "Manifest Signature"),
        ("signature_status", "Signature For Current File"),
        ("integrity_status", "Integrity Status"),
        ("release_status", "Policy Decision"),
    ]
    rows = []
    for key, label in fields:
        value = _display_value(_crypto_field_value(crypto, key))
        value_markup = (
            f'<code class="hash hash-block">{_e(value)}</code>'
            if "sha256" in key or key == "manifest_sha256"
            else f"<span>{_e(value)}</span>"
        )
        rows.append(
            '<div class="crypto-row">'
            f'<div class="crypto-label">{_e(label)}</div>'
            f"<div>{value_markup}</div>"
            "</div>"
        )
    return "".join(rows)


def _crypto_field_value(crypto: dict[str, Any], key: str) -> object:
    manifest = crypto.get("manifest")
    if key == "version" and isinstance(manifest, dict):
        return manifest.get("version", "N/A")
    return crypto.get(key, "N/A")


def _tamper_panel(tamper: dict[str, Any] | None) -> str:
    if not tamper:
        return ""
    return (
        "<section>"
        "<h2>Attack Simulator</h2>"
        '<div class="crypto-row"><div class="crypto-label">Tampered</div>'
        f"<div>{_e(tamper.get('tampered'))}</div></div>"
        '<div class="crypto-row"><div class="crypto-label">Method</div>'
        f"<div>{_e(tamper.get('tamper_method'))}</div></div>"
        '<div class="crypto-row"><div class="crypto-label">Previous SHA-256</div>'
        f'<div><code class="hash hash-block">{_e(tamper.get("previous_sha256"))}</code></div></div>'
        '<div class="crypto-row"><div class="crypto-label">Current SHA-256</div>'
        f'<div><code class="hash hash-block">{_e(tamper.get("current_sha256"))}</code></div></div>'
        "</section>"
    )


def _module_note(text: str) -> str:
    return f'<p class="module-note">{_e(text)}</p>'


def _security_pipeline_section(payload: dict[str, Any], audit_log: dict[str, Any] | None = None) -> str:
    summary = payload["summary"]
    crypto = payload["findings"]["crypto"]
    repository_integrity = payload["findings"]["repository_integrity"]
    changed_files = repository_integrity.get("changed_files") or []
    manifest = crypto.get("manifest") if isinstance(crypto.get("manifest"), dict) else {}
    audit_status = (audit_log or {}).get("status", "Valid")
    steps = [
        (
            "Repository Files",
            "Changed: " + ", ".join(changed_files) if changed_files else "No tracked file changes",
            "red" if changed_files else "green",
            "The demo tracks package.json, app.js, workflow.yml, and README.md as a small virtual repository.",
        ),
        (
            "SHA-256",
            _display_value(summary["hash_status"]),
            _check_status_class(summary["hash_status"]),
            "A one-way digest is recomputed from the current release file and compared with the manifest.",
        ),
        (
            "Merkle Root",
            _repository_integrity_pipeline_value(repository_integrity),
            _check_status_class(summary["merkle_status"]),
            "Leaf hashes are combined into one root so any tracked file change changes the repository fingerprint.",
        ),
        (
            "Manifest",
            f"v{manifest.get('version', 'N/A')}" if manifest else _display_value(NOT_APPLICABLE),
            _check_status_class(summary["hash_status"]),
            "The manifest stores file name, version, SHA-256, timestamp, and the signed release state.",
        ),
        (
            "Digital Signature",
            _display_value(summary["signature_status"]),
            _signature_class(summary["signature_status"]),
            "The public key verifies the signature over the manifest hash; the gate is invalid if the file no longer matches it.",
        ),
        (
            "Policy Decision",
            _display_value(payload["release_status"]),
            _status_class(payload["release_status"]),
            f"Audit chain: {audit_status}. The final decision combines source, workflow, crypto, and logging evidence.",
        ),
    ]
    cards = []
    for index, (title, value, class_name, explanation) in enumerate(steps, start=1):
        cards.append(
            f'<div class="pipeline-step {class_name}">'
            f'<div class="step-index">{index}</div>'
            f'<h3>{_e(title)}</h3>'
            f'<div class="step-value">{_e(value)}</div>'
            f'<p>{_e(explanation)}</p>'
            "</div>"
        )
    return (
        '<section class="pipeline-section">'
        '<div class="panel-kicker">Security Pipeline</div>'
        "<h2>Repository Files &rarr; SHA-256 &rarr; Merkle Root &rarr; Manifest &rarr; Digital Signature &rarr; Policy Decision</h2>"
        '<div class="pipeline-grid">'
        + "".join(cards)
        + "</div>"
        "</section>"
    )


def _repository_integrity_panel(repository_integrity: dict[str, Any]) -> str:
    if repository_integrity.get("root_match") is None:
        return (
            '<section class="report-card merkle-card"><h2>Merkle Tree Repository Integrity</h2>'
            + _key_value_table(
                [
                    ("Status", _display_value(NOT_APPLICABLE)),
                    ("Expected Merkle Root", "N/A"),
                    ("Current Merkle Root", "N/A"),
                ]
            )
            + _module_note(str(repository_integrity.get("explanation", "")))
            + "</section>"
        )

    rows = []
    for entry in repository_integrity.get("files", []):
        row_class = "changed-row" if entry.get("changed") else ""
        rows.append(
            f'<tr class="{row_class}">'
            f"<td>{_e(entry.get('display_name', ''))}</td>"
            f"<td>{_e(entry.get('path', ''))}</td>"
            f"<td><code>{_e(_short_hash(entry.get('baseline_sha256')))}</code></td>"
            f"<td><code>{_e(_short_hash(entry.get('current_sha256')))}</code></td>"
            f"<td><span class=\"pill {'red' if entry.get('changed') else 'green'}\">{_e(entry.get('status', ''))}</span></td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr><th>Virtual File</th><th>Path</th><th>Baseline Hash</th><th>Current Hash</th><th>Status</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    roots = (
        '<div class="crypto-row"><div class="crypto-label">Expected Merkle Root</div>'
        f'<div><code class="hash hash-block">{_e(repository_integrity.get("expected_root"))}</code></div></div>'
        '<div class="crypto-row"><div class="crypto-label">Current Merkle Root</div>'
        f'<div><code class="hash hash-block">{_e(repository_integrity.get("current_root"))}</code></div></div>'
    )
    return (
        '<section class="report-card merkle-card"><h2>Merkle Tree Repository Integrity</h2>'
        + table
        + roots
        + _module_note(str(repository_integrity.get("explanation", "")))
        + "</section>"
    )


def _release_manifest_panel(crypto: dict[str, Any]) -> str:
    manifest = crypto.get("manifest") if isinstance(crypto.get("manifest"), dict) else {}
    rows = [
        ("File Name", manifest.get("file_name") or manifest.get("file") or crypto.get("file_name", "N/A")),
        ("Version", manifest.get("version", "N/A")),
        ("Stored SHA-256", crypto.get("stored_sha256", "N/A")),
        ("Timestamp", manifest.get("timestamp") or manifest.get("created_at", "N/A")),
        ("Stored Verification Status", manifest.get("verification_status", "N/A")),
        ("Runtime Verification Status", crypto.get("manifest_verification_status", "N/A")),
    ]
    return (
        '<section class="report-card"><h2>Release Manifest</h2>'
        + _key_value_table(rows)
        + _module_note("Concept: a manifest is the release bill of materials. It records what should be shipped before policy verifies what is actually present.")
        + "</section>"
    )


def _signature_explanation_panel(crypto: dict[str, Any]) -> str:
    rows = [
        ("Private Key Step", "Demo signer creates an RSA-PSS signature over the manifest hash."),
        ("Public Key Step", "RepoGuard verifies that signature with release/public_key.pem."),
        ("Signed Payload", crypto.get("signed_payload", "manifest-sha256")),
        ("Manifest Signature", _display_value(crypto.get("manifest_signature_status", "N/A"))),
        ("Current File Covered", _display_value(crypto.get("signature_covers_current_release", "N/A"))),
        ("Explanation", crypto.get("message", "N/A")),
    ]
    return (
        '<section class="report-card"><h2>Digital Signature Verification</h2>'
        + _key_value_table(rows)
        + _module_note("Concept: signatures provide authenticity, while the manifest hash and file hash together show whether the trusted signature still describes this exact artifact.")
        + "</section>"
    )


def _audit_log_panel(audit_log: dict[str, Any] | None) -> str:
    if not audit_log:
        return ""
    rows = []
    for event in audit_log.get("events", []):
        class_name = "changed-row" if event.get("chainStatus") == "Broken" else ""
        rows.append(
            f'<tr class="{class_name}">'
            f"<td>{_e(event.get('index', ''))}</td>"
            f"<td>{_e(event.get('event', ''))}</td>"
            f"<td>{_e(event.get('detail', ''))}</td>"
            f"<td><code>{_e(_short_hash(event.get('previousHash')))}</code></td>"
            f"<td><code>{_e(_short_hash(event.get('currentHash')))}</code></td>"
            f"<td><span class=\"pill {'red' if event.get('chainStatus') == 'Broken' else 'green'}\">{_e(event.get('chainStatus', ''))}</span></td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr><th>#</th><th>Event</th><th>What Changed</th><th>previousHash</th><th>currentHash</th><th>Chain</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    return (
        '<section class="report-card audit-card"><h2>Hash-Chain Audit Log</h2>'
        + table
        + _module_note("Tamper-evident logging: " + str(audit_log.get("explanation", "")))
        + "</section>"
    )


def _display_value(value: object) -> str:
    translations = {
        None: "N/A",
        True: "Evet",
        False: "Hayır",
        "APPROVED": "ONAYLI",
        "BLOCKED": "BLOKE",
        "Passed": "Geçti",
        "Failed": "Başarısız",
        "Valid": "Geçerli",
        "Invalid": "Geçersiz",
        "Missing": "Eksik",
        "Error": "Hata",
        NOT_APPLICABLE: "Uygulanamaz",
        "No Release": "Yayın yok",
        "NOT_APPLICABLE": "Uygulanamaz",
        "Verified": "Doğrulandı",
        "Hash Mismatch": "Hash Uyuşmazlığı",
        "SIGNED": "İmzalandı",
        "Critical": "KRİTİK",
        "High": "YÜKSEK",
        "Medium": "ORTA",
        "Low": "DÜŞÜK",
        "zip entry added": "ZIP içine küçük demo dosyası eklendi",
        "demo bytes appended": "Dosya sonuna demo baytları eklendi",
    }
    return str(translations.get(value, value))


def _attack_state_panel(title: str, payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    signature_status = summary["signature_status"]
    release_status = payload["release_status"]
    panel_class = _status_class(release_status)
    rows = [
        ("Yayın Durumu", _badge(_display_value(release_status), panel_class)),
        ("Güvenlik Puanı", _badge(f"{payload['security_score']}/100", _score_class(payload["security_score"]))),
        (
            "SHA-256",
            _badge(_display_value(summary["hash_status"]), _check_status_class(summary["hash_status"])),
        ),
        (
            "Merkle Root",
            _badge(
                _display_value(summary.get("merkle_status", "Passed")),
                _check_status_class(summary.get("merkle_status")),
            ),
        ),
        ("Dijital İmza", _badge(_display_value(signature_status), _signature_class(signature_status))),
    ]
    return (
        f'<section class="state-panel state-{panel_class}">'
        '<div class="state-heading">'
        f'<div><div class="panel-kicker">Durum karşılaştırması</div><h2>{_e(title)}</h2></div>'
        f'<span class="state-score {panel_class}">{_e(_display_value(release_status))}</span>'
        "</div>"
        + "".join(
            '<div class="state-row">'
            f'<div class="state-label">{_e(label)}</div>'
            f"<div>{value}</div>"
            "</div>"
            for label, value in rows
        )
        + "</section>"
    )


def _attack_verdicts(simulation: dict[str, Any]) -> str:
    after = simulation["after"]
    crypto = after["findings"]["crypto"]
    badges = [_badge(f"Yayın Durumu: {_display_value(after['release_status'])}", _status_class(after["release_status"]))]

    if crypto.get("hash_match") is True:
        badges.append(_badge("SHA-256 doğrulandı", "green"))
    else:
        badges.append(_badge("Hash uyuşmazlığı", "red"))

    if crypto.get("signature_status") == "Valid":
        badges.append(_badge("Dijital imza geçerli", "green"))
    else:
        badges.append(_badge("Dijital imza geçersiz", "red"))

    repository_integrity = after["findings"].get("repository_integrity", {})
    if repository_integrity.get("root_match") is False:
        badges.append(_badge("Merkle root uyuşmazlığı", "red"))

    audit_log = simulation.get("audit_log") or {}
    if audit_log.get("valid") is False:
        badges.append(_badge("Audit zinciri kırık", "red"))

    if _has_critical_secret(after):
        badges.append(_badge("KRİTİK secret bulgusu", "red"))
    if _has_high_cicd_risk(after):
        badges.append(_badge("YÜKSEK RİSK CI/CD yetkisi", "red"))

    if simulation.get("errors"):
        badges.append(_badge("Demo hatası", "yellow"))

    return '<div class="verdicts">' + "".join(badges) + "</div>"


def _attack_result_table(simulation: dict[str, Any]) -> str:
    after = simulation["after"]
    crypto = after["findings"]["crypto"]
    attack_result = simulation.get("attack_result") or {}
    rows = [
        ("Senaryo", simulation.get("action_label", "Onaylı Başlangıç")),
        ("Yayın Durumu", _display_value(after["release_status"])),
        ("Hash Kontrolü", "Hash uyuşmazlığı" if crypto.get("hash_match") is not True else "SHA-256 doğrulaması geçti"),
        (
            "İmza Kontrolü",
            "Dijital imza geçersiz"
            if crypto.get("signature_status") != "Valid"
            else "Dijital imza doğrulaması geçti",
        ),
    ]

    if simulation.get("action") == "break-signature" and crypto.get("signature_status") != "Valid":
        rows.append(("Açık Anahtar Kontrolü", "Açık anahtar imza doğrulaması başarısız"))

    repository_integrity = after["findings"].get("repository_integrity", {})
    if repository_integrity.get("root_match") is False:
        changed_files = ", ".join(repository_integrity.get("changed_files") or ["tracked file"])
        rows.append(("Merkle Root", f"Changed file hash detected: {changed_files}; repository root no longer matches baseline."))

    critical_secrets = [
        finding
        for finding in after["findings"]["secrets"]
        if str(finding.get("severity", "")).lower() == "critical"
    ]
    if critical_secrets:
        first = critical_secrets[0]
        rows.append(
            (
                "Secret Tarayıcı",
                f"KRİTİK secret bulgusu: {first.get('file_path', 'bilinmeyen dosya')}:"
                f"{first.get('line_number', '?')}",
            )
        )

    high_cicd = [
        finding
        for finding in after["findings"]["cicd"]
        if str(finding.get("risk_level", "")).lower() == "high"
    ]
    if high_cicd:
        first = high_cicd[0]
        rows.append(
            (
                "CI/CD Tarayıcı",
                f"YÜKSEK RİSK bulgusu: {first.get('detected_config', 'riskli workflow ayarı')}",
            )
        )

    if attack_result.get("target"):
        rows.append(("Değişen Dosya", attack_result["target"]))

    audit_log = simulation.get("audit_log") or {}
    if audit_log.get("valid") is False:
        rows.append(("Tamper-Evident Log", f"Broken at event #{audit_log.get('broken_at')}; currentHash no longer matches event content."))

    rows.append(("Bilgi Güvenliği Kavramı", _scenario_concept(str(simulation.get("action", "baseline")))))

    return _key_value_table(rows)


def _attack_details_panel(attack_result: dict[str, Any] | None) -> str:
    if not attack_result:
        return ""

    rows = [
        ("Saldırı", attack_result.get("label", "N/A")),
        ("Hedef", attack_result.get("target", "N/A")),
        ("Sonuç", attack_result.get("message", "Değişiklik uygulandı.")),
    ]
    if attack_result.get("tamper_method"):
        rows.append(("Kurcalama Yöntemi", _display_value(attack_result["tamper_method"])))
    if attack_result.get("previous_sha256"):
        rows.append(("Önceki SHA-256", attack_result["previous_sha256"]))
    if attack_result.get("current_sha256"):
        rows.append(("Yeni SHA-256", attack_result["current_sha256"]))

    return '<section class="report-card"><h2>Saldırı Değişikliği</h2>' + _key_value_table(rows) + "</section>"


def _error_panel(errors: list[str]) -> str:
    if not errors:
        return ""
    rows = [(f"Hata {index}", error) for index, error in enumerate(errors, start=1)]
    return '<section class="report-card"><h2>Demo Hataları</h2>' + _key_value_table(rows) + "</section>"


def _key_value_table(rows: list[tuple[object, object]]) -> str:
    body = "".join(
        "<tr>"
        f"<th>{_e(label)}</th>"
        f"<td>{_format_table_value(value)}</td>"
        "</tr>"
        for label, value in rows
    )
    return f'<table class="kv-table"><tbody>{body}</tbody></table>'


def _format_table_value(value: object) -> str:
    text = str(value)
    if len(text) >= 48 and all(character in "0123456789abcdefABCDEF" for character in text):
        return f'<code class="hash hash-block">{_e(text)}</code>'
    return _e(text)


def _badge(value: object, class_name: str) -> str:
    return f'<span class="pill {class_name}">{_e(value)}</span>'


def _has_critical_secret(payload: dict[str, Any]) -> bool:
    return any(
        str(finding.get("severity", "")).lower() == "critical"
        for finding in payload["findings"]["secrets"]
    )


def _has_high_cicd_risk(payload: dict[str, Any]) -> bool:
    return any(
        str(finding.get("risk_level", "")).lower() == "high"
        for finding in payload["findings"]["cicd"]
    )


def _status_class(status: object) -> str:
    return "green" if status == "APPROVED" else "red"


def _score_class(score: int) -> str:
    if score >= 80:
        return "green"
    if score >= 50:
        return "yellow"
    return "red"


def _count_class(count: int) -> str:
    return "green" if count == 0 else "red"


def _signature_class(status: object) -> str:
    if status == "Valid":
        return "green"
    if status in {NOT_APPLICABLE, "No Release", "N/A"}:
        return "green"
    if status in {"Missing", "Error"}:
        return "yellow"
    return "red"


def _check_status_class(status: object) -> str:
    if status in {"Passed", "Valid", "Verified", NOT_APPLICABLE, "No Release", "N/A"}:
        return "green"
    if status in {"Missing"}:
        return "yellow"
    return "red"


def _repository_integrity_pipeline_value(repository_integrity: dict[str, Any]) -> str:
    if repository_integrity.get("root_match") is True:
        return "Matched"
    if repository_integrity.get("root_match") is False:
        return "Mismatch"
    return _display_value(NOT_APPLICABLE)


def _risk_class(severity: object) -> str:
    normalized = str(severity or "").lower()
    if normalized in {"critical", "high"}:
        return "red"
    if normalized == "medium":
        return "yellow"
    return "green"


def build_api_health_payload() -> dict[str, Any]:
    """Describe the local API surface for the static frontend."""

    return {
        "status": "ok",
        "service": "RepoGuard",
        "features": [
            "repository_scan",
            "secret_detection",
            "dependency_risk_check",
            "cicd_risk_check",
            "release_hash_validation",
            "signature_validation",
            "manifest_verification",
            "repository_merkle_integrity",
            "score_breakdown",
            "attack_simulation",
        ],
        "endpoints": {
            "scan": "/api/scan",
            "attack_status": "/api/status",
            "attack_run": "/api/attack",
            "attack_reset": "/api/reset",
        },
        "demo_repositories": sorted(DEMO_REPOS),
        "attack_actions": ATTACK_ACTIONS,
        "defaults": {
            "release_file_name": DEFAULT_RELEASE_FILE_NAME,
            "score_mode": "dashboard",
        },
    }


def _request_value(data: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = data.get(key)
        if value is not None:
            return str(value)
    return default


def _request_bool(data: dict[str, Any], *keys: str, default: bool = False) -> bool:
    for key in keys:
        if key not in data:
            continue
        value = data[key]
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


class AttackSimulationRequestHandler(BaseHTTPRequestHandler):
    """Local HTTP handler for the RepoGuard frontend, scan API, and attack demo."""

    server_version = "RepoGuardServer/1.0"

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API.
        self._send_no_content()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API.
        parsed = urlparse(self.path)
        path = parsed.path
        if path in {"/", "/index.html"} or path.startswith(("/css/", "/js/", "/assets/")):
            self._send_static(path)
            return
        if path in {"/attack-simulation", "/repoguard-dashboard.html"}:
            self._send_html(render_attack_simulation_page(build_attack_simulation_payload()))
            return
        if path == "/api/health":
            self._send_json(build_api_health_payload())
            return
        if path == "/api/scan":
            query_data = {key: values[-1] for key, values in parse_qs(parsed.query).items() if values}
            self._handle_scan_request(query_data)
            return
        if path == "/api/status":
            self._send_json(build_attack_simulation_payload())
            return
        self._send_not_found()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API.
        path = urlparse(self.path).path
        if path == "/attack":
            attack = self._read_request_data().get("attack", "")
            self._send_html(render_attack_simulation_page(build_attack_simulation_payload(attack)))
            return
        if path == "/reset":
            self._send_html(render_attack_simulation_page(build_attack_simulation_payload()))
            return
        if path == "/api/scan":
            self._handle_scan_request(self._read_request_data())
            return
        if path == "/api/attack":
            attack = self._read_request_data().get("attack", "")
            self._send_json(build_attack_simulation_payload(attack))
            return
        if path == "/api/reset":
            self._send_json(build_attack_simulation_payload())
            return
        self._send_not_found()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _handle_scan_request(self, request_data: dict[str, Any]) -> None:
        repo_source = _request_value(request_data, "repo_source", "repoSource", "repo_url", "repoUrl", "repo").strip()
        if not repo_source:
            self._send_json(
                {
                    "error": "repo_source is required.",
                    "details": "Send a demo repository name, local repository path, or public GitHub URL.",
                    "demo_repositories": sorted(DEMO_REPOS),
                },
                status=400,
            )
            return

        release_file_name = _request_value(
            request_data,
            "release_file_name",
            "releaseFileName",
            default=DEFAULT_RELEASE_FILE_NAME,
        ).strip() or DEFAULT_RELEASE_FILE_NAME
        score_mode = _request_value(request_data, "score_mode", "scoreMode", default="dashboard").strip() or "dashboard"
        tamper_release = _request_bool(request_data, "tamper_release", "tamperRelease", default=False)

        try:
            payload = build_dashboard_summary(
                repo_source,
                release_file_name=release_file_name,
                tamper_release=tamper_release,
                score_mode=score_mode,
            )
        except (ValueError, DependencyCheckerError) as error:
            self._send_json(
                {
                    "error": str(error),
                    "repo_source": repo_source,
                    "demo_repositories": sorted(DEMO_REPOS),
                },
                status=400,
            )
            return
        except Exception as error:  # Keep API failures structured for the UI.
            self._send_json(
                {
                    "error": f"Unexpected scan failure: {error}",
                    "repo_source": repo_source,
                },
                status=500,
            )
            return

        payload["api_metadata"] = {
            "ok": True,
            "generated_at": _utc_now(),
            "release_file_name": release_file_name,
            "score_mode": score_mode,
            "tamper_release": tamper_release,
        }
        self._send_json(payload)

    def _read_request_data(self) -> dict[str, Any]:
        try:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            content_length = 0
        raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        content_type = self.headers.get("Content-Type", "")

        if "application/json" in content_type:
            try:
                parsed = json.loads(raw_body or "{}")
            except json.JSONDecodeError:
                return {}
            if isinstance(parsed, dict):
                return {str(key): value for key, value in parsed.items()}
            return {}

        parsed_form = parse_qs(raw_body)
        return {key: values[0] for key, values in parsed_form.items() if values}

    def _send_static(self, requested_path: str) -> None:
        relative_path = "index.html" if requested_path in {"", "/"} else unquote(requested_path).lstrip("/")
        frontend_root = FRONTEND_ROOT.resolve()
        file_path = (frontend_root / relative_path).resolve()
        try:
            file_path.relative_to(frontend_root)
        except ValueError:
            self._send_not_found()
            return

        if not file_path.exists() or not file_path.is_file():
            self._send_not_found()
            return

        content = file_path.read_bytes()
        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "text/javascript"}:
            content_type = f"{content_type}; charset=utf-8"

        self.send_response(200)
        self._send_common_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_no_content(self) -> None:
        self.send_response(204)
        self._send_common_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _send_common_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")

    def _send_html(self, content: str, status: int = 200) -> None:
        encoded = content.encode("utf-8")
        self.send_response(status)
        self._send_common_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self._send_common_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_not_found(self) -> None:
        self._send_html("<h1>Not Found</h1>", status=404)


def serve_attack_simulation(host: str, port: int) -> int:
    server = ThreadingHTTPServer((host, port), AttackSimulationRequestHandler)
    actual_host, actual_port = server.server_address
    print(f"RepoGuard frontend and API running at http://{actual_host}:{actual_port}/")
    print(f"Live attack simulation is available at http://{actual_host}:{actual_port}/attack-simulation")
    print("Press Ctrl+C to stop the server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping RepoGuard live attack simulation.")
    finally:
        server.server_close()
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the RepoGuard dashboard across all scanner modules.")
    parser.add_argument(
        "repo_source",
        nargs="?",
        default="secure-demo-repo",
        help="vulnerable-demo-repo, secure-demo-repo, a local path, or a GitHub URL.",
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB_PATH),
        help="Path to vulnerability_db.json.",
    )
    parser.add_argument(
        "--release-file",
        default=DEFAULT_RELEASE_FILE_NAME,
        help="Release artifact name inside the repo's release folder.",
    )
    parser.add_argument(
        "--tamper-release",
        action="store_true",
        help="Tamper with the selected repo's release artifact before scanning.",
    )
    parser.add_argument(
        "--score-mode",
        choices=["dashboard", "strict"],
        default="dashboard",
        help="dashboard keeps slide scores readable; strict subtracts every finding penalty.",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print only the structured JSON payload.",
    )
    parser.add_argument(
        "--html",
        help="Write a static HTML dashboard to the provided file path.",
    )
    parser.add_argument(
        "--attack-html",
        help="Write the live attack simulation page shell to the provided file path.",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start the local RepoGuard frontend/API server.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for --serve.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for --serve.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    if args.serve:
        return serve_attack_simulation(args.host, args.port)

    if args.attack_html:
        try:
            simulation = build_attack_simulation_payload()
            html_path = write_attack_simulation_page(simulation, args.attack_html)
        except (ValueError, OSError) as error:
            print(f"Error: could not write attack simulation page: {error}", file=sys.stderr)
            return 2
        print(f"Attack simulation page written to {html_path}")
        return 0

    try:
        payload = build_dashboard_summary(
            args.repo_source,
            db_path=args.db,
            release_file_name=args.release_file,
            tamper_release=args.tamper_release,
            score_mode=args.score_mode,
        )
    except (ValueError, DependencyCheckerError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    if args.html:
        try:
            html_path = write_html_dashboard(payload, args.html)
        except OSError as error:
            print(f"Error: could not write HTML dashboard: {error}", file=sys.stderr)
            return 2
        payload["html_dashboard"] = str(html_path)

    if args.json_only:
        print(json.dumps(payload, indent=2))
        return 1 if payload["errors"] else 0

    print(render_terminal_report(payload))
    print("\nStructured JSON Summary")
    print("-" * 23)
    print(json.dumps(payload, indent=2))
    return 1 if payload["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

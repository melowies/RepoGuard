"""RepoGuard Secret Scanner.

Scans common project files for accidentally committed secrets and returns
masked, structured findings that are safe to display in a dashboard.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


SCAN_EXTENSIONS = {".py", ".js", ".json", ".yml", ".yaml", ".txt"}
ENV_FILENAMES = {".env", ".env.example", ".env.sample", ".env.template"}

SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<key_quote>[\"']?)"
    r"(?P<name>[A-Z0-9_]*(?:API_KEY|SECRET_KEY|JWT_SECRET|PASSWORD|TOKEN)[A-Z0-9_]*)"
    r"(?P=key_quote)"
    r"\s*(?P<separator>[:=])\s*"
    r"(?P<quote>[\"']?)"
    r"(?P<value>[^\"'\s,#}]*)"
    r"(?P=quote)",
)

SK_LIVE_PATTERN = re.compile(r"sk_live_[A-Za-z0-9_\-]+", re.IGNORECASE)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


@dataclass
class SecretScanner:
    """Reusable scanner for RepoGuard.

    The scanner returns findings only. Files that cannot be read or appear to
    be binary are skipped safely and recorded in ``warnings`` for callers that
    want operational details.
    """

    repo_path: str
    warnings: list[str] = field(default_factory=list)

    def scan(self) -> list[dict]:
        root = Path(self.repo_path).expanduser()
        if not root.exists():
            raise ValueError(f"Invalid path: '{self.repo_path}' does not exist.")
        if not root.is_dir():
            raise ValueError(f"Invalid path: '{self.repo_path}' is not a directory.")

        findings: list[dict] = []

        for file_path in root.rglob("*"):
            if not file_path.is_file() or not self._should_scan_file(file_path):
                continue

            lines = self._read_text_lines(file_path)
            if lines is None:
                continue

            relative_path = file_path.relative_to(root).as_posix()
            for line_number, line in enumerate(lines, start=1):
                findings.extend(self._scan_line(relative_path, line_number, line, file_path))

        return findings

    def _should_scan_file(self, file_path: Path) -> bool:
        return file_path.name.lower() in ENV_FILENAMES or file_path.suffix.lower() in SCAN_EXTENSIONS

    def _read_text_lines(self, file_path: Path) -> list[str] | None:
        try:
            raw_content = file_path.read_bytes()
        except OSError as error:
            self.warnings.append(f"Unreadable file skipped: {file_path} ({error})")
            return None

        if b"\x00" in raw_content:
            self.warnings.append(f"Binary file skipped: {file_path}")
            return None

        try:
            return raw_content.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            self.warnings.append(f"Non-text file skipped: {file_path}")
            return None

    def _scan_line(self, relative_path: str, line_number: int, line: str, file_path: Path) -> list[dict]:
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            return []

        findings: list[dict] = []

        if PRIVATE_KEY_PATTERN.search(line):
            findings.append(
                self._build_finding(
                    relative_path,
                    line_number,
                    "Private Key",
                    "-----BEGIN **** PRIVATE KEY-----",
                    "Critical",
                    value="PRIVATE KEY MATERIAL",
                )
            )

        for match in SECRET_ASSIGNMENT_PATTERN.finditer(line):
            name = match.group("name")
            value = match.group("value").strip()
            if not value or self._is_safe_placeholder(file_path, value):
                continue

            findings.append(
                self._build_finding(
                    relative_path,
                    line_number,
                    self._secret_type_from_name(name),
                    self._mask_assignment(line, match),
                    self._severity_from_name(name),
                    value=value,
                )
            )

        for match in SK_LIVE_PATTERN.finditer(line):
            if self._overlaps_assignment(match, line):
                continue
            findings.append(
                self._build_finding(
                    relative_path,
                    line_number,
                    "Live API Key",
                    self._mask_value(match.group(0)),
                    "Critical",
                    value=match.group(0),
                )
            )

        return findings

    def _is_safe_placeholder(self, file_path: Path, value: str) -> bool:
        safe_placeholder_names = {".env.example", ".env.sample", ".env.template"}
        return file_path.name.lower() in safe_placeholder_names and value == ""

    def _secret_type_from_name(self, name: str) -> str:
        upper_name = name.upper()
        if "JWT_SECRET" in upper_name:
            return "JWT Secret"
        if "SECRET_KEY" in upper_name:
            return "Secret Key"
        if "PASSWORD" in upper_name:
            return "Password"
        if "TOKEN" in upper_name:
            return "Token"
        return "API Key"

    def _severity_from_name(self, name: str) -> str:
        upper_name = name.upper()
        if "API_KEY" in upper_name or "SECRET" in upper_name or "TOKEN" in upper_name:
            return "Critical"
        if "PASSWORD" in upper_name:
            return "High"
        return "Medium"

    def _mask_assignment(self, line: str, match: re.Match[str]) -> str:
        value = match.group("value")
        masked_value = self._mask_value(value)
        prefix = line[match.start("key_quote") : match.start("value")]
        quote = match.group("quote")
        return f"{prefix}{masked_value}{quote}"

    def _mask_value(self, value: str) -> str:
        if value.lower().startswith("sk_live_"):
            remainder = value[len("sk_live_") :]
            if "_" in remainder:
                tail = remainder.rsplit("_", 1)[-1]
                return f"sk_live_****_{tail}"
            return f"sk_live_****{remainder[-4:]}" if len(remainder) > 4 else "sk_live_****"

        if len(value) <= 4:
            return "****"
        return f"****{value[-3:]}"

    def _overlaps_assignment(self, sk_match: re.Match[str], line: str) -> bool:
        for assignment_match in SECRET_ASSIGNMENT_PATTERN.finditer(line):
            starts_inside = assignment_match.start("value") <= sk_match.start() < assignment_match.end("value")
            ends_inside = assignment_match.start("value") < sk_match.end() <= assignment_match.end("value")
            if starts_inside or ends_inside:
                return True
        return False

    def _build_finding(
        self,
        file_path: str,
        line_number: int,
        secret_type: str,
        masked_preview: str,
        severity: str,
        value: str | None = None,
    ) -> dict:
        entropy_score = _shannon_entropy(value or "")
        return {
            "file_path": file_path,
            "line_number": line_number,
            "secret_type": secret_type,
            "masked_preview": masked_preview.strip(),
            "severity": severity,
            "entropy_score": round(entropy_score, 2),
            "reason": self._reason(secret_type, severity, entropy_score),
            "recommendation": self._recommendation(severity),
        }

    def _reason(self, secret_type: str, severity: str, entropy_score: float) -> str:
        signals = [f"Regex matched {secret_type.lower()} naming patterns"]
        if entropy_score >= 3.5:
            signals.append("value has token-like entropy")
        if severity == "Critical":
            signals.append("credential type could grant direct access if it were real")
        return "; ".join(signals) + "."

    def _recommendation(self, severity: str) -> str:
        if severity == "Critical":
            return (
                "Remove the secret from source code, rotate the key, and use environment "
                "variables or a secret manager."
            )
        if severity == "High":
            return "Remove the password from source code, rotate it, and load it from a protected secret store."
        return "Review this value and replace it with a safe placeholder if it is not required in source code."


def scan_secrets(repo_path: str) -> list[dict]:
    """Scan a repository path and return safe-to-display secret findings."""

    return SecretScanner(repo_path).scan()


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a project folder for accidentally committed secrets.")
    parser.add_argument("repo_path", help="Path to the repository or project folder to scan.")
    parser.add_argument(
        "--show-warnings",
        action="store_true",
        help="Print skipped unreadable or binary files to stderr.",
    )
    args = parser.parse_args()

    scanner = SecretScanner(args.repo_path)
    try:
        findings = scanner.scan()
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    print(json.dumps(findings, indent=2))

    if args.show_warnings:
        for warning in scanner.warnings:
            print(f"Warning: {warning}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

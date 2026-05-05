"""RepoGuard Dependency Risk Checker.

Scans npm and pip dependency files in a local folder or a public GitHub
repository URL, then returns structured findings for versions listed in a
local vulnerability database.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_VULNERABILITY_DB = {
    "npm": {
        "lodash@4.17.15": {
            "severity": "High",
            "reason": "Demo vulnerable version",
            "recommended": "4.17.21",
        },
        "express@4.16.0": {
            "severity": "Medium",
            "reason": "Demo outdated version",
            "recommended": "4.18.x",
        },
    },
    "pip": {
        "django==2.2.0": {
            "severity": "High",
            "reason": "Demo outdated framework version",
            "recommended": "4.x or newer supported version",
        },
        "requests==2.19.0": {
            "severity": "Medium",
            "reason": "Demo outdated HTTP library",
            "recommended": "2.31.0",
        },
    },
}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
IGNORED_DIRECTORY_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
    ".venv",
}

GITHUB_SSH_PATTERN = re.compile(
    r"^git@github\.com:(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
REQUIREMENT_PATTERN = re.compile(r"^\s*(?P<name>[A-Za-z0-9_.-]+)\s*==\s*(?P<version>[^\s#;]+)\s*(?:#.*)?$")


class DependencyCheckerError(Exception):
    """Base exception for clear CLI and dashboard integration errors."""


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    repo: str

    @property
    def name(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}.git"

    @property
    def zip_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}/archive/HEAD.zip"


@dataclass
class DependencyRiskScanner:
    """Reusable dependency scanner for RepoGuard.

    The scanner returns findings only. Non-fatal issues, such as an invalid
    package.json or unsupported requirements.txt line, are recorded in
    ``warnings`` so dashboard code can decide whether to display them.
    """

    db_path: str = "vulnerability_db.json"
    max_dependency_file_size: int = 1024 * 1024
    max_zip_download_size: int = 50 * 1024 * 1024
    max_zip_extract_size: int = 100 * 1024 * 1024
    max_zip_file_count: int = 10_000
    warnings: list[str] = field(default_factory=list)

    def scan(self, repo_source: str) -> list[dict]:
        vulnerability_index = self._load_vulnerability_index()
        github_repo = parse_github_url(repo_source)

        if github_repo:
            with tempfile.TemporaryDirectory(prefix="repoguard-deps-") as temp_dir:
                repo_path = self._download_github_repo(github_repo, Path(temp_dir))
                return self._scan_repository_path(
                    repo_path,
                    vulnerability_index,
                    source_type="github",
                    source_name=github_repo.name,
                )

        if _looks_like_url(repo_source):
            raise DependencyCheckerError(
                "Invalid GitHub URL. Use a public repository URL like "
                "https://github.com/owner/repo."
            )

        repo_path = self._resolve_local_repo_path(repo_source)
        return self._scan_repository_path(
            repo_path,
            vulnerability_index,
            source_type="local",
            source_name=Path(repo_source.rstrip("\\/")).name or repo_path.name,
        )

    def _resolve_local_repo_path(self, repo_source: str) -> Path:
        repo_path = Path(repo_source).expanduser()
        if repo_path.exists() and repo_path.is_dir():
            return repo_path.resolve()

        # Presentation convenience: the root checker can still accept the
        # short demo names when they live under repoguard-demo.
        script_dir = Path(__file__).resolve().parent
        demo_candidate = script_dir / "repoguard-demo" / repo_source
        if demo_candidate.exists() and demo_candidate.is_dir():
            return demo_candidate.resolve()

        if repo_path.exists() and not repo_path.is_dir():
            raise DependencyCheckerError(f"Invalid local repository path: '{repo_source}' is not a directory.")
        raise DependencyCheckerError(f"Invalid local repository path: '{repo_source}' does not exist.")

    def _load_vulnerability_index(self) -> dict[str, dict[tuple[str, str], dict]]:
        db_file = Path(self.db_path)
        if not db_file.exists():
            raise DependencyCheckerError(f"Missing vulnerability database: '{self.db_path}'.")
        if not db_file.is_file():
            raise DependencyCheckerError(f"Invalid vulnerability database path: '{self.db_path}' is not a file.")

        try:
            raw_data = json.loads(db_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise DependencyCheckerError(
                f"Malformed vulnerability database '{self.db_path}': {error.msg} at line {error.lineno}."
            ) from error
        except OSError as error:
            raise DependencyCheckerError(f"Could not read vulnerability database '{self.db_path}': {error}.") from error

        if not isinstance(raw_data, dict):
            raise DependencyCheckerError("Malformed vulnerability database: top-level value must be an object.")

        return {
            "npm": self._build_npm_index(raw_data.get("npm", {})),
            "pip": self._build_pip_index(raw_data.get("pip", {})),
        }

    def _build_npm_index(self, npm_data: object) -> dict[tuple[str, str], dict]:
        if not isinstance(npm_data, dict):
            raise DependencyCheckerError("Malformed vulnerability database: 'npm' must be an object.")

        index: dict[tuple[str, str], dict] = {}
        for key, details in npm_data.items():
            if not isinstance(key, str) or not isinstance(details, dict):
                raise DependencyCheckerError("Malformed vulnerability database: npm entries must be objects.")

            package_name, version = _split_npm_key(key)
            if not package_name or not version:
                raise DependencyCheckerError(f"Malformed vulnerability database: invalid npm key '{key}'.")

            index[(package_name.lower(), version.lower())] = details
        return index

    def _build_pip_index(self, pip_data: object) -> dict[tuple[str, str], dict]:
        if not isinstance(pip_data, dict):
            raise DependencyCheckerError("Malformed vulnerability database: 'pip' must be an object.")

        index: dict[tuple[str, str], dict] = {}
        for key, details in pip_data.items():
            if not isinstance(key, str) or not isinstance(details, dict):
                raise DependencyCheckerError("Malformed vulnerability database: pip entries must be objects.")

            if "==" not in key:
                raise DependencyCheckerError(f"Malformed vulnerability database: invalid pip key '{key}'.")
            package_name, version = key.split("==", 1)
            package_name = package_name.strip()
            version = version.strip()
            if not package_name or not version:
                raise DependencyCheckerError(f"Malformed vulnerability database: invalid pip key '{key}'.")

            index[(package_name.lower(), version.lower())] = details
        return index

    def _download_github_repo(self, github_repo: GitHubRepo, temp_dir: Path) -> Path:
        git_path = shutil.which("git")
        clone_error = ""

        if git_path:
            clone_target = temp_dir / "repo"
            try:
                result = subprocess.run(
                    [git_path, "clone", "--depth", "1", github_repo.clone_url, str(clone_target)],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                clone_error = "git clone timed out"
                if error.stderr:
                    clone_error = f"{clone_error}: {_sanitize_error_message(error.stderr)}"
            except OSError as error:
                clone_error = _sanitize_error_message(str(error))
            else:
                if result.returncode == 0:
                    return clone_target
                clone_error = _sanitize_error_message(result.stderr or result.stdout)
                if _looks_like_repo_not_found(clone_error):
                    raise DependencyCheckerError(f"GitHub repository not found or not public: {github_repo.name}.")

        try:
            return self._download_github_zip(github_repo, temp_dir)
        except DependencyCheckerError as error:
            if clone_error:
                raise DependencyCheckerError(
                    f"Could not download GitHub repository '{github_repo.name}'. "
                    f"git clone failed: {clone_error}. Zip download failed: {error}"
                ) from error
            raise

    def _download_github_zip(self, github_repo: GitHubRepo, temp_dir: Path) -> Path:
        try:
            with urllib.request.urlopen(github_repo.zip_url, timeout=45) as response:
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > self.max_zip_download_size:
                    raise DependencyCheckerError(
                        f"GitHub repository archive is too large to scan safely "
                        f"({content_length} bytes)."
                    )

                archive_bytes = self._read_limited_response(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise DependencyCheckerError(f"GitHub repository not found or not public: {github_repo.name}.") from error
            raise DependencyCheckerError(f"GitHub returned HTTP {error.code} for {github_repo.name}.") from error
        except urllib.error.URLError as error:
            raise DependencyCheckerError(f"Network failure while downloading {github_repo.name}: {error.reason}.") from error
        except TimeoutError as error:
            raise DependencyCheckerError(f"Network timeout while downloading {github_repo.name}.") from error
        except OSError as error:
            raise DependencyCheckerError(f"Network failure while downloading {github_repo.name}: {error}.") from error

        extract_dir = temp_dir / "zip"
        extract_dir.mkdir(parents=True, exist_ok=True)
        self._extract_limited_zip(archive_bytes, extract_dir)

        top_level_dirs = {path for path in extract_dir.iterdir() if path.is_dir()}
        if len(top_level_dirs) == 1:
            return next(iter(top_level_dirs))
        return extract_dir

    def _read_limited_response(self, response: object) -> bytes:
        chunks: list[bytes] = []
        total_size = 0

        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > self.max_zip_download_size:
                raise DependencyCheckerError(
                    f"GitHub repository archive is too large to scan safely "
                    f"(over {self.max_zip_download_size} bytes)."
                )
            chunks.append(chunk)

        return b"".join(chunks)

    def _extract_limited_zip(self, archive_bytes: bytes, extract_dir: Path) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                members = archive.infolist()
                if len(members) > self.max_zip_file_count:
                    raise DependencyCheckerError(
                        f"GitHub repository archive has too many files to scan safely "
                        f"({len(members)} files)."
                    )

                total_uncompressed_size = 0
                for member in members:
                    total_uncompressed_size += member.file_size
                    if total_uncompressed_size > self.max_zip_extract_size:
                        raise DependencyCheckerError(
                            f"GitHub repository archive is too large after extraction "
                            f"(over {self.max_zip_extract_size} bytes)."
                        )
                    self._extract_zip_member_safely(archive, member, extract_dir)
        except zipfile.BadZipFile as error:
            raise DependencyCheckerError("GitHub repository download was not a valid zip archive.") from error

    def _extract_zip_member_safely(self, archive: zipfile.ZipFile, member: zipfile.ZipInfo, extract_dir: Path) -> None:
        member_name = member.filename.replace("\\", "/")
        if member_name.startswith("/") or ".." in Path(member_name).parts:
            self.warnings.append(f"Unsafe zip path skipped: {member.filename}")
            return

        target_path = (extract_dir / member_name).resolve()
        extract_root = extract_dir.resolve()
        if extract_root not in target_path.parents and target_path != extract_root:
            self.warnings.append(f"Unsafe zip path skipped: {member.filename}")
            return

        if member.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
            return

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, target_path.open("wb") as destination:
            shutil.copyfileobj(source, destination)

    def _scan_repository_path(
        self,
        repo_path: Path,
        vulnerability_index: dict[str, dict[tuple[str, str], dict]],
        source_type: str,
        source_name: str,
    ) -> list[dict]:
        findings: list[dict] = []
        dependency_files_found = 0

        for file_path in _iter_dependency_files(repo_path):
            dependency_files_found += 1
            relative_path = file_path.relative_to(repo_path).as_posix()

            if _file_is_too_large(file_path, self.max_dependency_file_size):
                self.warnings.append(f"Dependency file skipped because it is too large: {relative_path}")
                continue

            if file_path.name == "package.json":
                findings.extend(
                    self._scan_package_json(
                        file_path,
                        relative_path,
                        vulnerability_index["npm"],
                        source_type,
                        source_name,
                    )
                )
            elif file_path.name == "requirements.txt":
                findings.extend(
                    self._scan_requirements_txt(
                        file_path,
                        relative_path,
                        vulnerability_index["pip"],
                        source_type,
                        source_name,
                    )
                )

        if dependency_files_found == 0:
            self.warnings.append("No package.json or requirements.txt files were found.")

        return findings

    def _scan_package_json(
        self,
        file_path: Path,
        relative_path: str,
        npm_index: dict[tuple[str, str], dict],
        source_type: str,
        source_name: str,
    ) -> list[dict]:
        try:
            package_data = json.loads(file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            self.warnings.append(f"Invalid package.json skipped: {relative_path} (line {error.lineno})")
            return []
        except OSError as error:
            self.warnings.append(f"Unreadable package.json skipped: {relative_path} ({error})")
            return []

        if not isinstance(package_data, dict):
            self.warnings.append(f"Invalid package.json skipped: {relative_path} (top-level value is not an object)")
            return []

        findings: list[dict] = []
        for section_name in ("dependencies", "devDependencies"):
            dependencies = package_data.get(section_name, {})
            if dependencies is None:
                continue
            if not isinstance(dependencies, dict):
                self.warnings.append(f"Invalid {section_name} skipped in {relative_path}")
                continue

            for package_name, version_value in dependencies.items():
                if not isinstance(package_name, str) or not isinstance(version_value, str):
                    continue
                normalized_version = _normalize_npm_version(version_value)
                vulnerability = npm_index.get((package_name.lower(), normalized_version.lower()))
                if vulnerability:
                    findings.append(
                        self._build_finding(
                            package_name=package_name,
                            current_version=normalized_version,
                            ecosystem="npm",
                            file_path=relative_path,
                            source_type=source_type,
                            source_name=source_name,
                            vulnerability=vulnerability,
                        )
                    )

        return findings

    def _scan_requirements_txt(
        self,
        file_path: Path,
        relative_path: str,
        pip_index: dict[tuple[str, str], dict],
        source_type: str,
        source_name: str,
    ) -> list[dict]:
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            self.warnings.append(f"Non-UTF-8 requirements.txt skipped: {relative_path}")
            return []
        except OSError as error:
            self.warnings.append(f"Unreadable requirements.txt skipped: {relative_path} ({error})")
            return []

        findings: list[dict] = []
        for line_number, line in enumerate(lines, start=1):
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("#"):
                continue

            match = REQUIREMENT_PATTERN.match(line)
            if not match:
                self.warnings.append(f"Unsupported requirements.txt line skipped: {relative_path}:{line_number}")
                continue

            package_name = match.group("name")
            version = match.group("version").strip()
            vulnerability = pip_index.get((package_name.lower(), version.lower()))
            if vulnerability:
                findings.append(
                    self._build_finding(
                        package_name=package_name,
                        current_version=version,
                        ecosystem="pip",
                        file_path=relative_path,
                        source_type=source_type,
                        source_name=source_name,
                        vulnerability=vulnerability,
                    )
                )

        return findings

    def _build_finding(
        self,
        package_name: str,
        current_version: str,
        ecosystem: str,
        file_path: str,
        source_type: str,
        source_name: str,
        vulnerability: dict,
    ) -> dict:
        severity = str(vulnerability.get("severity", "Medium"))
        if severity not in VALID_SEVERITIES:
            severity = "Medium"

        return {
            "package_name": package_name,
            "current_version": current_version,
            "ecosystem": ecosystem,
            "file_path": file_path,
            "source_type": source_type,
            "source_name": source_name,
            "severity": severity,
            "reason": str(vulnerability.get("reason", "Known risky dependency version")),
            "recommended_fixed_version": str(
                vulnerability.get("recommended_fixed_version", vulnerability.get("recommended", ""))
            ),
        }


def scan_dependencies(repo_source: str, db_path: str = "vulnerability_db.json") -> list[dict]:
    """Scan a local folder or public GitHub repository URL for risky dependencies."""

    return DependencyRiskScanner(db_path=db_path).scan(repo_source)


def ensure_demo_vulnerability_db(db_path: str = "vulnerability_db.json") -> None:
    """Create a presentation-friendly demo vulnerability DB if it is missing."""

    db_file = Path(db_path)
    if db_file.exists():
        return

    db_file.write_text(json.dumps(DEFAULT_VULNERABILITY_DB, indent=2), encoding="utf-8")


def parse_github_url(repo_source: str) -> GitHubRepo | None:
    ssh_match = GITHUB_SSH_PATTERN.match(repo_source.strip())
    if ssh_match:
        return GitHubRepo(owner=ssh_match.group("owner"), repo=ssh_match.group("repo"))

    parsed_url = urllib.parse.urlparse(repo_source)
    if parsed_url.scheme not in {"http", "https"}:
        return None
    if parsed_url.netloc.lower() not in {"github.com", "www.github.com"}:
        return None

    path_parts = [part for part in parsed_url.path.split("/") if part]
    if len(path_parts) != 2:
        raise DependencyCheckerError(
            "Invalid GitHub URL. Use the repository root URL, for example "
            "https://github.com/owner/repo."
        )

    owner, repo = path_parts
    if not _valid_github_name(owner) or not _valid_github_name(repo):
        raise DependencyCheckerError(
            "Invalid GitHub URL. Owner and repository names may contain letters, "
            "numbers, dots, underscores, and hyphens."
        )

    if repo.endswith(".git"):
        repo = repo[:-4]
    if not repo:
        raise DependencyCheckerError("Invalid GitHub URL. Repository name is missing.")

    return GitHubRepo(owner=owner, repo=repo)


def _iter_dependency_files(repo_path: Path) -> list[Path]:
    dependency_files: list[Path] = []

    for current_dir_name, dir_names, file_names in os.walk(repo_path):
        dir_names[:] = [name for name in dir_names if name not in IGNORED_DIRECTORY_NAMES]
        current_dir = Path(current_dir_name)
        for file_name in file_names:
            if file_name in {"package.json", "requirements.txt"}:
                dependency_files.append(current_dir / file_name)

    return dependency_files


def _split_npm_key(key: str) -> tuple[str, str]:
    separator_index = key.rfind("@")
    if separator_index <= 0:
        return "", ""
    return key[:separator_index].strip(), key[separator_index + 1 :].strip()


def _normalize_npm_version(version: str) -> str:
    normalized = version.strip()
    while normalized.startswith(("^", "~", "=", "v")):
        normalized = normalized[1:].strip()
    return normalized


def _file_is_too_large(file_path: Path, max_size: int) -> bool:
    try:
        return file_path.stat().st_size > max_size
    except OSError:
        return True


def _valid_github_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value))


def _looks_like_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return parsed.scheme in {"http", "https"} or value.startswith("git@")


def _looks_like_repo_not_found(message: str) -> bool:
    lower_message = message.lower()
    return "repository not found" in lower_message or "not found" in lower_message or "could not read from remote" in lower_message


def _sanitize_error_message(message: str) -> str:
    cleaned_lines = [line.strip() for line in message.splitlines() if line.strip()]
    cleaned_message = " ".join(cleaned_lines)
    return cleaned_message[:400] if cleaned_message else "unknown error"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan local or public GitHub repositories for risky dependency versions."
    )
    parser.add_argument("repo_source", help="Local repository folder or public GitHub repository URL.")
    parser.add_argument(
        "--db",
        default="vulnerability_db.json",
        help="Path to the local vulnerability database JSON file.",
    )
    parser.add_argument(
        "--show-warnings",
        action="store_true",
        help="Print non-fatal parsing and scanning warnings to stderr.",
    )
    parser.add_argument(
        "--create-demo-db",
        action="store_true",
        help="Create vulnerability_db.json with demo entries if it is missing.",
    )
    args = parser.parse_args()

    if args.create_demo_db:
        ensure_demo_vulnerability_db(args.db)

    scanner = DependencyRiskScanner(db_path=args.db)
    try:
        findings = scanner.scan(args.repo_source)
    except DependencyCheckerError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    print(json.dumps(findings, indent=2))

    if args.show_warnings:
        for warning in scanner.warnings:
            print(f"Warning: {warning}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

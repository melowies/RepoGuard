"""RepoGuard CI/CD Workflow Risk Scanner.

Scans GitHub Actions workflow files in a local folder or public GitHub
repository URL and returns structured, safe-to-display risk findings.

CI/CD workflows run with tokens and permissions. If the workflow is
over-permissive or contains hardcoded secrets, repository security and release
integrity can be affected.
"""

from __future__ import annotations

import argparse
import io
import json
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

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - depends on the user's environment.
    yaml = None


VALID_RISK_LEVELS = {"Critical", "High", "Medium", "Low"}
WORKFLOW_EXTENSIONS = {".yml", ".yaml"}
SECRET_KEYWORDS = ("API_KEY", "TOKEN", "PASSWORD", "SECRET", "PRIVATE_KEY", "ACCESS_KEY")
BROAD_PERMISSION_KEYS = {"contents", "packages", "actions", "deployments", "id-token"}
HIGH_IMPACT_PERMISSION_KEYS = {"actions", "deployments", "id-token"}
RISKY_DEPLOY_WORDS = ("deploy", "release", "publish")

GITHUB_SSH_PATTERN = re.compile(
    r"^git@github\.com:(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
PERMISSIONS_WRITE_ALL_PATTERN = re.compile(r"^\s*permissions\s*:\s*write-all\s*(?:#.*)?$", re.IGNORECASE)
USES_UNPINNED_BRANCH_PATTERN = re.compile(
    r"^\s*-\s*uses\s*:\s*[\"']?(?P<action>[^\"'\s#]+@(?P<branch>master|main))[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
USES_ACTION_PATTERN = re.compile(
    r"^\s*-\s*uses\s*:\s*[\"']?(?P<action>[^\"'\s#]+)[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<key_quote>[\"']?)"
    r"(?P<name>[A-Za-z0-9_-]*(?:API_KEY|TOKEN|PASSWORD|SECRET|PRIVATE_KEY|ACCESS_KEY)[A-Za-z0-9_-]*)"
    r"(?P=key_quote)"
    r"\s*(?P<separator>[:=])\s*"
    r"(?P<quote>[\"']?)"
    r"(?P<value>[^\"'\s,#}]*)"
    r"(?P=quote)",
    re.IGNORECASE,
)
PERMISSION_BLOCK_START_PATTERN = re.compile(r"^(?P<indent>\s*)permissions\s*:\s*(?P<value>.*)$", re.IGNORECASE)
PERMISSION_WRITE_PATTERN = re.compile(
    r"^\s*(?P<permission>contents|packages|actions|deployments|id-token)\s*:\s*write\b",
    re.IGNORECASE,
)
INLINE_PERMISSION_WRITE_PATTERN = re.compile(
    r"(?P<permission>contents|packages|actions|deployments|id-token)\s*:\s*write\b",
    re.IGNORECASE,
)
JOBS_START_PATTERN = re.compile(r"^(?P<indent>\s*)jobs\s*:\s*(?:#.*)?$", re.IGNORECASE)
JOB_NAME_PATTERN = re.compile(r"^(?P<indent>\s*)(?P<name>[A-Za-z0-9_.-]+)\s*:\s*(?:#.*)?$")
STEP_NAME_PATTERN = re.compile(r"^\s*-\s*name\s*:\s*(?P<name>.+)$", re.IGNORECASE)


class CICDScannerError(Exception):
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
class WorkflowContext:
    workflow_file: str
    source_type: str
    source_name: str


@dataclass
class BroadPermission:
    line_number: int
    detected_config: str
    risk_level: str


@dataclass
class RiskyName:
    line_number: int
    name_type: str
    name: str


@dataclass
class CICDRiskScanner:
    """Reusable CI/CD scanner for RepoGuard.

    The scanner focuses on GitHub Actions because those workflow files often
    control repository tokens, permissions, secrets, and deployment access.
    Non-fatal issues are recorded in ``warnings`` so dashboard code can decide
    whether to display them.
    """

    max_workflow_file_size: int = 1024 * 1024
    max_zip_download_size: int = 50 * 1024 * 1024
    max_zip_extract_size: int = 100 * 1024 * 1024
    max_zip_file_count: int = 10_000
    warnings: list[str] = field(default_factory=list)

    def scan(self, repo_source: str) -> list[dict]:
        github_repo = parse_github_url(repo_source)

        if github_repo:
            with tempfile.TemporaryDirectory(prefix="repoguard-cicd-") as temp_dir:
                repo_path = self._download_github_repo(github_repo, Path(temp_dir))
                return self._scan_repository_path(
                    repo_path,
                    source_type="github",
                    source_name=github_repo.name,
                )

        if _looks_like_url(repo_source):
            raise CICDScannerError(
                "Invalid GitHub URL. Use a public repository URL like "
                "https://github.com/owner/repo."
            )

        repo_path = self._resolve_local_repo_path(repo_source)
        return self._scan_repository_path(
            repo_path,
            source_type="local",
            source_name=Path(repo_source.rstrip("\\/")).name or repo_path.name,
        )

    def _resolve_local_repo_path(self, repo_source: str) -> Path:
        repo_path = Path(repo_source).expanduser()
        if repo_path.exists() and repo_path.is_dir():
            return repo_path.resolve()

        # Presentation convenience: root-level commands can use the short demo
        # folder names even though they live under repoguard-demo.
        script_dir = Path(__file__).resolve().parent
        demo_candidate = script_dir / "repoguard-demo" / repo_source
        if demo_candidate.exists() and demo_candidate.is_dir():
            return demo_candidate.resolve()

        if repo_path.exists() and not repo_path.is_dir():
            raise CICDScannerError(f"Invalid local repository path: '{repo_source}' is not a directory.")
        raise CICDScannerError(f"Invalid local repository path: '{repo_source}' does not exist.")

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
                    raise CICDScannerError(f"GitHub repository not found or not public: {github_repo.name}.")

        try:
            return self._download_github_zip(github_repo, temp_dir)
        except CICDScannerError as error:
            if clone_error:
                raise CICDScannerError(
                    f"Could not download GitHub repository '{github_repo.name}'. "
                    f"git clone failed: {clone_error}. Zip download failed: {error}"
                ) from error
            raise

    def _download_github_zip(self, github_repo: GitHubRepo, temp_dir: Path) -> Path:
        try:
            with urllib.request.urlopen(github_repo.zip_url, timeout=45) as response:
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > self.max_zip_download_size:
                    raise CICDScannerError(
                        f"GitHub repository archive is too large to scan safely "
                        f"({content_length} bytes)."
                    )

                archive_bytes = self._read_limited_response(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise CICDScannerError(f"GitHub repository not found or not public: {github_repo.name}.") from error
            raise CICDScannerError(f"GitHub returned HTTP {error.code} for {github_repo.name}.") from error
        except urllib.error.URLError as error:
            raise CICDScannerError(f"Network failure while downloading {github_repo.name}: {error.reason}.") from error
        except TimeoutError as error:
            raise CICDScannerError(f"Network timeout while downloading {github_repo.name}.") from error
        except OSError as error:
            raise CICDScannerError(f"Network failure while downloading {github_repo.name}: {error}.") from error

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
                raise CICDScannerError(
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
                    raise CICDScannerError(
                        f"GitHub repository archive has too many files to scan safely "
                        f"({len(members)} files)."
                    )

                total_uncompressed_size = 0
                for member in members:
                    total_uncompressed_size += member.file_size
                    if total_uncompressed_size > self.max_zip_extract_size:
                        raise CICDScannerError(
                            f"GitHub repository archive is too large after extraction "
                            f"(over {self.max_zip_extract_size} bytes)."
                        )
                    self._extract_zip_member_safely(archive, member, extract_dir)
        except zipfile.BadZipFile as error:
            raise CICDScannerError("GitHub repository download was not a valid zip archive.") from error

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

    def _scan_repository_path(self, repo_path: Path, source_type: str, source_name: str) -> list[dict]:
        workflow_files = _iter_workflow_files(repo_path)
        if not workflow_files:
            self.warnings.append("No .github/workflows/*.yml or *.yaml files were found.")
            return []

        findings: list[dict] = []
        for file_path in workflow_files:
            relative_path = file_path.relative_to(repo_path).as_posix()

            if _file_is_too_large(file_path, self.max_workflow_file_size):
                self.warnings.append(f"Workflow file skipped because it is too large: {relative_path}")
                continue

            context = WorkflowContext(relative_path, source_type, source_name)
            findings.extend(self._scan_workflow_file(file_path, context))

        findings.sort(key=lambda finding: (finding["workflow_file"], finding.get("line_number") or 0, finding["detected_config"]))
        return findings

    def _scan_workflow_file(self, file_path: Path, context: WorkflowContext) -> list[dict]:
        lines = self._read_text_lines(file_path, context.workflow_file)
        if lines is None:
            return []

        if yaml is not None:
            self._parse_yaml_for_warning_only("\n".join(lines), context.workflow_file)

        text_findings, broad_permissions, risky_names = self._scan_text_rules(lines, context)
        text_findings.extend(self._build_risky_deploy_findings(context, broad_permissions, risky_names))
        return _dedupe_findings(text_findings)

    def _read_text_lines(self, file_path: Path, relative_path: str) -> list[str] | None:
        try:
            raw_content = file_path.read_bytes()
        except OSError as error:
            self.warnings.append(f"Unreadable workflow file skipped: {relative_path} ({error})")
            return None

        if b"\x00" in raw_content:
            self.warnings.append(f"Binary workflow file skipped: {relative_path}")
            return None

        try:
            return raw_content.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            self.warnings.append(f"Non-UTF-8 workflow file skipped: {relative_path}")
            return None

    def _parse_yaml_for_warning_only(self, content: str, relative_path: str) -> object | None:
        try:
            return yaml.safe_load(content)  # type: ignore[union-attr]
        except Exception as error:  # PyYAML exposes parser-specific exception classes.
            self.warnings.append(f"Invalid YAML in {relative_path}; text-based CI/CD checks were still applied ({error}).")
            return None

    def _scan_text_rules(
        self,
        lines: list[str],
        context: WorkflowContext,
    ) -> tuple[list[dict], list[BroadPermission], list[RiskyName]]:
        findings: list[dict] = []
        broad_permissions: list[BroadPermission] = []
        risky_names: list[RiskyName] = []
        permission_block_indent: int | None = None
        jobs_block_indent: int | None = None

        for line_number, line in enumerate(lines, start=1):
            if _is_comment_or_blank(line):
                continue

            stripped_line = line.strip()
            current_indent = _indent_width(line)

            if permission_block_indent is not None and current_indent <= permission_block_indent:
                permission_block_indent = None
            if jobs_block_indent is not None and current_indent <= jobs_block_indent and not stripped_line.startswith("-"):
                jobs_block_indent = None

            if PERMISSIONS_WRITE_ALL_PATTERN.match(line):
                detected_config = "permissions: write-all"
                findings.append(
                    self._build_finding(
                        context,
                        line_number,
                        detected_config,
                        "High",
                        "The workflow has excessive repository permissions. If compromised, it may modify repository contents or releases.",
                        "Use least privilege permissions, for example permissions: contents: read.",
                    )
                )
                broad_permissions.append(BroadPermission(line_number, detected_config, "High"))

            if _line_mentions_pull_request_target(line):
                findings.append(
                    self._build_finding(
                        context,
                        line_number,
                        _safe_line_preview(stripped_line),
                        "High",
                        "The pull_request_target trigger runs in the base repository context and can be risky when untrusted pull request code is handled incorrectly.",
                        "Use pull_request for untrusted code, or carefully isolate checkout, scripts, and secrets when pull_request_target is required.",
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(_strip_comment(line)):
                findings.append(
                    self._build_finding(
                        context,
                        line_number,
                        _safe_line_preview(stripped_line),
                        "High",
                        "Piping a downloaded script directly into a shell can execute unreviewed remote code in the CI runner.",
                        "Download, verify, pin, and review installer scripts before execution.",
                    )
                )

            findings.extend(self._scan_secret_line(line, line_number, context))

            action_match = USES_ACTION_PATTERN.match(line)
            unpinned_match = USES_UNPINNED_BRANCH_PATTERN.match(line)
            if action_match and "@" not in action_match.group("action"):
                findings.append(
                    self._build_finding(
                        context,
                        line_number,
                        f"uses: {action_match.group('action')}",
                        "High",
                        "The action does not include a pinned ref, so the workflow can run code that changes without review.",
                        "Pin actions to a version tag such as @v4 or to a full commit SHA.",
                    )
                )
            elif unpinned_match:
                branch = unpinned_match.group("branch")
                findings.append(
                    self._build_finding(
                        context,
                        line_number,
                        f"uses: {unpinned_match.group('action')}",
                        "Medium",
                        f"The action is pinned to the moving {branch} branch, so its behavior can change unexpectedly.",
                        "Pin actions to a version tag such as @v4 or to a full commit SHA.",
                    )
                )

            permission_match = PERMISSION_BLOCK_START_PATTERN.match(line)
            if permission_match:
                inline_value = _strip_comment(permission_match.group("value")).strip()
                if inline_value in {"", "|", ">"}:
                    permission_block_indent = len(permission_match.group("indent"))
                broad_permissions.extend(self._scan_inline_permissions(line, line_number, context, findings))
            elif permission_block_indent is not None:
                permission_write_match = PERMISSION_WRITE_PATTERN.match(line)
                if permission_write_match:
                    broad_permissions.append(
                        self._add_broad_permission_finding(
                            context,
                            findings,
                            line_number,
                            permission_write_match.group("permission").lower(),
                        )
                    )

            jobs_match = JOBS_START_PATTERN.match(line)
            if jobs_match:
                jobs_block_indent = len(jobs_match.group("indent"))
            elif jobs_block_indent is not None:
                job_match = JOB_NAME_PATTERN.match(line)
                if job_match and _indent_width(line) > jobs_block_indent and _contains_risky_deploy_word(job_match.group("name")):
                    risky_names.append(RiskyName(line_number, "job", job_match.group("name")))

            step_match = STEP_NAME_PATTERN.match(line)
            if step_match and _contains_risky_deploy_word(step_match.group("name")):
                risky_names.append(RiskyName(line_number, "step", _clean_name_value(step_match.group("name"))))

        return findings, broad_permissions, risky_names

    def _scan_secret_line(self, line: str, line_number: int, context: WorkflowContext) -> list[dict]:
        if _is_comment_or_blank(line):
            return []

        findings: list[dict] = []
        for match in SECRET_ASSIGNMENT_PATTERN.finditer(line):
            secret_name = match.group("name")
            secret_value = match.group("value").strip()
            if _is_workflow_keyword_assignment(secret_name, secret_value):
                continue
            if not secret_value:
                continue
            if _is_github_expression(secret_value) or _is_safe_secret_placeholder(secret_value):
                continue

            findings.append(
                self._build_finding(
                    context,
                    line_number,
                    _mask_assignment(line, match),
                    "Critical",
                    "A hardcoded secret in a workflow can be exposed to logs, pull requests, or compromised jobs.",
                    "Remove the hardcoded value, rotate it if it was real, and store it in GitHub Actions secrets or an external secret manager.",
                )
            )

        return findings

    def _scan_inline_permissions(
        self,
        line: str,
        line_number: int,
        context: WorkflowContext,
        findings: list[dict],
    ) -> list[BroadPermission]:
        permission_match = PERMISSION_BLOCK_START_PATTERN.match(line)
        if not permission_match:
            return []

        inline_value = _strip_comment(permission_match.group("value"))
        if not inline_value or inline_value.lower().strip() == "write-all":
            return []

        broad_permissions: list[BroadPermission] = []
        for inline_match in INLINE_PERMISSION_WRITE_PATTERN.finditer(inline_value):
            broad_permissions.append(
                self._add_broad_permission_finding(
                    context,
                    findings,
                    line_number,
                    inline_match.group("permission").lower(),
                )
            )
        return broad_permissions

    def _add_broad_permission_finding(
        self,
        context: WorkflowContext,
        findings: list[dict],
        line_number: int,
        permission_name: str,
    ) -> BroadPermission:
        risk_level = "High" if permission_name in HIGH_IMPACT_PERMISSION_KEYS else "Medium"
        detected_config = f"{permission_name}: write"
        findings.append(
            self._build_finding(
                context,
                line_number,
                detected_config,
                risk_level,
                f"The workflow grants write access for {permission_name}, increasing the impact of a compromised workflow run.",
                "Grant only the permissions each job needs, and prefer read-only access unless write access is required.",
            )
        )
        return BroadPermission(line_number, detected_config, risk_level)

    def _build_risky_deploy_findings(
        self,
        context: WorkflowContext,
        broad_permissions: list[BroadPermission],
        risky_names: list[RiskyName],
    ) -> list[dict]:
        if not broad_permissions or not risky_names:
            return []

        broad_summary = _summarize_broad_permissions(broad_permissions)
        has_high_broad_permission = any(permission.risk_level == "High" for permission in broad_permissions)
        risk_level = "High" if has_high_broad_permission else "Medium"
        findings: list[dict] = []

        for risky_name in risky_names:
            findings.append(
                self._build_finding(
                    context,
                    risky_name.line_number,
                    f"{risky_name.name_type} '{risky_name.name}' with broad permissions ({broad_summary})",
                    risk_level,
                    "Deployment, release, or publishing jobs can affect production artifacts; broad permissions make compromise more damaging.",
                    "Move deploy and release jobs to the smallest possible permission set and require environment approvals for sensitive deployments.",
                )
            )

        return findings

    def _build_finding(
        self,
        context: WorkflowContext,
        line_number: int | None,
        detected_config: str,
        risk_level: str,
        why_it_matters: str,
        recommendation: str,
    ) -> dict:
        if risk_level not in VALID_RISK_LEVELS:
            risk_level = "Medium"

        return {
            "workflow_file": context.workflow_file,
            "line_number": line_number,
            "detected_config": detected_config,
            "risk_level": risk_level,
            "why_it_matters": why_it_matters,
            "recommendation": recommendation,
            "source_type": context.source_type,
            "source_name": context.source_name,
        }


def scan_cicd_risks(repo_source: str) -> list[dict]:
    """Scan a local folder or public GitHub repository URL for CI/CD risks."""

    return CICDRiskScanner().scan(repo_source)


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
        raise CICDScannerError(
            "Invalid GitHub URL. Use the repository root URL, for example "
            "https://github.com/owner/repo."
        )

    owner, repo = path_parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _valid_github_name(owner) or not _valid_github_name(repo):
        raise CICDScannerError(
            "Invalid GitHub URL. Owner and repository names may contain letters, "
            "numbers, dots, underscores, and hyphens."
        )
    if not repo:
        raise CICDScannerError("Invalid GitHub URL. Repository name is missing.")

    return GitHubRepo(owner=owner, repo=repo)


def _iter_workflow_files(repo_path: Path) -> list[Path]:
    workflows_dir = repo_path / ".github" / "workflows"
    if not workflows_dir.exists() or not workflows_dir.is_dir():
        return []

    workflow_files = [
        file_path
        for file_path in workflows_dir.iterdir()
        if file_path.is_file() and file_path.suffix.lower() in WORKFLOW_EXTENSIONS
    ]
    return sorted(workflow_files, key=lambda path: path.name.lower())


def _file_is_too_large(file_path: Path, max_size: int) -> bool:
    try:
        return file_path.stat().st_size > max_size
    except OSError:
        return True


def _valid_github_name(value: str) -> bool:
    return bool(value and re.fullmatch(r"[A-Za-z0-9_.-]+", value))


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


def _is_comment_or_blank(line: str) -> bool:
    stripped_line = line.strip()
    return not stripped_line or stripped_line.startswith("#")


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_comment(line: str) -> str:
    in_single_quote = False
    in_double_quote = False

    for index, character in enumerate(line):
        if character == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
        elif character == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
        elif character == "#" and not in_single_quote and not in_double_quote:
            return line[:index]

    return line


def _line_mentions_pull_request_target(line: str) -> bool:
    return bool(re.search(r"\bpull_request_target\b", _strip_comment(line)))


def _contains_risky_deploy_word(value: str) -> bool:
    normalized = _clean_name_value(value).lower()
    return any(word in normalized for word in RISKY_DEPLOY_WORDS)


def _clean_name_value(value: str) -> str:
    cleaned = _strip_comment(value).strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        return cleaned[1:-1]
    return cleaned


def _is_github_expression(value: str) -> bool:
    return value.startswith("${{") or "secrets." in value.lower() or "github." in value.lower()


def _is_safe_secret_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").lower()
    return normalized in {"example", "placeholder", "changeme", "change-me", "todo", "none", "null", "dummy"}


def _is_workflow_keyword_assignment(name: str, value: str) -> bool:
    normalized_name = name.strip().lower()
    normalized_value = value.strip().strip("\"'").lower()
    if normalized_name in BROAD_PERMISSION_KEYS and normalized_value in {"read", "write", "none"}:
        return True
    if normalized_name == "secrets" and normalized_value == "inherit":
        return True
    return False


def _safe_line_preview(line: str) -> str:
    return _strip_comment(line).strip()


def _mask_assignment(line: str, match: re.Match[str]) -> str:
    value = match.group("value")
    prefix = line[match.start("key_quote") : match.start("value")]
    quote = match.group("quote")
    return f"{prefix}{_mask_secret_value(value)}{quote}".strip()


def _mask_secret_value(value: str) -> str:
    cleaned_value = value.strip()
    if cleaned_value in {"|", ">"}:
        return "****"
    if len(cleaned_value) <= 4:
        return "****"
    return f"****{cleaned_value[-3:]}"


def _summarize_broad_permissions(broad_permissions: list[BroadPermission]) -> str:
    unique_configs = sorted({permission.detected_config for permission in broad_permissions})
    return ", ".join(unique_configs[:3]) + (", ..." if len(unique_configs) > 3 else "")


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[object, ...]] = set()
    deduped: list[dict] = []

    for finding in findings:
        key = (
            finding["workflow_file"],
            finding.get("line_number"),
            finding["detected_config"],
            finding["risk_level"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return deduped


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan local or public GitHub repositories for risky GitHub Actions workflow configuration."
    )
    parser.add_argument("repo_source", help="Local repository folder or public GitHub repository URL.")
    parser.add_argument(
        "--show-warnings",
        action="store_true",
        help="Print non-fatal parsing and scanning warnings to stderr.",
    )
    args = parser.parse_args()

    scanner = CICDRiskScanner()
    try:
        findings = scanner.scan(args.repo_source)
    except CICDScannerError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    print(json.dumps(findings, indent=2))

    if args.show_warnings:
        for warning in scanner.warnings:
            print(f"Warning: {warning}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# RepoGuard

RepoGuard is an educational repository security scanner and dashboard. It checks a repository for exposed secrets, vulnerable dependencies, risky CI/CD workflow settings, release hash mismatches, invalid signatures, and repository integrity changes.

The project includes a Python scanning backend, a local web dashboard, and two demo repositories that make the expected scan results easy to present.

## Features

- Secret scanning for common API keys, tokens, passwords, and private key material.
- Dependency risk checks for `package.json` and `requirements.txt` files.
- CI/CD workflow analysis for risky GitHub Actions patterns and overly broad permissions.
- Release verification with SHA-256 hashes, RSA-PSS signatures, manifest validation, and repository integrity checks.
- A local dashboard UI with summary cards, detailed findings, recommendations, and a controlled attack simulation screen.
- Demo repositories for both a secure baseline and an intentionally vulnerable project.

## Project Structure

- `dashboard.py` - Runs all scanner modules, calculates the security score, renders reports, and serves the local API/dashboard.
- `secret_scanner.py` - Detects accidentally committed secrets and masks sensitive evidence.
- `dependency_checker.py` - Finds vulnerable or risky dependency versions in demo package manifests.
- `cicd_scanner.py` - Reviews GitHub Actions workflow files for risky automation patterns.
- `crypto_verifier.py` - Verifies release artifacts with hashing, signatures, manifests, and integrity checks.
- `repo-guard/` - Static frontend for the local RepoGuard dashboard.
- `repoguard-demo/` - Secure and vulnerable repositories used for classroom or presentation demos.
- `vulnerability_db.json` - Small local vulnerability knowledge base used by the dependency checker.

## Requirements

- Python 3.11 or newer
- `cryptography` for RSA signing and verification

Install dependencies:

```powershell
pip install -r requirements.txt
```

Most scanners use only the Python standard library. The `cryptography` package is required for the release signature features.

## Run The Dashboard

From the project root:

```powershell
python dashboard.py --serve
```

Open:

```text
http://127.0.0.1:8765
```

Useful demo inputs:

- `secure-demo-repo`
- `vulnerable-demo-repo`

The dashboard also accepts a local repository folder path or a public GitHub repository URL.

## CLI Examples

Run the full dashboard scan:

```powershell
python dashboard.py repoguard-demo\secure-demo-repo
```

Scan for secrets:

```powershell
python secret_scanner.py repoguard-demo\vulnerable-demo-repo
```

Check dependencies:

```powershell
python dependency_checker.py repoguard-demo\vulnerable-demo-repo
```

Review CI/CD workflows:

```powershell
python cicd_scanner.py repoguard-demo\vulnerable-demo-repo
```

Verify a release artifact:

```powershell
python crypto_verifier.py verify --file repoguard-demo\secure-demo-repo\release\app-v1.0.zip --signature repoguard-demo\secure-demo-repo\release\app-v1.0.zip.sig --public-key repoguard-demo\secure-demo-repo\release\public_key.pem --manifest repoguard-demo\secure-demo-repo\release\manifest.json
```

## Demo Safety Notes

This repository contains intentionally insecure demo files under `repoguard-demo/vulnerable-demo-repo`. All embedded secrets are fake classroom values designed only to exercise the scanner.

Private signing keys should never be committed to a real repository. Demo private key material is excluded from Git tracking with `.gitignore`; the included public keys, manifests, signatures, and release artifacts are enough to run the verification demo.

## Suggested GitHub Description

Educational repository security scanner with a local dashboard for secret detection, dependency risk checks, CI/CD review, and release integrity verification.

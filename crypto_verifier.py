"""RepoGuard Cryptographic Release Verification.

This module verifies release artifacts with two checks:

1. SHA-256 hashing proves integrity by detecting file changes.
2. RSA-PSS digital signatures prove authenticity when the public key is trusted.

In a real system, private keys must never be committed to the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
except ImportError:  # pragma: no cover - depends on the user's environment.
    InvalidSignature = None  # type: ignore[assignment]
    hashes = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]
    padding = None  # type: ignore[assignment]
    rsa = None  # type: ignore[assignment]
    utils = None  # type: ignore[assignment]


ALGORITHM = "RSA-PSS-SHA256"
CHUNK_SIZE = 1024 * 1024
DEFAULT_MANIFEST_NAME = "manifest.json"
PRIVATE_KEY_NAME = "private_key.pem"
PUBLIC_KEY_NAME = "public_key.pem"
SIGNED_PAYLOAD = "manifest-sha256"
TAMPER_MARKER = b"\nRepoGuard tamper simulation bytes.\n"


class CryptoVerifierError(Exception):
    """Base exception for clear CLI and dashboard integration errors."""


class JsonArgumentParser(argparse.ArgumentParser):
    """argparse variant that keeps CLI failures JSON-friendly."""

    def error(self, message: str) -> None:
        _print_json(
            {
                "error": "cli_error",
                "message": message,
            }
        )
        raise SystemExit(2)


def generate_sha256(file_path: str) -> str:
    """Return the SHA-256 hex digest for a file, reading in chunks."""

    path = Path(file_path).expanduser()
    if not path.exists():
        raise CryptoVerifierError(f"Missing release file: {path}")
    if not path.is_file():
        raise CryptoVerifierError(f"Release path is not a file: {path}")

    digest = hashlib.sha256()
    try:
        with path.open("rb") as release_file:
            for chunk in iter(lambda: release_file.read(CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as error:
        raise CryptoVerifierError(f"Unreadable release file: {path} ({error})") from error

    return digest.hexdigest()


def generate_key_pair(output_dir: str) -> dict[str, Any]:
    """Generate RSA private/public keys for demo signing.

    In a real system, private keys must never be committed to the repository.
    """

    _require_cryptography()

    output_path = Path(output_dir).expanduser()
    private_key_path = output_path / PRIVATE_KEY_NAME
    public_key_path = output_path / PUBLIC_KEY_NAME

    try:
        output_path.mkdir(parents=True, exist_ok=True)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        public_key_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    except OSError as error:
        raise CryptoVerifierError(f"Could not write key files in {output_path}: {error}") from error

    return {
        "private_key_file": private_key_path.as_posix(),
        "public_key_file": public_key_path.as_posix(),
        "algorithm": ALGORITHM,
        "message": "RSA key pair generated. Keep private_key.pem secret.",
        "warning": "In a real system, private keys must never be committed to the repository.",
    }


def sign_release(file_path: str, private_key_path: str, output_signature_path: str) -> dict[str, Any]:
    """Sign a release manifest digest and create a manifest.json beside it."""

    _require_cryptography()

    release_path = _require_file(file_path, "release file")
    key_path = _require_file(private_key_path, "private key")
    signature_path = Path(output_signature_path).expanduser()
    manifest_path = release_path.parent / DEFAULT_MANIFEST_NAME

    current_sha256 = generate_sha256(str(release_path))
    private_key = _load_private_key(key_path)
    manifest = _build_release_manifest(release_path, current_sha256, signature_path)
    manifest_sha256 = generate_manifest_sha256(manifest)
    digest_bytes = bytes.fromhex(manifest_sha256)

    try:
        signature = private_key.sign(
            digest_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        signature_path.parent.mkdir(parents=True, exist_ok=True)
        signature_path.write_bytes(signature)
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as error:
        raise CryptoVerifierError(f"Could not write signature or manifest: {error}") from error

    return {
        "file_name": release_path.name,
        "sha256": current_sha256,
        "manifest_sha256": manifest_sha256,
        "signature_file": signature_path.as_posix(),
        "manifest_file": manifest_path.as_posix(),
        "algorithm": ALGORITHM,
        "signed_payload": SIGNED_PAYLOAD,
        "message": "Release manifest signed and manifest.json created.",
    }


def verify_release(
    file_path: str,
    signature_path: str,
    public_key_path: str,
    expected_hash: str | None = None,
    manifest_path: str | None = None,
) -> dict[str, Any]:
    """Verify release integrity and authenticity.

    Returns a deterministic, dashboard-friendly dictionary instead of raising
    for normal verification failures.
    """

    release_path = Path(file_path).expanduser()
    signature_file = Path(signature_path).expanduser()
    public_key_file = Path(public_key_path).expanduser()
    manifest_file = Path(manifest_path).expanduser() if manifest_path else release_path.parent / DEFAULT_MANIFEST_NAME

    file_name = release_path.name or Path(file_path).name
    algorithm = ALGORITHM
    stored_sha256 = expected_hash

    if not _cryptography_available():
        return _verification_result(
            file_name=file_name,
            current_sha256=None,
            stored_sha256=stored_sha256,
            hash_match=False,
            signature_status="Error",
            integrity_status="Failed",
            release_status="BLOCKED",
            algorithm=algorithm,
            message="cryptography dependency is missing. Install it with: pip install cryptography",
        )

    manifest_data: dict[str, Any] | None = None
    manifest_sha256: str | None = None
    signed_payload = "release-sha256"
    if manifest_file.exists():
        try:
            manifest_data = _load_manifest(manifest_file)
            manifest_sha256 = generate_manifest_sha256(manifest_data)
        except CryptoVerifierError as error:
            return _verification_result(
                file_name=file_name,
                current_sha256=_safe_sha256(release_path),
                stored_sha256=stored_sha256,
                hash_match=False,
                signature_status="Error",
                integrity_status="Failed",
                release_status="BLOCKED",
                algorithm=algorithm,
                message=str(error),
            )
        stored_sha256 = expected_hash or _manifest_sha256(manifest_data)
        algorithm = str(manifest_data.get("algorithm") or ALGORITHM)
        signed_payload = str(manifest_data.get("signed_payload") or SIGNED_PAYLOAD)

    current_sha256 = _safe_sha256(release_path)
    if current_sha256 is None:
        return _verification_result(
            file_name=file_name,
            current_sha256=None,
            stored_sha256=stored_sha256,
            hash_match=False,
            signature_status="Error",
            integrity_status="Failed",
            release_status="BLOCKED",
            algorithm=algorithm,
            message=f"Missing or unreadable release file: {release_path}",
        )

    if stored_sha256 is None:
        stored_sha256 = current_sha256

    hash_match = current_sha256 == stored_sha256

    if not signature_file.exists():
        return _verification_result(
            file_name=file_name,
            current_sha256=current_sha256,
            stored_sha256=stored_sha256,
            hash_match=hash_match,
            signature_status="Missing",
            integrity_status="Verified" if hash_match else "Failed",
            release_status="BLOCKED",
            algorithm=algorithm,
            message=f"Missing signature file: {signature_file}",
        )
    if not public_key_file.exists():
        return _verification_result(
            file_name=file_name,
            current_sha256=current_sha256,
            stored_sha256=stored_sha256,
            hash_match=hash_match,
            signature_status="Missing",
            integrity_status="Verified" if hash_match else "Failed",
            release_status="BLOCKED",
            algorithm=algorithm,
            message=f"Missing public key file: {public_key_file}",
        )

    try:
        public_key = _load_public_key(public_key_file)
        signature = signature_file.read_bytes()
        public_key.verify(
            signature,
            bytes.fromhex(manifest_sha256 or current_sha256),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        manifest_signature_valid = True
    except InvalidSignature:
        manifest_signature_valid = False
    except (OSError, ValueError, CryptoVerifierError) as error:
        return _verification_result(
            file_name=file_name,
            current_sha256=current_sha256,
            stored_sha256=stored_sha256,
            hash_match=hash_match,
            signature_status="Error",
            integrity_status="Verified" if hash_match else "Failed",
            release_status="BLOCKED",
            algorithm=algorithm,
            message=f"Signature verification error: {error}",
            manifest_sha256=manifest_sha256,
            signed_payload=signed_payload,
            manifest=manifest_data,
        )

    signature_valid_for_current_release = manifest_signature_valid and hash_match
    signature_status = "Valid" if signature_valid_for_current_release else "Invalid"
    approved = hash_match and signature_valid_for_current_release
    if approved:
        message = "Manifest signature is valid and the signed SHA-256 matches the current release file."
    elif not manifest_signature_valid:
        message = "The manifest signature does not verify with the trusted public key."
    elif not hash_match:
        message = "The manifest signature verifies, but the current release file no longer matches the signed manifest hash."
    else:
        message = "Release signature is invalid."

    return _verification_result(
        file_name=file_name,
        current_sha256=current_sha256,
        stored_sha256=stored_sha256,
        hash_match=hash_match,
        signature_status=signature_status,
        integrity_status="Verified" if hash_match else "Failed",
        release_status="APPROVED" if approved else "BLOCKED",
        algorithm=algorithm,
        message=message,
        manifest_sha256=manifest_sha256,
        signed_payload=signed_payload,
        manifest=manifest_data,
        manifest_signature_status="Valid" if manifest_signature_valid else "Invalid",
        signature_covers_current_release=hash_match,
        manifest_verification_status="Verified" if hash_match else "Hash Mismatch",
    )


def tamper_release_file(file_path: str) -> dict[str, Any]:
    """Modify a release file in a small, deterministic demo-friendly way."""

    release_path = _require_file(file_path, "release file")
    old_sha256 = generate_sha256(str(release_path))

    try:
        if zipfile.is_zipfile(release_path):
            with zipfile.ZipFile(release_path, mode="a", compression=zipfile.ZIP_DEFLATED) as zip_file:
                zip_info = zipfile.ZipInfo("repoguard-tamper-demo.txt")
                zip_info.date_time = (2026, 4, 29, 0, 0, 0)
                zip_info.compress_type = zipfile.ZIP_DEFLATED
                zip_file.writestr(zip_info, "RepoGuard tamper simulation.\n")
            tamper_method = "zip entry added"
        else:
            with release_path.open("ab") as release_file:
                release_file.write(TAMPER_MARKER)
            tamper_method = "demo bytes appended"
    except OSError as error:
        raise CryptoVerifierError(f"Could not tamper release file: {release_path} ({error})") from error
    except zipfile.BadZipFile as error:
        raise CryptoVerifierError(f"Could not tamper zip release file: {release_path} ({error})") from error

    new_sha256 = generate_sha256(str(release_path))
    return {
        "file_name": release_path.name,
        "tampered": True,
        "tamper_method": tamper_method,
        "previous_sha256": old_sha256,
        "current_sha256": new_sha256,
        "hash_match": old_sha256 == new_sha256,
        "message": "Release file modified for tamper simulation. Verification should now be BLOCKED.",
    }


def _cryptography_available() -> bool:
    return all(
        dependency is not None
        for dependency in (InvalidSignature, hashes, serialization, padding, rsa, utils)
    )


def _require_cryptography() -> None:
    if not _cryptography_available():
        raise CryptoVerifierError("cryptography dependency is missing. Install it with: pip install cryptography")


def _require_file(file_path: str, label: str) -> Path:
    path = Path(file_path).expanduser()
    if not path.exists():
        raise CryptoVerifierError(f"Missing {label}: {path}")
    if not path.is_file():
        raise CryptoVerifierError(f"{label.capitalize()} path is not a file: {path}")
    return path


def _load_private_key(private_key_path: Path) -> Any:
    try:
        key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as error:
        raise CryptoVerifierError(f"Invalid private key format: {private_key_path} ({error})") from error

    if not hasattr(key, "sign"):
        raise CryptoVerifierError(f"Invalid private key format: {private_key_path}")
    return key


def _load_public_key(public_key_path: Path) -> Any:
    try:
        key = serialization.load_pem_public_key(public_key_path.read_bytes())
    except (OSError, ValueError, TypeError) as error:
        raise CryptoVerifierError(f"Invalid public key format: {public_key_path} ({error})") from error

    if not hasattr(key, "verify"):
        raise CryptoVerifierError(f"Invalid public key format: {public_key_path}")
    return key


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    try:
        raw_manifest = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(raw_manifest)
    except OSError as error:
        raise CryptoVerifierError(f"Unreadable manifest.json: {manifest_path} ({error})") from error
    except json.JSONDecodeError as error:
        raise CryptoVerifierError(f"Malformed manifest.json: {manifest_path} ({error.msg})") from error

    if not isinstance(manifest, dict):
        raise CryptoVerifierError(f"Malformed manifest.json: {manifest_path} (expected a JSON object)")
    return manifest


def _manifest_sha256(manifest: dict[str, Any]) -> str | None:
    value = manifest.get("sha256") or manifest.get("stored_sha256")
    return str(value) if value is not None else None


def generate_manifest_sha256(manifest: dict[str, Any]) -> str:
    """Return the SHA-256 digest for the canonical signed manifest payload."""

    return hashlib.sha256(_canonical_manifest_bytes(manifest)).hexdigest()


def _canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _build_release_manifest(release_path: Path, current_sha256: str, signature_path: Path) -> dict[str, Any]:
    timestamp = _utc_now()
    return {
        "file_name": release_path.name,
        "file": release_path.name,
        "version": _infer_release_version(release_path.name),
        "sha256": current_sha256,
        "timestamp": timestamp,
        "created_at": timestamp,
        "verification_status": "APPROVED",
        "signature_file": signature_path.name,
        "public_key_file": PUBLIC_KEY_NAME,
        "algorithm": ALGORITHM,
        "signed_payload": SIGNED_PAYLOAD,
    }


def _infer_release_version(file_name: str) -> str:
    stem = Path(file_name).stem
    marker = "-v"
    if marker in stem:
        version = stem.rsplit(marker, 1)[-1]
        if version:
            return version if version.count(".") >= 2 else f"{version}.0"
    return "1.0.0"


def _safe_sha256(release_path: Path) -> str | None:
    try:
        return generate_sha256(str(release_path))
    except CryptoVerifierError:
        return None


def _verification_result(
    *,
    file_name: str,
    current_sha256: str | None,
    stored_sha256: str | None,
    hash_match: bool,
    signature_status: str,
    integrity_status: str,
    release_status: str,
    algorithm: str,
    message: str,
    **extra: Any,
) -> dict[str, Any]:
    result = {
        "file_name": file_name,
        "current_sha256": current_sha256,
        "stored_sha256": stored_sha256,
        "hash_match": hash_match,
        "signature_status": signature_status,
        "integrity_status": integrity_status,
        "release_status": release_status,
        "algorithm": algorithm,
        "message": message,
    }
    result.update(extra)
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=False))


def main() -> int:
    parser = JsonArgumentParser(
        description="Verify RepoGuard release artifacts with SHA-256 and RSA-PSS signatures."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=JsonArgumentParser)

    keys_parser = subparsers.add_parser("generate-keys", help="Generate RSA signing keys.")
    keys_parser.add_argument("--out", required=True, help="Output directory for private_key.pem and public_key.pem.")

    sign_parser = subparsers.add_parser("sign", help="Sign a release artifact and write manifest.json.")
    sign_parser.add_argument("--file", required=True, help="Release artifact to sign.")
    sign_parser.add_argument("--private-key", required=True, help="RSA private key PEM file.")
    sign_parser.add_argument("--out", required=True, help="Output signature file, for example app-v1.0.zip.sig.")

    verify_parser = subparsers.add_parser("verify", help="Verify a release artifact.")
    verify_parser.add_argument("--file", required=True, help="Release artifact to verify.")
    verify_parser.add_argument("--signature", required=True, help="Signature file to verify.")
    verify_parser.add_argument("--public-key", required=True, help="RSA public key PEM file.")
    verify_parser.add_argument("--manifest", help="manifest.json containing the stored SHA-256 hash.")
    verify_parser.add_argument("--expected-hash", help="Expected SHA-256 hash if no manifest is available.")

    tamper_parser = subparsers.add_parser("tamper", help="Tamper with a release artifact for demo purposes.")
    tamper_parser.add_argument("--file", required=True, help="Release artifact to modify.")

    args = parser.parse_args()

    try:
        if args.command == "generate-keys":
            _print_json(generate_key_pair(args.out))
        elif args.command == "sign":
            _print_json(sign_release(args.file, args.private_key, args.out))
        elif args.command == "verify":
            result = verify_release(
                args.file,
                args.signature,
                args.public_key,
                expected_hash=args.expected_hash,
                manifest_path=args.manifest,
            )
            _print_json(result)
            return 0 if result["release_status"] == "APPROVED" else 1
        elif args.command == "tamper":
            _print_json(tamper_release_file(args.file))
        else:
            _print_json(
                {
                    "error": "unsupported_command",
                    "message": f"Unsupported command: {args.command}",
                }
            )
            return 2
    except CryptoVerifierError as error:
        _print_json(
            {
                "error": "crypto_verifier_error",
                "message": str(error),
            }
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

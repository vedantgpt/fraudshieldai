import os
import hashlib
import zipfile
from datetime import datetime
from typing import Dict, Optional

try:
    from androguard.core.bytecodes.apk import APK
except Exception:
    APK = None


class APKIngestionEngine:
    """Validate, hash, and extract metadata from an APK."""

    def __init__(self, upload_dir: str):
        self.upload_dir = upload_dir
        os.makedirs(upload_dir, exist_ok=True)

    def ingest(self, apk_path: str) -> Dict:
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")
        if not zipfile.is_zipfile(apk_path):
            raise ValueError(f"File is not a valid APK: {apk_path}")

        sha256 = self.sha256_file(apk_path)
        size = os.path.getsize(apk_path)
        metadata = {
            "file_path": apk_path,
            "file_name": os.path.basename(apk_path),
            "sha256": sha256,
            "file_size": size,
            "ingested_at": datetime.utcnow().isoformat(),
        }

        if APK is not None:
            try:
                apk = APK(apk_path)
                metadata.update({
                    "package_name": apk.get_package() or "",
                    "version_name": apk.get_androidversion_name() or "",
                    "version_code": apk.get_androidversion_code() or "",
                    "min_sdk": apk.get_min_sdk_version() or "",
                    "target_sdk": apk.get_target_sdk_version() or "",
                    "permissions": apk.get_permissions() or [],
                    "activities": apk.get_activities() or [],
                    "services": apk.get_services() or [],
                    "receivers": apk.get_receivers() or [],
                    "providers": apk.get_providers() or [],
                    "certificate": self._cert_summary(apk),
                    "signature": apk.get_signature_name() or "",
                })
            except Exception as exc:
                metadata["androguard_error"] = str(exc)

        return metadata

    @staticmethod
    def sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _cert_summary(self, apk) -> Optional[str]:
        try:
            cert = apk.get_certificate(apk.get_signature_name() or "META-INF/CERT.RSA")
            if cert:
                return {
                    "issuer": cert.issuer.human_friendly if hasattr(cert.issuer, "human_friendly") else str(cert.issuer),
                    "subject": cert.subject.human_friendly if hasattr(cert.subject, "human_friendly") else str(cert.subject),
                    "sha256_fingerprint": cert.sha256_fingerprint.replace(" ", ""),
                    "not_before": cert["not_before"].isoformat() if "not_before" in cert else "",
                    "not_after": cert["not_after"].isoformat() if "not_after" in cert else "",
                }
        except Exception:
            pass
        return None

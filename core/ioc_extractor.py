import os
import re
from typing import List, Dict


class IOCExtractor:
    """Extract indicators of compromise from APK source and manifest."""

    PATTERNS = {
        "domain": re.compile(
            r"(?:https?://|//)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{1,5})?",
            re.IGNORECASE,
        ),
        "url": re.compile(
            r"https?://[\w\-._~:/?#[\]@!$&'()*+,;=.%]+",
            re.IGNORECASE,
        ),
        "ip": re.compile(
            r"(?<![\d.])\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b(?!\d*[\.])"
        ),
        "email": re.compile(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            re.IGNORECASE,
        ),
    }

    FALSE_POSITIVE_DOMAINS = {
        "schemas.android.com", "android.com", "google.com", "gstatic.com",
        "googleapis.com", "firebaseio.com", "github.com", "stackoverflow.com",
        "apache.org", "jetbrains.com", "kotlinlang.org", "java.com", "oracle.com",
        "slf4j.org", "json.org", "w3.org", "xml.org",
    }

    FALSE_POSITIVE_IPS = {
        "0.0.0.0", "127.0.0.1", "255.255.255.255", "192.168.0.1", "192.168.1.1",
        "10.0.0.1", "172.16.0.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    }

    FALSE_POSITIVE_URLS = {
        "http://schemas.android.com/apk/res/android",
        "http://schemas.android.com/apk/res-auto",
        "https://schemas.android.com/apk/res/android",
        "https://schemas.android.com/apk/res-auto",
        "https://www.w3.org/2000/svg",
        "http://www.w3.org/2000/svg",
        "https://play.google.com/store",
        "http://play.google.com/store",
        "https://www.google.com",
        "http://www.google.com",
        "https://firebase.google.com",
        "https://developer.android.com",
    }

    COMMON_TLDS = {
        "com", "org", "net", "io", "app", "dev", "co", "ai", "me", "info", "biz",
        "top", "xyz", "pw", "cc", "link", "click", "download", "online", "site",
        "club", "work",
    }

    COUNTRY_CODE_TLDS = {
        "us", "uk", "eu", "in", "cn", "ru", "tk", "ml", "cf", "ga", "cm", "pt",
        "br", "de", "fr", "es", "it", "jp", "kr", "nl", "pl", "tr",
    }

    NON_DOMAIN_KEYWORDS = (
        "permission", "intent", "action", "category", "service", "provider",
        "receiver", "activity", "broadcast", "launcher", "granturipermissions",
        "notification", "messaging", "firebase", "default", "components",
        "modules", "webview", "fileprovider", "contentprovider", "sdk",
        "cct", "vnd",
    )

    NON_DOMAIN_PREFIXES = (
        "android.", "androidx.", "com.android.", "com.google.android.",
        "java.", "javax.", "kotlin.", "org.jetbrains.", "com.facebook.react.",
    )

    def extract(self, source_path: str) -> Dict[str, List[str]]:
        raw_text = self._read_text(source_path)
        iocs = {key: [] for key in self.PATTERNS}
        iocs["hash"] = []
        iocs["apk_signature"] = []

        seen = {key: set() for key in self.PATTERNS}
        for ptype, compiled in self.PATTERNS.items():
            for match in compiled.finditer(raw_text):
                val = match.group(0)
                if ptype == "domain":
                    if not self._is_valid_domain(val):
                        continue
                if ptype == "url" and val.lower() in self.FALSE_POSITIVE_URLS:
                    continue
                if ptype == "ip" and (val in self.FALSE_POSITIVE_IPS or self._looks_like_version(val)):
                    continue
                if val not in seen[ptype]:
                    seen[ptype].add(val)
                    iocs[ptype].append(val)

        # SHA256 hashes in code (40/64 hex)
        hashes = set(re.findall(r"\b[a-fA-F0-9]{64}\b", raw_text))
        iocs["hash"] = sorted(hashes)

        return iocs

    @staticmethod
    def _looks_like_version(ip: str) -> bool:
        """Reject IP matches that are actually version strings (e.g., 9.17.3.0)."""
        if not ip:
            return True
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return True
        if any(n > 255 for n in nums):
            return True
        # Common version pattern: first octet <= 9 and last octet == 0 (e.g., 9.17.3.0)
        if nums[0] <= 9 and nums[-1] == 0:
            return True
        # All octets are single digit (very common in version strings)
        if all(n <= 9 for n in nums):
            return True
        return False

    def _is_valid_domain(self, val: str) -> bool:
        """Reject domain matches that are actually Android identifiers or reversed package names."""
        val = val.strip()
        if not val:
            return False
        val_lower = val.lower()
        if any(fp in val_lower for fp in self.FALSE_POSITIVE_DOMAINS):
            return False
        if any(k in val_lower for k in self.NON_DOMAIN_KEYWORDS):
            return False
        if any(val_lower.startswith(p) for p in self.NON_DOMAIN_PREFIXES):
            return False
        segments = val.split(".")
        if not segments:
            return False
        # Reversed package names often start with a common TLD (e.g., com.thewalleyapp)
        if segments[0].lower() in self.COMMON_TLDS and len(segments) < 3:
            return False
        # Reversed package names often use a country-code TLD as the first segment (e.g., cm.aptoide.pt)
        if (
            segments[0].lower() in self.COUNTRY_CODE_TLDS
            and segments[-1].lower() in (self.COMMON_TLDS | self.COUNTRY_CODE_TLDS)
        ):
            return False
        # Reject any package-name-like segment (PascalCase, camelCase, underscores)
        for seg in segments:
            if "_" in seg:
                return False
            if seg.isupper() and len(seg) > 1:
                return False
            # PascalCase / camelCase segments are typical of Java class names, not real domains
            if seg and seg[0].isupper() and not seg.isupper() and not seg.islower():
                return False
        return True

    def extract_from_apk(self, apk_path: str) -> Dict[str, List[str]]:
        """Extract IOCs from an APK file by reading all text entries."""
        import zipfile
        raw_text = []
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for info in zf.infolist():
                    if info.filename.endswith((".java", ".kt", ".xml", ".smali", ".txt", ".json", ".dex")):
                        try:
                            raw_text.append(zf.read(info.filename).decode("utf-8", errors="ignore"))
                        except Exception:
                            continue
        except Exception:
            pass
        return self.extract_from_text("\n".join(raw_text))

    def extract_from_text(self, text: str) -> Dict[str, List[str]]:
        iocs = {key: [] for key in self.PATTERNS}
        iocs["hash"] = []
        iocs["apk_signature"] = []
        seen = {key: set() for key in self.PATTERNS}
        for ptype, compiled in self.PATTERNS.items():
            for match in compiled.finditer(text):
                val = match.group(0)
                if ptype == "domain" and not self._is_valid_domain(val):
                    continue
                if ptype == "url" and val.lower() in self.FALSE_POSITIVE_URLS:
                    continue
                if ptype == "ip" and (val in self.FALSE_POSITIVE_IPS or self._looks_like_version(val)):
                    continue
                if val not in seen[ptype]:
                    seen[ptype].add(val)
                    iocs[ptype].append(val)
        hashes = set(re.findall(r"\b[a-fA-F0-9]{64}\b", text))
        iocs["hash"] = sorted(hashes)
        return iocs

    def _read_text(self, source_path: str) -> str:
        parts = []
        for root, _, files in os.walk(source_path):
            for fname in files:
                if not fname.endswith((".java", ".kt", ".xml", ".smali", ".txt", ".json")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        parts.append(f.read())
                except Exception:
                    continue
        return "\n".join(parts)

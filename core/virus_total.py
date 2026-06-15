import time
from typing import Dict, List, Optional
import requests
import base64

from config import ENABLE_VIRUSTOTAL, VIRUSTOTAL_API_KEY


class VirusTotalClient:
    """Lookup APK hashes, URLs, IPs, and domains against VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or VIRUSTOTAL_API_KEY
        self.enabled = ENABLE_VIRUSTOTAL and bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def _get(self, endpoint: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        try:
            r = requests.get(f"{self.BASE_URL}{endpoint}", headers=self._headers(), timeout=20)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                time.sleep(1)
            return {"error": f"HTTP {r.status_code}", "data": None}
        except Exception as exc:
            return {"error": str(exc), "data": None}

    def lookup_file(self, sha256: str) -> Optional[Dict]:
        result = self._get(f"/files/{sha256}")
        if not result or "error" in result:
            return result
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "type": "file",
            "value": sha256,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attrs.get("reputation", 0),
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    def lookup_url(self, url: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        result = self._get(f"/urls/{url_id}")
        if not result or result.get("error"):
            # Try to submit/analyze if not found
            try:
                r = requests.post(f"{self.BASE_URL}/urls", headers=self._headers(), data={"url": url}, timeout=20)
                if r.status_code in (200, 201):
                    result = r.json()
            except Exception:
                pass
        if not result or "error" in result:
            return result
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "type": "url",
            "value": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "link": f"https://www.virustotal.com/gui/url/{url_id}",
        }

    def lookup_domain(self, domain: str) -> Optional[Dict]:
        result = self._get(f"/domains/{domain}")
        if not result or "error" in result:
            return result
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "type": "domain",
            "value": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "link": f"https://www.virustotal.com/gui/domain/{domain}",
        }

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        result = self._get(f"/ip_addresses/{ip}")
        if not result or "error" in result:
            return result
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "type": "ip",
            "value": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "link": f"https://www.virustotal.com/gui/ip-address/{ip}",
        }

    def enrich_iocs(self, sha256: str, iocs: Dict) -> Dict:
        """Enrich all IOCs with VirusTotal results."""
        if not self.enabled:
            return {"enabled": False, "results": []}
        results = []
        file_result = self.lookup_file(sha256)
        if file_result:
            results.append(file_result)
        for url in (iocs.get("urls") or [])[:5]:
            r = self.lookup_url(url)
            if r:
                results.append(r)
        for domain in (iocs.get("domains") or [])[:5]:
            r = self.lookup_domain(domain)
            if r:
                results.append(r)
        for ip in (iocs.get("ips") or [])[:5]:
            r = self.lookup_ip(ip)
            if r:
                results.append(r)
        return {"enabled": True, "results": results}

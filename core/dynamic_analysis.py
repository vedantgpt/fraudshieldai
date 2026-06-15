import os
import time
import subprocess
from typing import Dict, List, Optional
from datetime import datetime
import requests

from config import (
    ENABLE_DYNAMIC_ANALYSIS,
    DYNAMIC_ANALYSIS_TIMEOUT,
    MOBSF_URL,
    MOBSF_API_KEY,
    ADB_PATH,
    EMULATOR_NAME,
    FRIDA_SERVER_PATH,
)


class DynamicAnalysisSandbox:
    """
    Dynamic analysis sandbox for Android APKs.

    Supports (in order of preference):
      1. MobSF dynamic analysis API
      2. ADB + Frida on a running emulator/device
      3. Simulated/behavioral sandbox fallback based on static indicators

    The fallback ensures the pipeline always produces behavioral findings even
    when no emulator or sandbox is available.
    """

    def __init__(self):
        self.mobsf_url = MOBSF_URL.rstrip("/")
        self.mobsf_api_key = MOBSF_API_KEY
        self.adb_path = ADB_PATH
        self.emulator_name = EMULATOR_NAME
        self.frida_server_path = FRIDA_SERVER_PATH
        self.timeout = DYNAMIC_ANALYSIS_TIMEOUT

    # ------------------------------------------------------------------
    # Capability detection
    # ------------------------------------------------------------------

    def _mobsf_available(self) -> bool:
        if not self.mobsf_api_key:
            return False
        try:
            r = requests.get(f"{self.mobsf_url}/api/v1/projects", headers={"Authorization": self.mobsf_api_key}, timeout=5)
            return r.status_code in (200, 401)
        except Exception:
            return False

    def _adb_available(self) -> bool:
        try:
            result = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, timeout=10)
            return "device" in result.stdout
        except Exception:
            return False

    def _frida_available(self) -> bool:
        try:
            import frida
            _ = frida.get_device_manager()
            return True
        except Exception:
            return False

    def capabilities(self) -> Dict[str, bool]:
        return {
            "mobsf": self._mobsf_available(),
            "adb": self._adb_available(),
            "frida": self._frida_available(),
            "mock_fallback": True,
        }

    # ------------------------------------------------------------------
    # Public runner
    # ------------------------------------------------------------------

    def run(self, apk_path: str, package_name: Optional[str] = None, static_analysis: Optional[Dict] = None) -> Dict:
        if not ENABLE_DYNAMIC_ANALYSIS:
            result = self._run_mock(apk_path, package_name, static_analysis, reason="ENABLE_DYNAMIC_ANALYSIS=false")
            return self._enrich_result(result)

        caps = self.capabilities()
        if caps["mobsf"]:
            result = self._run_mobsf(apk_path, package_name)
            if result:
                return self._enrich_result(result)
        if caps["adb"] and caps["frida"]:
            result = self._run_frida_adb(apk_path, package_name)
            if result:
                return self._enrich_result(result)
        if caps["adb"]:
            result = self._run_adb_only(apk_path, package_name)
            if result:
                return self._enrich_result(result)

        result = self._run_mock(apk_path, package_name, static_analysis, reason="No live sandbox tools available")
        return self._enrich_result(result)

    def _enrich_result(self, result: Dict) -> Dict:
        result["behavioral_indicators"] = self.behavioral_indicators(result)
        result["dynamic_score"] = self.dynamic_score(result)
        return result

    # ------------------------------------------------------------------
    # MobSF integration
    # ------------------------------------------------------------------

    def _run_mobsf(self, apk_path: str, package_name: Optional[str]) -> Optional[Dict]:
        try:
            headers = {"Authorization": self.mobsf_api_key}

            # Upload
            with open(apk_path, "rb") as f:
                files = {"file": (os.path.basename(apk_path), f, "application/octet-stream")}
                r = requests.post(f"{self.mobsf_url}/api/v1/upload", files=files, headers=headers, timeout=60)
            if r.status_code != 200:
                return None
            upload_data = r.json()
            hash_val = upload_data.get("hash")
            if not hash_val:
                return None

            # Start dynamic analysis
            r = requests.post(
                f"{self.mobsf_url}/api/v1/dynamic/start_analysis",
                data={"hash": hash_val},
                headers=headers,
                timeout=60,
            )
            if r.status_code != 200:
                return None

            time.sleep(self.timeout)

            # Get dynamic report
            r = requests.post(
                f"{self.mobsf_url}/api/v1/dynamic/report_json",
                data={"hash": hash_val},
                headers=headers,
                timeout=60,
            )
            if r.status_code != 200:
                return None
            report = r.json()

            return self._normalize_mobsf_report(report, package_name or hash_val)
        except Exception as exc:
            return {"sandbox": "mobsf", "is_simulated": False, "error": str(exc), "findings": []}

    def _normalize_mobsf_report(self, report: Dict, package_name: str) -> Dict:
        findings = []
        dyn = report.get("dynamic_analysis", {})

        for entry in dyn.get("network", []):
            findings.append({
                "type": "network_request",
                "severity": "HIGH",
                "description": "[REAL] Network request observed during dynamic analysis",
                "evidence": entry,
            })
        for entry in dyn.get("domain", []):
            findings.append({
                "type": "dns_query",
                "severity": "MEDIUM",
                "description": "[REAL] DNS query observed during dynamic analysis",
                "evidence": entry,
            })
        for entry in dyn.get("accessibility", []):
            findings.append({
                "type": "accessibility_event",
                "severity": "CRITICAL",
                "description": "[REAL] Accessibility event observed",
                "evidence": entry,
            })
        for entry in dyn.get("clipboard", []):
            findings.append({
                "type": "clipboard_access",
                "severity": "MEDIUM",
                "description": "[REAL] Clipboard access observed",
                "evidence": entry,
            })

        return {
            "sandbox": "mobsf",
            "is_simulated": False,
            "package_name": package_name,
            "findings": findings,
            "raw_report": report,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # ------------------------------------------------------------------
    # ADB + Frida integration
    # ------------------------------------------------------------------

    def _run_frida_adb(self, apk_path: str, package_name: Optional[str]) -> Optional[Dict]:
        if not package_name:
            return None
        try:
            self._adb_shell(["install", "-r", apk_path])
            self._adb_shell(["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"])

            frida_script = """
            Java.perform(function() {
                var targets = ['android.telephony.SmsManager', 'android.content.ClipboardManager', 'android.view.accessibility.AccessibilityNodeInfo', 'java.net.URL', 'android.app.Dialog'];
                targets.forEach(function(cls) {
                    try {
                        var clazz = Java.use(cls);
                        var methods = clazz.class.getDeclaredMethods();
                        methods.forEach(function(m) {
                            var overloads = clazz[m.getName()].overloads;
                            overloads.forEach(function(ovl) {
                                ovl.implementation = function() {
                                    send({type: 'hook', class: cls, method: m.getName(), args: Array.prototype.slice.call(arguments)});
                                    return ovl.apply(this, arguments);
                                };
                            });
                        });
                    } catch(e) {}
                });
            });
            """
            import frida
            device = frida.get_usb_device()
            pid = device.spawn([package_name])
            session = device.attach(pid)
            script = session.create_script(frida_script)
            events = []
            script.on("message", lambda msg, data: events.append(msg.get("payload", {})))
            script.load()
            device.resume(pid)
            time.sleep(self.timeout)
            session.detach()
            return self._normalize_frida_events(events, package_name)
        except Exception as exc:
            return {"sandbox": "frida_adb", "is_simulated": False, "error": str(exc), "findings": []}

    def _normalize_frida_events(self, events: List[Dict], package_name: str) -> Dict:
        findings = []
        for ev in events:
            etype = ev.get("type", "unknown")
            cls = ev.get("class", "")
            method = ev.get("method", "")
            findings.append({
                "type": etype,
                "class": cls,
                "method": method,
                "severity": "HIGH",
                "description": f"Hooked {cls}.{method} at runtime",
                "evidence": ev,
            })
        return {
            "sandbox": "frida_adb",
            "is_simulated": False,
            "package_name": package_name,
            "findings": findings,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _run_adb_only(self, apk_path: str, package_name: Optional[str]) -> Optional[Dict]:
        if not package_name:
            return None
        try:
            self._adb_shell(["install", "-r", apk_path])
            self._adb_shell(["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"])
            time.sleep(self.timeout)

            logcat = self._adb_shell(["logcat", "-d", "-s", "AndroidRuntime:D", f"{package_name}:D"])
            findings = []
            if logcat:
                findings.append({
                    "type": "logcat",
                    "severity": "INFO",
                    "description": "Logcat output collected during dynamic run",
                    "evidence": logcat[:2000],
                })

            return {
                "sandbox": "adb_only",
                "is_simulated": False,
                "package_name": package_name,
                "findings": findings,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as exc:
            return {"sandbox": "adb_only", "is_simulated": False, "error": str(exc), "findings": []}

    def _adb_shell(self, args: List[str]) -> str:
        cmd = [self.adb_path] + args
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout + result.stderr

    def _basic_apk_info(self, apk_path: str):
        """Return (permissions, services) from an APK using androguard."""
        try:
            from androguard.core.bytecodes.apk import APK
            apk = APK(apk_path)
            return set(apk.get_permissions() or []), apk.get_services() or []
        except Exception:
            return set(), []

    # ------------------------------------------------------------------
    # Simulated fallback sandbox
    # ------------------------------------------------------------------

    def _run_mock(self, apk_path: str, package_name: Optional[str], static_analysis: Optional[Dict], reason: str) -> Dict:
        findings = []
        if static_analysis:
            iocs = static_analysis.get("iocs", {})
            fraud = static_analysis.get("fraud_findings", [])
            perms = set(static_analysis.get("manifest", {}).get("permissions", []))
            fraud_ids = {f["id"] for f in fraud}
            services = static_analysis.get("manifest", {}).get("services", [])
        else:
            iocs = {}
            fraud = []
            fraud_ids = set()
            perms, services = self._basic_apk_info(apk_path)

        # Extract IOCs from source if static_analysis not provided
        if not iocs:
            from core.ioc_extractor import IOCExtractor
            iocs = IOCExtractor().extract_from_apk(apk_path)

        # Network / C2 behavior inferred from hardcoded URLs/IPs
        for url in iocs.get("urls", [])[:5]:
            findings.append({
                "type": "network_request",
                "severity": "HIGH",
                "description": "[SIMULATED] APK made HTTP request to hardcoded URL at runtime",
                "evidence": url,
            })
        for domain in iocs.get("domains", [])[:5]:
            findings.append({
                "type": "dns_query",
                "severity": "MEDIUM",
                "description": "[SIMULATED] DNS query observed for hardcoded domain",
                "evidence": domain,
            })
        for ip in iocs.get("ips", [])[:5]:
            findings.append({
                "type": "network_request",
                "severity": "HIGH",
                "description": "[SIMULATED] Direct IP connection attempt observed",
                "evidence": ip,
            })

        # SMS
        if "android.permission.READ_SMS" in perms or "android.permission.RECEIVE_SMS" in perms or "FRAUD_SMS_READ" in fraud_ids:
            findings.append({
                "type": "sms_activity",
                "severity": "CRITICAL",
                "description": "[SIMULATED] SMS/OTP interception activity observed",
                "evidence": "READ_SMS / RECEIVE_SMS permission or SMS interception code",
            })

        # Clipboard
        if "FRAUD_CLIPBOARD" in fraud_ids:
            findings.append({
                "type": "clipboard_access",
                "severity": "MEDIUM",
                "description": "[SIMULATED] Clipboard read/write observed",
                "evidence": "ClipboardManager usage in code",
            })

        # Accessibility
        if "FRAUD_ACCESSIBILITY" in fraud_ids or "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
            findings.append({
                "type": "accessibility_event",
                "severity": "CRITICAL",
                "description": "[SIMULATED] Accessibility service abused to read UI or perform clicks",
                "evidence": "BIND_ACCESSIBILITY_SERVICE or AccessibilityService code",
            })

        # Overlay
        if "FRAUD_SCREEN_OVERLAY" in fraud_ids or "android.permission.SYSTEM_ALERT_WINDOW" in perms:
            findings.append({
                "type": "screen_overlay",
                "severity": "CRITICAL",
                "description": "[SIMULATED] Screen overlay drawn over other apps",
                "evidence": "SYSTEM_ALERT_WINDOW or TYPE_APPLICATION_OVERLAY usage",
            })

        # Background services
        if services:
            findings.append({
                "type": "background_service",
                "severity": "MEDIUM",
                "description": "[SIMULATED] Background services started and ran persistently",
                "evidence": f"Services: {', '.join(services[:5])}",
            })

        # File operations
        if any(p in perms for p in ["android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"]):
            findings.append({
                "type": "file_creation",
                "severity": "MEDIUM",
                "description": "[SIMULATED] Files created on external storage",
                "evidence": "External storage permissions present",
            })

        return {
            "sandbox": "mock",
            "is_simulated": True,
            "reason": reason,
            "package_name": package_name or os.path.basename(apk_path),
            "findings": findings,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def dynamic_score(self, dynamic_results: Dict) -> int:
        """Return a 0-40 dynamic contribution to the risk score."""
        findings = dynamic_results.get("findings", [])
        if not findings:
            return 0
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        return min(40, critical * 10 + high * 6 + medium * 3)

    def behavioral_indicators(self, dynamic_results: Dict) -> List[str]:
        indicators = []
        for f in dynamic_results.get("findings", []):
            t = f.get("type", "")
            if t == "network_request":
                indicators.append("Network communication observed")
            elif t == "dns_query":
                indicators.append("DNS resolution observed")
            elif t == "sms_activity":
                indicators.append("SMS activity observed")
            elif t == "clipboard_access":
                indicators.append("Clipboard access observed")
            elif t == "accessibility_event":
                indicators.append("Accessibility abuse observed")
            elif t == "screen_overlay":
                indicators.append("Screen overlay observed")
            elif t == "background_service":
                indicators.append("Persistent background service")
            elif t == "file_creation":
                indicators.append("File creation observed")
        return list(set(indicators))

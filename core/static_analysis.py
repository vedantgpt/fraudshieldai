import os
import re
from typing import List, Dict
from static_tools.code_scanner import CodeScanner
from static_tools.scan_android_manifest import ScanAndroidManifest
from static_tools.sensitive_info_extractor import SensitiveInfoExtractor


class FraudStaticAnalysisEngine:
    """Run static analysis tuned for fraudulent/banking malware."""

    FRAUD_PATTERNS = [
        {
            "id": "FRAUD_SMS_READ",
            "title": "SMS / OTP Interception Capability",
            "severity": "CRITICAL",
            "mitre": "T1412",
            "description": "Code reads or processes SMS messages, which may be used to steal OTPs.",
            "pattern": r"(SmsMessage|createFromPdu|getDisplayMessageBody|READ_SMS|RECEIVE_SMS|onReceive.*sms)",
        },
        {
            "id": "FRAUD_ACCESSIBILITY",
            "title": "Accessibility Service Abuse",
            "severity": "CRITICAL",
            "mitre": "T1516",
            "description": "AccessibilityService can be abused to overlay clicks, read screen content, and bypass MFA.",
            "pattern": r"(AccessibilityService|onAccessibilityEvent|performAction|ACTION_CLICK|getRootInActiveWindow)",
        },
        {
            "id": "FRAUD_SCREEN_OVERLAY",
            "title": "Screen Overlay / Window Abuse",
            "severity": "CRITICAL",
            "mitre": "T1516",
            "description": "TYPE_APPLICATION_OVERLAY or system_alert_window usage enables fake banking app overlays.",
            "pattern": r"(TYPE_APPLICATION_OVERLAY|SYSTEM_ALERT_WINDOW|addView.*WindowManager|FLAG_NOT_FOCUSABLE|FLAG_NOT_TOUCH_MODAL)",
        },
        {
            "id": "FRAUD_BANK_IMPERSONATION",
            "title": "Banking Brand Impersonation",
            "severity": "HIGH",
            "mitre": "T1659",
            "description": "Source contains strings mimicking well-known banking or payment applications.",
            "pattern": r"(?i)\b(sbi|hdfc|icici|axis|kotak|paytm|phonepe|gpay|googlepay|bankofamerica|chase|wellsfargo|citibank|paypal|venmo|zelle|netbanking|netbank)\b",
        },
        {
            "id": "FRAUD_C2_NETWORK",
            "title": "Command & Control Network Communication",
            "severity": "HIGH",
            "mitre": "T1071",
            "description": "Raw sockets, hardcoded HTTP to IP, or shell-style downloaders suggest remote command capability.",
            "pattern": r"(?i)(ServerSocket\s*\(|Socket\s*\(.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|https?://[^/\s]*(?:\.top|\.xyz|\.tk|\.ml|\.cf|\.gq|\.pw|\.cc|\.ru|\.cn|\.apk|\.download|\.click|\.link)|\bcurl\b|\bwget\b|/bin/sh|cmd\.exe|powershell|\.exec\s*\()",
        },
        {
            "id": "FRAUD_CREDENTIAL_CAPTURE",
            "title": "Credential / Input Capture",
            "severity": "CRITICAL",
            "mitre": "T1417",
            "description": "Code explicitly captures passwords, PINs, or login credentials from input fields.",
            "pattern": r"(?i)(getText\(\).*pass|getText\(\).*pin|password.*getText|pin.*getText|login.*password|credential.*getText|harvest.*pass|steal.*pass|OnKeyListener.*pass|OnKeyListener.*pin)",
        },
        {
            "id": "FRAUD_DEVICE_ADMIN",
            "title": "Device Admin / Privilege Abuse",
            "severity": "HIGH",
            "mitre": "T1401",
            "description": "DeviceAdminReceiver or lock-task usage can enforce persistence and prevent uninstall.",
            "pattern": r"(DeviceAdminReceiver|DevicePolicyManager|lockNow|wipeData|setLockTaskPackages)",
        },
        {
            "id": "FRAUD_ROOT_EMULATOR_CHECK",
            "title": "Root / Emulator Detection",
            "severity": "MEDIUM",
            "mitre": "T1518",
            "description": "Code checks for root or emulator via specific evasion APIs or file paths.",
            "pattern": r"(?i)(\bisRooted\b|\bcheckRoot\b|\btest-keys\b|\bsuperuser\b|\bbusybox\b|\bqemu\b|\bgenymotion\b|\bisEmulator\b|/system/bin/su|/su/bin/su|/system/xbin/su|Build\.HARDWARE.*(goldfish|ranchu|generic)|Build\.FINGERPRINT.*(generic|test-keys))",
        },
        {
            "id": "FRAUD_CLIPBOARD",
            "title": "Clipboard Access",
            "severity": "MEDIUM",
            "mitre": "T1414",
            "description": "Clipboard access can capture OTPs or copied credentials.",
            "pattern": r"(ClipboardManager|getPrimaryClip|setPrimaryClip|OnPrimaryClipChangedListener)",
        },
        {
            "id": "FRAUD_CONTACTS_CALL_LOG",
            "title": "Contacts / Call Log Harvesting",
            "severity": "HIGH",
            "mitre": "T1433",
            "description": "Reads contacts or call logs for social engineering or targeting.",
            "pattern": r"(READ_CONTACTS|READ_CALL_LOG|ContactsContract|CallLog\.C)",
        },
    ]

    DANGEROUS_PERMISSION_WEIGHTS = {
        "android.permission.READ_SMS": 15,
        "android.permission.SEND_SMS": 20,
        "android.permission.RECEIVE_SMS": 15,
        "android.permission.BIND_ACCESSIBILITY_SERVICE": 30,
        "android.permission.SYSTEM_ALERT_WINDOW": 30,
        "android.permission.READ_PHONE_STATE": 10,
        "android.permission.RECORD_AUDIO": 10,
        "android.permission.READ_CONTACTS": 10,
        "android.permission.READ_CALL_LOG": 10,
        "android.permission.CAMERA": 5,
        "android.permission.ACCESS_FINE_LOCATION": 10,
        "android.permission.INTERNET": 0,
    }

    def __init__(self, source_path: str, apk_path: str = None):
        self.source_path = source_path
        self.apk_path = apk_path
        self.code_scanner = CodeScanner(source_path)
        self.manifest_scanner = ScanAndroidManifest()
        self.sensitive_extractor = SensitiveInfoExtractor()
        self._compiled_fraud = []
        for check in self.FRAUD_PATTERNS:
            try:
                self._compiled_fraud.append((check, re.compile(check["pattern"], re.IGNORECASE)))
            except re.error as exc:
                print(f"[-] Bad fraud pattern {check['id']}: {exc}")

    def analyze(self, extracted_source_path: str) -> Dict:
        # Run existing code scanner
        code_findings = self.code_scanner.scan_all()

        # Run manifest analysis
        manifest_results = self.manifest_scanner.extract_manifest_info(extracted_source_path)

        # Run fraud-specific code patterns
        fraud_findings = self._scan_fraud_patterns()

        # Extract IOCs and secrets from source
        file_paths = self.sensitive_extractor.get_all_file_paths(extracted_source_path)
        secrets = self.sensitive_extractor.extract_all_sensitive_info(file_paths, extracted_source_path)
        insecure = self.sensitive_extractor.extract_insecure_request_protocol(file_paths)

        return {
            "code_findings": code_findings,
            "fraud_findings": fraud_findings,
            "manifest": manifest_results,
            "hardcoded_secrets": secrets,
            "insecure_requests": insecure,
            "permission_weights": self._permission_weights(manifest_results.get("permissions", [])),
        }

    def _scan_fraud_patterns(self) -> List[Dict]:
        findings = []
        seen = set()
        for root, _, files in os.walk(self.source_path):
            for fname in files:
                if not fname.endswith((".java", ".kt", ".xml")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, 1):
                            for chk, compiled in self._compiled_fraud:
                                if compiled.search(line):
                                    key = (chk["id"], fpath, line_no)
                                    if key in seen:
                                        continue
                                    seen.add(key)
                                    rel = os.path.relpath(fpath, self.source_path)
                                    findings.append({
                                        "id": chk["id"],
                                        "title": chk["title"],
                                        "severity": chk["severity"],
                                        "mitre": chk["mitre"],
                                        "description": chk["description"],
                                        "file": rel,
                                        "line": line_no,
                                        "evidence": line.strip()[:200],
                                    })
                except Exception:
                    continue
        return findings

    def _permission_weights(self, permissions: List[str]) -> Dict[str, int]:
        weights = {}
        for perm in permissions:
            if perm in self.DANGEROUS_PERMISSION_WEIGHTS:
                weights[perm] = self.DANGEROUS_PERMISSION_WEIGHTS[perm]
        return weights

    def summarize_fraud_indicators(self, analysis: Dict) -> List[str]:
        indicators = []
        if analysis.get("permission_weights"):
            high = [p for p, w in analysis["permission_weights"].items() if w >= 20]
            if high:
                indicators.append(f"High-value permissions: {', '.join(high)}")
        ids = {f["id"] for f in analysis.get("fraud_findings", [])}
        if "FRAUD_SMS_READ" in ids or "FRAUD_SMS_READ" in {f["id"] for f in analysis.get("code_findings", [])}:
            indicators.append("OTP/SMS interception capability detected")
        if "FRAUD_ACCESSIBILITY" in ids:
            indicators.append("Accessibility abuse capable of MFA bypass")
        if "FRAUD_SCREEN_OVERLAY" in ids:
            indicators.append("Screen overlay capable of UI hijacking")
        if "FRAUD_BANK_IMPERSONATION" in ids:
            indicators.append("Banking brand impersonation strings found")
        if "FRAUD_C2_NETWORK" in ids:
            indicators.append("Network C2 behavior present")
        if "FRAUD_CREDENTIAL_CAPTURE" in ids:
            indicators.append("Credential capture behavior present")
        return indicators

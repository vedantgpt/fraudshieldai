from typing import List, Dict


MITRE_TECHNIQUES = {
    "T1412": {
        "technique": "Capture SMS Messages",
        "tactic": "Collection",
        "description": "Malware intercepts SMS/OTP messages to hijack accounts or MFA flows.",
    },
    "T1516": {
        "technique": "Accessibility Features",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Abuses Android accessibility services to read screen content, perform actions, and bypass MFA.",
    },
    "T1659": {
        "technique": "Impersonate Legitimate Account",
        "tactic": "Initial Access",
        "description": "Pretends to be a legitimate banking or payment application to trick users.",
    },
    "T1071": {
        "technique": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Uses HTTP/HTTPS or sockets to communicate with a remote command server.",
    },
    "T1417": {
        "technique": "Input Capture",
        "tactic": "Collection",
        "description": "Captures keystrokes, text input, or WebView form data to harvest credentials.",
    },
    "T1401": {
        "technique": "Device Administrator Abuse",
        "tactic": "Persistence",
        "description": "Uses device admin APIs to maintain persistence or lock the device.",
    },
    "T1518": {
        "technique": "Software Discovery",
        "tactic": "Discovery",
        "description": "Detects root, emulators, or security tools to evade analysis.",
    },
    "T1414": {
        "technique": "Clipboard Data",
        "tactic": "Collection",
        "description": "Reads or writes clipboard data to steal copied credentials or OTPs.",
    },
    "T1433": {
        "technique": "Access Call Logs / Contact List",
        "tactic": "Collection",
        "description": "Harvests contacts or call logs for targeting or social engineering.",
    },
    "T1533": {
        "technique": "Data from Local System",
        "tactic": "Collection",
        "description": "Reads local files, databases, or shared preferences for sensitive data.",
    },
    "T1575": {
        "technique": "Native API",
        "tactic": "Execution",
        "description": "Uses Android APIs for malicious execution or data access.",
    },
    "T1406": {
        "technique": "Obfuscated Code",
        "tactic": "Defense Evasion",
        "description": "Uses obfuscation, reflection, or dynamic loading to hide behavior.",
    },
    "T1628": {
        "technique": "Hide Artifacts",
        "tactic": "Defense Evasion",
        "description": "Attempts to hide code, network traffic, or malicious artifacts.",
    },
}

ID_TO_TECHNIQUE = {
    "FRAUD_SMS_READ": "T1412",
    "FRAUD_ACCESSIBILITY": "T1516",
    "FRAUD_SCREEN_OVERLAY": "T1516",
    "FRAUD_BANK_IMPERSONATION": "T1659",
    "FRAUD_C2_NETWORK": "T1071",
    "FRAUD_CREDENTIAL_CAPTURE": "T1417",
    "FRAUD_DEVICE_ADMIN": "T1401",
    "FRAUD_ROOT_EMULATOR_CHECK": "T1518",
    "FRAUD_CLIPBOARD": "T1414",
    "FRAUD_CONTACTS_CALL_LOG": "T1433",
    "DYN_DEXCLASSLOADER": "T1406",
    "DYN_REFLECTION": "T1406",
    "DYN_RUNTIME_EXEC": "T1575",
    "DYN_PROCESS_BUILDER": "T1575",
    "STORAGE_SHARED_PREFS": "T1533",
    "STORAGE_CLIPBOARD": "T1414",
    "STORAGE_WORLD_READ": "T1533",
    "STORAGE_WORLD_WRITE": "T1533",
    "SSL_TRUST_ALL_CERTS": "T1628",
    "SSL_HOSTNAME_ALL": "T1628",
    "SSL_WEAK_TRUSTMANAGER": "T1628",
    "WEBVIEW_JS_INTERFACE": "T1417",
    "WEBVIEW_SSL_IGNORE": "T1628",
    "MANIFEST_EXPORTED_NO_PERM": "T1659",
    "MANIFEST_DEBUGGABLE": "T1628",
    "MANIFEST_ALLOW_BACKUP": "T1533",
    "MANIFEST_GRANT_URI": "T1533",
}


class MITREMappingEngine:
    """Map static findings to MITRE ATT&CK for Mobile techniques."""

    def map(self, fraud_findings: List[Dict], code_findings: List[Dict] = None) -> List[Dict]:
        mapped = []
        seen = set()
        all_findings = list(fraud_findings or [])
        if code_findings:
            all_findings += code_findings

        for finding in all_findings:
            tid = ID_TO_TECHNIQUE.get(finding.get("id"))
            if not tid:
                continue
            key = (tid, finding.get("id"))
            if key in seen:
                continue
            seen.add(key)
            technique = MITRE_TECHNIQUES.get(tid, {})
            mapped.append({
                "technique_id": tid,
                "technique": technique.get("technique", "Unknown"),
                "tactic": technique.get("tactic", "Unknown"),
                "description": technique.get("description", ""),
                "evidence": finding.get("evidence", ""),
                "finding_id": finding.get("id"),
                "finding_title": finding.get("title"),
            })

        return mapped

    def tactics_summary(self, mappings: List[Dict]) -> Dict[str, List[str]]:
        summary = {}
        for m in mappings:
            tactic = m.get("tactic", "Unknown")
            summary.setdefault(tactic, []).append(m["technique_id"])
        return {k: sorted(set(v)) for k, v in summary.items()}

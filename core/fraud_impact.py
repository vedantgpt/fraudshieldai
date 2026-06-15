from typing import List, Dict


class BankingFraudImpactEngine:
    """Assess banking fraud impact from static analysis results."""

    def assess(self, analysis: Dict) -> Dict:
        fraud_ids = {f["id"] for f in analysis.get("fraud_findings", [])}
        permissions = set(analysis.get("manifest", {}).get("permissions", []))
        secrets = analysis.get("hardcoded_secrets", [])
        iocs = analysis.get("iocs", {})

        can_steal_otp = (
            "FRAUD_SMS_READ" in fraud_ids
            or "android.permission.READ_SMS" in permissions
            or "android.permission.RECEIVE_SMS" in permissions
        )
        can_capture_credentials = (
            "FRAUD_CREDENTIAL_CAPTURE" in fraud_ids
            or "FRAUD_ACCESSIBILITY" in fraud_ids
            or "WEBVIEW_JS_INTERFACE" in {f["id"] for f in analysis.get("code_findings", [])}
        )
        can_bypass_mfa = "FRAUD_ACCESSIBILITY" in fraud_ids or "FRAUD_SCREEN_OVERLAY" in fraud_ids
        can_overlay_banking = "FRAUD_SCREEN_OVERLAY" in fraud_ids or "android.permission.SYSTEM_ALERT_WINDOW" in permissions
        can_perform_transactions = (
            can_capture_credentials and can_steal_otp
        )
        can_impersonate_bank = "FRAUD_BANK_IMPERSONATION" in fraud_ids

        affected_assets = []
        if can_steal_otp:
            affected_assets.append("SMS/OTP channel")
        if can_capture_credentials:
            affected_assets.append("User credentials")
        if can_bypass_mfa:
            affected_assets.append("MFA/2FA flows")
        if can_overlay_banking:
            affected_assets.append("Banking app UI")
        if can_impersonate_bank:
            affected_assets.append("Bank brand reputation")

        narrative = self._build_narrative(
            can_steal_otp, can_capture_credentials, can_bypass_mfa,
            can_overlay_banking, can_perform_transactions, can_impersonate_bank
        )

        business_impact = self._business_impact(
            can_steal_otp, can_capture_credentials, can_bypass_mfa,
            can_overlay_banking, can_perform_transactions
        )

        return {
            "can_steal_otp": can_steal_otp,
            "can_capture_credentials": can_capture_credentials,
            "can_bypass_mfa": can_bypass_mfa,
            "can_overlay_banking_apps": can_overlay_banking,
            "can_perform_transactions": can_perform_transactions,
            "can_impersonate_bank": can_impersonate_bank,
            "fraud_risk_narrative": narrative,
            "business_impact": business_impact,
            "affected_assets": affected_assets,
            "fraud_indicators": self._indicators(fraud_ids, iocs, secrets),
        }

    def _build_narrative(self, otp, cred, mfa, overlay, txn, impersonate) -> str:
        parts = []
        if impersonate:
            parts.append("The APK impersonates a banking or payment brand to trick users into installing it.")
        if cred:
            parts.append("It contains code capable of capturing login credentials or input fields.")
        if otp:
            parts.append("It can intercept SMS messages, including one-time passwords (OTPs).")
        if mfa:
            parts.append("Accessibility abuse or overlay techniques may allow it to bypass MFA prompts.")
        if overlay:
            parts.append("Screen overlay capability enables UI hijacking over legitimate banking applications.")
        if txn:
            parts.append("Combined credential and OTP capture could allow unauthorized financial transactions.")
        if not parts:
            return "No clear banking fraud indicators were detected in this sample."
        return " ".join(parts)

    def _business_impact(self, otp, cred, mfa, overlay, txn) -> str:
        if txn:
            return "Critical: direct financial loss, account takeover, and unauthorized transactions are possible."
        if mfa or overlay:
            return "High: MFA bypass or UI hijacking puts customer accounts and funds at significant risk."
        if cred and otp:
            return "High: credential plus OTP capture enables account takeover."
        if cred or otp:
            return "Medium: partial account compromise capability exists."
        return "Low: no direct banking fraud capability identified."

    def _indicators(self, fraud_ids: set, iocs: Dict, secrets: List) -> List[str]:
        indicators = []
        if "FRAUD_SMS_READ" in fraud_ids:
            indicators.append("OTP/SMS interception code")
        if "FRAUD_ACCESSIBILITY" in fraud_ids:
            indicators.append("Accessibility service abuse")
        if "FRAUD_SCREEN_OVERLAY" in fraud_ids:
            indicators.append("Screen overlay / UI hijacking")
        if "FRAUD_BANK_IMPERSONATION" in fraud_ids:
            indicators.append("Banking brand impersonation")
        if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
            indicators.append("Hardcoded network IOCs")
        if secrets:
            indicators.append("Hardcoded secrets or keys")
        return indicators

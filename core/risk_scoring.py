from typing import Dict, List


class RiskScoringEngine:
    """Compute a 0-100 fraud risk score from static/dynamic/AI inputs."""

    WEIGHTS = {
        "READ_SMS": 15,
        "SEND_SMS": 20,
        "RECEIVE_SMS": 15,
        "BIND_ACCESSIBILITY_SERVICE": 30,
        "SYSTEM_ALERT_WINDOW": 30,
        "C2_NETWORK": 25,
        "CREDENTIAL_CAPTURE": 30,
        "OVERLAY_ATTACK": 30,
        "BANK_IMPERSONATION": 25,
        "DEVICE_ADMIN": 20,
        "ROOT_EMULATOR_CHECK": 10,
        "HARDCODED_SECRET": 10,
        "HARDCODED_C2": 15,
        "INSECURE_HTTP": 15,
    }

    def calculate(self, analysis: Dict, fraud_impact: Dict, ai_confidence: float = 0.0) -> Dict:
        static_score = 0

        perm_weights = analysis.get("permission_weights", {})
        for perm, weight in perm_weights.items():
            short = perm.replace("android.permission.", "")
            if short in self.WEIGHTS:
                static_score += self.WEIGHTS[short]

        fraud_ids = {f["id"] for f in analysis.get("fraud_findings", [])}
        if "FRAUD_C2_NETWORK" in fraud_ids:
            static_score += self.WEIGHTS["C2_NETWORK"]
        if "FRAUD_CREDENTIAL_CAPTURE" in fraud_ids:
            static_score += self.WEIGHTS["CREDENTIAL_CAPTURE"]
        if "FRAUD_SCREEN_OVERLAY" in fraud_ids:
            static_score += self.WEIGHTS["OVERLAY_ATTACK"]
        if "FRAUD_BANK_IMPERSONATION" in fraud_ids:
            static_score += self.WEIGHTS["BANK_IMPERSONATION"]
        if "FRAUD_DEVICE_ADMIN" in fraud_ids:
            static_score += self.WEIGHTS["DEVICE_ADMIN"]
        if "FRAUD_ROOT_EMULATOR_CHECK" in fraud_ids:
            static_score += self.WEIGHTS["ROOT_EMULATOR_CHECK"]

        if analysis.get("hardcoded_secrets"):
            static_score += min(len(analysis["hardcoded_secrets"]) * 5, self.WEIGHTS["HARDCODED_SECRET"])
        if analysis.get("insecure_requests"):
            static_score += min(len(analysis["insecure_requests"]) * 3, self.WEIGHTS["INSECURE_HTTP"])

        iocs = analysis.get("iocs", {})
        if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
            static_score += self.WEIGHTS["HARDCODED_C2"]

        # Dynamic score placeholder (0 in MVP unless enabled)
        dynamic_score = analysis.get("dynamic_score", 0)

        # Fraud score from impact engine
        fraud_score = 0
        if fraud_impact.get("can_perform_transactions"):
            fraud_score = 40
        elif fraud_impact.get("can_bypass_mfa") or fraud_impact.get("can_overlay_banking_apps"):
            fraud_score = 35
        elif fraud_impact.get("can_steal_otp") and fraud_impact.get("can_capture_credentials"):
            fraud_score = 30
        elif fraud_impact.get("can_steal_otp") or fraud_impact.get("can_capture_credentials"):
            fraud_score = 20
        elif fraud_impact.get("can_impersonate_bank"):
            fraud_score = 15

        ai_score = int(ai_confidence * 20)  # up to 20 points

        total = min(100, static_score + dynamic_score + fraud_score + ai_score)
        category = self.category(total)

        return {
            "score": total,
            "category": category,
            "static_score": static_score,
            "dynamic_score": dynamic_score,
            "fraud_score": fraud_score,
            "ai_confidence": ai_score,
            "components": {
                "static": static_score,
                "dynamic": dynamic_score,
                "fraud": fraud_score,
                "ai": ai_score,
            },
        }

    @staticmethod
    def category(score: int) -> str:
        if score < 20:
            return "Safe"
        if score < 50:
            return "Suspicious"
        if score < 80:
            return "High Risk"
        return "Critical"

    def risk_factors(self, analysis: Dict, fraud_impact: Dict) -> List[str]:
        factors = []
        if fraud_impact.get("can_steal_otp"):
            factors.append("OTP/SMS interception")
        if fraud_impact.get("can_capture_credentials"):
            factors.append("Credential capture")
        if fraud_impact.get("can_bypass_mfa"):
            factors.append("MFA bypass capability")
        if fraud_impact.get("can_overlay_banking_apps"):
            factors.append("Banking app overlay")
        if fraud_impact.get("can_perform_transactions"):
            factors.append("Transaction fraud potential")
        if fraud_impact.get("can_impersonate_bank"):
            factors.append("Bank impersonation")
        if analysis.get("iocs", {}).get("urls") or analysis.get("iocs", {}).get("domains"):
            factors.append("Hardcoded C2 endpoints")
        if analysis.get("hardcoded_secrets"):
            factors.append("Hardcoded secrets/keys")
        dynamic = analysis.get("dynamic_analysis", {})
        for indicator in dynamic.get("behavioral_indicators", []):
            factors.append(f"Dynamic: {indicator}")
        return factors

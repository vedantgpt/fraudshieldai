import os
import re
from typing import Dict, Optional


class AIReverseEngineeringAnalyst:
    """Use Gemini to explain APK behavior, threat, and banking impact."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.client = None
        self.model = None
        self._init_client()

    def _init_client(self):
        if not self.api_key:
            return
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self.client = genai
            self.model = genai.GenerativeModel("gemini-1.5-flash")
        except Exception as exc:
            print(f"[-] Gemini init failed: {exc}")
            self.client = None
            self.model = None

    def summarize(self, source_path: str, manifest: Dict, analysis: Dict, iocs: Dict) -> Dict:
        if not self.model:
            return self._fallback_summary(manifest, analysis, iocs)

        prompt = self._build_prompt(manifest, analysis, iocs)
        try:
            response = self.model.generate_content(prompt)
            text = response.text or ""
            return self._parse_response(text)
        except Exception as exc:
            print(f"[-] Gemini inference failed: {exc}")
            return self._fallback_summary(manifest, analysis, iocs)

    def _build_prompt(self, manifest: Dict, analysis: Dict, iocs: Dict) -> str:
        fraud = [f"- {f['id']}: {f['title']}" for f in analysis.get("fraud_findings", [])[:10]]
        perms = analysis.get("manifest", {}).get("permissions", [])[:20]
        urls = iocs.get("urls", [])[:10]
        prompt = f"""You are an expert Android malware analyst assisting a bank fraud team.
Analyze the following APK static analysis results and produce a concise investigation summary.

Package: {manifest.get('package_name', 'unknown')}
Permissions: {', '.join(perms)}

Fraud indicators:
{chr(10).join(fraud) if fraud else 'None'}

Hardcoded URLs/IPs:
{', '.join(urls) if urls else 'None'}

Respond ONLY in this format:
Functionality: <one sentence describing what the app does>
Threat: <one sentence describing the malicious threat>
Intent: <one sentence describing the attacker intent>
BankingImpact: <one sentence describing the banking fraud impact>
Confidence: <float 0.0-1.0>
"""
        return prompt

    def _parse_response(self, text: str) -> Dict:
        result = {
            "functionality": "",
            "threat": "",
            "intent": "",
            "banking_impact": "",
            "confidence": 0.0,
            "raw": text,
        }
        for line in text.splitlines():
            if line.lower().startswith("functionality:"):
                result["functionality"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("threat:"):
                result["threat"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("intent:"):
                result["intent"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("bankingimpact:"):
                result["banking_impact"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("confidence:"):
                try:
                    result["confidence"] = float(re.findall(r"[0-9.]+", line)[0])
                except Exception:
                    result["confidence"] = 0.5
        return result

    def _fallback_summary(self, manifest: Dict, analysis: Dict, iocs: Dict) -> Dict:
        fraud = analysis.get("fraud_findings", [])
        has_otp = any(f["id"] == "FRAUD_SMS_READ" for f in fraud)
        has_acc = any(f["id"] == "FRAUD_ACCESSIBILITY" for f in fraud)
        has_overlay = any(f["id"] == "FRAUD_SCREEN_OVERLAY" for f in fraud)
        has_bank = any(f["id"] == "FRAUD_BANK_IMPERSONATION" for f in fraud)
        has_c2 = any(f["id"] == "FRAUD_C2_NETWORK" for f in fraud)

        parts = [f"Package {manifest.get('package_name', 'unknown')} analyzed."]
        if has_bank:
            parts.append("It appears to impersonate a banking or payment brand.")
        if has_otp:
            parts.append("It can intercept SMS messages, likely to steal OTPs.")
        if has_acc:
            parts.append("Accessibility service abuse may enable MFA bypass or automated clicks.")
        if has_overlay:
            parts.append("Screen overlay capability could be used to hijack banking app UI.")
        if has_c2:
            parts.append("Hardcoded network indicators suggest remote command-and-control.")
        if not any([has_otp, has_acc, has_overlay, has_bank, has_c2]):
            parts.append("No strong fraud indicators were detected; treat as suspicious or low-risk.")

        summary = " ".join(parts)
        return {
            "functionality": summary,
            "threat": summary,
            "intent": "Defraud bank customers or hijack financial accounts.",
            "banking_impact": "Potential account takeover, unauthorized transactions, and MFA bypass.",
            "confidence": 0.5,
            "raw": "",
            "fallback": True,
        }

    def chat(self, question: str, context: str) -> str:
        if not self.model:
            return f"[AI offline] {question}\n\nBased on available context: {context[:500]}..."
        prompt = f"""Context: {context}\n\nUser question: {question}\n
Answer briefly as a malware analyst. If the answer is not in the context, say so."""
        try:
            response = self.model.generate_content(prompt)
            return response.text or ""
        except Exception as exc:
            return f"[AI error: {exc}]"

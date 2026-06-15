import os
import json
import html as html_module
from datetime import datetime
from typing import Dict
from xhtml2pdf import pisa


class AIInvestigationReportGenerator:
    """Generate executive PDF/HTML/JSON investigation reports."""

    def __init__(self, reports_dir: str):
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)

    def generate(self, investigation: Dict, fmt: str = "pdf") -> str:
        if fmt == "json":
            return self._generate_json(investigation)
        if fmt == "html":
            return self._generate_html(investigation)
        if fmt == "pdf":
            return self._generate_pdf(investigation)
        raise ValueError(f"Unsupported report format: {fmt}")

    def _safe(self, text) -> str:
        return html_module.escape(str(text)) if text is not None else ""

    def _generate_json(self, investigation: Dict) -> str:
        apk_name = investigation["metadata"]["file_name"]
        out_path = os.path.join(self.reports_dir, f"{apk_name}_investigation.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(investigation, f, indent=2, default=str)
        return out_path

    def _generate_html(self, investigation: Dict) -> str:
        apk_name = investigation["metadata"]["file_name"]
        out_path = os.path.join(self.reports_dir, f"{apk_name}_investigation.html")
        html = self._render_html(investigation)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
        return out_path

    def _generate_pdf(self, investigation: Dict) -> str:
        apk_name = investigation["metadata"]["file_name"]
        html_path = self._generate_html(investigation)
        pdf_path = os.path.join(self.reports_dir, f"{apk_name}_investigation.pdf")
        with open(html_path, "r", encoding="utf-8") as f:
            source_html = f.read()
        with open(pdf_path, "w+b") as result_file:
            pisa.CreatePDF(source_html, dest=result_file)
        return pdf_path

    def _render_html(self, inv: Dict) -> str:
        meta = inv.get("metadata", {})
        risk = inv.get("risk_score", {})
        classification = inv.get("classification", {})
        ai = inv.get("ai_summary", {})
        fraud = inv.get("fraud_impact", {})
        mitre = inv.get("mitre_mapping", [])
        iocs = inv.get("iocs", {})
        static = inv.get("static_analysis", {})

        risk_color = "green" if risk.get("score", 0) < 50 else "orange" if risk.get("score", 0) < 80 else "red"

        sections = []
        sections.append(f"<h1>FraudShield AI Investigation Report</h1>")
        sections.append(f"<p><strong>APK:</strong> {self._safe(meta.get('file_name'))}</p>")
        sections.append(f"<p><strong>Package:</strong> {self._safe(meta.get('package_name'))}</p>")
        sections.append(f"<p><strong>SHA256:</strong> {self._safe(meta.get('sha256'))}</p>")
        sections.append(f"<p><strong>Generated:</strong> {self._safe(datetime.utcnow().isoformat())}</p>")

        sections.append(f"<h2>Executive Summary</h2>")
        sections.append(f"<p>Risk Score: <span style='color:{risk_color};font-size:24px'><strong>{risk.get('score',0)} / 100 ({risk.get('category','Unknown')})</strong></span></p>")
        sections.append(f"<p>Classification: <strong>{self._safe(classification.get('class'))}</strong> (confidence {classification.get('confidence',0)})</p>")
        sections.append(f"<p>{self._safe(ai.get('banking_impact', ai.get('threat','')))}</p>")

        sections.append("<h2>Technical Findings</h2>")
        sections.append(self._list_html(static.get("fraud_findings", []), "fraud"))

        sections.append("<h2>Behavioral Findings</h2>")
        sections.append(f"<p>{self._safe(ai.get('functionality',''))}</p>")
        sections.append(f"<p><strong>Threat:</strong> {self._safe(ai.get('threat',''))}</p>")
        sections.append(f"<p><strong>Intent:</strong> {self._safe(ai.get('intent',''))}</p>")
        sections.append(self._dynamic_findings_html(inv.get("dynamic_analysis", {})))

        sections.append("<h2>Malware Classification</h2>")
        sections.append(f"<p>Class: {self._safe(classification.get('class'))}</p>")
        sections.append(f"<p>Confidence: {classification.get('confidence',0)}</p>")
        sections.append(self._simple_list_html(classification.get('evidence', [])))

        sections.append("<h2>MITRE ATT&CK Mapping</h2>")
        sections.append(self._mitre_html(mitre))

        sections.append("<h2>Fraud Impact</h2>")
        sections.append(self._fraud_html(fraud))

        sections.append("<h2>Risk Score Breakdown</h2>")
        sections.append(self._risk_html(risk))

        sections.append("<h2>Indicators of Compromise</h2>")
        sections.append(self._iocs_html(iocs))

        sections.append("<h2>VirusTotal Enrichment</h2>")
        sections.append(self._virustotal_html(inv.get("virus_total", {})))

        sections.append("<h2>Recommendations</h2>")
        sections.append(self._recommendations_html(fraud, risk))

        style = """
        <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1, h2 { color: #1a1a1a; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
        code { background: #f5f5f5; padding: 2px 4px; }
        </style>
        """
        return f"<!DOCTYPE html><html><head>{style}</head><body>{''.join(sections)}</body></html>"

    def _list_html(self, findings, label):
        if not findings:
            return "<p>No findings.</p>"
        rows = []
        for f in findings[:50]:
            rows.append(
                f"<tr><td>{self._safe(f.get('severity'))}</td><td>{self._safe(f.get('id'))}</td>"
                f"<td>{self._safe(f.get('title'))}</td><td><code>{self._safe(f.get('file'))}:{f.get('line','')}</code></td>"
                f"<td><code>{self._safe(f.get('evidence',''))}</code></td></tr>"
            )
        return (
            '<table><thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Location</th><th>Evidence</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table>"
        )

    def _simple_list_html(self, items):
        if not items:
            return "<p>None</p>"
        return "<ul>" + "".join(f"<li>{self._safe(item)}</li>" for item in items) + "</ul>"

    def _mitre_html(self, mappings):
        if not mappings:
            return "<p>No MITRE mappings.</p>"
        rows = []
        for m in mappings:
            rows.append(
                f"<tr><td>{self._safe(m.get('technique_id'))}</td><td>{self._safe(m.get('technique'))}</td>"
                f"<td>{self._safe(m.get('tactic'))}</td><td>{self._safe(m.get('description'))}</td></tr>"
            )
        return (
            '<table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Description</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table>"
        )

    def _fraud_html(self, fraud):
        items = [
            f"<li>Can steal OTP: {fraud.get('can_steal_otp', False)}</li>",
            f"<li>Can capture credentials: {fraud.get('can_capture_credentials', False)}</li>",
            f"<li>Can bypass MFA: {fraud.get('can_bypass_mfa', False)}</li>",
            f"<li>Can overlay banking apps: {fraud.get('can_overlay_banking_apps', False)}</li>",
            f"<li>Can perform transactions: {fraud.get('can_perform_transactions', False)}</li>",
            f"<li>Can impersonate bank: {fraud.get('can_impersonate_bank', False)}</li>",
        ]
        return "<ul>" + "".join(items) + "</ul>" + f"<p><strong>Narrative:</strong> {self._safe(fraud.get('fraud_risk_narrative'))}</p>"

    def _risk_html(self, risk):
        comp = risk.get("components", {})
        return (
            f"<ul>"
            f"<li>Static: {comp.get('static',0)}</li>"
            f"<li>Dynamic: {comp.get('dynamic',0)}</li>"
            f"<li>Fraud: {comp.get('fraud',0)}</li>"
            f"<li>AI confidence: {comp.get('ai',0)}</li>"
            f"</ul>"
        )

    def _virustotal_html(self, vt: Dict) -> str:
        if not vt.get("enabled"):
            return "<p>VirusTotal enrichment is disabled. Set ENABLE_VIRUSTOTAL=true and VIRUSTOTAL_API_KEY to enable.</p>"
        results = vt.get("results", [])
        if not results:
            return "<p>No VirusTotal results available.</p>"
        rows = []
        for r in results:
            rows.append(
                f"<tr><td>{self._safe(r.get('type'))}</td><td>{self._safe(r.get('value'))}</td>"
                f"<td>{r.get('malicious',0)}</td><td>{r.get('suspicious',0)}</td>"
                f"<td>{r.get('undetected',0)}</td><td>{r.get('harmless',0)}</td>"
                f"<td><a href='{self._safe(r.get('link',''))}'>VT link</a></td></tr>"
            )
        return (
            '<table><thead><tr><th>Type</th><th>Value</th><th>Malicious</th><th>Suspicious</th>'
            '<th>Undetected</th><th>Harmless</th><th>Link</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table>"
        )

    def _iocs_html(self, iocs):
        html = []
        for key in ["urls", "domains", "ips", "emails", "hash"]:
            vals = iocs.get(key, [])
            html.append(f"<h3>{key.upper()}</h3>")
            html.append(self._simple_list_html(vals[:20]))
        return "".join(html)

    def _dynamic_findings_html(self, dynamic_analysis: Dict) -> str:
        findings = dynamic_analysis.get("findings", [])
        if not findings:
            return "<p>No dynamic behavioral findings recorded.</p>"
        simulated = dynamic_analysis.get("is_simulated", True)
        warning = ""
        if simulated:
            warning = "<p><strong>Warning:</strong> No live Android emulator, MobSF, or ADB device was available. The findings below are simulated from static indicators and should be verified with a real sandbox.</p>"
        rows = []
        for f in findings:
            rows.append(
                f"<tr><td>{self._safe(f.get('type'))}</td><td>{self._safe(f.get('severity'))}</td>"
                f"<td>{self._safe(f.get('description'))}</td><td><code>{self._safe(f.get('evidence',''))}</code></td></tr>"
            )
        return (
            warning
            + '<h3>Dynamic Sandbox Findings</h3><table><thead><tr><th>Type</th><th>Severity</th><th>Description</th><th>Evidence</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table>"
        )

    def _recommendations_html(self, fraud, risk):
        recs = []
        if fraud.get("can_perform_transactions"):
            recs.append("Block the APK immediately and revoke any associated customer credentials/OTP sessions.")
        if fraud.get("can_bypass_mfa") or fraud.get("can_overlay_banking_apps"):
            recs.append("Alert fraud teams to MFA bypass and overlay attack patterns; enforce device integrity checks.")
        if fraud.get("can_steal_otp"):
            recs.append("Review SMS-based OTP controls and consider push/number-matching MFA.")
        if fraud.get("can_impersonate_bank"):
            recs.append("Issue customer advisory about the impersonated brand and phishing vectors.")
        if risk.get("score", 0) >= 50:
            recs.append("Add extracted IOCs to firewalls, DNS blacklists, and SIEM watchlists.")
        if not recs:
            recs.append("Continue monitoring; no immediate action required.")
        return self._simple_list_html(recs)

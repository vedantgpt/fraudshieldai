import os
import shutil
from datetime import datetime
from typing import Dict

from config import BASE_DIR, UPLOAD_DIR, APP_SOURCE_DIR, REPORTS_DIR, VECTOR_DB_DIR, GEMINI_API_KEY, ENABLE_DYNAMIC_ANALYSIS
from core.ingestion import APKIngestionEngine
from core.reverse_engineering import ReverseEngineeringEngine
from core.static_analysis import FraudStaticAnalysisEngine
from core.ioc_extractor import IOCExtractor
from core.mitre_mapper import MITREMappingEngine
from core.fraud_impact import BankingFraudImpactEngine
from core.risk_scoring import RiskScoringEngine
from core.malware_classifier import MalwareClassificationEngine
from core.ai_analyst import AIReverseEngineeringAnalyst
from core.report_generator import AIInvestigationReportGenerator
from core.threat_graph import ThreatGraphVisualizer
from core.dynamic_analysis import DynamicAnalysisSandbox
from core.virus_total import VirusTotalClient
from db.vector_store import VectorStore
from db.models import SessionLocal, APK, StaticFinding, DynamicFinding, IOC as IOCModel, MITREMapping as MITREMappingModel, RiskScore, Report


class AnalysisOrchestrator:
    """End-to-end orchestrator for FraudShield AI investigation."""

    def __init__(self):
        self.ingestion = APKIngestionEngine(UPLOAD_DIR)
        self.reverse_engineering = ReverseEngineeringEngine(BASE_DIR)
        self.ioc_extractor = IOCExtractor()
        self.mitre_mapper = MITREMappingEngine()
        self.fraud_impact = BankingFraudImpactEngine()
        self.risk_scoring = RiskScoringEngine()
        self.classifier = MalwareClassificationEngine()
        self.ai_analyst = AIReverseEngineeringAnalyst(GEMINI_API_KEY)
        self.report_generator = AIInvestigationReportGenerator(REPORTS_DIR)
        self.threat_graph = ThreatGraphVisualizer()
        self.dynamic_sandbox = DynamicAnalysisSandbox()
        self.virus_total = VirusTotalClient()
        self.vector_store = VectorStore(VECTOR_DB_DIR)

    def investigate(self, apk_path: str) -> Dict:
        # 1. Ingestion
        metadata = self.ingestion.ingest(apk_path)
        apk_name = metadata["file_name"]
        source_dir = os.path.join(APP_SOURCE_DIR, apk_name)

        # 2. Reverse engineering
        decompile_result = self.reverse_engineering.decompile(apk_path, source_dir)
        if not decompile_result["success"]:
            metadata["decompile_error"] = decompile_result.get("error", "")

        # 3. Static analysis
        static_engine = FraudStaticAnalysisEngine(source_dir, apk_path=apk_path)
        static_analysis = static_engine.analyze(source_dir)
        static_analysis["iocs"] = self.ioc_extractor.extract(source_dir)

        # 3b. Threat intelligence enrichment (VirusTotal)
        virus_total_enrichment = self.virus_total.enrich_iocs(
            metadata["sha256"], static_analysis["iocs"]
        )

        # 4. Dynamic analysis sandbox
        dynamic_results = self.dynamic_sandbox.run(
            apk_path,
            package_name=static_analysis.get("manifest", {}).get("package_name"),
            static_analysis=static_analysis,
        )
        static_analysis["dynamic_analysis"] = dynamic_results
        static_analysis["dynamic_score"] = self.dynamic_sandbox.dynamic_score(dynamic_results)

        # 5. MITRE mapping
        mitre_mapping = self.mitre_mapper.map(
            static_analysis.get("fraud_findings", []),
            static_analysis.get("code_findings", []),
        )

        # 6. Fraud impact
        fraud_impact = self.fraud_impact.assess(static_analysis)

        # 7. AI reverse engineering summary
        ai_summary = self.ai_analyst.summarize(
            source_dir,
            static_analysis.get("manifest", {}),
            static_analysis,
            static_analysis.get("iocs", {}),
        )

        # 8. Malware classification
        classification = self.classifier.classify(static_analysis, fraud_impact)

        # 9. Risk scoring
        risk_score = self.risk_scoring.calculate(static_analysis, fraud_impact, ai_summary.get("confidence", 0.0))
        risk_score["risk_factors"] = self.risk_scoring.risk_factors(static_analysis, fraud_impact)

        # 10. Build investigation object
        investigation = {
            "metadata": metadata,
            "static_analysis": static_analysis,
            "dynamic_analysis": dynamic_results,
            "mitre_mapping": mitre_mapping,
            "fraud_impact": fraud_impact,
            "ai_summary": ai_summary,
            "classification": classification,
            "risk_score": risk_score,
            "iocs": static_analysis.get("iocs", {}),
            "virus_total": virus_total_enrichment,
            "created_at": datetime.utcnow().isoformat(),
        }

        # 11. Reports
        json_path = self.report_generator.generate(investigation, fmt="json")
        pdf_path = self.report_generator.generate(investigation, fmt="pdf")
        html_path = self.report_generator.generate(investigation, fmt="html")
        mmd_path = self.threat_graph.save_mermaid(investigation, REPORTS_DIR)

        investigation["reports"] = {
            "json": json_path,
            "pdf": pdf_path,
            "html": html_path,
            "mermaid": mmd_path,
        }

        # 12. Persist to relational database
        self._persist_investigation(investigation)

        # 13. Store in vector DB for chatbot
        self.vector_store.store_investigation(investigation)

        return investigation

    def _persist_investigation(self, investigation: Dict):
        db = SessionLocal()
        try:
            apk_id = investigation["metadata"]["sha256"]
            # APK record
            apk = db.query(APK).filter_by(sha256=apk_id).first()
            if not apk:
                apk = APK(
                    id=apk_id,
                    file_name=investigation["metadata"].get("file_name"),
                    package_name=investigation["metadata"].get("package_name"),
                    sha256=apk_id,
                    file_size=investigation["metadata"].get("file_size"),
                    version_name=investigation["metadata"].get("version_name"),
                    version_code=str(investigation["metadata"].get("version_code", "")),
                    metadata_json=investigation["metadata"],
                )
                db.add(apk)
                db.commit()

            # Static findings
            static = investigation.get("static_analysis", {})
            for f in static.get("fraud_findings", []) + static.get("code_findings", []) + static.get("manifest", {}).get("manifest_security", []):
                db.add(StaticFinding(
                    apk_id=apk_id,
                    finding_id=f.get("id", ""),
                    title=f.get("title", ""),
                    severity=f.get("severity", ""),
                    file_path=f.get("file", ""),
                    line=f.get("line", 0) or 0,
                    evidence=f.get("evidence", ""),
                ))

            # Dynamic findings
            for f in investigation.get("dynamic_analysis", {}).get("findings", []):
                db.add(DynamicFinding(
                    apk_id=apk_id,
                    finding_type=f.get("type", ""),
                    severity=f.get("severity", ""),
                    description=f.get("description", ""),
                    evidence=str(f.get("evidence", "")),
                    sandbox=investigation.get("dynamic_analysis", {}).get("sandbox", ""),
                ))

            # IOCs
            for ioc_type, values in investigation.get("iocs", {}).items():
                for value in values:
                    db.add(IOCModel(apk_id=apk_id, ioc_type=ioc_type, value=str(value)))

            # MITRE mappings
            for m in investigation.get("mitre_mapping", []):
                db.add(MITREMappingModel(
                    apk_id=apk_id,
                    technique_id=m.get("technique_id", ""),
                    technique=m.get("technique", ""),
                    tactic=m.get("tactic", ""),
                    evidence=m.get("evidence", ""),
                ))

            # Risk score
            risk = investigation.get("risk_score", {})
            db.add(RiskScore(
                apk_id=apk_id,
                score=risk.get("score", 0),
                category=risk.get("category", ""),
                static_score=risk.get("static_score", 0),
                dynamic_score=risk.get("dynamic_score", 0),
                fraud_score=risk.get("fraud_score", 0),
                ai_confidence=risk.get("ai_confidence", 0.0),
            ))

            # Reports
            for report_type, file_path in investigation.get("reports", {}).items():
                db.add(Report(apk_id=apk_id, report_type=report_type, file_path=file_path))

            db.commit()
        except Exception as exc:
            db.rollback()
            print(f"[-] DB persistence failed: {exc}")
        finally:
            db.close()

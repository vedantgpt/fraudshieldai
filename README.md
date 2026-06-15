# FraudShield AI

**Generative AI-Powered Automated Malware Investigation Platform for Fraudulent Android APKs**

FraudShield AI transforms the APKDeepLens static analyzer into an end-to-end autonomous fraud investigation platform. It is designed for banks, financial institutions, fraud teams, and SOC analysts to rapidly investigate suspicious Android APKs.

---

## What is FraudShield AI?

FraudShield AI combines:

- APK ingestion and reverse engineering
- Static analysis tuned for banking malware
- Generative AI (Gemini) reverse engineering explanation
- Malware classification
- IOC extraction and threat intelligence
- MITRE ATT&CK mapping
- Banking fraud impact assessment
- Weighted risk scoring
- AI-generated investigation reports (PDF, HTML, JSON)
- Security Copilot chatbot with RAG
- Attack-chain graph visualization

---

## Architecture

```
Streamlit Frontend (frontend/app.py)
        ↓
FastAPI Backend (api/main.py)
        ↓
Analysis Orchestrator (core/orchestrator.py)
        ↓
Static Engine → AI Analyst → MITRE Mapper → Fraud Impact → Risk Engine → Report Generator → Vector DB
```

---

## Quick Start

### 1. Install dependencies

```bash
python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY (optional but recommended)
# Set FRAUDSHIELD_API_KEY to require API authentication
# Set ENABLE_VIRUSTOTAL=true and VIRUSTOTAL_API_KEY for threat enrichment
# Set ENABLE_DYNAMIC_ANALYSIS=true for live sandbox analysis
```

### 3. Start the backend

```bash
uvicorn api.main:app --reload
```

### 4. Start the frontend (in another terminal)

```bash
streamlit run frontend/app.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## Legacy CLI

The original APKDeepLens CLI remains available:

```bash
python APKDeepLens.py -apk testing_apps/smartplug.apk -report json
```

---

## Core Modules

| Module | File | Description |
|--------|------|-------------|
| APK Ingestion | `core/ingestion.py` | Validate, hash, and extract APK metadata |
| Reverse Engineering | `core/reverse_engineering.py` | Decompile APK with bundled JADX |
| Static Analysis | `core/static_analysis.py` | Fraud-focused static analysis |
| Dynamic Analysis | `core/dynamic_analysis.py` | MobSF / Frida / ADB / simulated sandbox |
| IOC Extraction | `core/ioc_extractor.py` | Extract URLs, IPs, domains, emails, hashes |
| VirusTotal | `core/virus_total.py` | Enrich IOCs with VT reputation |
| MITRE Mapping | `core/mitre_mapper.py` | Map behaviors to MITRE ATT&CK |
| Fraud Impact | `core/fraud_impact.py` | Banking fraud impact assessment |
| Risk Scoring | `core/risk_scoring.py` | Weighted 0-100 risk score |
| Malware Classification | `core/malware_classifier.py` | Classify malware family |
| AI Analyst | `core/ai_analyst.py` | Gemini-powered reverse engineering summary |
| Report Generator | `core/report_generator.py` | PDF/HTML/JSON reports |
| Threat Graph | `core/threat_graph.py` | Mermaid attack-chain graph |
| Orchestrator | `core/orchestrator.py` | End-to-end workflow |
| API | `api/main.py` | FastAPI backend |
| Frontend | `frontend/app.py` | Streamlit UI |
| Chatbot | `chat/copilot.py` | RAG Security Copilot |
| Database | `db/models.py` | SQLAlchemy models (SQLite default, PostgreSQL ready) |
| Vector DB | `db/vector_store.py` | ChromaDB retrieval store |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| POST | `/api/upload` | Upload APK file |
| POST | `/api/investigate` | Run full investigation |
| POST | `/api/dynamic_analysis` | Run dynamic analysis sandbox |
| GET | `/api/reports/{json\|pdf\|html\|mermaid}` | Download report |
| POST | `/api/chat` | Ask the Security Copilot |

---

## Files Added / Transformed

- `prd.md` — Product Requirements Document
- `config.py` — Central configuration
- `api/main.py` — FastAPI backend
- `frontend/app.py` — Streamlit frontend
- `core/` — New analysis engines
- `db/` — Database and vector store models
- `chat/` — Security Copilot chatbot
- `requirements.txt` — Updated dependencies
- `.env.example` — Environment template

---

## Troubleshooting

### JADX does not create output

The bundled JADX requires a compatible Java installation. If you see `INFO - loading ...` with no output, try upgrading Java to 11 or newer and ensure `JAVA_HOME` is set. If JADX still fails, FraudShield AI falls back to androguard to extract the manifest so the pipeline can continue.

### ChromaDB / sentence-transformers import error

The RAG chatbot uses ChromaDB and sentence-transformers. If the local environment has a broken or incompatible PyTorch installation, the chatbot will still answer using the Gemini model and available context, but vector retrieval may be disabled. For full RAG support, ensure `torch` and `sentence-transformers` are installed correctly for your Python version.

### Dynamic Analysis Sandbox

Set `ENABLE_DYNAMIC_ANALYSIS=true` to enable live sandbox analysis. The sandbox tries (in order):
1. MobSF dynamic analysis API (`MOBSF_URL`, `MOBSF_API_KEY`)
2. ADB + Frida on a connected emulator/device (`ADB_PATH`, `FRIDA_SERVER_PATH`)
3. ADB-only logcat collection
4. Simulated behavioral sandbox fallback based on static indicators

When no live tools are available, the fallback produces simulated dynamic findings so the pipeline always completes. Simulated findings are clearly labeled `[SIMULATED]` in reports and UI.

### False positives

The fraud detection rules use conservative regexes to reduce false positives. Banking brand impersonation requires explicit bank/payment brand names, C2 detection focuses on raw sockets and hardcoded IPs, and the IP regex excludes version strings. If you still see false positives, review the rules in `core/static_analysis.py` and `core/ioc_extractor.py`.

### Security hardening

The API supports optional `FRAUDSHIELD_API_KEY` authentication, upload size limits (`MAX_UPLOAD_SIZE_MB`), and rate limiting (`RATE_LIMIT_ENABLED`). Set these in `.env` for production deployments.

## License

See [LICENSE](LICENSE).

## Product Requirements

See [prd.md](prd.md) for the full PRD.

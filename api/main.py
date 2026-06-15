import json
import os
import re
import time
import uuid
from typing import Optional
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Header, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from config import (
    UPLOAD_DIR,
    REPORTS_DIR,
    FRAUDSHIELD_API_KEY,
    MAX_UPLOAD_SIZE_MB,
    RATE_LIMIT_ENABLED,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
)
from core.orchestrator import AnalysisOrchestrator
from chat.copilot import SecurityCopilotChatbot
from db.models import init_db

app = FastAPI(title="FraudShield AI", version="1.0")

init_db()
orchestrator = AnalysisOrchestrator()
chatbot = SecurityCopilotChatbot()

MAX_UPLOAD_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

# In-memory rate limiter: {client_ip: [(timestamp, count)]}
_rate_limit_store = {}


def _sanitize_filename(name: str) -> str:
    """Sanitize uploaded filenames to prevent path traversal and unsafe chars."""
    base = os.path.basename(name)
    base = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
    if not base.lower().endswith(".apk"):
        base += ".apk"
    return base


def _verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """Require API key only when FRAUDSHIELD_API_KEY is configured."""
    if not FRAUDSHIELD_API_KEY:
        return None
    if x_api_key != FRAUDSHIELD_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key


def _rate_limit_check(request: Request):
    if not RATE_LIMIT_ENABLED:
        return
    client = request.client.host if request.client else "unknown"
    now = time.time()
    window = _rate_limit_store.get(client, [])
    window = [t for t in window if now - t < RATE_LIMIT_WINDOW_SECONDS]
    if len(window) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    window.append(now)
    _rate_limit_store[client] = window


class ChatRequest(BaseModel):
    apk_id: str
    question: str


@app.get("/")
def root():
    return {"service": "FraudShield AI", "version": "1.0", "status": "ok"}


@app.post("/api/upload")
def upload_apk(
    request: Request,
    file: UploadFile = File(...),
    api_key: Optional[str] = Depends(_verify_api_key),
):
    _rate_limit_check(request)
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only APK files are allowed.")
    safe_name = _sanitize_filename(file.filename)
    file_id = f"{uuid.uuid4().hex}_{safe_name}"
    path = os.path.join(UPLOAD_DIR, file_id)

    total = 0
    with open(path, "wb") as f:
        for chunk in iter(lambda: file.file.read(8192), b""):
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                f.close()
                os.remove(path)
                raise HTTPException(status_code=413, detail=f"Upload exceeds {MAX_UPLOAD_SIZE_MB} MB limit")
            f.write(chunk)
    return {"file_id": file_id, "path": path, "filename": safe_name}


@app.post("/api/investigate")
def investigate(
    request: Request,
    file_id: str = Form(...),
    api_key: Optional[str] = Depends(_verify_api_key),
):
    _rate_limit_check(request)
    path = os.path.join(UPLOAD_DIR, file_id)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File not found. Upload first.")
    investigation = orchestrator.investigate(path)
    return investigation


@app.get("/api/reports/{report_type}")
def get_report(
    request: Request,
    report_type: str,
    apk_id: str,
    api_key: Optional[str] = Depends(_verify_api_key),
):
    _rate_limit_check(request)
    if report_type not in {"json", "pdf", "html", "mermaid"}:
        raise HTTPException(status_code=400, detail="Report type must be json, pdf, html, or mermaid.")
    safe_apk_id = re.sub(r"[^a-zA-Z0-9._-]", "_", apk_id)
    ext = ".mmd" if report_type == "mermaid" else f".{report_type}"
    candidates = [f for f in os.listdir(REPORTS_DIR) if f.startswith(safe_apk_id) and f.endswith(ext)]
    if not candidates:
        raise HTTPException(status_code=404, detail="Report not found.")
    report_path = os.path.join(REPORTS_DIR, candidates[0])
    if report_type in {"json", "mermaid"}:
        return FileResponse(report_path, media_type="text/plain")
    if report_type == "html":
        return FileResponse(report_path, media_type="text/html")
    return FileResponse(report_path, media_type="application/pdf", filename=candidates[0])


@app.post("/api/dynamic_analysis")
def run_dynamic_analysis(
    request: Request,
    file_id: str = Form(...),
    api_key: Optional[str] = Depends(_verify_api_key),
):
    _rate_limit_check(request)
    path = os.path.join(UPLOAD_DIR, file_id)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File not found. Upload first.")
    from androguard.core.bytecodes.apk import APK
    try:
        package = APK(path).get_package()
    except Exception:
        package = None
    result = orchestrator.dynamic_sandbox.run(path, package_name=package)
    return result


@app.post("/api/chat")
def chat(
    request: Request,
    req: ChatRequest,
    api_key: Optional[str] = Depends(_verify_api_key),
):
    _rate_limit_check(request)
    fallback_context = ""
    candidates = [f for f in os.listdir(REPORTS_DIR) if f.endswith("_investigation.json")]
    for candidate in candidates:
        path = os.path.join(REPORTS_DIR, candidate)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("metadata", {}).get("sha256") == req.apk_id:
                fallback_context = json.dumps(data, indent=2)
                break
        except Exception:
            continue
    result = chatbot.ask(req.apk_id, req.question, fallback_context=fallback_context)
    return result

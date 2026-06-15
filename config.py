import os
import logging
from dotenv import load_dotenv

load_dotenv()

# Suppress noisy reportlab/xhtml2pdf layout warnings during PDF generation
logging.getLogger("reportlab.platypus").setLevel(logging.ERROR)
logging.getLogger("xhtml2pdf").setLevel(logging.ERROR)

# Suppress verbose androguard / chromadb logs
logging.getLogger("androguard").setLevel(logging.WARNING)
logging.getLogger("chromadb").setLevel(logging.WARNING)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
APP_SOURCE_DIR = os.path.join(BASE_DIR, "app_source")
VECTOR_DB_DIR = os.path.join(BASE_DIR, "vector_db")

# Security settings
FRAUDSHIELD_API_KEY = os.getenv("FRAUDSHIELD_API_KEY", "")
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "100"))
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "false").lower() == "true"
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///" + os.path.join(BASE_DIR, "fraudshield.db")
)

# Dynamic Analysis Sandbox settings
ENABLE_DYNAMIC_ANALYSIS = os.getenv("ENABLE_DYNAMIC_ANALYSIS", "false").lower() == "true"
DYNAMIC_ANALYSIS_TIMEOUT = int(os.getenv("DYNAMIC_ANALYSIS_TIMEOUT", "60"))
MOBSF_URL = os.getenv("MOBSF_URL", "http://127.0.0.1:8000")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "")
ADB_PATH = os.getenv("ADB_PATH", "adb")
EMULATOR_NAME = os.getenv("EMULATOR_NAME", "")
FRIDA_SERVER_PATH = os.getenv("FRIDA_SERVER_PATH", "")

ENABLE_VIRUSTOTAL = os.getenv("ENABLE_VIRUSTOTAL", "false").lower() == "true"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(APP_SOURCE_DIR, exist_ok=True)
os.makedirs(VECTOR_DB_DIR, exist_ok=True)

"""FraudShield AI Security Copilot Chatbot."""
from typing import Dict, List
from core.ai_analyst import AIReverseEngineeringAnalyst
from db.vector_store import VectorStore
from config import VECTOR_DB_DIR, GEMINI_API_KEY


class SecurityCopilotChatbot:
    """RAG-based chatbot answering questions about APK investigations."""

    def __init__(self):
        self.vector_store = VectorStore(VECTOR_DB_DIR)
        self.ai = AIReverseEngineeringAnalyst(GEMINI_API_KEY)

    def ask(self, apk_id: str, question: str, history: List[Dict] = None, fallback_context: str = "") -> Dict:
        history = history or []
        retrieved = []
        if self.vector_store.collection:
            retrieved = self.vector_store.query(question, apk_id=apk_id, n_results=5)
        context = self._build_context(retrieved) if retrieved else fallback_context
        answer = self.ai.chat(question, context)

        return {
            "question": question,
            "answer": answer,
            "context": [r["text"] for r in retrieved],
        }

    def _build_context(self, retrieved: List[Dict]) -> str:
        parts = []
        for r in retrieved:
            meta = r.get("meta", {})
            parts.append(f"[{meta.get('type', 'unknown')}] {r['text']}")
        return "\n".join(parts)

"""FraudShield AI vector store for chatbot retrieval."""
import os
import json
from typing import Dict, List


class VectorStore:
    """Simple persistent vector store using ChromaDB for retrieval."""

    def __init__(self, persist_dir: str):
        self.persist_dir = persist_dir
        self.client = None
        self.collection = None
        self._embedding_fn = None
        self._init()

    def _init(self):
        try:
            import chromadb
            from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
            self.client = chromadb.PersistentClient(
                path=self.persist_dir,
                settings=chromadb.Settings(anonymized_telemetry=False),
            )
            self._embedding_fn = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
            self.collection = self.client.get_or_create_collection(
                name="fraudshield_investigations",
                embedding_function=self._embedding_fn,
            )
        except Exception as exc:
            print(f"[-] ChromaDB init failed: {exc}")
            self.collection = None

    def store_investigation(self, investigation: Dict):
        if not self.collection:
            return
        apk_id = investigation["metadata"]["sha256"]
        chunks = self._chunks(investigation)
        docs = [chunk["text"] for chunk in chunks]
        ids = [f"{apk_id}_{i}" for i in range(len(docs))]
        metadatas = [chunk["meta"] for chunk in chunks]
        try:
            self.collection.add(documents=docs, ids=ids, metadatas=metadatas)
        except Exception as exc:
            print(f"[-] Vector store add failed: {exc}")

    def query(self, question: str, apk_id: str = None, n_results: int = 5) -> List[Dict]:
        if not self.collection:
            return []
        try:
            where = {"apk_id": apk_id} if apk_id else None
            results = self.collection.query(query_texts=[question], n_results=n_results, where=where)
            out = []
            for i, doc in enumerate(results.get("documents", [[]])[0]):
                meta = results.get("metadatas", [[]])[0][i] if results.get("metadatas") else {}
                out.append({"text": doc, "meta": meta})
            return out
        except Exception as exc:
            print(f"[-] Vector store query failed: {exc}")
            return []

    def _chunks(self, investigation: Dict) -> List[Dict]:
        apk_id = investigation["metadata"]["sha256"]
        chunks = []
        meta = {
            "apk_id": apk_id,
            "package": investigation["metadata"].get("package_name", ""),
            "file_name": investigation["metadata"].get("file_name", ""),
        }
        chunks.append({"text": json.dumps(investigation["ai_summary"]), "meta": {**meta, "type": "ai_summary"}})
        chunks.append({"text": json.dumps(investigation["fraud_impact"]), "meta": {**meta, "type": "fraud_impact"}})
        chunks.append({"text": json.dumps(investigation["risk_score"]), "meta": {**meta, "type": "risk_score"}})
        for ioc_type, values in investigation.get("iocs", {}).items():
            if values:
                chunks.append({"text": f"{ioc_type}: {', '.join(values[:10])}", "meta": {**meta, "type": "ioc"}})
        for finding in investigation.get("static_analysis", {}).get("fraud_findings", [])[:10]:
            chunks.append({"text": f"{finding['id']}: {finding['title']} - {finding['description']}", "meta": {**meta, "type": "finding"}})
        return chunks

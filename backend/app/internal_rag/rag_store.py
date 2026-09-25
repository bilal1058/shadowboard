"""Local file-backed vector index supporting PDFs and Markdown documents.

Ingests:
- Enterprise PDFs (via pypdf)
- Markdown and text documents
- Classifies access tiers (PUBLIC_INTERNAL, RESTRICTED_CONFIDENTIAL, EXTERNAL_INGESTED)
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

DOCUMENTS_DIR = Path(__file__).parent / "documents"
STOP_WORDS = {
    "a", "about", "above", "after", "again", "all", "am", "an", "and", "any", "are", "as", "at",
    "be", "because", "been", "before", "being", "below", "between", "both", "but", "by",
    "could", "did", "do", "does", "doing", "down", "during", "each", "few", "for", "from",
    "further", "had", "has", "have", "having", "he", "her", "here", "hers", "herself", "him",
    "himself", "his", "how", "i", "if", "in", "into", "is", "it", "its", "itself", "just",
    "me", "more", "most", "my", "myself", "no", "nor", "not", "now", "of", "off", "on", "once",
    "only", "or", "other", "our", "ours", "ourselves", "out", "over", "own", "same", "she",
    "should", "so", "some", "such", "than", "that", "the", "their", "theirs", "them", "themselves",
    "then", "there", "these", "they", "this", "those", "through", "to", "too", "under", "until",
    "up", "very", "was", "we", "were", "what", "when", "where", "which", "while", "who", "whom",
    "why", "with", "would", "you", "your", "yours", "yourself", "yourselves", "please", "can"
}

TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_]{2,}")


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN_PATTERN.findall(text.lower()) if t not in STOP_WORDS]


def chunk_document(text: str, chunk_size: int = 110) -> list[str]:
    words = text.split()
    return [" ".join(words[start:start + chunk_size]) for start in range(0, len(words), chunk_size)] or [text]


def determine_access_tier(stem: str) -> str:
    s = stem.lower()
    if any(k in s for k in ("confidential", "executive", "secret", "compensation", "acquisition", "escrow")):
        return "RESTRICTED_CONFIDENTIAL"
    if any(k in s for k in ("vendor", "invoice", "resume", "ticket", "external", "trojan")):
        return "EXTERNAL_INGESTED"
    return "PUBLIC_INTERNAL"


class LocalVectorStore:
    def __init__(self, documents_dir: Path = DOCUMENTS_DIR):
        self.documents_dir = documents_dir
        self.chunks: list[dict[str, Any]] = []
        self.documents_catalog: list[dict[str, Any]] = []
        self.vocabulary: dict[str, int] = {}
        self.vectors: np.ndarray = np.empty((0, 0))
        self.reload()

    @staticmethod
    def _extract_pdf_text(pdf_path: Path) -> str:
        try:
            import pypdf
            reader = pypdf.PdfReader(str(pdf_path))
            pages = []
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    pages.append(extracted)
            return "\n\n".join(pages)
        except Exception as e:
            return f"Error reading PDF {pdf_path.name}: {e}"

    def reload(self) -> None:
        chunks: list[dict[str, Any]] = []
        catalog: list[dict[str, Any]] = []

        all_files = sorted(list(self.documents_dir.glob("*.md")) + list(self.documents_dir.glob("*.pdf")) + list(self.documents_dir.glob("*.txt")))

        for document_path in all_files:
            file_type = document_path.suffix.lower().lstrip(".")
            if file_type == "pdf":
                text = self._extract_pdf_text(document_path)
            else:
                text = document_path.read_text(encoding="utf-8", errors="replace")

            access_tier = determine_access_tier(document_path.stem)
            doc_chunks = chunk_document(text)

            catalog.append({
                "document_id": document_path.stem,
                "document_name": document_path.name,
                "file_type": file_type.upper(),
                "size_bytes": document_path.stat().st_size,
                "access_tier": access_tier,
                "chunk_count": len(doc_chunks),
                "preview": text[:160].strip().replace("\n", " ") + "..."
            })

            for index, chunk in enumerate(doc_chunks, start=1):
                chunks.append({
                    "document_id": document_path.stem,
                    "document_name": document_path.name,
                    "file_type": file_type.upper(),
                    "access_tier": access_tier,
                    "chunk_id": f"{document_path.stem}:{index}",
                    "text": chunk,
                })

        if not chunks:
            raise RuntimeError("Internal RAG document corpus is empty.")

        self.chunks = chunks
        self.documents_catalog = catalog

        vocabulary = sorted({token for chunk in self.chunks for token in tokenize(chunk["text"])})
        self.vocabulary = {token: index for index, token in enumerate(vocabulary)}
        self.vectors = np.vstack([self._embed(chunk["text"]) for chunk in self.chunks])

    def _embed(self, text: str) -> np.ndarray:
        vector = np.zeros(len(self.vocabulary), dtype=float)
        for token, count in Counter(tokenize(text)).items():
            index = self.vocabulary.get(token)
            if index is not None:
                vector[index] = count
        norm = np.linalg.norm(vector)
        return vector / norm if norm else vector

    def search(
        self,
        query: str,
        top_k: int = 3,
        allowed_access_tiers: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Rank only documents the authenticated principal may retrieve.

        Filtering after similarity ranking leaks restricted document existence and
        can expose it through model context.  The ACL predicate is therefore
        applied before scoring and before any result metadata is returned.
        """
        query_vector = self._embed(query)
        scores = self.vectors @ query_vector
        candidate_indices = [
            index for index, chunk in enumerate(self.chunks)
            if allowed_access_tiers is None or chunk["access_tier"] in allowed_access_tiers
        ]
        ranked_indices = sorted(candidate_indices, key=lambda index: scores[index], reverse=True)[:top_k]
        retrieved_at = datetime.now(timezone.utc).isoformat()
        return [
            {
                **self.chunks[index],
                "similarity": round(float(scores[index]), 4),
                "retrieved_at": retrieved_at,
            }
            for index in ranked_indices
            if scores[index] > 0
        ]

    def get_catalog(self) -> list[dict[str, Any]]:
        return self.documents_catalog


internal_vector_store = LocalVectorStore()

from __future__ import annotations
import hashlib

class LocalHashEmbedder:
    """Deterministic offline embedder for local fixtures; no model/network download."""
    def __init__(self, dimensions: int = 32): self.dimensions = dimensions
    def embed(self, text: str) -> list[float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        return [((digest[i % len(digest)] / 255.0) * 2.0) - 1.0 for i in range(self.dimensions)]

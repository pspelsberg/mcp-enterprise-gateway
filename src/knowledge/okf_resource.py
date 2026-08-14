from pathlib import Path
import re
from src.core.models import ConceptNotFoundError

class OKFResourceProvider:
    def __init__(self, root: str|Path): self.root=Path(root).resolve()
    def read(self, concept_id: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", concept_id): raise ConceptNotFoundError("invalid concept id")
        path=(self.root/(concept_id+".md")).resolve()
        if self.root not in path.parents: raise ConceptNotFoundError("concept not found")
        try: return path.read_text(encoding="utf-8")
        except (FileNotFoundError, IsADirectoryError): raise ConceptNotFoundError("concept not found")

import math
import re
from collections.abc import Mapping
from src.core.models import KnowledgeUnavailableError, KnowledgeHybridUnavailableError, UnauthorizedProjectError

MAX_RESULT_FIELD_BYTES = 100 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024

class LanceDBAdapter:
    def __init__(self, table=None, embedder=None, allowed_projects=None):
        self.table = table
        self.embedder = embedder
        self.allowed_projects = set(allowed_projects) if allowed_projects is not None else None

    def _has_fts_index(self) -> bool:
        try:
            indices = self.table.list_indices()
            for index in indices:
                index_type = str(getattr(index, "index_type", "")).upper()
                columns = getattr(index, "columns", []) or []
                if index_type in {"FTS", "INVERTED"} and "text" in columns:
                    return True
        except Exception:
            return False
        return False

    def query(self, query: str, project_id: str, top_k: int, search_mode: str = "vector"):
        if not isinstance(query, str) or not query or len(query.encode("utf-8")) > 100 * 1024:
            raise KnowledgeUnavailableError("invalid query")
        if not isinstance(top_k, int) or isinstance(top_k, bool) or not 1 <= top_k <= 50:
            raise KnowledgeUnavailableError("invalid result limit")
        if search_mode not in {"vector", "hybrid"}:
            raise KnowledgeUnavailableError("invalid search mode")
        if not isinstance(project_id, str) or len(project_id.encode("utf-8")) > 128 or not re.fullmatch(r"[a-zA-Z0-9_-]+", project_id):
            raise KnowledgeUnavailableError("invalid project id")
        if self.allowed_projects is not None and project_id not in self.allowed_projects:
            raise UnauthorizedProjectError("project is not authorized")
        if self.table is None:
            raise KnowledgeUnavailableError("vector database is unavailable")
        if search_mode == "hybrid" and not self._has_fts_index():
            raise KnowledgeHybridUnavailableError("full-text search is unavailable")
        try:
            vector = self.embedder.embed(query) if self.embedder else query
            if search_mode == "hybrid":
                # LanceDB's hybrid builder combines vector and BM25/FTS and
                # uses reciprocal-rank fusion by default.
                search = self.table.search(query_type="hybrid", fts_columns="text").vector(vector).text(query)
            else:
                search = self.table.search(vector)
            try:
                filtered = search.where(f"project_id = '{project_id}'", prefilter=True)
            except TypeError:
                # Compatibility with minimal test doubles and older SDKs.
                filtered = search.where(f"project_id = '{project_id}'")
            rows = filtered.limit(top_k).to_list()
        except KnowledgeHybridUnavailableError:
            raise
        except Exception as exc:
            if search_mode == "hybrid":
                raise KnowledgeHybridUnavailableError("hybrid query failed") from exc
            raise KnowledgeUnavailableError("vector query failed") from exc
        result = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise KnowledgeUnavailableError("vector result schema is invalid")
            try:
                if search_mode == "hybrid":
                    score = float(row.get("_relevance_score", row.get("_score", 0.0)))
                    score = max(0.0, score)
                else:
                    distance = float(row.get("_distance", row.get("distance", 0.0)))
                    score = 1.0 / (1.0 + max(0.0, distance))
                if not math.isfinite(score):
                    raise ValueError("non-finite search score")
            except (TypeError, ValueError):
                raise KnowledgeUnavailableError("vector result score is invalid")
            if row.get("project_id") != project_id:
                continue
            if "text" not in row or "source" not in row:
                raise KnowledgeUnavailableError("vector schema is invalid")
            text, source = str(row["text"]), str(row["source"])
            if len(text.encode("utf-8")) > MAX_RESULT_FIELD_BYTES or len(source.encode("utf-8")) > MAX_RESULT_FIELD_BYTES:
                raise KnowledgeUnavailableError("vector result is too large")
            result.append({"text": text, "source": source, "score": score})
            if sum(len(str(item["text"]).encode("utf-8")) + len(str(item["source"]).encode("utf-8")) for item in result) > MAX_RESULT_BYTES:
                raise KnowledgeUnavailableError("vector result is too large")
        return sorted(result, key=lambda x: x["score"], reverse=True)

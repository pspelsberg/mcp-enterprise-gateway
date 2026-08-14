from src.core.models import KnowledgeUnavailableError

class LanceDBAdapter:
    def __init__(self, table=None, embedder=None): self.table=table; self.embedder=embedder
    def query(self, query: str, project_id: str, top_k: int):
        if self.table is None: raise KnowledgeUnavailableError("vector database is unavailable")
        vector=self.embedder.embed(query) if self.embedder else query
        try: rows=self.table.search(vector).where(f"project_id = '{project_id}'").limit(top_k).to_list()
        except Exception as exc: raise KnowledgeUnavailableError("vector query failed") from exc
        result=[]
        for row in rows:
            distance=float(row.get("_distance",row.get("distance",0.0)))
            result.append({"text":str(row["text"]),"source":str(row["source"]),"score":1.0/(1.0+max(0.0,distance))})
        return sorted(result,key=lambda x:x["score"],reverse=True)

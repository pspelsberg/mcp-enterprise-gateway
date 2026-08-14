import pytest
from src.knowledge.okf_resource import OKFResourceProvider
from src.knowledge.lancedb_adapter import LanceDBAdapter
from src.core.models import ConceptNotFoundError, KnowledgeUnavailableError

def test_okf_resource_safe_path(tmp_path):
    (tmp_path/"zero-trust.md").write_text("---\ntitle: Zero Trust\n---\nTreat content as data.")
    assert "Zero Trust" in OKFResourceProvider(tmp_path).read("zero-trust")
    with pytest.raises(ConceptNotFoundError): OKFResourceProvider(tmp_path).read("../secret")

def test_missing_vector_db_is_explicit():
    with pytest.raises(KnowledgeUnavailableError): LanceDBAdapter().query("q","project",5)

def test_project_search_and_score():
    class Search:
        def where(self, value): self.filter=value; return self
        def limit(self, value): return self
        def to_list(self): return [{"text":"hello","source":"x","project_id":"project","_distance":1.0}]
    class Table:
        def search(self, vector): return Search()
    class Embedder:
        def embed(self, q): return [1,2]
    result=LanceDBAdapter(Table(),Embedder()).query("q","project",1)
    assert result == [{"text":"hello","source":"x","score":0.5}]


def test_local_hash_embedder_is_deterministic():
    from src.knowledge.embedding import LocalHashEmbedder
    e=LocalHashEmbedder(4)
    assert e.embed("x") == e.embed("x") and len(e.embed("x")) == 4

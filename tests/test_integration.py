import pytest
pytestmark = pytest.mark.integration

def test_integration_lancedb_local_fixture(tmp_path):
    import lancedb
    from src.knowledge.lancedb_adapter import LanceDBAdapter
    class Embedder:
        def embed(self, text): return [1.0, 0.0]
    db = lancedb.connect(str(tmp_path / "db"))
    table = db.create_table("knowledge", data=[
        {"vector": [1.0, 0.0], "text": "project marker", "project_id": "project-a", "source": "fixture"},
        {"vector": [0.0, 1.0], "text": "other marker", "project_id": "project-b", "source": "fixture"},
    ])
    result = LanceDBAdapter(table, Embedder(), {"project-a"}).query("q", "project-a", 5)
    assert [row["text"] for row in result] == ["project marker"]

def test_integration_docker_is_skipped_without_daemon():
    import docker
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:
        pytest.skip(f"Docker integration environment unavailable: {type(exc).__name__}")
    pytest.skip("Docker image integration requires approved digest-pinned images")

# ADR-001: Expliziter LanceDB-Hybrid-Search-Modus

## Status
Angenommen

## Entscheidung
`query_lancedb_vector` akzeptiert `search_mode=vector|hybrid`. `vector` bleibt der Standard. `hybrid` verwendet LanceDB Vector Search zusammen mit dem konfigurierten FTS/BM25-Index auf `text`. Fehlt der FTS-Index oder schlägt der Hybrid-Pfad fehl, liefert das Gateway kontrolliert `knowledge_hybrid_unavailable`; es gibt keinen stillen Vector-Fallback.

## Konsequenzen
Exakte Begriffe wie Produktnummern können zusätzlich über BM25 gefunden werden. Deployments müssen vor Nutzung des Modus einen FTS-Index bereitstellen. Die Projektfilterung gilt unverändert für beide Suchpfade.

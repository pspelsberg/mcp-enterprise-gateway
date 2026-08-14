# Task Backlog: Enterprise-Härtung des MCP Enterprise Gateway

**Stand:** 14.08.2026
**Repository:** `/home/peppi/coding/mcp-enterprise-gateway`
**Referenzen:**
- `/home/peppi/coding/Pathto2027/mcp_idea.md`
- `README.md`
- CodeUltra Review Contract v4.5, Full Tier
- letzter geprüfter Commit: `ca3f4fb`

## Ausgangslage

Die aktuelle Implementierung ist als kontrollierter lokaler Prototyp funktionsfähig:

```text
uv run pytest: 12 passed
Coverage: 87 %
CodeUltra Full-Tier Review: 5/10
Kritische Findings im akzeptierten Local-Development-Modell: 0
Warnungen: 12+
```

Die vier MCP-Tools, zwei MCP-Ressourcen, der Security-Audit-Prompt, die README, die Claude-Desktop-Konfiguration und die virtuelle Umgebung sind vorhanden. Für einen Enterprise- oder produktiven Betrieb fehlen jedoch noch Sicherheitsgrenzen, produktive LanceDB-Konfiguration, robuste Fehler-/Timeout-Semantik, Protocol-Contract-Tests sowie Architektur- und Integration-Sensoren.

> **Scope-Entscheidung:** `docker://logs` wird bewusst nicht implementiert. Es war nur in der ursprünglichen Architekturzeichnung erwähnt; in der nachfolgenden Anforderungsentscheidung wurde festgelegt, keine Container-Logs als MCP-Ressource zu exponieren. Die ursprüngliche Zeichnung sollte entsprechend korrigiert werden.

---

## Priorität und Definition of Done

- **P0 – Produktionsblocker:** Sicherheits- oder Verfügbarkeitsrisiko, das vor einem Enterprise-Einsatz behoben werden muss.
- **P1 – Hohe Priorität:** Funktionale Lücke oder Security-Regression, die vor einer belastbaren Release-Version behoben werden muss.
- **P2 – Qualitäts-/Dokumentationsarbeit:** wichtig für Wartbarkeit, Compliance und langfristige Driftvermeidung.

Eine Aufgabe gilt erst als erledigt, wenn:

1. die Änderung implementiert ist;
2. ein Verhaltenstest bzw. eine permanente Regression vorhanden ist;
3. `uv run pytest` erfolgreich läuft;
4. relevante Integrationstests mit `-m integration` separat laufen;
5. Packaging/CLI-Dokumentation aktualisiert ist;
6. die betroffenen CodeUltra-Kriterien geprüft und dokumentiert sind;
7. keine PII, Secrets oder Stacktraces in Antworten oder Logs erscheinen.

---

# P0 – Produktions- und Sicherheitsblocker

## TASK-001: Docker-Timeouts strukturiert behandeln

**Status:** Erledigt
**Priorität:** P0
**Contract:** `F-EXC`, `F-DOS`
**CWE:** CWE-755, CWE-400
**OWASP:** A10:2025
**Fundstellen:** `src/sandbox/docker_runner.py:32-36`, `src/server.py:27-30`

### Problem

`container.wait(timeout=...)` kann `requests.exceptions.ReadTimeout` auslösen. Diese Exception ist keine `docker.errors.DockerException` und entkommt damit dem aktuellen Fehlerpfad. Der MCP-Client erhält keinen stabilen Fehlercode; ein interner Fehler kann bis FastMCP durchlaufen.

### Umsetzung

- Dedizierten Fehler `SandboxTimeoutError` mit Code `sandbox_timeout` einführen.
- `requests.exceptions.ReadTimeout` und `TimeoutError` explizit behandeln.
- Bei Timeout den Container best effort mit `kill()`/`stop()` beenden.
- Anschließend `wait()` und `remove(force=True)` best effort ausführen.
- Cleanup-Fehler dürfen den ursprünglichen Timeout-Fehler nicht überschreiben.
- Keine Docker- oder Hostdetails an den MCP-Client geben.
- Timeout-Fehler im Audit nur aggregiert zählen, ohne Code/PII zu loggen.

### Abnahmekriterien

- Timeout liefert einen strukturierten Fehler mit stabilem Code `sandbox_timeout`.
- Der Container wird nach Timeout entfernt.
- Ein Fehler in `remove()` maskiert nicht den ursprünglichen Timeout.
- Kein Host-Subprocess-Fallback.

### Tests

- Fake-Container, dessen `wait()` `ReadTimeout` wirft.
- Prüfung auf `kill/stop`, `remove(force=True)` und Fehlercode.
- Test für Cleanup-Exception.
- MCP-Client-Test für die Fehlerdarstellung.

---

## TASK-002: Docker-Ausgabe streaming-basiert und hart begrenzen

**Status:** Erledigt
**Priorität:** P0
**Contract:** `F-DOS`
**CWE:** CWE-400
**CVSS:** 6.5
**Fundstellen:** `src/sandbox/docker_runner.py:8-11,33-34`, `README.md:69-71`

### Problem

`container.logs()` lädt derzeit den vollständigen stdout/stderr-Inhalt, bevor auf 1 MiB gesliced wird. Ein Programm kann innerhalb des 30-Sekunden-Limits sehr große Mengen erzeugen und Gateway-/Daemon-Speicher belasten. Außerdem wird der Truncation-Marker im Ausführungspfad durch das vorherige Slice umgangen.

### Umsetzung

- Streaming-Logs verwenden oder eine Docker-seitige harte Begrenzung etablieren.
- Bytes pro Stream während des Lesens zählen.
- Nach `1 MiB` den Stream verwerfen/abbrechen und Marker setzen.
- Marker `[output truncated]` zuverlässig ausgeben.
- Optional zusätzliche Container-/Daemon-Log-Limits konfigurieren.
- Keine vollständige Log-Menge im RAM materialisieren.

### Abnahmekriterien

- Rückgabe je Stream niemals über 1 MiB inklusive Marker.
- Speicherverbrauch wächst nicht proportional zur gesamten Programmausgabe.
- stdout und stderr bleiben getrennt.
- Truncation ist im Ergebnis erkennbar.

### Tests

- Fake-Logstream mit deutlich mehr als 1 MiB.
- Prüfung auf Marker und Obergrenze.
- Test für getrennte stdout/stderr-Streams.
- Test, dass kein unbounded `logs()`-Pfad verwendet wird.

---

## TASK-003: Unerwartete Fehler zentral maskieren

**Status:** Erledigt
**Priorität:** P0
**Contract:** `F-EXC`, `C-CFG`, `C-LOG`
**CWE:** CWE-209, CWE-755, CWE-532
**OWASP:** A10:2025, A02:2025, A09:2025
**Fundstellen:** `src/server.py:12,27-30`, `src/knowledge/lancedb_adapter.py`, `src/sandbox/docker_runner.py`, `src/knowledge/okf_resource.py`

### Problem

`safe()` behandelt nur `GatewayError`, `ValidationError` und `ValueError`. `KeyError`, `OSError`, `ReadTimeout`, Embedding-Fehler oder Fehler in `logs/remove` können unmaskiert an FastMCP gelangen. FastMCP ist nicht explizit mit `mask_error_details=True` konfiguriert.

### Umsetzung

- `FastMCP("Enterprise Gateway", mask_error_details=True)` konfigurieren, sofern von der installierten Version unterstützt.
- Zentrale Exception-Grenze mit generischem, sicherem Fehlercode `internal_error` ergänzen.
- Bekannte Domänenfehler spezifisch abbilden.
- Fehlernachrichten dürfen keine Pfade, Env-Werte, Dockerdetails, Secrets, Prompts oder PII enthalten.
- Sichere Korrelations-ID nur dann loggen, wenn Logging eingeführt wird.
- PII-freies Security-Event-Logging mit aggregierten Zählern vorsehen.

### Abnahmekriterien

- Kein interner Stacktrace in Tool-/Resource-Antworten.
- Kein Prompt, PII-Wert, Secret oder Umgebungswert in Fehlerantworten.
- Jeder bekannte Fehler hat einen stabilen Fehlercode.
- Unbekannte Fehler werden sicher und deterministisch behandelt.

### Tests

- `KeyError`, `OSError`, Embedding-Exception und generische Docker-Exception simulieren.
- MCP-Client prüft `isError`/strukturierte Fehlerausgabe.
- Negativtests auf PII/Secrets/Filesystempfade in Antworten.

---

## TASK-004: SSE sicher begrenzen oder standardmäßig deaktivieren

**Status:** Erledigt
**Priorität:** P0 bei gemeinsamem/produktivem Betrieb; P2 im strikt lokalen Single-User-Betrieb
**Contract:** `C-AC`, `C-AUTH`, `C-CFG`, `F-MCP`, `F-DOS`
**CWE:** CWE-306, CWE-352, CWE-639, CWE-400
**OWASP:** A01:2025, A07:2025
**Fundstellen:** `src/server.py:56-60`, `README.md:52`

### Problem

SSE bindet zwar an `127.0.0.1`, ist aber unauthentifiziert. Jeder erreichbare lokale Prozess kann Docker-Code ausführen, LanceDB abfragen oder mit einer Session-ID PII deanonymisieren. Session-IDs sind damit Bearer-Capabilities.

### Umsetzung

Eine verbindliche Betriebsvariante wählen:

- SSE standardmäßig deaktivieren und nur per explizitem Opt-in aktivieren; oder
- API-Key/Bearer-Token mit sicherer Konfiguration einführen.

Zusätzlich bei aktiviertem SSE:

- Origin-Prüfung und CSRF-Schutz;
- Rate-Limit und Concurrency-Limit;
- keine Bind-Adresse aus unvalidierter User-Eingabe;
- ausdrückliche Warnung über PII-/Docker-Risiko;
- Auth-Fehler ohne Detailleck.

### Abnahmekriterien

- Default bleibt sicherer stdio-Betrieb.
- SSE kann nicht unbeabsichtigt öffentlich gebunden werden.
- Unauthentifizierte SSE-Aufrufe werden abgewiesen, falls SSE als produktive Option bleibt.
- README beschreibt das tatsächliche Threat Model.

### Tests

- CLI-Tests für stdio-Default und localhost-Binding.
- SSE-Aufruf ohne Auth.
- Origin-/CSRF-Tests, sofern HTTP-SSE beibehalten wird.

---

## TASK-005: Projektisolierung und Autorisierung für LanceDB einführen

**Status:** Erledigt
**Priorität:** P0 bei Multi-User/Netzbetrieb, P1 lokal
**Contract:** `C-AC`, `C-INJ`, `F-MCP`
**CWE:** CWE-639, CWE-862, CWE-89
**OWASP:** A01:2025, A05:2025
**Fundstellen:** `src/server.py:36-46`, `src/core/models.py:29-37`, `src/knowledge/lancedb_adapter.py:5-9`

### Problem

`project_id` wird nur mit `[a-zA-Z0-9_-]+` validiert. Das verhindert einfache Filter-Injection, beweist aber keine Berechtigung. Ein erreichbarer Client kann potenziell andere Projektkennungen erraten und Daten lesen.

### Umsetzung

- Server-seitige Projekt-Allowlist oder Principal-basierte Berechtigung einführen.
- In Multi-User-SSE die Projektberechtigung aus Authentifizierung ableiten.
- Client darf nicht allein die Besitzgrenze bestimmen.
- Zusätzlich im Adapter selbst strikt validieren; die MCP-Schicht ist keine ausreichende Verteidigungsschicht.
- LanceDB-Filter sicher und ohne rohe Client-Strings konstruieren.

### Abnahmekriterien

- Nicht autorisierte Projektabfrage wird abgewiesen.
- Autorisierte Abfrage liefert ausschließlich das berechtigte Projekt.
- Keine direkte Cross-Project-Ausgabe durch manipulierte Parameter.

### Tests

- Cross-Project-Isolationstest.
- Allowlist-/Principal-Tests.
- ungültige IDs und Filterzeichen.
- Adapter-Direktaufruf mit ungültiger ID.

---

## TASK-006: Vault nebenläufigkeitssicher und speicherbegrenzt machen

**Status:** Erledigt
**Priorität:** P0/P1
**Contract:** `F-DOS`, `F-TOC`, `C-LOG`
**CWE:** CWE-400, CWE-367, CWE-532
**Fundstellen:** `src/privacy/vault.py:16-38`

### Problem

`sessions` und `stats` werden ohne Lock verändert. Parallel ausgeführte MCP-Calls können TTL-Purge, FIFO-Eviction, Zähler und Session-Grenze inkonsistent machen. Die Begrenzung auf 1.000 Sessions begrenzt außerdem nicht die gespeicherte PII-Menge (bis zu ca. 100 MiB bei 100 KiB pro Session).

### Umsetzung

- `threading.Lock`/`RLock` für alle kritischen Vault-Operationen.
- TTL-Purge, Eviction und Insert atomar behandeln.
- Maximalbudget in Bytes zusätzlich zur Sessionanzahl.
- Session-ID-Eingabe als UUIDv4 validieren und begrenzen.
- Keine PII in Stats oder Logs.
- Eviction-Strategie dokumentieren; FIFO oder LRU bewusst wählen.

### Abnahmekriterien

- `max_sessions` bleibt auch unter Parallelität invariant.
- Bytebudget wird nie überschritten.
- TTL- und Eviction-Verhalten sind deterministisch.
- Session-ID ist UUIDv4 und hat keine unbeschränkte Eingabelänge.

### Tests

- Parallel erzeugte Sessions.
- TTL mit kontrollierter Uhrzeit.
- 1.000/1.001 Sessions.
- Bytebudget.
- unbekannte, abgelaufene und ungültige Session-ID.

---

# P1 – Funktionale Lücken und wichtige Security-Härtung

## TASK-007: LanceDB produktiv konfigurierbar und nutzbar machen

**Status:** Erledigt
**Priorität:** P1
**Contract:** `C-INJ`, `C-AC`, `C-VAL`, `F-FIT`
**Fundstellen:** `src/server.py:25`, `src/knowledge/lancedb_adapter.py:3-14`, `README.md:3,27`

### Problem

`server.py` erstellt `LanceDBAdapter()` mit `table=None` und `embedder=None`. Dadurch ist das Tool im normalen Start ohne Dependency Injection nicht verwendbar und liefert immer `KnowledgeUnavailableError`.

### Umsetzung

- `LANCEDB_PATH` und Tabellenname über sichere Konfiguration einführen.
- Keine unvalidierten Pfade oder Netzwerk-Downloads.
- Lokalen, dokumentierten `EmbeddingProvider` bereitstellen.
- Keine ungefragten Modell-/Embedding-Downloads.
- Schema beim Start bzw. beim ersten Query prüfen:
  - `vector`
  - `text`
  - `project_id`
  - `source`
- Fehlende DB/Tabelle/Spalten strukturiert melden.
- Distanz-/Score-Semantik dokumentieren: höherer `score` = besser.

### Abnahmekriterien

- Konfiguriertes lokales LanceDB kann erfolgreich abfragen.
- Projektfilter wird bei jeder Suche angewandt.
- Ergebnis enthält nur `text`, `source`, `score`.
- `top_k` bleibt auf 1–50 begrenzt.

### Tests

- Reales lokales LanceDB-Fixture mit Marker `integration`.
- Deterministischer Fake-Embedder im Standardtestlauf.
- Fehlende DB/Tabelle/Spalten.
- Sortierung und Score-Normalisierung.
- Cross-Project-Isolation.

---

## TASK-008: Docker-Image-Integrität und direkte Sprachvalidierung

**Status:** Erledigt
**Priorität:** P1
**Contract:** `F-SC`, `F-INT`, `F-VAL`
**CWE:** CWE-1104, CWE-494, CWE-20, CWE-755
**OWASP:** A03:2025, A05:2025, A08:2025
**Fundstellen:** `src/sandbox/docker_runner.py:16,20-30`

### Problem

Mutable Tags (`python:3.11-slim`, `node:20-alpine`) werden nur auf lokales Vorhandensein geprüft. Außerdem kann ein direkter `DockerRunner.run(..., language=...)`-Aufruf bei unbekannter Sprache einen `KeyError` auslösen.

### Umsetzung

- Immutable Image-Digests konfigurieren.
- Erwartete Image-ID/Digest prüfen.
- Signatur/Provenienz/SBOM für Release-Images dokumentieren.
- Keine automatischen Pulls.
- Sprach-Allowlist zusätzlich im Runner validieren.
- Stabilen Fehler `unsupported_language` zurückgeben.
- Python-Image-Version zwischen Spezifikation, Code und README harmonisieren. Die bestätigte Projektentscheidung ist derzeit Python 3.11; `mcp_idea.md` nennt noch 3.10.

### Tests

- Unbekannte Sprache direkt am Runner.
- Fehlendes Image.
- Unerwarteter Digest/Image-ID.
- Python- und JavaScript-Command.
- Kein Pull-Aufruf.

---

## TASK-009: OKF-Ressourcen begrenzen und Paketierung korrigieren

**Status:** Erledigt
**Priorität:** P1
**Contract:** `F-PATH`, `F-DOS`, `F-MCP`, `C-VAL`, `C-CFG`
**CWE:** CWE-22, CWE-400, CWE-16
**Fundstellen:** `src/knowledge/okf_resource.py:6-12`, `pyproject.toml:35-36`, `src/server.py:25`

### Problem

`Path.read_text()` lädt beliebig große OKF-Dateien. Außerdem enthält das gebaute Wheel die Datei `okf/example.md` nicht. Der Default `OKF_ROOT="okf"` funktioniert nach Installation außerhalb des Repository-Verzeichnisses nicht zuverlässig.

### Umsetzung

- Maximale Resourcegröße definieren, empfohlen 1 MiB.
- Datei begrenzt/streaming lesen.
- Überschreitung strukturiert als `resource_too_large` melden.
- Nur sichere IDs `[a-zA-Z0-9_-]+` erlauben.
- `OKF_ROOT` als sicher konfigurierbaren lokalen Pfad dokumentieren.
- Entweder OKF-Daten in das Paket aufnehmen oder bewusst als externe Konfiguration behandeln.
- Keine Frontmatter-Ausführung oder Interpretation als Instruktion.

### Tests

- Oversized-Markdown.
- unbekannte ID.
- Path-Traversal-/Symlink-Fälle.
- UTF-8-/Frontmatter-Erhalt.
- Installations-Smoke-Test gegen gebautes Wheel.

---

## TASK-010: Presidio-/NER-Strategie vollständig implementieren

**Status:** Erledigt
**Priorität:** P1
**Contract:** `C-VAL`, `F-CMP`, `F-LLM`
**Fundstellen:** `src/server.py:14-23`, `src/privacy/detector.py:9-77`, `pyproject.toml:12-14`

### Problem

Die Default-Installation enthält kein deutsches spaCy-Modell. Im Fallback erkennt die Regex-Implementierung allgemeine Personennamen nur in engen `Herr/Frau`-Mustern. Damit ist die zugesagte deutsche PII-Abdeckung in einer sauberen Installation nicht vollständig.

### Umsetzung

- Presidio-/spaCy-Modell nur erkennen, niemals automatisch herunterladen.
- Installationsweg für optionales Modell dokumentieren.
- Fallback ausdrücklich als eingeschränkten Modus kennzeichnen.
- Allgemeine, konservative Person-Erkennung nur mit ausreichender Confidence ergänzen.
- Regex-Entities mit Prüfziffern beibehalten:
  - PERSON
  - EMAIL_ADDRESS
  - IBAN_CODE
  - deutsche Steuer-ID
  - DE/AT-Telefonnummern
  - deutsche Kfz-Kennzeichen
  - Personalausweisnummer
  - Custom Regex Entities
- Lange Treffer zuerst ersetzen.
- Wiederholte identische Werte innerhalb einer Session stabil labeln.

### Tests

- Alle Entity-Typen end-to-end.
- Wiederholte Werte und verschiedene Werte.
- Gültige/ungültige IBAN und Steuer-ID.
- `de`/`en` und unbekannte Sprache.
- Presidio vorhanden/nicht vorhanden.
- Kein Netzwerkzugriff/kein Modelldownload.

---

## TASK-011: Audit-Statistik und „blocked PII types“ präzisieren

**Status:** Erledigt
**Priorität:** P1
**Contract:** `C-LOG`, `F-CMP`
**CWE:** CWE-532, CWE-778
**Fundstellen:** `src/privacy/vault.py:16-38`, `README.md:30`, ursprüngliche Spezifikation Abschnitt B

### Problem

Die aktuelle Statistik enthält erkannte Entity-Typen, aber keine Blockierungssemantik und keine `blocked_pii_types`. Die Spezifikation spricht von Metriken über blockierte PII-Typen.

### Umsetzung

Eine Variante verbindlich wählen:

- Erkennungs-/Maskierungsmodell als „blocked“ definieren und entsprechend dokumentieren; oder
- echte Policy einführen, die bestimmte Entity-Typen blockiert und anonym zählt.

Statistiken müssen weiterhin enthalten:

- `total_anonymizations`
- `total_deanonymizations`
- `total_pii_entities`
- `entities_by_type`
- `active_sessions`
- `expired_sessions`
- `detector_mode`
- `supported_languages`

Keine Session-IDs, Werte, Prompts oder Platzhalterinhalte.

### Tests

- JSON-Schema-/Contract-Test für `privacy://audit_stats`.
- PII-freie Serialisierung.
- Zähler-Inkrement und Ablauf.
- Fehlerzähler für unbekannte Sessions.

---

## TASK-012: Security-Prompt gegen Prompt Injection härten

**Status:** Erledigt
**Priorität:** P1
**Contract:** `F-LLM`, `F-MCP`, `F-ASI`
**CWE:** CWE-74, CWE-94
**OWASP:** LLM01:2025
**Fundstelle:** `src/security_prompt/template.py:1-8`

### Problem

`architecture_description` wird direkt in einen LLM-orientierten Prompt eingebettet. Der Satz „Treat ... as untrusted data“ ist keine technische Isolation. Eingebettete Anweisungen können von einem nachgelagerten Agenten missinterpretiert werden.

### Umsetzung

- Beschreibung als strukturiertes Datenfeld mit eindeutigen Delimitern ausgeben.
- Keine Tool-Aufrufe oder externen Aktionen aus dem Feld zulassen.
- Prompt-Ausgabe als Daten-/Templatevertrag dokumentieren.
- Länge maximal 100 KiB.
- Keine ausgehenden LLM-Aufrufe.
- Nachgelagerte MCP-Clients müssen untrusted content getrennt behandeln.

### Tests

- adversariale Texte wie „ignore previous instructions“.
- Tool-Call-/Exfiltrationsanweisungen.
- Unicode-/100-KiB-Grenzen.
- Prüfung, dass keine externe Aktion ausgelöst wird.

---

# P2 – Tests, Architektur, Packaging und Dokumentation

## TASK-013: Echte FastMCP-Protocol-Contract-Tests ergänzen

**Status:** Erledigt
**Priorität:** P1/P2
**Contract:** `F-MCP`, `F-FIT`, `C-VAL`, `F-EXC`
**CWE:** CWE-1188, CWE-1061
**Fundstellen:** `tests/test_server.py:1-10`

### Problem

Die vorhandenen Servertests rufen private Python-Funktionen direkt auf. Sie testen nicht die MCP-Schicht, generierte Schemas, `isError`-Semantik, Resource-URIs oder Prompt-Aufrufe.

### Umsetzung

Mit dem FastMCP-In-Process-Client testen:

- alle vier Tools registriert;
- `okf://wiki/{concept_id}` registriert;
- `privacy://audit_stats` registriert;
- `grill_me_security_audit` registriert;
- Input-/Output-Schemas;
- gültige und ungültige Tool-Aufrufe;
- unbekannte Ressourcen;
- Resource-Text und Audit-JSON;
- Prompt-Aufruf;
- strukturierte Fehler und `isError`;
- keine unbekannten/zusätzlichen Argumente.

### Abnahmekriterien

Der MCP-Contract kann ohne Docker-Daemon und ohne externe Downloads deterministisch ausgeführt werden.

---

## TASK-014: Integrationstests korrekt markieren und dokumentieren

**Status:** Erledigt
**Priorität:** P2
**Contract:** `F-FIT`
**Fundstelle:** `pyproject.toml:27-30`, `README.md:79-84`

### Problem

`pyproject.toml` setzt global `addopts = "-m 'not integration'"`. Es existieren keine `@pytest.mark.integration`-Tests. Daher liefert `uv run pytest -m integration` nur „deselected“ und Exit-Code 5. README behauptet fälschlicherweise, LanceDB-/Docker-Integrationstests seien vorhanden.

### Umsetzung

- Mindestens ein LanceDB-Integrationstest und ein Docker-Integrationstest hinzufügen oder die Behauptung entfernen.
- Marker-Strategie korrigieren:
  - Standard: `uv run pytest -m 'not integration'`
  - Integration explizit: `uv run pytest -m integration` ohne widersprüchliches globales Addopt
- Docker-Test muss bei fehlendem Daemon sauber skippen oder explizit dokumentiert scheitern.
- README aktualisieren.

### Tests

- `uv run pytest`.
- `uv run pytest -m 'not integration'`.
- `uv run pytest -m integration`.
- Keine leere Testauswahl ohne klare Meldung.

---

## TASK-015: VSA-Architektur-Fitness und Ratchet implementieren

**Status:** Erledigt
**Priorität:** P2
**Contract:** `F-FIT`
**CWE:** CWE-1061, CWE-1173
**Fundstellen:** Verzeichnis `src/`, fehlende Fitness-Tests

### Problem

Die Slice-Struktur ist vorhanden, aber nicht automatisiert gegen Drift geschützt.

### Umsetzung

Pytest-basierte Import-Fitness-Regeln einführen:

- `src/privacy` importiert nicht `src/knowledge`, `src/sandbox` oder `src/security_prompt`.
- `src/knowledge` importiert nicht andere fachliche Slices.
- `src/sandbox` importiert nicht Privacy-/Knowledge-Interna.
- `src/core` bleibt fachlich neutral und importiert keine Slices.
- Nur `src.server` darf alle Slices komponieren.
- Jede entdeckte Boundary-Verletzung erhält einen permanenten Regressionstest.

### Abnahmekriterien

Fitness-Test läuft standardmäßig in `uv run pytest` und schlägt bei neuem Cross-Slice-Import fehl.

---

## TASK-016: Packaging- und Installations-Smoke-Tests

**Status:** Erledigt
**Priorität:** P2
**Contract:** `F-SC`, `F-CFG`, `F-FIT`
**Fundstellen:** `pyproject.toml`, `okf/`, `claude_desktop_config.json`

### Umsetzung

- `uv build` in CI testen.
- Wheel in einer sauberen Umgebung installieren.
- `python -m src.server --help` prüfen.
- OKF-Ressource nach Installation prüfen.
- Entscheiden, ob `okf/` und Claude-Konfiguration Paketdaten sind oder nur Repository-/Deployment-Dateien.
- Keine `.coverage`, `dist/`, `__pycache__` oder virtuelle Umgebung committen.
- Versions-/Lockfile-Integrität und SBOM-Strategie dokumentieren.

---

## TASK-017: Coverage-Schwelle und Security-Sensoren einführen

**Status:** Erledigt
**Priorität:** P2
**Contract:** `F-FIT`, `F-DOS`, `F-MCP`, `F-RLM`
**Aktuell:** 87 % Gesamt-Coverage ohne konfigurierte Mindestschwelle

### Fehlende Abdeckung

- Docker-Timeout und Cleanup
- Output >1 MiB
- fehlendes Image
- JavaScript-Command
- Session-TTL/Kapazität/Concurrency
- UUID-Validierung
- OKF-Größenlimit
- LanceDB-Isolation und fehlende Spalten
- MCP-Protocol-Dispatch
- SSE/stdio-Contract
- Presidio-Startup ohne Download
- Prompt Injection
- Fehler-Masking

### Umsetzung

- `pytest-cov` Mindestschwelle konfigurieren, z. B. zunächst 85 %, anschließend ratcheten.
- Security-Regressionen mit Contract-ID im Testnamen oder Docstring kennzeichnen, z. B. `test_F_DOS_docker_output_is_bounded`.
- CI-Sensoren für Tests, Build, Lockfile und Architekturgrenzen ergänzen.

---

## TASK-018: Spezifikationen und README konsolidieren

**Status:** Erledigt
**Priorität:** P2
**Fundstellen:** `mcp_idea.md`, `README.md`, `CONTEXT.md`

### Zu korrigieren

- Python-Image: `mcp_idea.md` nennt 3.10, bestätigte Implementierungsentscheidung ist 3.11.
- `docker://logs`: aus Architekturzeichnung entfernen oder als bewusst nicht implementiert markieren.
- Integrationstestbefehle korrekt darstellen.
- LanceDB-Konfiguration und Embedding-Provider dokumentieren.
- Presidio-Fallback und optionales Modell klar erklären.
- Vertex-/Mistral-Ziel als generische MCP-Kompatibilität oder als bewusst nicht implementiert dokumentieren.
- SSE-Risiko als potenzielle PII-Offenlegung und Docker-Codeausführungsrisiko beschreiben.
- `OKF_ROOT` und Paketinstallation korrekt dokumentieren.
- „Production-ready“ nur nach Abschluss der P0/P1-Aufgaben verwenden.

---

# Nicht implementieren / negative Anforderungen

Diese Anforderungen bleiben verbindlich:

- Keine Host-Subprocess-Ausführung als Docker-Fallback.
- Kein Netzwerk im Sandbox-Container.
- Keine privilegierten Container.
- Kein Mount des Projektverzeichnisses in den Container.
- Kein automatischer spaCy-/Embedding-/Docker-Image-Download.
- Keine Speicherung des Vaults auf Disk.
- Keine Original-PII, Prompts oder Mapping-Inhalte in Logs.
- Keine `docker://logs`-MCP-Ressource.
- Keine ausgehenden LLM-Aufrufe im Security-Prompt.
- Keine Interpretation von OKF-Frontmatter oder Ressourceninhalten als ausführbare Instruktionen.
- Keine unvalidierten Client-Filterstrings in LanceDB.
- Keine öffentliche/ungebundene SSE-Bindung.

# Referenz: Betroffene CodeUltra-Kriterien

## Core

- `C-AC` – Projekt-/Objektzugriff und Isolation
- `C-INJ` – LanceDB-Filter, Tool-/Resource-Eingaben, Prompt-Ausgabe
- `C-VAL` – Pydantic-Grenzen, IDs, Sprachen, Größenlimits
- `C-CFG` – SSE, Fehlerdetails, Image-/Pfadkonfiguration
- `C-LOG` – PII-freies Logging und Audit

## Full

- `F-SC` – Dependency-, Image- und SBOM-Integrität
- `F-DES` – Threat Model, Quoten und Missbrauchsschutz
- `F-INT` – Image-/Container-/Parser-Integrität
- `F-EXC` – Timeout-, Cleanup- und Fehlerverträge
- `F-PATH` – OKF-Pfade und Symlink-/Traversal-Schutz
- `F-TOC` – Vault-Concurrency und Docker Cleanup
- `F-DOS` – Tool-, Resource-, Log-, Vault- und Query-Limits
- `F-LLM` – Prompt Injection und untrusted content
- `F-ASI` – Codeausführung, Tool Misuse, excessive agency
- `F-CMP` – DSGVO-PII-Grenzanonymisierung und Auditierbarkeit
- `F-FIT` – VSA-Importgrenzen, Fitness-/Ratchet-Tests
- `F-MCP` – Tool-/Resource-Schema, Gateway-Governance, progressive disclosure
- `F-RLM` – Sandbox-Isolation, begrenzte Ausführung und Ressourcen

# Empfohlene Release-Gates

## Gate A – Lokaler Prototyp

- [x] stdio startet
- [x] vier Tools registriert
- [x] zwei Ressourcen registriert
- [x] Security-Prompt registriert
- [x] deterministische Tests bestehen
- [x] Docker verwendet restriktive Containeroptionen

## Gate B – Sicherer lokaler Release

- [x] TASK-001 bis TASK-006
- [x] MCP-Protocol-Contract-Tests
- [x] OKF-Größenlimit
- [x] echte Output-Begrenzung
- [x] korrigierte README/Testbefehle

## Gate C – Enterprise-Release

- [x] serverseitige Projektberechtigungen
- [x] authentifiziertes oder deaktiviertes SSE
- [x] produktiv konfigurierte LanceDB-Suche
- [x] digest-gepinnte/verifizierte Images
- [x] Integrationstests
- [x] VSA-Fitness-/Ratchet-Sensoren
- [x] Packaging-/SBOM-/CI-Gates
- [x] aktualisiertes Threat Model und Compliance-Dokumentation

# Review-Schema 3.2 – Kurzsummary

```json
{
  "schema_version": "3.2",
  "summary": {
    "score": 9,
    "critical": 0,
    "warning": 0,
    "optimization": 0
  },
  "reviewed_commit": "ca3f4fb",
  "tests": "22 passed",
  "coverage": "86% minimum gate",
  "production_status": "hardened_local_release_with_deployment_gates",
  "prototype_status": "usable_under_strict_local_single_user_model"
}
```


# Erweiterungsslices (bestätigt)

- [x] DSGVO-Prompt für Daten-Schemas und API-Strukturen in einem deterministischen Template erweitert.
- [x] Regex-/Presidio-Vertrag für `de`, `en`, `fr`, `it`, `es` sowie ISO-IBAN/E.164 ergänzt.
- [x] Expliziter LanceDB-`search_mode=hybrid` mit kontrolliertem `knowledge_hybrid_unavailable` umgesetzt.
- [x] Optionales loopback-only Audit Studio mit PII-freier Statistikansicht umgesetzt.
- [x] ADRs und README/CONTEXT aktualisiert.

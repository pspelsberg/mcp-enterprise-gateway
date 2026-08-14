# Enterprise Privacy & Context Gateway

Begriffe des MCP-Gateways für datenschutzbewusste lokale Kontext- und Codewerkzeuge.

## Gateway und MCP

**Enterprise Gateway**:
Lokaler MCP-Server, der Datenschutz-, Wissens- und Sandbox-Funktionen für MCP-Clients bündelt.
_Avoid_: Remote Gateway, Cloud Gateway

**MCP Tool**:
Eine vom Gateway bereitgestellte, aufrufbare Operation mit validierten Eingaben und strukturiertem Ergebnis.
_Avoid_: Plugin, beliebiger Host-Aufruf

**MCP Resource**:
Eine vom Gateway bereitgestellte, adressierbare Kontextquelle, deren Inhalt als Daten und nicht als auszuführende Instruktion gilt.
_Avoid_: Prompt-Datei, Tool

## Datenschutz

**PII**:
Personenbezogene Information, die im Gateway erkannt, durch einen stabilen Platzhalter ersetzt und nur temporär einer Sitzung zugeordnet wird.
_Avoid_: Secret, beliebiger Text

**Session Vault**:
Flüchtiger, ausschließlich im Arbeitsspeicher gehaltener Zuordnungsraum zwischen anonymisierten Platzhaltern und ursprünglichen PII-Werten.
_Avoid_: Datenbank, persistenter Cache

**Anonymized Prompt**:
Ein Prompt, in dem erkannte PII durch sitzungsgebundene Platzhalter ersetzt wurde.
_Avoid_: Verschlüsselter Prompt, redigierter Prompt

## Wissen

**Project-Isolated Vector Search**:
Eine Vektorsuche, deren Ergebnisse ausschließlich zu einer serverseitig validierten Projektkennung gehören.
_Avoid_: globale Suche, unbeschränkte Suche

**OKF Concept**:
Ein lokales Markdown-Konzept mit YAML-Frontmatter, das über eine sichere MCP-Resource-Adresse exponiert wird.
_Avoid_: ausführbares Dokument, Remote-Wiki

## Ausführung

**Docker Sandbox**:
Ein nicht privilegierter, netzwerkisolierter und ressourcenbegrenzter Container zur Ausführung erlaubter Programmiersprachen.
_Avoid_: Host-Prozess, lokale Subprocess-Ausführung

**Local Development Mode**:
Betrieb mit primärem stdio-Transport und optionalem, ausschließlich an localhost gebundenem SSE-Transport ohne Benutzerkonten.
_Avoid_: öffentliches Deployment, authentifiziertes Multi-Tenant-System

## Architektur

**Vertical Slice**:
Eine fachlich geschlossene Funktionseinheit mit eigenem Eingangs- und Ausgangsvertrag innerhalb des modularen Monolithen.
_Avoid_: technische Schicht, globales Utility-Modul

**Gateway Core**:
Gemeinsam genutzte Verträge und Konfiguration, die keine fachliche Slice-Logik besitzen.
_Avoid_: Ablage für beliebige Cross-Slice-Logik

## Erweiterte Suche und Audit

**Hybrid Search**:
Eine Suche, die semantische Vektorsuche mit indexierter Volltextsuche für exakte Begriffe kombiniert.
_Avoid_: stiller Fallback, globale Volltextsuche

**Audit Studio**:
Optionale lokale Darstellung ausschließlich aggregierter, PII-freier Datenschutzmetriken.
_Avoid_: Monitoring für Mehrbenutzerbetrieb, PII-Dashboard

## Maskierungsrichtlinien

**Whitelist**:
Literal abgeglichene Begriffe, die von der PII-Maskierung ausgenommen sind.
_Avoid_: reguläre Ausdrücke als Whitelist

**Blacklist**:
Literal abgeglichene Begriffe, die unabhängig vom Detektor zwingend als Custom-PII maskiert werden.
_Avoid_: optionale oder strategieabhängige Anwendung

**Maskierungsstrategie**:
Auswahl zwischen rückführbaren Platzhaltern sowie nicht rückführbaren Redaction- oder Hash-Ausgaben.
_Avoid_: Deanonymisierung von Redaction/Hash

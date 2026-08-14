# ADR-002: Optionales lokales Audit Studio

## Status
Angenommen

## Entscheidung
Das Audit Studio wird als optionaler Python-Stdlib-Slice über `python -m src.audit_studio` gestartet. Es bindet ausschließlich an `127.0.0.1` und stellt nur aggregierte Werte aus `privacy://audit_stats` bereit. Prompts, PII, Session-IDs und Vault-Mappings sind nicht zugänglich.

## Konsequenzen
Die UI ist für lokale Einzelbenutzerdiagnose gedacht und kein authentifiziertes Enterprise-Dashboard. Für Remote- oder Mehrbenutzerbetrieb ist sie nicht freigegeben. Die Oberfläche verwendet keine externen CDNs und setzt eine restriktive CSP.

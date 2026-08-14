"""Optional loopback-only dashboard for aggregate privacy statistics.

The dashboard is deliberately an independent presentation slice. It proxies
only a validated loopback audit endpoint and never imports the gateway
composition root or receives PII/session mappings.
"""
from __future__ import annotations
import argparse
import json
import os
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from secrets import token_urlsafe
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

_HOST = "127.0.0.1"
_MAX_STATS_BYTES = 64 * 1024
_ALLOWED_STATS = {"total_anonymizations", "total_deanonymizations", "total_pii_entities",
                  "entities_by_type", "blocked_pii_types", "expired_sessions", "active_sessions",
                  "failed_deanonymizations", "detector_mode", "detector_modes", "supported_languages"}
_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'"><title>Audit Studio</title><style>body{font:16px sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}canvas{width:100%;max-height:320px;border:1px solid #ddd}li{margin:.3rem 0}</style></head><body><h1>Privacy Audit Studio</h1><p>Aggregated local metrics only. No prompts, PII or session IDs are displayed.</p><canvas id="chart" width="800" height="300"></canvas><h2>Metrics</h2><ul id="metrics"></ul><script>
async function load(){const r=await fetch('/api/audit_stats', {credentials:'same-origin'});if(!r.ok)throw Error('stats unavailable');const d=await r.json();const ul=document.querySelector('#metrics');ul.innerHTML='';for(const [k,v] of Object.entries(d)){const li=document.createElement('li');li.textContent=k+': '+(typeof v==='object'?JSON.stringify(v):v);ul.append(li)}const entries=Object.entries(d.blocked_pii_types||{});const c=document.querySelector('#chart'),x=c.getContext('2d');const max=Math.max(1,...entries.map(e=>e[1]));entries.forEach((e,i)=>{const w=700/Math.max(1,entries.length),h=240*e[1]/max;x.fillStyle='#245';x.fillRect(50+i*w,260-h,w-8,h);x.fillStyle='#000';x.fillText(e[0],50+i*w,280);x.fillText(e[1],50+i*w,255-h)})}load().catch(e=>document.querySelector('#metrics').textContent=e.message);
</script></body></html>"""

def _loopback_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("audit upstream must be a credential-free HTTP URL")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("audit upstream must target loopback")
    if parsed.port is not None and not 1024 <= parsed.port <= 65535:
        raise ValueError("audit upstream port is invalid")
    return value

def _safe_stats(raw: bytes) -> dict:
    if len(raw) > _MAX_STATS_BYTES:
        raise ValueError("audit response is too large")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("audit response is invalid")
    return {key: value[key] for key in _ALLOWED_STATS if key in value}

def _fetch_stats() -> dict:
    url = _loopback_url(os.getenv("AUDIT_STATS_URL", "http://127.0.0.1:8000/privacy/audit_stats"))
    token = os.getenv("AUDIT_STUDIO_UPSTREAM_TOKEN") or os.getenv("MCP_SSE_TOKEN")
    request = Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    with urlopen(request, timeout=2) as response:
        return _safe_stats(response.read(_MAX_STATS_BYTES + 1))

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): return
    def _authorized(self) -> bool:
        token = os.getenv("AUDIT_STUDIO_TOKEN")
        authorization = self.headers.get("Authorization", "")
        cookies = self.headers.get("Cookie", "")
        cookie_token = next((part.split("=", 1)[1] for part in cookies.split(";") if part.strip().startswith("audit_token=") and "=" in part), "")
        expected = f"Bearer {token}" if token else ""
        return bool(token and len(token) >= 32 and (hmac.compare_digest(authorization, expected) or hmac.compare_digest(cookie_token, token)))
    def do_GET(self):
        if self.path == "/":
            token = os.getenv("AUDIT_STUDIO_TOKEN")
            if not token or len(token) < 32:
                self.send_response(503); self.end_headers(); return
            body=_HTML.encode(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Set-Cookie", "audit_token=" + token + "; HttpOnly; SameSite=Strict; Path=/"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
        if self.path == "/api/audit_stats":
            if not self._authorized():
                body = b'{"error":"unauthorized"}'; self.send_response(401); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
            try:
                body=json.dumps(_fetch_stats(), ensure_ascii=False, sort_keys=True).encode()
                self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
            except Exception:
                self.send_error(502, "audit stats unavailable")
            return
        self.send_error(404)
    def do_POST(self): self.send_error(405)

def main():  # pragma: no cover
    parser=argparse.ArgumentParser(description="Optional loopback-only aggregate audit dashboard")
    parser.add_argument("--port", type=int, default=8765)
    args=parser.parse_args()
    if not 1024 <= args.port <= 65535: parser.error("port must be between 1024 and 65535")
    token = os.getenv("AUDIT_STUDIO_TOKEN")
    if not token:
        token = token_urlsafe(32); os.environ["AUDIT_STUDIO_TOKEN"] = token
        print("Audit Studio generated a temporary local token; use the displayed URL only locally.")
    if len(token) < 32: parser.error("AUDIT_STUDIO_TOKEN must contain at least 32 characters")
    server=ThreadingHTTPServer((_HOST,args.port),_Handler)
    print(f"Audit Studio listening on http://{_HOST}:{args.port}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
if __name__ == "__main__": main()

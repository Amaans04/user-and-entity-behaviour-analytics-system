"""Ingest API - lets agents and log shippers push events over HTTP.

Endpoints (JSON responses)::

    GET  /api/v1/health
    GET  /api/v1/workspaces/<workspace>/status                 (token)
    POST /api/v1/workspaces/<workspace>/ingest/<stream>        (token)
         body: JSON array, JSON-lines or CSV  (Content-Type: application/json,
               application/x-ndjson or text/csv); <stream> = auth | access | network |
               resource | users | devices | ground_truth

Authenticate with ``Authorization: Bearer <token>`` (tokens are created by an admin
in the dashboard, Administration -> API tokens, and are scoped to a workspace).

The API does no parsing or scoring itself: an accepted batch is written atomically
into the workspace's ``inbox/`` as ``<stream>__api-<time>.<ext>`` and returns
``202 Accepted``. The collector service imports and scores it on its next tick, so
pushed data and dropped files follow exactly the same, single code path.

Built on the standard library (no web framework needed); run it through the service:
``python -m ueba.service --api``.
"""
from __future__ import annotations

import json
import re
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import auth
from . import workspace as W
from .sources import SCHEMA

MAX_BODY = 64 * 1024 * 1024
VERSION = "1"
_ROUTE = re.compile(r"^/api/v1/workspaces/([a-z0-9-]+)/(status|ingest)(?:/([a-z_]+))?/?$")


class Handler(BaseHTTPRequestHandler):
    server_version = "UEBA-Ingest/1"
    console_db = None            # overridable in tests

    def log_message(self, fmt, *args):   # keep the service output readable
        pass

    def _json(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _token(self) -> str:
        h = self.headers.get("Authorization", "")
        return h[7:].strip() if h.lower().startswith("bearer ") else self.headers.get("X-API-Key", "").strip()

    def _workspace(self, slug: str):
        try:
            ws = W.get(slug)
        except KeyError:
            self._json(404, {"error": f"unknown workspace '{slug}'"})
            return None
        if ws.is_demo:
            self._json(403, {"error": "the demo workspace is read-only"})
            return None
        if not auth.verify_token(self._token(), slug, db=self.console_db):
            auth.audit("api", "api.denied", workspace=slug, detail=self.client_address[0], db=self.console_db)
            self._json(401, {"error": "missing, invalid or out-of-scope API token"})
            return None
        return ws

    def do_GET(self):
        if self.path.rstrip("/") == "/api/v1/health":
            return self._json(200, {"status": "ok", "api_version": VERSION, "time": time.strftime("%Y-%m-%dT%H:%M:%S")})
        m = _ROUTE.match(self.path)
        if not m or m.group(2) != "status":
            return self._json(404, {"error": "not found"})
        ws = self._workspace(m.group(1))
        if ws:
            st = ws.status()
            self._json(200, {"workspace": ws.slug, "name": ws.name, "state": st["state"],
                             "coverage": st["coverage"], "learning_days": st["learning_days"],
                             "queued_files": st["inbox"], "last_analysis": st["last_analysis"]})

    def do_POST(self):
        m = _ROUTE.match(self.path)
        if not m or m.group(2) != "ingest":
            return self._json(404, {"error": "not found"})
        stream = m.group(3) or ""
        if stream not in SCHEMA:
            return self._json(400, {"error": f"stream must be one of {sorted(SCHEMA)}"})
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return self._json(400, {"error": "empty body"})
        if length > MAX_BODY:
            return self._json(413, {"error": f"body larger than {MAX_BODY // 2**20} MB - send smaller batches"})
        ws = self._workspace(m.group(1))
        if not ws:
            return
        body = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        head = body.lstrip()[:1]
        ext = ("csv" if "csv" in ctype else "json" if head == b"[" else "jsonl" if head == b"{" else "csv")
        if ext == "json":
            try:
                json.loads(body)
            except ValueError:
                return self._json(400, {"error": "body is not valid JSON"})
        ws.inbox.mkdir(parents=True, exist_ok=True)
        name = f"{stream}__api-{time.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}.{ext}"
        part = ws.inbox / (name + ".part")
        part.write_bytes(body)
        part.replace(ws.inbox / name)          # atomic: the worker never sees half a batch
        rows = body.count(b"\n") + (0 if body.endswith(b"\n") else 1) - (1 if ext == "csv" else 0)
        self._json(202, {"queued": name, "rows": max(rows, 0) if ext != "json" else len(json.loads(body)),
                         "stream": stream})


def make_server(host: str = "127.0.0.1", port: int = 8600, console_db=None) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"console_db": console_db})
    srv = ThreadingHTTPServer((host, port), handler)
    srv.daemon_threads = True
    return srv

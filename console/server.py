"""DefenseClaw Console: local web server (127.0.0.1 only)."""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from console import commands, data, security  # noqa: E402

ALLOWED_PORT = security.PORT
INTERVAL_S = 15
_STATIC = re.compile(r"[a-z]+\.(?:html|css|js)")
_TYPES = {"html": "text/html; charset=utf-8", "css": "text/css; charset=utf-8", "js": "text/javascript; charset=utf-8"}
_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class Console(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, cli: str, db: Path, folder: Path):
        super().__init__(address, Handler)
        self.cli, self.db, self.folder = cli, Path(db), Path(folder)
        self.key = security.load_key(self.folder / ".key")
        self.log = self.folder / "console.log"
        self.state: dict = {"reachable": None, "loading": True, "errors": []}
        self._lock = threading.Lock()
        self._cli_lock = threading.Lock()  # never two refresh rounds at once
        self.generation = 0  # increases with every action; older refreshes are discarded

    def accept(self, z: dict, gen: int) -> bool:
        with self._lock:
            if gen != self.generation:
                return False
            self.state = z
            return True

    def refresh(self) -> None:
        with self._cli_lock:
            with self._lock:
                gen = self.generation
            self.accept(data.state(self.cli), gen)

    def after_action(self) -> None:
        with self._lock:
            self.generation += 1
        self.refresh()

    def loop(self) -> None:
        while True:
            try:
                self.refresh()
            except Exception as exc:  # the background thread must never die
                with self._lock:
                    self.state = {**self.state, "errors": [f"internal: {exc}"]}
            time.sleep(INTERVAL_S)


class Handler(BaseHTTPRequestHandler):
    server: Console

    def log_message(self, *args):  # no access log (the URL contains the key)
        pass

    def _reply(self, status: int, body: bytes, ctype: str = "application/json; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in _SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._reply(status, json.dumps(obj, ensure_ascii=False).encode())

    def _file(self, name: str) -> None:
        p = self.server.folder / "static" / name
        if not _STATIC.fullmatch(name) or not p.is_file():
            return self._json(404, {"error": "not found"})
        self._reply(200, p.read_bytes(), _TYPES[name.rsplit(".", 1)[1]])

    def _host_ok(self) -> bool:
        if not security.host_ok(self.headers.get("Host"), ALLOWED_PORT):
            self._json(403, {"error": "host"})
            return False
        return True

    def _api_ok(self) -> bool:
        if not security.key_ok(self.headers.get("X-Console-Key"), self.server.key):
            self._json(401, {"error": "key"})
            return False
        return True

    def do_GET(self):
        if not self._host_ok():
            return
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        if path == f"/k/{self.server.key}/":
            return self._file("index.html")
        if path.startswith("/static/"):
            return self._file(path[len("/static/"):])
        if not path.startswith("/api/"):
            return self._json(404, {"error": "not found"})
        if not self._api_ok():
            return
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        if path == "/api/state":
            return self._json(200, self.server.state)
        if path == "/api/counts":
            return self._json(200, data.counts(self.server.db))
        if path == "/api/events":
            return self._json(200, data.events(self.server.db, session=q.get("session") or None,
                                               kind=q.get("kind") or None,
                                               verdict=q.get("verdict") or None))
        if path.startswith("/api/event/"):
            return self._json(200, data.event(self.server.db, path[len("/api/event/"):]))
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return
        if urlsplit(self.path).path != "/api/action":
            return self._json(404, {"error": "not found"})
        if not security.origin_ok(self.headers.get("Origin"), ALLOWED_PORT):
            return self._json(403, {"error": "origin"})
        if not self._api_ok():
            return
        try:
            length = min(int(self.headers.get("Content-Length") or 0), 10_000)
            body = json.loads(self.rfile.read(length) or b"{}")
            argv = commands.build_argv(str(body.get("action", "")), str(body.get("target", "")),
                                       str(body.get("confirmation", "")))
        except (ValueError, json.JSONDecodeError, AttributeError) as exc:
            return self._json(400, {"ok": False, "output": str(exc)})
        result = commands.run(argv, self.server.cli, log=self.server.log)
        self.server.after_action()  # reply only once the new state is loaded
        return self._json(200, result)


def start(port: int = security.PORT, cli: str = str(Path.home() / ".local/bin/defenseclaw"),
          db: Path = Path.home() / ".defenseclaw/audit.db", folder: Path = Path(__file__).resolve().parents[1],
          refresh: bool = True) -> Console:
    s = Console(("127.0.0.1", port), cli, db, folder)
    if refresh:
        threading.Thread(target=s.loop, daemon=True).start()
    return s


if __name__ == "__main__":
    s = start()
    url = f"http://127.0.0.1:{security.PORT}/k/{s.key}/"
    target = s.folder / "URL.txt"
    target.unlink(missing_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(url + "\n")
    s.serve_forever()

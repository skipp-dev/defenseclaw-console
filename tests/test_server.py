import http.client
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from console import server as srv  # noqa: E402
from tests.test_data import make_db  # noqa: E402


@pytest.fixture
def run(tmp_path):
    calls = tmp_path / "calls"
    cli = tmp_path / "cli"
    cli.write_text(f'#!/bin/bash\necho "$@" >> {calls}\ncase "$1" in status) echo "{{}}";; *) echo "[]";; esac\n')
    cli.chmod(0o755)
    folder = tmp_path / "app"
    (folder / "static").mkdir(parents=True)
    (folder / "static" / "index.html").write_text("<html>CONSOLE</html>")
    (folder / "static" / "app.js").write_text("// js")
    s = srv.start(port=0, cli=str(cli), db=make_db(tmp_path), folder=folder, refresh=False)
    port = s.server_address[1]
    srv.ALLOWED_PORT = port
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    yield {"port": port, "k": s.key, "calls": calls}
    s.shutdown()
    s.server_close()


def _req(run, method, path, host=None, headers=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", run["port"], timeout=5)
    h = {"Host": host or f"127.0.0.1:{run['port']}", **(headers or {})}
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
    r = c.getresponse()
    return r.status, r.read().decode(), dict(r.getheaders())


def _k(run):
    return {"X-Console-Key": run["k"]}


def _post_headers(run):
    return {**_k(run), "Origin": f"http://127.0.0.1:{run['port']}", "Content-Type": "application/json"}


def test_foreign_host_403(run):
    assert _req(run, "GET", f"/k/{run['k']}/", host="evil.com")[0] == 403
    assert _req(run, "GET", "/api/counts", host=f"evil.com:{run['port']}", headers=_k(run))[0] == 403


def test_api_without_key_401(run):
    assert _req(run, "GET", "/api/counts")[0] == 401
    assert _req(run, "GET", "/api/counts", headers={"X-Console-Key": "wrong"})[0] == 401
    status, text, headers = _req(run, "GET", "/api/counts", headers=_k(run))
    assert status == 200 and json.loads(text)["seen"] == 5
    assert headers["Cache-Control"] == "no-store" and "default-src 'self'" in headers["Content-Security-Policy"]


def test_index_only_with_key(run):
    assert _req(run, "GET", "/")[0] == 404
    assert _req(run, "GET", "/k/wrong/")[0] == 404
    status, text, _ = _req(run, "GET", f"/k/{run['k']}/")
    assert status == 200 and "CONSOLE" in text


def test_static_file_outside_404(run):
    assert _req(run, "GET", "/static/app.js")[0] == 200
    for p in ["/static/../console/server.py", "/static/%2e%2e/console/server.py", "/static/"]:
        assert _req(run, "GET", p)[0] == 404, p


def test_post_foreign_origin_403(run):
    body = {"action": "alert_ack", "target": "abc-1"}
    for origin in [None, "https://evil.com"]:
        headers = {**_k(run), "Content-Type": "application/json", **({"Origin": origin} if origin else {})}
        assert _req(run, "POST", "/api/action", headers=headers, body=body)[0] == 403
    assert not run["calls"].exists()


def test_invalid_action_400_without_cli_call(run):
    for body in [{"action": "skill_block", "target": "--all"}, {"action": "uninstall", "target": "x"},
                 {"action": "mode", "target": "action"}]:
        assert _req(run, "POST", "/api/action", headers=_post_headers(run), body=body)[0] == 400
    assert not run["calls"].exists()


def test_valid_action_calls_cli_then_refreshes(run):
    status, text, _ = _req(run, "POST", "/api/action", headers=_post_headers(run),
                           body={"action": "alert_ack", "target": "abc-1"})
    assert status == 200 and json.loads(text)["ok"] is True
    lines = run["calls"].read_text().splitlines()
    assert "alerts acknowledge --id abc-1" in lines
    assert "status --json" in lines[lines.index("alerts acknowledge --id abc-1"):]  # refreshed right away


def test_event_routes(run):
    s, text, _ = _req(run, "GET", "/api/events?session=sessB", headers=_k(run))
    assert s == 200 and all(e["session"] == "sessB" for e in json.loads(text)["events"])
    s, text, _ = _req(run, "GET", "/api/event/ti1", headers=_k(run))
    assert s == 200 and json.loads(text)["row"]["tool"] == "Bash"


def test_stale_background_refresh_does_not_overwrite(tmp_path):
    folder = tmp_path / "app2"
    folder.mkdir()
    k = srv.Console(("127.0.0.1", 0), "/bin/false", tmp_path / "x.db", folder)
    try:
        gen = k.generation
        k.generation += 1  # an action ran in the meantime
        assert k.accept({"new": False}, gen) is False
        assert k.accept({"new": True}, k.generation) is True and k.state == {"new": True}
    finally:
        k.server_close()

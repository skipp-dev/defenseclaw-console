"""Console data: official CLI JSON output and audit.db (read-only)."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import subprocess
from pathlib import Path

CONTENT_FIELDS = ("gen_ai.tool.call.arguments", "gen_ai.tool.call.result",
                  "gen_ai.input.messages", "gen_ai.output.messages")
KINDS = ("tool_invocation", "llm_prompt", "llm_response", "hook_decision", "scan-finding",
         "watcher-block", "quarantine", "protected-file-changed", "alert")
MAX_CONTENT = 200_000
_PARTS = {
    "status": ["status", "--json"],
    "alerts": ["alerts", "--json", "--limit", "200"],
    "skills": ["skill", "list", "--json"],
    "plugins": ["plugin", "list", "--json"],
    "tools": ["tool", "list", "--json"],
}
_LAST: dict[str, tuple] = {}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def state(cli: str, config: Path = Path.home() / ".defenseclaw/config.yaml", timeout: int = 30) -> dict:
    """Call the official commands; on failure the last good value (and its time) is kept."""
    out: dict = {"errors": [], "part_as_of": {}}
    for part, argv in _PARTS.items():
        try:
            r = subprocess.run([cli, *argv], shell=False, capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0:
                raise RuntimeError(f"exit {r.returncode}: {(r.stderr or r.stdout).strip()[:200]}")
            _LAST[part] = (json.loads(r.stdout), _now())
        except (subprocess.TimeoutExpired, OSError, RuntimeError, json.JSONDecodeError) as exc:
            out["errors"].append(f"{part}: {exc}")
        value, when = _LAST.get(part, (None, None))
        out[part], out["part_as_of"][part] = value, when
    # as_of = time of the last successful status call (not "now")
    out["as_of"] = out["part_as_of"].get("status")
    status_fresh = not any(e.startswith("status:") for e in out["errors"])
    running = isinstance(out.get("status"), dict) and (out["status"].get("sidecar") or {}).get("running") is True
    out["reachable"] = bool(status_fresh and running)
    try:
        out["config"] = Path(config).read_text()
    except OSError as exc:
        out["config"] = ""
        out["errors"].append(f"config: {exc}")
    out["checkpoints"] = checkpoints()
    return out


def checkpoints(settings: Path = Path.home() / ".claude/settings.json") -> dict:
    """Which Claude Code events carry DefenseClaw hooks, and how many of your own hooks per event."""
    try:
        hooks = json.loads(Path(settings).read_text()).get("hooks", {}) or {}
    except (OSError, json.JSONDecodeError, AttributeError):
        return {"defenseclaw": [], "own": {}, "errors": ["settings.json not readable"]}
    dc, own = [], {}
    for event_name, groups in hooks.items():
        commands = [str(h.get("command") or "") for g in groups or [] if isinstance(g, dict)
                    for h in g.get("hooks") or [] if isinstance(h, dict)]
        if any(".defenseclaw/" in c for c in commands):
            dc.append(event_name)
        n = sum(1 for c in commands if ".defenseclaw/" not in c)
        if n:
            own[event_name] = n
    return {"defenseclaw": sorted(dc), "own": own}


def _connect(db: Path, timeout: float) -> sqlite3.Connection:
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=timeout)
    c.row_factory = sqlite3.Row
    return c


def _payload(row) -> dict:
    try:
        p = json.loads(row["payload_json"] or "{}")
        return p if isinstance(p, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _verdict(p: dict) -> str:
    action = p.get("defenseclaw.guardrail.effective_action")
    if action == "block" or p.get("defenseclaw.guardrail.enforced") in (1, True):
        return "blocked"
    if action != "allow":
        return "unknown"  # new/missing value after an upgrade: never silently "allowed"
    if p.get("defenseclaw.guardrail.would_block") in (1, True):
        return "would_block"
    return "allowed"


def _since(hours: int | None) -> str:
    if hours is None:
        return ""
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def _empty() -> dict:
    return {"seen": 0, "allowed": 0, "would_block": 0, "blocked": 0, "unknown": 0}


def counts(db: Path, since_hours: int | None = 24, timeout: float = 2) -> dict:
    out = {**_empty(), "per_session": {}, "per_hour": [], "per_checkpoint": {}, "errors": []}
    try:
        with _connect(db, timeout) as c:
            rows = c.execute(
                "SELECT timestamp, session_id, payload_json FROM audit_events "
                "WHERE action='hook_decision' AND timestamp >= ? ORDER BY timestamp", (_since(since_hours),)
            ).fetchall()
    except sqlite3.Error as exc:
        out["errors"].append(f"audit.db: {exc}")
        return out
    hours: dict[str, dict] = {}
    for r in rows:
        p = _payload(r)
        v = _verdict(p)
        event_name = p.get("defenseclaw.hook.event") or "?"
        out["per_checkpoint"][event_name] = out["per_checkpoint"].get(event_name, 0) + 1
        sid = str(r["session_id"] or p.get("gen_ai.conversation.id") or "-")[:8]
        for target in (out, out["per_session"].setdefault(sid, _empty()),
                       hours.setdefault((r["timestamp"] or "")[:13], _empty())):
            target["seen"] += 1
            target[v] += 1
    out["per_hour"] = [{"hour": h, **w} for h, w in sorted(hours.items())]
    return out


_CONTENT_LABEL = (("gen_ai.tool.call.arguments", "tool input"),
                  ("gen_ai.tool.call.result", "tool result"),
                  ("gen_ai.input.messages", "prompt"),
                  ("gen_ai.output.messages", "model response"))


def _summary(kind: str, row, p: dict) -> str:
    """Summary WITHOUT content (screen sharing); content only when a row is expanded."""
    if kind == "hook_decision":
        text = f"{p.get('defenseclaw.hook.event', '')} → {p.get('defenseclaw.guardrail.effective_action', '')}"
    elif any(f in p for f, _ in _CONTENT_LABEL):
        parts = []
        for field, label in _CONTENT_LABEL:
            if field in p:
                v = p[field]
                n = len(v) if isinstance(v, str) else len(json.dumps(v))
                parts.append(f"{label}, {n:,} chars")
        text = " · ".join(parts) + " – expand to view"
    else:
        text = " ".join(str(x) for x in (row["target"], row["details"]) if x)
    return " ".join(text.split())[:160]


def events(db: Path, limit: int = 200, session: str | None = None, kind: str | None = None,
           verdict: str | None = None, timeout: float = 2) -> dict:
    # A verdict filter matches the tiles: checkpoint decisions of the last 24 h only.
    if verdict not in _empty() or verdict == "seen":
        verdict = None
    kinds = ("hook_decision",) if verdict else (kind,) if kind in KINDS else KINDS
    sql = (f"SELECT id, timestamp, action, target, details, severity, session_id, tool_name, payload_json "
           f"FROM audit_events WHERE action IN ({','.join('?' * len(kinds))})")
    args: list = list(kinds)
    if session:
        sql += " AND session_id LIKE ?"
        args.append(session + "%")
    if verdict:
        sql += " AND timestamp >= ?"
        args.append(_since(24))
    sql += " ORDER BY timestamp DESC"
    if not verdict:  # the verdict is computed in Python, so the limit is applied after filtering
        sql += " LIMIT ?"
        args.append(int(limit))
    try:
        with _connect(db, timeout) as c:
            rows = c.execute(sql, args).fetchall()
    except sqlite3.Error as exc:
        return {"events": [], "errors": [f"audit.db: {exc}"]}
    out = []
    for r in rows:
        p = _payload(r)
        if verdict and _verdict(p) != verdict:
            continue
        if len(out) >= limit:
            break
        out.append({
            "id": r["id"], "time": r["timestamp"], "kind": r["action"],
            "session": str(r["session_id"] or p.get("gen_ai.conversation.id") or ""),
            "tool": r["tool_name"] or p.get("gen_ai.tool.name") or "",
            "summary": _summary(r["action"], r, p), "severity": r["severity"] or "",
            "verdict": _verdict(p) if r["action"] == "hook_decision" else "",
        })
    return {"events": out, "errors": []}


def _full(row) -> dict:
    p = _payload(row)
    contents, truncated = {}, {}
    for f in CONTENT_FIELDS:
        if f in p:
            v = p.pop(f)
            v = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
            if len(v) > MAX_CONTENT:
                truncated[f] = len(v)
                v = v[:MAX_CONTENT]
            contents[f] = v
    return {"id": row["id"], "time": row["timestamp"], "kind": row["action"], "target": row["target"],
            "details": (row["details"] or "")[:MAX_CONTENT], "severity": row["severity"],
            "session": row["session_id"], "tool": row["tool_name"], "fields": p,
            "contents": contents, "truncated_from": truncated}


def event(db: Path, id: str, timeout: float = 2) -> dict:
    cols = "id, timestamp, action, target, details, severity, session_id, tool_name, payload_json"
    try:
        with _connect(db, timeout) as c:
            row = c.execute(f"SELECT {cols} FROM audit_events WHERE id = ?", (id,)).fetchone()
            if row is None:
                return {"errors": ["not found"]}
            op = _payload(row).get("defenseclaw.operation.id")
            related = []
            if op:
                related = c.execute(
                    f"SELECT {cols} FROM audit_events WHERE id != ? AND "
                    "json_extract(payload_json, '$.\"defenseclaw.operation.id\"') = ? ORDER BY timestamp LIMIT 50",
                    (id, op)).fetchall()
    except sqlite3.Error as exc:
        return {"errors": [f"audit.db: {exc}"]}
    return {"row": _full(row), "related": [_full(v) for v in related]}

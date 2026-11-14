# DefenseClaw Console

A small, local, self-refreshing web console for monitoring and managing
[Cisco DefenseClaw](https://github.com/cisco-ai-defense/defenseclaw) on a single machine.

It shows what DefenseClaw saw, let through, would have blocked and actually blocked across your
Claude Code sessions, and it lets you acknowledge alerts, switch between observe and enforce mode,
and block or allow skills, plugins and tools, all from the browser instead of the terminal.

> **Unofficial.** This is a personal side project. It is not affiliated with, endorsed by or supported
> by Cisco. "DefenseClaw" refers to Cisco's open-source project, which this console only reads from
> and drives through its official command-line interface.

## What it shows

- **Header:** whether the gateway is running, the current mode (observe/enforce), the outage behaviour
  (fail-open/closed), whether only local rules are used, and whether the asset watcher only alerts or
  takes action. The time shown is the last *successful* refresh; it turns amber when older than a minute.
- **Tiles and hourly chart (24 h):** decisions seen, allowed, would block (observe mode), blocked,
  and an `unknown` bucket for decision values the console does not recognise.
- **Per session:** the same counts per Claude Code session.
- **Events:** prompts, tool calls, model responses, decisions, scan findings, watcher and quarantine
  events. Collapsed rows only show which content field is present and how long it is; the full content
  (prompts, tool inputs and outputs) appears only when you expand a row, so nothing sensitive is on screen
  while you share it. The list pauses while a row is open.
- **Alerts:** acknowledge or dismiss each alert.
- **Skills and plugins:** block, allow, unblock, or restore from quarantine.
- **Tools:** block, allow, or remove a tool from the block/allow list.
- **Checkpoints:** the Claude Code hook events DefenseClaw registered, with trigger counts, and how many
  of your own hooks sit alongside them.
- **Settings:** the current `~/.defenseclaw/config.yaml`.

## Security model

The console exposes unredacted prompts and tool output (DefenseClaw's audit database stores them in
plain text), and it can change DefenseClaw's enforcement. It is built accordingly:

- Binds to `127.0.0.1:18990` only. Requests with any other `Host` header are rejected (DNS rebinding).
- A random 256-bit key is required: in the page URL (`/k/<key>/`) and in the `X-Console-Key` header of
  every API call. The key is stored in `.key` (mode 0600); the full URL is written to `URL.txt` (0600).
- Mutations are `POST` only and additionally require a same-origin `Origin` header. There are no CORS
  headers, so another web page in your browser can neither read data nor trigger an action.
- Every action maps to a fixed allowlist of official `defenseclaw` CLI commands, run without a shell.
  Names are validated (no leading `-`, no spaces or shell characters) before any command is built.
- Switching to enforce mode requires typing the word `ENFORCE`, because it takes effect immediately in
  every running Claude Code session.
- All content is inserted with `textContent`; a strict Content-Security-Policy forbids inline script
  and style.
- `audit.db` is opened read-only. The console never writes DefenseClaw's own files.
- No access log is written (the URL contains the key). Actions are logged to `console.log`.

Treat the URL like a password. Anyone who has it and can reach `127.0.0.1` on your machine can read your
prompts and change enforcement.

## Requirements

- macOS (tested on macOS 27, Apple silicon). Linux should work but is untested.
- DefenseClaw 1.0.8 or later, installed per user and initialised with the Claude Code connector
  (`defenseclaw quickstart --connector claudecode`). The console expects the CLI at
  `~/.local/bin/defenseclaw` and the audit database at `~/.defenseclaw/audit.db`.
- Python 3.9 or later, standard library only. By default `start.sh` uses DefenseClaw's own virtual
  environment (`~/.defenseclaw/.venv/bin/python`) and falls back to `python3`; override with
  `DEFENSECLAW_CONSOLE_PYTHON`.

## Run it

```bash
git clone https://github.com/<owner>/defenseclaw-console.git
cd defenseclaw-console
./start.sh            # serves http://127.0.0.1:18990/k/<key>/
cat URL.txt           # open this address in your browser
```

To keep it running and start it at login, use the launchd example in
[`examples/com.example.defenseclaw-console.plist`](examples/com.example.defenseclaw-console.plist).

To rotate the key: delete `.key` and restart; the old URL stops working.

## A caveat worth knowing: "observe" does not cover the asset watcher

DefenseClaw has two independent switches. `guardrail.mode: observe` only governs hook decisions on tool
calls. The **asset watcher** (`gateway.watcher.skill|plugin|mcp.take_action`, `watch.auto_block`) is on
by default and quarantines skills and plugins with critical or high findings, even in observe mode. Any
file change inside a skill folder triggers a rescan. If you want a pure observation setup, set:

```bash
defenseclaw config set gateway.watcher.skill.take_action false
defenseclaw config set gateway.watcher.plugin.take_action false
defenseclaw config set gateway.watcher.mcp.take_action false
defenseclaw config set watch.auto_block false
```

The console's header shows "Watcher: alert only" once all four are set.

## Tests

```bash
python3 -m pip install pytest
python3 -m pytest tests -q
```

The suite (40 tests) covers key handling, Host/Origin checks, name validation, the command allowlist,
no-shell execution, timeouts, locked databases, stale state after a CLI failure, a stopped gateway,
unknown decision values, truncation of huge content, and stale background refreshes after an action.
The CLI is replaced by small fake scripts; the tests never touch a real DefenseClaw install.

## Known limitations

- The path key is compared with `==` rather than in constant time.
- The request handler has no socket timeout.
- Non-content fields of an expanded event are not truncated.
- SQLite connections rely on garbage collection to close.
- If DefenseClaw is uninstalled while the launchd agent is loaded, launchd keeps restarting the console.
- Only the Claude Code connector is handled for mode switching.

## License

[Apache License 2.0](LICENSE), the same license as DefenseClaw itself.

## Project layout

```text
console/   security.py  commands.py  data.py  server.py
static/    index.html   app.js       style.css
tests/     pytest suite with fake CLIs and a synthetic audit database
docs/      DESIGN.md (requirements and decisions), IMPLEMENTATION.md (build notes and review)
examples/  launchd agent
start.sh   start script
```

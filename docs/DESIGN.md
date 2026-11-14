# DefenseClaw Console – Design

Approved 14 Nov 2026. Translated from the original working notes.

## Purpose

Monitor and manage a local DefenseClaw install (local rules only, observe mode, connected to Claude Code)
from the browser instead of the terminal: see which checkpoints and settings apply and what was seen,
allowed, would have been blocked and was actually blocked; and take three kinds of action: acknowledge
alerts, switch observe ↔ enforce, block or allow skills, plugins and tools.

## Goals

- One page that refreshes itself every 10 seconds.
- Show: state (gateway running, version, mode, outage behaviour, local-only), the asset watcher setting
  (alert only vs. takes action), the hook checkpoints, counts per hour and per session (seen / allowed /
  would block / blocked), active alerts, skills, plugins, the tool list, quarantine.
- Show the content of prompts, tool inputs, tool results and model responses.
- Act: acknowledge/dismiss alerts; switch mode; block, allow, unblock, restore skills/plugins/tools.

## Non-goals

- No upload, no hosted page, no access from outside the machine.
- No Cisco AI Defense integration and no key management.
- No Grafana.

## Must never happen

- A foreign web page in the browser silently triggers an action (CSRF) or reads data.
- A single misclick switches every session to enforce mode.
- The console writes DefenseClaw's own files (bypassing the official paths).

## Approaches considered

- **A (chosen):** own local page, Python standard library, reads via the official `defenseclaw … --json`
  commands and read-only from `audit.db`; actions only via official commands.
- **B:** DefenseClaw's bundled Grafana stack (Docker, six containers) plus a separate page for actions.
  Two places and a permanent load.
- **C:** Grafana plus the terminal UI (`defenseclaw tui`). Does not meet "manage in the browser".

## How it is built

- Server `console/server.py`, `127.0.0.1:18990` only, standard library.
- Protection: random key in the URL and in a request header; Host header must be `127.0.0.1:18990` or
  `localhost:18990`; actions only via `POST` with a same-origin `Origin` header and the key; a fixed list
  of allowed commands; names validated; never through a shell.
- Enforce mode: two steps (button, then typing `ENFORCE`), with a note that it takes effect in every
  Claude Code session at once.
- Data: `status --json`, `alerts --json`, `skill list --json`, `plugin list --json`, `tool list --json`,
  `config.yaml` (read), counts from `audit.db` (read-only URI). The CLI round takes about six seconds, so
  the server refreshes it in a background thread every 15 seconds and requests only read the last result.
- Content: the event list shows a summary without content; the full content appears only when a row is
  expanded (protects during screen sharing). Text is always inserted as text, never as HTML.
- Appearance: dark, matte, easy on the eyes, readable. Status colours were checked for colour-vision
  deficiency against the dark surface (allowed `#5d8cc8`, would block `#c9952e`, blocked `#c85656`) and
  always appear together with a symbol and a label.
- Start: launchd agent with `KeepAlive`; the URL with the key is written to `URL.txt`.

# DefenseClaw Console – Implementation notes

Built test-first in six tasks, then reviewed as a whole by an independent reviewer.

## Tasks

1. **Security** (`console/security.py`): key file (0600), Host and Origin checks, name validation.
2. **Commands** (`console/commands.py`): fixed allowlist mapping actions to `defenseclaw` argv; enforce mode
   requires the confirmation word; execution with `shell=False`, timeout, ANSI stripping, action log.
3. **Data** (`console/data.py`): CLI JSON with last-good values and per-part timestamps; counts per
   hour/session/checkpoint from `hook_decision` rows; event list and event detail with related rows (same
   `defenseclaw.operation.id`); content truncated at 200,000 characters; read-only SQLite.
4. **Server** (`console/server.py`): routes `/k/<key>/`, `/static/*`, `/api/state`, `/api/counts`,
   `/api/events`, `/api/event/<id>`, `POST /api/action`; security headers; background refresh; after each
   action the state is refreshed before replying, and a generation counter discards older refreshes.
5. **Front end** (`static/`): tiles, stacked hourly bars with tooltip and table view, sessions, events with
   expandable content, alerts, skills/plugins, tools, checkpoints, settings. Sections are only redrawn when
   their data changed, so text selection and click targets survive the 10-second refresh.
6. **Running permanently**: launchd agent with `KeepAlive`.

## Decisions made during the build

- `state()` takes the config path as a parameter so it can be tested.
- Host/Origin checks take the port as a parameter so the server can be tested on a free port.
- The URL file holds the key and is created with mode 0600; there is no access log.
- Inline `style` attributes were replaced by CSS classes because the CSP (`style-src 'self'`) blocked them.
- The event list pauses while a row is open; in browser testing, rows moved under the pointer otherwise.
- The colour palette was chosen with a colour-vision validator; the first, more muted palette failed
  (green and ochre were indistinguishable for deuteranopia).

## Independent review

No critical findings. Fixed, each with a test that failed first:

- The event list returned an empty list instead of an error when the database was locked.
- Collapsed rows showed the first 160 characters of content, defeating the screen-sharing protection.
- Unknown decision values were counted as "allowed"; they now go to an `unknown` bucket.
- The "as of" time was "now" even when every CLI call failed; it is now the last successful refresh, and a
  stopped gateway is shown as stopped.
- A refresh started before an action could overwrite the newer state; repeated clicks produced CLI errors.
- A non-string session id or a `null` hook command raised a `TypeError` that froze the state.

Deferred (minor): constant-time comparison of the path key, a socket timeout for the handler, truncation of
non-content fields, explicit closing of SQLite connections, and a clean exit when DefenseClaw is removed.

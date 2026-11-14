"""Access control for the console: secret key, Host/Origin checks, allowed names."""

from __future__ import annotations

import hmac
import os
import re
import secrets
from pathlib import Path

PORT = 18990
_NAME = re.compile(r"[A-Za-z0-9._@:/][A-Za-z0-9._@:/-]{0,127}")


def load_key(path: Path) -> str:
    """Read the key; create it on first use (mode 0600)."""
    path = Path(path)
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    os.chmod(path, 0o600)
    return key


def host_ok(host: str | None, port: int = PORT) -> bool:
    return host in {f"127.0.0.1:{port}", f"localhost:{port}"}


def origin_ok(origin: str | None, port: int = PORT) -> bool:
    return origin in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}


def key_ok(sent: str | None, real: str) -> bool:
    if not sent or not real:
        return False
    return hmac.compare_digest(sent.encode(), real.encode())


def name_ok(name: str) -> bool:
    """Names passed to the CLI: no leading '-', no spaces or shell characters."""
    return isinstance(name, str) and _NAME.fullmatch(name) is not None

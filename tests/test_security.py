import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from console import security as s  # noqa: E402


def test_key_is_created_0600(tmp_path):
    p = tmp_path / ".key"
    k = s.load_key(p)
    assert len(k) >= 40
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_key_is_stable(tmp_path):
    p = tmp_path / ".key"
    assert s.load_key(p) == s.load_key(p)


def test_foreign_host_rejected():
    assert s.host_ok("127.0.0.1:18990")
    assert s.host_ok("localhost:18990")
    for h in ["evil.com:18990", "127.0.0.1:80", "127.0.0.1", None, ""]:
        assert not s.host_ok(h), h


def test_foreign_origin_rejected():
    assert s.origin_ok("http://127.0.0.1:18990")
    assert s.origin_ok("http://localhost:18990")
    for o in ["https://example.com", "null", None, "", "http://127.0.0.1:18991"]:
        assert not s.origin_ok(o), o


def test_wrong_key():
    assert s.key_ok("abc", "abc")
    assert not s.key_ok("abd", "abc")
    assert not s.key_ok(None, "abc")
    assert not s.key_ok("", "abc")


def test_name_ok():
    for n in ["prove-over-population", "@claudecode/Bash", "01a1d9aa-3ae0-7c4c-a2eb-b149f7d6491e", "observe"]:
        assert s.name_ok(n), n
    for n in ["--all", "-x", "a b", "a;rm", "", "x" * 129, "a\nb", "$(id)"]:
        assert not s.name_ok(n), n

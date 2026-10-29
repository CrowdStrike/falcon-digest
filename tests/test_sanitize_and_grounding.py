"""Unit tests for error sanitization, config validation, and the LLM grounding check.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    Falcon Digest
`-------'                         `-------'

Falcon Digest — AI-Powered Falcon Security Dashboard

Copyright 2024 CrowdStrike, Inc.

MIT License — see LICENSE file for details.
"""

import json
import os
import sys
import threading
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# sanitize_error
# ---------------------------------------------------------------------------

class TestSanitizeError:

    def _s(self, *args, **kwargs):
        from falcon_cache import sanitize_error
        return sanitize_error(*args, **kwargs)

    def test_strips_posix_paths(self):
        out = self._s("Error at /Users/someone/crwd_mcp/falcon_cache.py line 3")
        assert "/Users" not in out and "[path]" in out

    def test_strips_quoted_posix_path(self):
        assert self._s("File '/opt/app/x.py'") == "File '[path]'"

    def test_strips_windows_paths(self):
        out = self._s(r"C:\Users\someone\app\x.py not found")
        assert "Users" not in out and out.startswith("[path]")

    def test_keeps_urls(self):
        msg = "GET https://api.crowdstrike.com/alerts/queries/v2 failed"
        assert self._s(msg) == msg

    def test_keeps_plain_text(self):
        assert self._s("and/or ok") == "and/or ok"

    def test_truncates(self):
        out = self._s("x" * 500, max_len=50)
        assert out == "x" * 50 + "…"

    def test_accepts_exceptions(self):
        assert "boom" in self._s(ValueError("boom"))


# ---------------------------------------------------------------------------
# Cache persistence never falls back to plaintext
# ---------------------------------------------------------------------------

class TestCacheNoPlaintextFallback:

    def test_save_skipped_when_encryption_fails(self, tmp_path, monkeypatch):
        for mod_name in list(sys.modules):
            if mod_name == "falcon_cache":
                del sys.modules[mod_name]
        import falcon_cache as fc_mod
        fc_mod.FalconCache._instance = None
        fc_mod.FalconCache._lock_cls = threading.Lock()
        monkeypatch.setattr(fc_mod, "CACHE_FILE", str(tmp_path / ".falcon_cache.json"))
        cache = fc_mod.FalconCache()
        cache._cache["k"] = {"data": '{"secret": "data"}',
                             "fetched_at": datetime.now(tz=timezone.utc).isoformat() + "Z"}
        monkeypatch.setattr(fc_mod, "encrypt_cache", lambda payload: None)
        cache._save_to_file()
        assert not os.path.exists(fc_mod.CACHE_FILE)
        assert not os.path.exists(fc_mod.CACHE_FILE + ".tmp")


# ---------------------------------------------------------------------------
# validate_config / validate_llm_config
# ---------------------------------------------------------------------------

class TestValidation:

    def test_validate_config_requires_falcon_creds_only(self, monkeypatch):
        from crwd_mcp_server import validate_config, ConfigError
        monkeypatch.setenv("FALCON_CLIENT_ID", "id")
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "secret")
        for k in ("LLM_ENDPOINT", "LLM_API_KEY", "LLM_PROVIDER"):
            monkeypatch.delenv(k, raising=False)
        validate_config()  # LLM not required
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "")
        with pytest.raises(ConfigError) as exc:
            validate_config()
        assert "FALCON_CLIENT_SECRET" in str(exc.value)

    def test_llm_config_keyless_is_valid(self, monkeypatch):
        from crwd_mcp_server import validate_llm_config
        monkeypatch.setenv("LLM_ENDPOINT", "http://localhost:11434")
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        validate_llm_config()

    def test_llm_config_requires_endpoint(self, monkeypatch):
        from crwd_mcp_server import validate_llm_config, ConfigError
        monkeypatch.delenv("LLM_ENDPOINT", raising=False)
        with pytest.raises(ConfigError) as exc:
            validate_llm_config()
        assert "LLM_ENDPOINT" in str(exc.value)

    def test_llm_config_rejects_unknown_provider(self, monkeypatch):
        from crwd_mcp_server import validate_llm_config, ConfigError
        monkeypatch.setenv("LLM_ENDPOINT", "http://localhost:11434")
        monkeypatch.setenv("LLM_PROVIDER", "foo")
        with pytest.raises(ConfigError) as exc:
            validate_llm_config()
        assert "foo" in str(exc.value)


# ---------------------------------------------------------------------------
# Grounding check (validate_response)
# ---------------------------------------------------------------------------

class _FakeCache:
    def __init__(self, entries, running=True):
        self._entries = entries
        self.is_running = running
        self.refresh_count = 1
        self.last_refresh = None
        self.entry_count = len(entries)

    def get_all(self):
        return {k: dict(v) for k, v in self._entries.items()}


@pytest.fixture
def grounding(monkeypatch):
    """Return a helper that installs fake cache contents and runs validate_response."""
    import mcp_api_client

    def _run(text, cached=None, extra=None, running=True):
        entries = {
            "security_posture": {"data": json.dumps(cached or {}), "fetched_at": "2026-01-01T00:00:00Z"},
        }
        monkeypatch.setattr(mcp_api_client, "falcon_cache", _FakeCache(entries, running))
        mcp_api_client._known_ids_memo["stamp"] = None  # each case installs new cache contents
        return mcp_api_client.validate_response(text, extra)

    return _run


class TestGrounding:

    def test_cache_scan_is_memoized_until_refresh(self, monkeypatch):
        import mcp_api_client
        fake = _FakeCache({"k": {"data": json.dumps({"ip": "10.9.9.9"}), "fetched_at": ""}})
        calls = []
        orig = fake.get_all
        fake.get_all = lambda: calls.append(1) or orig()
        monkeypatch.setattr(mcp_api_client, "falcon_cache", fake)
        mcp_api_client._known_ids_memo["stamp"] = None
        mcp_api_client.validate_response("seen 10.9.9.9")
        mcp_api_client.validate_response("seen 10.9.9.9 again")
        assert len(calls) == 1
        fake.refresh_count += 1
        mcp_api_client.validate_response("seen 10.9.9.9")
        assert len(calls) == 2

    def test_known_ip_not_mangled_by_unknown_prefix(self, grounding):
        text = "Hosts 10.0.0.10 and 10.0.0.1 talked."
        out = grounding(text, cached={"hosts": [{"local_ip": "10.0.0.10"}]})
        assert out.startswith(text)
        assert "~~" not in out
        note = out[len(text):]
        assert "`10.0.0.1`" in note
        assert "10.0.0.10" not in note
        assert note.count("10.0.0.1") == 1

    def test_unknown_cve_listed_once(self, grounding):
        text = "Patch CVE-2024-9999 now. Again: cve-2024-9999."
        out = grounding(text, cached={"cves": ["CVE-2023-0001"]})
        assert out.startswith(text)
        note = out[len(text):]
        assert note.count("CVE-2024-9999") == 1
        assert "~~" not in out

    def test_identifier_in_tool_results_is_known(self, grounding):
        text = "Found CVE-2025-1234 on 192.168.1.50."
        tool_result = json.dumps({"vulns": [{"cve": "CVE-2025-1234", "ip": "192.168.1.50"}]})
        out = grounding(text, cached={"cves": ["CVE-2023-0001"], "ip": "10.1.1.1"}, extra=[tool_result])
        assert out == text

    def test_all_known_unchanged(self, grounding):
        text = "CVE-2023-0001 affects 10.1.1.1."
        out = grounding(text, cached={"cves": ["CVE-2023-0001"], "hosts": ["10.1.1.1"]})
        assert out == text

    def test_empty_reference_data_flags_nothing(self, grounding):
        text = "CVE-2024-9999 on 10.9.9.9"
        assert grounding(text, cached={}) == text

    def test_cache_not_running_and_no_tools(self, grounding):
        text = "CVE-2024-9999 on 10.9.9.9"
        assert grounding(text, cached={"cves": ["CVE-2023-0001"]}, running=False) == text


# ---------------------------------------------------------------------------
# Local endpoint detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("endpoint,expected", [
    ("http://localhost:11434", True),
    ("http://127.0.0.1:11434", True),
    ("http://0.0.0.0:11434", True),
    ("http://[::1]:11434", True),
    ("http://192.168.1.50:11434", True),
    ("http://ollama.local:11434", True),
    ("https://api.anthropic.com", False),
    ("https://localhost-proxy.corp.example", False),
    ("https://8.8.8.8", False),
    ("", False),
])
def test_is_local_endpoint(endpoint, expected):
    import mcp_api_client
    assert mcp_api_client._is_local_endpoint(endpoint) is expected


def test_local_model_never_gets_tools_even_without_cache(monkeypatch):
    import mcp_api_client
    monkeypatch.setenv("LLM_ENDPOINT", "http://127.0.0.1:11434")
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setattr(mcp_api_client, "falcon_cache", _FakeCache({}, running=False))
    sent = {}

    class _Resp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}

    def _post(url, headers=None, json=None, timeout=None):
        sent.update(json)
        return _Resp()

    monkeypatch.setattr(mcp_api_client._session, "post", _post)
    mcp_api_client.call_llm([{"role": "user", "content": "hi"}], tools=mcp_api_client.TOOL_DEFINITIONS)
    assert "tools" not in sent


def test_tool_error_is_sanitized_at_source(monkeypatch):
    import mcp_api_client

    def _boom(**kw):
        raise RuntimeError("failed reading /Users/someone/app/venv/lib/x.py")

    monkeypatch.setattr(mcp_api_client, "search_alerts", _boom)
    out = mcp_api_client.execute_tool("search_alerts", {})
    assert "/Users/someone" not in out and "[path]" in out


def test_prompts_have_no_concrete_example_counts():
    src = open(os.path.join(os.path.dirname(__file__), "..", "mcp_api_client.py")).read()
    assert "201 Linux hosts" not in src

"""Tests for server/client/cache review fixes: error sanitizing at the source,
encrypted cache upgrade and backups, per-turn LLM time budget, local-model mode.

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

import asyncio
import json
import os
import re
import stat
import sys
import threading
import time
from unittest.mock import MagicMock

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crwd_mcp_server as srv
import mcp_api_client
from crwd_mcp_server import sanitize_error

LEAKY = "boom at /Users/someone/app/venv/lib/python3.13/site-packages/falconpy/_util.py"


def _clean(text) -> bool:
    return "/Users/someone" not in str(text) and "[path]" in str(text)


# ---------------------------------------------------------------------------
# Error sanitizing at the source (the five remaining sites)
# ---------------------------------------------------------------------------

class TestErrorSitesSanitized:

    @pytest.fixture
    def raising_client(self, monkeypatch):
        """Make get_falcon_client raise for the given service classes."""
        def _install(*classes, otherwise=None):
            def _get(cls):
                if cls in classes:
                    raise RuntimeError(LEAKY)
                if otherwise is not None:
                    return otherwise(cls)
                raise RuntimeError(LEAKY)
            monkeypatch.setattr(srv, "get_falcon_client", _get)
        return _install

    def test_identity_protection_init(self, raising_client):
        raising_client(srv.IdentityProtection)
        assert _clean(srv._get_identity_protection_sync(10)["error"])

    def test_cloud_security_init(self, raising_client):
        raising_client(srv.CloudSecurity)
        assert _clean(srv._get_cloud_security_sync(None, None, 10)["error"])

    def test_cloud_security_query(self, raising_client):
        client = MagicMock()
        client.combined_cloud_risks.side_effect = RuntimeError(LEAKY)
        raising_client(otherwise=lambda cls: client)
        assert _clean(srv._get_cloud_security_sync(None, None, 10)["error"])

    def test_exposure_management_init(self, raising_client):
        raising_client(srv.ExposureManagement)
        assert _clean(srv._get_exposure_management_sync(10)["error"])

    def test_ngsiem_mssp_fallback(self, monkeypatch):
        fc = MagicMock()
        fc.query_children.return_value = {"status_code": 200, "body": {"resources": ["child-1"]}}
        fc.get_children.return_value = {"status_code": 200, "body": {"resources": []}}

        def _get(cls):
            if cls is srv.FlightControl:
                return fc
            raise RuntimeError(LEAKY)  # parent NGSIEM fallback fails

        monkeypatch.setattr(srv, "get_falcon_client", _get)
        monkeypatch.setattr(srv, "NGSIEM", MagicMock(side_effect=RuntimeError(LEAKY)))  # child queries fail
        result = json.loads(asyncio.run(srv.get_ngsiem_ingestion(hours=1)))
        assert result["is_mssp"] is True
        assert "parent fallback also failed" in result["error"]
        assert _clean(result["error"])
        assert all(_clean(c["error"]) for c in result["children"])

    def test_no_raw_exception_interpolation_left(self):
        src = open(srv.__file__).read()
        raw = [l.strip() for l in src.splitlines()
               if re.search(r'\["error"\]\s*=\s*f".*\{(?:e|str\(e\))\}', l)]
        assert raw == []


# ---------------------------------------------------------------------------
# Relative path stripping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("msg,expected", [
    ("err in venv/lib/python3.13/site-packages/falconpy/_util.py line 5", "err in [path] line 5"),
    ("file config/settings.yaml bad", "file [path] bad"),
    ("GET https://api.crowdstrike.com/alerts/queries/v2 failed", "GET https://api.crowdstrike.com/alerts/queries/v2 failed"),
    ("see https://x.example.com/a/b.json now", "see https://x.example.com/a/b.json now"),
    ("and/or ok", "and/or ok"),
    ("version 1.2.3 ok", "version 1.2.3 ok"),
    ("e.g. foo.bar", "e.g. foo.bar"),
])
def test_relative_paths(msg, expected):
    assert sanitize_error(msg) == expected


# ---------------------------------------------------------------------------
# Cache: plaintext re-encrypted on load; backups encrypted and pruned
# ---------------------------------------------------------------------------

@pytest.fixture
def cache_env(tmp_path, monkeypatch):
    """Point the cache file/backup dir at tmp_path and return a fresh-cache factory."""
    import falcon_cache as fc_mod
    monkeypatch.setattr(fc_mod, "CACHE_FILE", str(tmp_path / ".falcon_cache.json"))
    monkeypatch.setattr(fc_mod, "CACHE_BACKUP_DIR", str(tmp_path / ".falcon_cache_backups"))

    def _fresh():
        fc_mod.FalconCache._instance = None
        fc_mod.FalconCache._lock_cls = threading.Lock()
        return fc_mod.FalconCache()

    yield fc_mod, tmp_path, _fresh
    fc_mod.FalconCache._instance = None
    fc_mod.FalconCache._lock_cls = threading.Lock()


def _plain_payload(fp=""):
    return {"_meta": {"cid_fingerprint": fp}, "entries": {"k": {"data": '{"tenant": "secret-data"}', "fetched_at": "2026-01-01T00:00:00Z"}}}


def _is_plaintext(path) -> bool:
    raw = open(path, "rb").read()
    return b"secret-data" in raw


class TestCacheUpgrade:

    def test_plaintext_cache_reencrypted_on_load(self, cache_env):
        fc_mod, tmp_path, fresh = cache_env
        cache_file = tmp_path / ".falcon_cache.json"
        cache_file.write_text(json.dumps(_plain_payload(fc_mod._get_cid_fingerprint())))
        cache = fresh()
        assert cache.get("k") == '{"tenant": "secret-data"}'
        assert not _is_plaintext(cache_file)
        from falcon_secrets import decrypt_cache
        assert decrypt_cache(cache_file.read_bytes())["entries"]["k"]["data"] == '{"tenant": "secret-data"}'

    def test_plaintext_left_when_encryption_unavailable(self, cache_env, monkeypatch):
        fc_mod, tmp_path, fresh = cache_env
        monkeypatch.setattr(fc_mod, "encrypt_cache", lambda d: None)
        cache_file = tmp_path / ".falcon_cache.json"
        cache_file.write_text(json.dumps(_plain_payload(fc_mod._get_cid_fingerprint())))
        cache = fresh()
        assert cache.get("k")  # still usable
        assert cache_file.exists()  # left in place (logged), not destroyed

    def test_cid_mismatch_backup_is_encrypted(self, cache_env):
        fc_mod, tmp_path, fresh = cache_env
        (tmp_path / ".falcon_cache.json").write_text(json.dumps(_plain_payload("other-cid")))
        fresh()
        backups = list((tmp_path / ".falcon_cache_backups").iterdir())
        assert len(backups) == 1 and backups[0].suffix == ".enc"
        assert not _is_plaintext(backups[0])
        assert not (tmp_path / ".falcon_cache.json").exists()
        assert stat.S_IMODE(os.stat(tmp_path / ".falcon_cache_backups").st_mode) == 0o700
        assert stat.S_IMODE(os.stat(backups[0]).st_mode) == 0o600

    def test_cid_mismatch_without_encryption_deletes(self, cache_env, monkeypatch):
        fc_mod, tmp_path, fresh = cache_env
        monkeypatch.setattr(fc_mod, "encrypt_cache", lambda d: None)
        (tmp_path / ".falcon_cache.json").write_text(json.dumps(_plain_payload("other-cid")))
        fresh()
        assert not (tmp_path / ".falcon_cache.json").exists()
        bdir = tmp_path / ".falcon_cache_backups"
        assert not bdir.exists() or not any(_is_plaintext(p) for p in bdir.iterdir())

    def test_existing_plaintext_backups_secured_and_pruned(self, cache_env):
        fc_mod, tmp_path, fresh = cache_env
        bdir = tmp_path / ".falcon_cache_backups"
        bdir.mkdir()
        os.chmod(bdir, 0o755)
        for i in range(8):
            p = bdir / f"cache_2026010{i}_000000.json"
            p.write_text(json.dumps(_plain_payload("x")))
            os.utime(p, (1_000_000 + i, 1_000_000 + i))
        (bdir / "garbage.json").write_bytes(b"\x00not json")
        fresh()
        remaining = list(bdir.iterdir())
        assert len(remaining) <= fc_mod.MAX_CACHE_BACKUPS
        assert not any(_is_plaintext(p) for p in remaining)
        assert all(p.suffix == ".enc" for p in remaining)
        assert stat.S_IMODE(os.stat(bdir).st_mode) == 0o700

    def test_repeated_cid_changes_keep_newest_backups(self, cache_env):
        fc_mod, tmp_path, fresh = cache_env
        cache = fresh()
        for i in range(8):
            (tmp_path / ".falcon_cache.json").write_text(json.dumps(_plain_payload(f"cid-{i}")))
            cache._backup_and_clear_file()
        backups = list((tmp_path / ".falcon_cache_backups").iterdir())
        assert len(backups) == fc_mod.MAX_CACHE_BACKUPS
        assert not any(_is_plaintext(p) for p in backups)


# ---------------------------------------------------------------------------
# LLM per-turn time budget
# ---------------------------------------------------------------------------

class _FakeCache:
    is_running = False
    _last_refresh = None


@pytest.fixture
def llm_env(monkeypatch):
    monkeypatch.setenv("LLM_ENDPOINT", "https://llm.example.com")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("LLM_LOCAL_MODE", raising=False)
    monkeypatch.setattr(mcp_api_client, "falcon_cache", _FakeCache())
    return monkeypatch


class _OK:
    status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return {"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}


class TestTimeBudget:

    def test_expired_deadline_raises(self, llm_env):
        llm_env.setattr(mcp_api_client._session, "post", lambda *a, **k: _OK())
        with pytest.raises(mcp_api_client.LLMTimeoutError):
            mcp_api_client.call_llm([{"role": "user", "content": "hi"}], deadline=time.monotonic() - 1)

    def test_request_timeout_capped_by_remaining(self, llm_env):
        seen = {}

        def _post(url, headers=None, json=None, timeout=None):
            seen["timeout"] = timeout
            return _OK()

        llm_env.setattr(mcp_api_client._session, "post", _post)
        mcp_api_client.call_llm([{"role": "user", "content": "hi"}], deadline=time.monotonic() + 5)
        assert 0 < seen["timeout"] <= 5

    def test_no_deadline_uses_full_timeout(self, llm_env):
        seen = {}

        def _post(url, headers=None, json=None, timeout=None):
            seen["timeout"] = timeout
            return _OK()

        llm_env.setattr(mcp_api_client._session, "post", _post)
        mcp_api_client.call_llm([{"role": "user", "content": "hi"}])
        assert seen["timeout"] == mcp_api_client.REQUEST_TIMEOUT_SECONDS

    def test_retry_backoff_never_exceeds_budget(self, llm_env):
        sleeps = []
        llm_env.setattr(mcp_api_client.time, "sleep", lambda s: sleeps.append(s))

        def _post(*a, **k):
            raise requests.exceptions.ConnectionError("refused")

        llm_env.setattr(mcp_api_client._session, "post", _post)
        with pytest.raises(mcp_api_client.LLMTimeoutError):
            mcp_api_client.call_llm([{"role": "user", "content": "hi"}], deadline=time.monotonic() + 0.5)
        assert sleeps == []  # 1s backoff would overrun the 0.5s budget

    def test_read_timeout_after_deadline_is_budget_error(self, llm_env):
        def _post(*a, timeout=None, **k):
            time.sleep(0.05)
            raise requests.exceptions.ReadTimeout("slow")

        llm_env.setattr(mcp_api_client._session, "post", _post)
        with pytest.raises(mcp_api_client.LLMTimeoutError):
            mcp_api_client.call_llm([{"role": "user", "content": "hi"}], deadline=time.monotonic() + 0.01)

    def test_chat_passes_one_deadline_per_turn(self, llm_env):
        deadlines = []
        responses = iter([
            {"content": [{"type": "tool_use", "id": "t1", "name": "list_available_products", "input": {}}], "stop_reason": "tool_use"},
            {"content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"},
        ])

        def _call(messages, tools=None, system_context=None, *, deadline=None):
            deadlines.append(deadline)
            return next(responses)

        llm_env.setattr(mcp_api_client, "call_llm", _call)
        llm_env.setattr(mcp_api_client, "execute_tool", lambda n, i: "{}")
        before = time.monotonic()
        mcp_api_client.chat("hello")
        assert len(deadlines) == 2 and deadlines[0] == deadlines[1]
        assert before + mcp_api_client.TURN_TIME_BUDGET_SECONDS - 1 <= deadlines[0] <= time.monotonic() + mcp_api_client.TURN_TIME_BUDGET_SECONDS


# ---------------------------------------------------------------------------
# LLM_LOCAL_MODE
# ---------------------------------------------------------------------------

class TestLocalMode:

    @pytest.mark.parametrize("mode,endpoint,expected", [
        ("auto", "http://127.0.0.1:11434", True),
        ("auto", "https://api.anthropic.com", False),
        ("local", "https://api.anthropic.com", True),
        ("full", "http://127.0.0.1:11434", False),
        ("FULL", "http://10.0.0.5:8000", False),
        ("bogus", "http://127.0.0.1:11434", True),
        ("bogus", "https://api.anthropic.com", False),
    ])
    def test_use_local_mode(self, monkeypatch, mode, endpoint, expected):
        monkeypatch.setenv("LLM_LOCAL_MODE", mode)
        assert mcp_api_client._use_local_mode(endpoint) is expected

    def test_default_is_auto(self, monkeypatch):
        monkeypatch.delenv("LLM_LOCAL_MODE", raising=False)
        assert mcp_api_client._use_local_mode("http://localhost:11434") is True
        assert mcp_api_client._use_local_mode("https://api.openai.com") is False

    @pytest.mark.parametrize("mode,endpoint,tools_sent", [
        ("full", "http://10.0.0.5:8000", True),
        ("local", "https://llm.example.com", False),
    ])
    def test_call_llm_respects_mode(self, llm_env, mode, endpoint, tools_sent):
        llm_env.setenv("LLM_LOCAL_MODE", mode)
        llm_env.setenv("LLM_ENDPOINT", endpoint)
        sent = {}

        def _post(url, headers=None, json=None, timeout=None):
            sent.update(json)
            return _OK()

        llm_env.setattr(mcp_api_client._session, "post", _post)
        mcp_api_client.call_llm([{"role": "user", "content": "hi"}], tools=mcp_api_client.TOOL_DEFINITIONS)
        assert ("tools" in sent) is tools_sent


# ---------------------------------------------------------------------------
# Prompt hygiene
# ---------------------------------------------------------------------------

def test_prompts_have_no_concrete_example_counts():
    src = open(mcp_api_client.__file__).read()
    assert not re.search(r"\*\*[0-9][0-9,]* (?:hosts|Linux hosts|items)\*\*", src)
    assert "| Alerts | 156 |" not in src


def test_tool_guidance_is_consistent():
    src = open(mcp_api_client.__file__).read()
    assert "Do NOT call tools unless the user explicitly asks" not in src

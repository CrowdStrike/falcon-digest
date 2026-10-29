"""Unit tests for falcon_secrets (ConfigStore, key handling, migration, file helpers).

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

import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import falcon_secrets
from falcon_secrets import (
    ConfigStore, ConfigDecryptError, write_private_file, encrypt_cache, decrypt_cache,
)

SECRET = "super-secret-client-secret-value"


@pytest.fixture(autouse=True)
def isolated_key(tmp_path, monkeypatch):
    """Point the key file and default config path at tmp_path; no keychain."""
    monkeypatch.setattr(falcon_secrets, "_keyring_available", False)
    monkeypatch.setattr(falcon_secrets, "_KEY_FILE", str(tmp_path / ".falcon_config.key"))
    monkeypatch.setattr(falcon_secrets, "CONFIG_FILE", str(tmp_path / ".falcon_config.enc"))
    monkeypatch.setattr(falcon_secrets, "_KEY_LOCK_FILE", str(tmp_path / ".falcon_config.lock"))
    falcon_secrets._reset_key_cache()
    yield
    falcon_secrets._reset_key_cache()


@pytest.fixture
def cfg_path(tmp_path):
    return str(tmp_path / ".falcon_config.enc")


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class TestProfiles:

    def test_round_trip_and_no_plaintext(self, cfg_path):
        store = ConfigStore(path=cfg_path)
        store.save_profile("prod", "client-id-12345678", SECRET, "https://api.crowdstrike.com")

        store2 = ConfigStore(path=cfg_path)
        assert store2.load_error is None
        profiles = store2.list_profiles()
        assert len(profiles) == 1
        p = profiles[0]
        assert p["name"] == "prod" and p["active"] is True
        assert p["client_id_short"] == "12345678"
        assert SECRET not in repr(profiles)

        raw = open(cfg_path, "rb").read()
        assert SECRET.encode() not in raw
        assert b"client-id-12345678" not in raw
        assert _mode(cfg_path) == 0o600

    def test_blank_secret_keeps_existing(self, cfg_path, monkeypatch):
        store = ConfigStore(path=cfg_path)
        store.save_profile("prod", "cid-1", SECRET, "https://api.crowdstrike.com")
        store.save_profile("prod", "cid-2", "", "https://api.us-2.crowdstrike.com")
        for k in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL"):
            monkeypatch.delenv(k, raising=False)
        ConfigStore(path=cfg_path).inject_to_env()
        assert os.environ["FALCON_CLIENT_ID"] == "cid-2"
        assert os.environ["FALCON_CLIENT_SECRET"] == SECRET

    def test_blank_secret_on_new_profile_rejected(self, cfg_path):
        store = ConfigStore(path=cfg_path)
        with pytest.raises(ValueError):
            store.save_profile("new", "cid-1", "", "https://api.crowdstrike.com")
        assert not os.path.exists(cfg_path)

    def test_delete_active_profile_switches(self, cfg_path):
        store = ConfigStore(path=cfg_path)
        store.save_profile("a", "cid-a", "sec-a", "https://api.crowdstrike.com")
        store.save_profile("b", "cid-b", "sec-b", "https://api.crowdstrike.com")
        assert store.get_active_profile_name() == "a"
        assert store.set_active_profile("b") is True
        assert store.set_active_profile("missing") is False
        store.delete_profile("b")
        assert store.get_active_profile_name() == "a"


class TestLLMConfig:

    def test_api_key_never_exposed_by_default(self, cfg_path):
        store = ConfigStore(path=cfg_path)
        store.save_llm_config("http://localhost:11434", "llm-key-xyz", "openai", "qwen")
        llm = store.get_llm_config()
        assert "LLM_API_KEY" not in llm
        assert llm["LLM_API_KEY_SET"] is True
        assert store.get_llm_config(include_secret=True)["LLM_API_KEY"] == "llm-key-xyz"

    def test_none_keeps_key_and_empty_clears(self, cfg_path):
        store = ConfigStore(path=cfg_path)
        store.save_llm_config("https://api.anthropic.com", "llm-key-xyz")
        store.save_llm_config("https://api.anthropic.com", None, "anthropic", "m")
        assert store.get_llm_config(include_secret=True)["LLM_API_KEY"] == "llm-key-xyz"
        store.save_llm_config("https://api.anthropic.com", "", "anthropic", "m")
        assert store.get_llm_config(include_secret=True)["LLM_API_KEY"] == ""
        assert store.get_llm_config()["LLM_API_KEY_SET"] is False
        assert store.has_llm_config() is True


class TestInjectToEnv:

    def test_sets_and_pops_empty_values(self, cfg_path, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "stale-key")
        monkeypatch.setenv("LLM_MODEL", "stale-model")
        store = ConfigStore(path=cfg_path)
        store.save_profile("prod", "cid-1", SECRET, "https://api.crowdstrike.com")
        store.save_llm_config("http://localhost:11434", "", "openai", "")
        store.inject_to_env()
        assert os.environ["FALCON_CLIENT_ID"] == "cid-1"
        assert os.environ["LLM_ENDPOINT"] == "http://localhost:11434"
        assert os.environ["LLM_PROVIDER"] == "openai"
        assert "LLM_API_KEY" not in os.environ
        assert "LLM_MODEL" not in os.environ
        # Clean up keys we set so other tests aren't affected
        for k in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL",
                  "LLM_ENDPOINT", "LLM_PROVIDER"):
            monkeypatch.delenv(k, raising=False)

    def test_noop_without_config_file(self, cfg_path, monkeypatch):
        monkeypatch.setenv("FALCON_CLIENT_ID", "from-ide-env")
        monkeypatch.setenv("LLM_API_KEY", "from-ide-env")
        ConfigStore(path=cfg_path).inject_to_env()
        assert os.environ["FALCON_CLIENT_ID"] == "from-ide-env"
        assert os.environ["LLM_API_KEY"] == "from-ide-env"


class TestDecryptFailure:

    def test_wrong_key_fails_closed(self, cfg_path, monkeypatch):
        store = ConfigStore(path=cfg_path)
        store.save_profile("prod", "cid-1", SECRET, "https://api.crowdstrike.com")
        original = open(cfg_path, "rb").read()

        other_key = os.urandom(32)
        monkeypatch.setattr(falcon_secrets, "_get_or_create_key", lambda: other_key)
        falcon_secrets._reset_key_cache()  # the Fernet instance is cached per process
        store2 = ConfigStore(path=cfg_path)
        assert store2.load_error
        assert store2.has_config() is False
        with pytest.raises(ConfigDecryptError):
            store2.save_profile("evil", "cid-x", "sec-x", "https://api.crowdstrike.com")
        assert open(cfg_path, "rb").read() == original

    def test_missing_key_with_existing_config_raises(self, tmp_path):
        (tmp_path / ".falcon_config.enc").write_bytes(b"ciphertext")
        with pytest.raises(ConfigDecryptError):
            falcon_secrets._get_or_create_key()
        assert not (tmp_path / ".falcon_config.key").exists()

    def test_key_created_when_no_config(self, tmp_path):
        key = falcon_secrets._get_or_create_key()
        assert len(key) == 32
        key_path = tmp_path / ".falcon_config.key"
        assert key_path.read_bytes() == key
        assert _mode(key_path) == 0o600
        assert falcon_secrets._get_or_create_key() == key


class TestMigration:

    def _write_env(self, tmp_path, text):
        p = tmp_path / ".env"
        p.write_text(text)
        return str(p)

    def test_full_migration(self, tmp_path, cfg_path, monkeypatch):
        env = self._write_env(tmp_path, (
            "FALCON_CLIENT_ID=cid-1\n"
            f"FALCON_CLIENT_SECRET={SECRET}\n"
            "FALCON_BASE_URL=https://api.us-2.crowdstrike.com\n"
            "LLM_ENDPOINT=http://localhost:11434\n"
            "LLM_API_KEY=llm-key\n"
            "LLM_PROVIDER=openai\n"
            "LLM_MODEL=qwen2.5:7b-instruct\n"
        ))
        store = ConfigStore(path=cfg_path)
        assert store.migrate_from_env(env) is True
        assert not os.path.exists(env)
        assert _mode(env + ".migrated") == 0o600

        store2 = ConfigStore(path=cfg_path)
        p = store2.list_profiles()[0]
        assert p["client_id"] == "cid-1"
        assert p["base_url"] == "https://api.us-2.crowdstrike.com"
        llm = store2.get_llm_config(include_secret=True)
        assert llm["LLM_ENDPOINT"] == "http://localhost:11434"
        assert llm["LLM_API_KEY"] == "llm-key"
        assert llm["LLM_PROVIDER"] == "openai"
        assert llm["LLM_MODEL"] == "qwen2.5:7b-instruct"

    def test_llm_key_without_endpoint_preserved(self, tmp_path, cfg_path):
        env = self._write_env(tmp_path, (
            "FALCON_CLIENT_ID=cid-1\n"
            f"FALCON_CLIENT_SECRET={SECRET}\n"
            "LLM_API_KEY=orphan-key\n"
        ))
        store = ConfigStore(path=cfg_path)
        assert store.migrate_from_env(env) is True
        assert store.get_llm_config(include_secret=True)["LLM_API_KEY"] == "orphan-key"

    def test_bare_key_line_does_not_crash(self, tmp_path, cfg_path):
        env = self._write_env(tmp_path, "FALCON_CLIENT_ID\nFALCON_CLIENT_SECRET\nLLM_API_KEY\n")
        store = ConfigStore(path=cfg_path)
        assert store.migrate_from_env(env) is False
        assert os.path.exists(env)

    def test_missing_secret_leaves_env_untouched(self, tmp_path, cfg_path):
        text = "FALCON_CLIENT_ID=cid-1\nFALCON_CLIENT_SECRET=\n"
        env = self._write_env(tmp_path, text)
        store = ConfigStore(path=cfg_path)
        assert store.migrate_from_env(env) is False
        assert open(env).read() == text
        assert not os.path.exists(cfg_path)

    def test_noop_when_config_exists(self, tmp_path, cfg_path):
        store = ConfigStore(path=cfg_path)
        store.save_profile("existing", "cid-0", "sec-0", "https://api.crowdstrike.com")
        env = self._write_env(tmp_path, f"FALCON_CLIENT_ID=cid-1\nFALCON_CLIENT_SECRET={SECRET}\n")
        assert store.migrate_from_env(env) is False
        assert os.path.exists(env)
        assert [p["name"] for p in store.list_profiles()] == ["existing"]


class TestFileHelpers:

    def test_write_private_file_mode_and_cleanup(self, tmp_path):
        target = tmp_path / "secret.bin"
        target.write_bytes(b"old")
        os.chmod(target, 0o644)
        write_private_file(str(target), b"new-data")
        assert target.read_bytes() == b"new-data"
        assert _mode(target) == 0o600
        assert sorted(p.name for p in tmp_path.iterdir()) == ["secret.bin"]  # no temp files left

    def test_write_private_file_concurrent_writers(self, tmp_path):
        import threading
        target = str(tmp_path / "cache.bin")
        payloads = [bytes([i]) * 200_000 for i in range(8)]
        errors = []

        def _writer(data):
            try:
                for _ in range(20):
                    write_private_file(target, data)
            except Exception as e:  # pragma: no cover - failure path
                errors.append(e)

        threads = [threading.Thread(target=_writer, args=(p,)) for p in payloads]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert open(target, "rb").read() in payloads  # never a mix or truncated file
        assert sorted(p.name for p in tmp_path.iterdir()) == ["cache.bin"]

    def test_cache_encryption_round_trip(self):
        payload = {"entries": {"k": {"data": "{}"}}, "_meta": {"cid_fingerprint": "abc"}}
        blob = encrypt_cache(payload)
        assert blob and b"cid_fingerprint" not in blob
        assert decrypt_cache(blob) == payload

    def test_decrypt_garbage_returns_none(self):
        assert decrypt_cache(b"definitely not fernet") is None
        assert decrypt_cache(b'{"plain": "json"}') is None


# ---------------------------------------------------------------------------
# Multi-profile legacy migration, key store failures, concurrent key creation
# ---------------------------------------------------------------------------

LEGACY_MULTI = """# Hosted LLM (previous)
#LLM_API_KEY=old-cloud-key
#LLM_ENDPOINT=https://llm.example.com
#LLM_PROVIDER=anthropic

# Self-hosted LLM
LLM_API_KEY=not-needed
LLM_ENDPOINT=http://localhost:11434
LLM_PROVIDER=openai
LLM_MODEL=qwen2.5:7b-instruct

#lab-test
#FALCON_CLIENT_ID=id-lab
#FALCON_CLIENT_SECRET=secret-lab
#FALCON_BASE_URL=https://api.crowdstrike.com

#prod-us2
FALCON_CLIENT_ID=id-prod
FALCON_CLIENT_SECRET="secret-prod"
FALCON_BASE_URL=https://api.us-2.crowdstrike.com

#msp: someone@example.com
#FALCON_CLIENT_ID=id-msp
#FALCON_CLIENT_SECRET=secret-msp
#FALCON_BASE_URL=https://api.crowdstrike.com
"""


class TestLegacyMultiProfile:

    def test_parse_all_profiles_and_active(self):
        profiles, active = falcon_secrets.parse_legacy_env_profiles(LEGACY_MULTI)
        assert list(profiles) == ["lab-test", "prod-us2", "msp: someone@example.com"]
        assert active == "prod-us2"
        assert profiles["prod-us2"]["FALCON_CLIENT_SECRET"] == "secret-prod"  # quotes stripped
        assert profiles["prod-us2"]["FALCON_BASE_URL"] == "https://api.us-2.crowdstrike.com"
        assert profiles["lab-test"]["FALCON_CLIENT_SECRET"] == "secret-lab"

    def test_llm_blocks_are_not_profiles(self):
        profiles, _ = falcon_secrets.parse_legacy_env_profiles(LEGACY_MULTI)
        assert not any("LLM" in n for n in profiles)

    def test_headerless_active_block_is_default(self):
        profiles, active = falcon_secrets.parse_legacy_env_profiles(
            "FALCON_CLIENT_ID=a\nFALCON_CLIENT_SECRET=b\n")
        assert active == "default" and profiles["default"]["FALCON_CLIENT_ID"] == "a"

    def test_incomplete_profile_skipped(self):
        profiles, _ = falcon_secrets.parse_legacy_env_profiles("#x\n#FALCON_CLIENT_ID=only-id\n")
        assert profiles == {}

    def test_migrate_imports_every_profile(self, tmp_path, cfg_path):
        env = tmp_path / ".env"
        env.write_text(LEGACY_MULTI)
        store = ConfigStore(path=cfg_path)
        assert store.migrate_from_env(str(env)) is True
        names = {p["name"]: p["active"] for p in ConfigStore(path=cfg_path).list_profiles()}
        assert names == {"lab-test": False, "prod-us2": True, "msp: someone@example.com": False}
        llm = ConfigStore(path=cfg_path).get_llm_config(include_secret=True)
        assert llm["LLM_ENDPOINT"] == "http://localhost:11434" and llm["LLM_PROVIDER"] == "openai"
        assert (tmp_path / ".env.migrated").exists() and not env.exists()


class _BrokenKeyring:
    def get_password(self, *a):
        raise RuntimeError("keychain locked")

    def set_password(self, *a):  # pragma: no cover - must not be reached
        raise AssertionError("must not create a key when the keychain can't be read")


class TestKeyStore:

    def test_keychain_read_error_does_not_create_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr(falcon_secrets, "_keyring_available", True)
        monkeypatch.setattr(falcon_secrets, "_keyring", _BrokenKeyring())
        with pytest.raises(falcon_secrets.KeyUnavailableError):
            falcon_secrets._get_or_create_key()
        assert not (tmp_path / ".falcon_config.key").exists()
        assert falcon_secrets.encrypt_cache({"a": 1}) is None  # cache persistence is skipped

    def test_concurrent_first_run_gets_one_key(self, tmp_path):
        import threading
        keys, barrier = [], threading.Barrier(8)

        def _get():
            barrier.wait()
            keys.append(falcon_secrets._get_or_create_key())

        threads = [threading.Thread(target=_get) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(keys)) == 1
        assert open(tmp_path / ".falcon_config.key", "rb").read() == keys[0]

    def test_fernet_is_cached(self, monkeypatch):
        calls = []
        real = falcon_secrets._get_or_create_key
        monkeypatch.setattr(falcon_secrets, "_get_or_create_key", lambda: calls.append(1) or real())
        blob = falcon_secrets.encrypt_cache({"a": 1})
        assert falcon_secrets.decrypt_cache(blob) == {"a": 1}
        falcon_secrets.encrypt_cache({"b": 2})
        assert len(calls) == 1

"""Tests for the safety guards that keep tests and tools away from real data.

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
import subprocess
import sys
import tempfile

import pytest

import falcon_secrets
from tests._safety import UnsafeCleanupError, assert_safe_test_dir, clear_state

REPO = falcon_secrets.SOURCE_DIR


class TestDataDirLocation:

    def test_default_data_dir_is_outside_source_tree(self):
        assert not falcon_secrets._is_within(falcon_secrets.DEFAULT_APP_DIR, REPO)
        assert not falcon_secrets._is_within(REPO, falcon_secrets.DEFAULT_APP_DIR)

    def test_tests_run_in_temp_data_dir(self):
        assert falcon_secrets._is_within(falcon_secrets.APP_DIR, tempfile.gettempdir())

    def test_legacy_env_is_read_from_source_dir(self):
        assert falcon_secrets.LEGACY_ENV_FILE == os.path.join(REPO, ".env")


class TestUnsafeTestRunRefused:

    def test_import_with_pytest_and_real_data_dir_is_refused(self, tmp_path):
        """Importing project code next to pytest with a non-temp data dir must fail closed."""
        not_temp = os.path.join(os.path.expanduser("~"), ".falcon-digest-guard-probe-does-not-exist")
        env = {**os.environ, "FALCON_DIGEST_HOME": not_temp, "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring"}
        code = f"import sys, pytest; sys.path.insert(0, {REPO!r}); import falcon_secrets"
        proc = subprocess.run([sys.executable, "-I", "-c", code], cwd=str(tmp_path), env=env,
                              capture_output=True, text=True, timeout=60)
        assert proc.returncode != 0
        assert "Refusing to run tests against a non-temporary data directory" in proc.stderr
        assert not os.path.exists(not_temp)


class TestCleanupHelper:

    @pytest.mark.parametrize("target", [
        lambda: REPO,
        lambda: os.path.expanduser("~"),
        lambda: tempfile.gettempdir(),
        lambda: falcon_secrets.DEFAULT_APP_DIR,
        lambda: os.sep,
    ])
    def test_refuses_dangerous_dirs(self, target):
        with pytest.raises(UnsafeCleanupError):
            assert_safe_test_dir(target())

    def test_refuses_git_checkout_in_temp(self, tmp_path):
        (tmp_path / ".git").mkdir()
        with pytest.raises(UnsafeCleanupError):
            clear_state(str(tmp_path))

    def test_removes_only_state_files(self, tmp_path):
        for name in (".falcon_config.enc", ".falcon_users.json", ".falcon_cache.json", ".falcon_cache.json.abc.tmp"):
            (tmp_path / name).write_text("x")
        (tmp_path / ".falcon_cache_backups").mkdir()
        (tmp_path / ".falcon_cache_backups" / "cache_1.enc").write_text("x")
        (tmp_path / "keep_me.py").write_text("code")
        (tmp_path / "notes.md").write_text("notes")
        clear_state(str(tmp_path))
        assert sorted(p.name for p in tmp_path.iterdir()) == ["keep_me.py", "notes.md"]


class TestLegacyStateMove:

    def test_moves_named_files_without_overwriting(self, tmp_path, monkeypatch):
        src, dst = tmp_path / "src", tmp_path / "data"
        src.mkdir()
        dst.mkdir()
        (src / ".falcon_users.json").write_text("old-users")
        (src / ".falcon_cache.json").write_text("old-cache")
        (src / "mcp_dashboard.py").write_text("code")
        (dst / ".falcon_cache.json").write_text("current-cache")
        monkeypatch.setattr(falcon_secrets, "SOURCE_DIR", str(src))
        monkeypatch.setattr(falcon_secrets, "APP_DIR", str(dst))
        falcon_secrets._move_legacy_state()
        assert (dst / ".falcon_users.json").read_text() == "old-users"
        assert (dst / ".falcon_cache.json").read_text() == "current-cache"  # not overwritten
        assert (src / ".falcon_cache.json").exists()  # left in place
        assert (src / "mcp_dashboard.py").read_text() == "code"  # code untouched

    def test_migrated_env_lands_in_data_dir(self, tmp_path):
        src, dst = tmp_path / "src", tmp_path / "data"
        src.mkdir()
        dst.mkdir()
        env = src / ".env"
        env.write_text("FALCON_CLIENT_ID=abcdef0123456789\nFALCON_CLIENT_SECRET=dummySECRET1234567890\n")
        store = falcon_secrets.ConfigStore(path=str(dst / ".falcon_config.enc"))
        assert store.migrate_from_env(str(env)) is True
        assert not env.exists() and not (src / ".env.migrated").exists()
        assert (dst / ".env.migrated").exists()

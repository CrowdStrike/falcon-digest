"""Unit tests for falcon_auth.UserManager (hashing, roles, fail-closed loading, lockout).

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
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import falcon_auth
from falcon_auth import UserManager, UsersFileError, lockout_remaining


@pytest.fixture(autouse=True)
def fast_hashing_and_clean_lockouts(monkeypatch):
    """Use cheap PBKDF2 and reset the process-wide failed-login table per test."""
    monkeypatch.setattr(falcon_auth, "_PBKDF2_ITERATIONS", 1000)
    falcon_auth._failed_logins.clear()
    yield
    falcon_auth._failed_logins.clear()


@pytest.fixture
def users_path(tmp_path):
    return str(tmp_path / ".falcon_users.json")


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class TestUserBasics:

    def test_add_and_authenticate(self, users_path):
        mgr = UserManager(path=users_path)
        assert mgr.add_user("admin1", "correct-horse", role="admin") is None
        assert {k: v for k, v in (mgr.authenticate("admin1", "correct-horse") or {}).items() if k != "epoch"} == {"username": "admin1", "role": "admin"}

    def test_wrong_password(self, users_path):
        mgr = UserManager(path=users_path)
        mgr.add_user("viewer1", "correct-horse")
        assert mgr.authenticate("viewer1", "wrong-password") is None

    def test_file_stores_hash_not_password(self, users_path):
        mgr = UserManager(path=users_path)
        mgr.add_user("admin1", "super-secret-pw", role="admin")
        raw = open(users_path).read()
        assert "super-secret-pw" not in raw
        data = json.loads(raw)
        entry = data["users"]["admin1"]
        assert entry["password_hash"] and entry["salt"]
        assert _mode(users_path) == 0o600

    def test_case_insensitive_usernames(self, users_path):
        mgr = UserManager(path=users_path)
        mgr.add_user("Alice", "password123", role="admin")
        assert mgr.authenticate("Alice", "password123")["username"] == "alice"
        assert mgr.authenticate(" alice ", "password123")["username"] == "alice"
        assert {k: v for k, v in (mgr.get_user("ALICE") or {}).items() if k != "epoch"} == {"username": "alice", "role": "admin"}

    def test_unknown_user_returns_none(self, users_path):
        mgr = UserManager(path=users_path)
        mgr.add_user("admin1", "password123", role="admin")
        assert mgr.authenticate("nobody", "password123") is None
        assert mgr.authenticate("", "") is None

    def test_reload_from_disk(self, users_path):
        UserManager(path=users_path).add_user("admin1", "password123", role="admin")
        mgr2 = UserManager(path=users_path)
        assert mgr2.has_users()
        assert mgr2.authenticate("admin1", "password123")


class TestLastAdminProtection:

    def test_cannot_remove_last_admin(self, users_path):
        mgr = UserManager(path=users_path)
        mgr.add_user("admin1", "password123", role="admin")
        assert mgr.remove_user("admin1") is not None
        assert mgr.get_user("admin1") is not None

    def test_cannot_demote_last_admin(self, users_path):
        mgr = UserManager(path=users_path)
        mgr.add_user("admin1", "password123", role="admin")
        assert mgr.change_role("admin1", "viewer") is not None
        assert mgr.get_user("admin1")["role"] == "admin"

    def test_can_remove_admin_when_another_exists(self, users_path):
        mgr = UserManager(path=users_path)
        mgr.add_user("admin1", "password123", role="admin")
        mgr.add_user("admin2", "password123", role="admin")
        assert mgr.remove_user("ADMIN1") is None
        assert mgr.get_user("admin1") is None


class TestFailClosed:

    @pytest.mark.parametrize("content", ["{not valid json!!!", json.dumps({"nope": 1}), json.dumps({"users": []})])
    def test_corrupt_file_fails_closed(self, users_path, content):
        with open(users_path, "w") as f:
            f.write(content)
        mgr = UserManager(path=users_path)
        assert mgr.load_error
        assert mgr.has_users() is True  # never reopens first-run setup
        with pytest.raises(UsersFileError):
            mgr.add_user("attacker", "password123", role="admin")
        assert open(users_path).read() == content  # original file untouched

    def test_missing_file_is_first_run(self, users_path):
        mgr = UserManager(path=users_path)
        assert mgr.load_error is None
        assert mgr.has_users() is False


class TestLockout:

    def test_lockout_after_repeated_failures(self, users_path, monkeypatch):
        now = [1_000_000.0]
        monkeypatch.setattr(falcon_auth.time, "time", lambda: now[0])
        mgr = UserManager(path=users_path)
        mgr.add_user("admin1", "password123", role="admin")

        for _ in range(falcon_auth._MAX_FREE_ATTEMPTS):
            assert mgr.authenticate("admin1", "bad-password") is None
        assert lockout_remaining("admin1") > 0
        assert lockout_remaining("ADMIN1") > 0
        # Correct password is rejected while locked out
        assert mgr.authenticate("admin1", "password123") is None

        now[0] += falcon_auth._LOCKOUT_MAX_SECONDS + 1
        assert lockout_remaining("admin1") == 0
        assert mgr.authenticate("admin1", "password123") is not None
        assert "admin1" not in falcon_auth._failed_logins

    def test_unknown_users_are_throttled_too(self, users_path):
        mgr = UserManager(path=users_path)
        for _ in range(falcon_auth._MAX_FREE_ATTEMPTS):
            mgr.authenticate("ghost", "x")
        assert lockout_remaining("ghost") > 0


class TestSetupToken:

    def test_token_lifecycle(self, users_path):
        mgr = UserManager(path=users_path)
        token = mgr.get_or_create_setup_token()
        assert token
        assert mgr.get_or_create_setup_token() == token
        assert _mode(mgr.setup_token_path) == 0o600
        assert mgr.verify_setup_token(token) is True
        assert mgr.verify_setup_token(f"  {token}  ") is True
        assert mgr.verify_setup_token("wrong") is False
        assert mgr.verify_setup_token("") is False
        mgr.consume_setup_token()
        assert not os.path.exists(mgr.setup_token_path)
        assert mgr.verify_setup_token(token) is False


@pytest.fixture
def um(users_path):
    return UserManager(path=users_path)


class TestPerClientLockout:

    def test_lockout_is_per_client(self, um):
        um.add_user("admin", "correct-password", role="admin")
        for _ in range(6):
            assert um.authenticate("admin", "wrong", client="203.0.113.9") is None
        assert falcon_auth.lockout_remaining("admin", "203.0.113.9") > 0
        # the real admin on another address is not locked out
        assert falcon_auth.lockout_remaining("admin", "127.0.0.1") == 0
        assert um.authenticate("admin", "correct-password", client="127.0.0.1")

    def test_lockout_capped(self, um, monkeypatch):
        now = [1_000_000.0]
        monkeypatch.setattr(falcon_auth.time, "time", lambda: now[0])
        for _ in range(40):
            um.authenticate("ghost", "x", client="c")
        assert falcon_auth.lockout_remaining("ghost", "c") <= falcon_auth._LOCKOUT_MAX_SECONDS

    def test_tracking_is_bounded(self, um, monkeypatch):
        monkeypatch.setattr(falcon_auth, "_MAX_TRACKED", 50)
        for i in range(200):
            falcon_auth._record_failure(f"c|user{i}")
        assert len(falcon_auth._failed_logins) <= 50

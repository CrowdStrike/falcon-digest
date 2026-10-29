"""Headless tests for the dashboard's authentication gate and role checks.

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

Drives mcp_dashboard.py with Streamlit's AppTest. All state lives in the
per-run temp data dir set by tests/conftest.py; cleanup goes through the
guarded tests._safety.clear_state, never a directory wipe.
"""

import json
import os
import time
from datetime import datetime, timezone

import pytest
from streamlit.testing.v1 import AppTest

import falcon_auth
import falcon_cache
import falcon_secrets
from falcon_auth import UserManager
from falcon_secrets import config_store
from tests._safety import clear_state

DASHBOARD = os.path.join(falcon_secrets.SOURCE_DIR, "mcp_dashboard.py")
DEAD_URL = "http://127.0.0.1:9"  # Falcon calls fail fast
PW = "password-123"


def _fake_refresh(self):
    """Stand-in for FalconCache._refresh_all: no network, one dummy entry."""
    now = datetime.now(tz=timezone.utc)
    with self._lock:
        self._cache["security_posture"] = {"data": json.dumps({"risk_score": 0}), "fetched_at": now.isoformat() + "Z"}
    self._last_refresh = now
    self._refresh_count += 1


@pytest.fixture(autouse=True)
def isolated_app(monkeypatch):
    clear_state()
    falcon_secrets._reset_key_cache()
    config_store.reload()
    config_store.migration_warning = None
    falcon_auth._failed_logins.clear()
    falcon_auth._user_failures.clear()
    monkeypatch.setattr(falcon_auth, "_PBKDF2_ITERATIONS", 1000)
    for k in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL", "LLM_ENDPOINT", "LLM_API_KEY",
              "LLM_PROVIDER", "LLM_MODEL", "LLM_LOCAL_MODE", "FALCON_DIGEST_USE_ENV"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(falcon_cache.FalconCache, "_refresh_all", _fake_refresh)
    cache = falcon_cache.cache
    cache.stop()
    with cache._lock:
        cache._cache.clear()
    yield
    cache.stop()
    clear_state()
    falcon_secrets._reset_key_cache()
    config_store.reload()


def _app() -> AppTest:
    return AppTest.from_file(DASHBOARD, default_timeout=60).run()


def _labels(at, kind):
    return [w.label for w in getattr(at, kind)]


def _login(at, username, password=PW):
    next(w for w in at.text_input if w.label == "Username").input(username)
    next(w for w in at.text_input if w.label == "Password").input(password)
    return next(b for b in at.button if b.label == "Login").click().run()


def _seed(profiles=1, users=(("admin", "admin"), ("viewer", "viewer"))):
    for i in range(profiles):
        config_store.save_profile(f"p{i + 1}", f"clientid{i + 1:024d}", f"secret-{i + 1}", DEAD_URL)
    um = UserManager()
    for name, role in users:
        assert um.add_user(name, PW, role) is None
    return um


def _texts(at):
    out = []
    for kind in ("markdown", "caption", "info", "warning", "error", "success", "text"):
        out += [str(getattr(e, "value", "")) for e in getattr(at, kind)]
    return " ".join(out)


# ---------------------------------------------------------------------------
# First run and fail-closed startup
# ---------------------------------------------------------------------------

def test_first_run_requires_setup_token():
    at = _app()
    assert "Setup token" in _labels(at, "text_input")
    fields = {w.label: w for w in at.text_input}
    fields["Setup token"].input("wrong")
    fields["Username"].input("admin")
    fields["Password"].input(PW)
    fields["Confirm Password"].input(PW)
    at = next(b for b in at.button if b.label == "Create Admin Account").click().run()
    assert "Invalid setup token." in [e.value for e in at.error]
    assert not UserManager().has_users()

    token_path = UserManager().setup_token_path
    token = json.load(open(token_path))["token"]
    fields = {w.label: w for w in at.text_input}
    fields["Setup token"].input(token)
    fields["Password"].input(PW)
    fields["Confirm Password"].input(PW)
    at = next(b for b in at.button if b.label == "Create Admin Account").click().run()
    assert UserManager().get_user("admin")["role"] == "admin"
    assert not os.path.exists(token_path)
    assert "Add a Falcon API profile to get started." in [i.value for i in at.info]


def test_corrupt_users_file_fails_closed():
    with open(falcon_auth.USERS_FILE, "w") as f:
        f.write("{not json")
    at = _app()
    assert at.error
    assert "Setup token" not in _labels(at, "text_input")
    assert "Username" not in _labels(at, "text_input")


def test_undecryptable_config_fails_closed_and_recovers(monkeypatch):
    _seed()
    good_key = falcon_secrets._get_or_create_key()
    monkeypatch.setattr(falcon_secrets, "_get_or_create_key", lambda: b"x" * 32)
    falcon_secrets._reset_key_cache()
    config_store.reload()
    at = _app()
    assert at.error and "/" not in at.error[0].value  # no filesystem path shown
    assert "Username" not in _labels(at, "text_input")

    monkeypatch.setattr(falcon_secrets, "_get_or_create_key", lambda: good_key)
    falcon_secrets._reset_key_cache()
    at = at.run()  # no restart needed
    assert "Username" in _labels(at, "text_input")


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

def test_viewer_cannot_reach_admin_controls():
    _seed(profiles=2)
    at = _login(_app(), "viewer")
    buttons = _labels(at, "button")
    assert "Settings" not in buttons
    assert "Refresh Cache Now" not in buttons and "Start Cache" not in buttons
    assert "Cache poll interval (sec)" not in _labels(at, "slider")
    assert "CID Profile" not in _labels(at, "selectbox")
    period = next(s for s in at.selectbox if s.label == "Period")
    assert period.disabled

    at.session_state["_show_settings"] = True
    at = at.run()
    assert "Save Profile" not in _labels(at, "button")
    assert "Save LLM Settings" not in _labels(at, "button")


def test_admin_sees_admin_controls():
    _seed(profiles=2)
    at = _login(_app(), "admin")
    assert "Settings" in _labels(at, "button")
    assert "CID Profile" in _labels(at, "selectbox")
    assert "Cache poll interval (sec)" in _labels(at, "slider")
    assert not next(s for s in at.selectbox if s.label == "Period").disabled


def test_forged_role_in_session_is_corrected():
    _seed()
    at = _login(_app(), "viewer")
    at.session_state["current_user"] = {**at.session_state["current_user"], "role": "admin"}
    at = at.run()
    assert "Settings" not in _labels(at, "button")


# ---------------------------------------------------------------------------
# CID switching (B2)
# ---------------------------------------------------------------------------

def test_settings_activate_is_not_reverted_by_sidebar():
    _seed(profiles=2)
    at = _login(_app(), "admin")
    at = next(b for b in at.button if b.label == "Settings").click().run()
    at = next(b for b in at.button if b.key == "activate_p2").click().run()
    assert config_store.get_active_profile_name() == "p2"
    at = at.run()
    at = at.run()
    assert config_store.get_active_profile_name() == "p2"


def test_sidebar_selector_switches_profile():
    _seed(profiles=2)
    at = _login(_app(), "admin")
    at = next(s for s in at.selectbox if s.label == "CID Profile").set_value("p2").run()
    assert config_store.get_active_profile_name() == "p2"
    at = at.run()
    assert config_store.get_active_profile_name() == "p2"


def test_external_switch_is_not_reverted():
    _seed(profiles=2)
    at = _login(_app(), "admin")
    config_store.set_active_profile("p2")  # e.g. another admin session
    at = at.run()
    at = at.run()
    assert config_store.get_active_profile_name() == "p2"


# ---------------------------------------------------------------------------
# Sessions (N5, N9, N11)
# ---------------------------------------------------------------------------

def test_removed_user_is_logged_out():
    um = _seed()
    at = _login(_app(), "viewer")
    um.remove_user("viewer")
    at = at.run()
    assert "Username" in _labels(at, "text_input")


@pytest.mark.parametrize("change", ["password", "role"])
def test_password_or_role_change_ends_session(change):
    um = _seed()
    at = _login(_app(), "viewer")
    if change == "password":
        assert um.change_password("viewer", "new-password-456") is None
    else:
        assert um.change_role("viewer", "admin") is None
    at = at.run()
    assert "Username" in _labels(at, "text_input")


def test_idle_session_expires():
    _seed()
    at = _login(_app(), "viewer")
    at.session_state["_last_activity"] = time.time() - 9 * 3600
    at = at.run()
    assert "Username" in _labels(at, "text_input")


def test_logout_clears_session_data():
    _seed()
    at = _login(_app(), "admin")
    at.session_state["chat_messages"] = [{"role": "user", "content": "admin-only question"}]
    at = next(b for b in at.button if b.label == "Logout").click().run()
    assert "chat_messages" not in at.session_state
    at = _login(at, "viewer")
    assert "chat_messages" not in at.session_state or not at.session_state["chat_messages"]


def test_demoted_admin_period_change_is_ignored():
    um = _seed(users=(("admin", "admin"), ("admin2", "admin")))
    at = _login(_app(), "admin")
    hours_before = falcon_cache.cache.hours
    assert um.change_role("admin", "viewer") is None  # callback runs with the stale role
    period = next(s for s in at.selectbox if s.label == "Period")
    at = period.set_value(6).run()
    assert falcon_cache.cache.hours == hours_before
    assert "Username" in _labels(at, "text_input")


# ---------------------------------------------------------------------------
# Secrets never reach the browser
# ---------------------------------------------------------------------------

def test_stored_secrets_not_rendered():
    config_store.save_profile("p1", "clientid000000000000000001", "PROFILE-SECRET-XYZ", DEAD_URL)
    config_store.save_llm_config("https://llm.example.invalid", "SUPER-SECRET-KEY-123", "anthropic", "")
    UserManager().add_user("admin", PW, "admin")
    at = _login(_app(), "admin")
    at = next(b for b in at.button if b.label == "Settings").click().run()
    values = [str(w.value) for w in at.text_input]
    rendered = _texts(at) + " ".join(values)
    assert "SUPER-SECRET-KEY-123" not in rendered
    assert "PROFILE-SECRET-XYZ" not in rendered
    assert next(w for w in at.text_input if w.label == "LLM API Key").value == ""


# ---------------------------------------------------------------------------
# Login throttling and env-var mode
# ---------------------------------------------------------------------------

def test_lockout_after_repeated_failures():
    _seed()
    at = _app()
    for _ in range(6):
        at = _login(at, "admin", "wrong-password")
    assert any("Too many failed attempts" in e.value for e in at.error)


def test_env_var_mode_dashboard(monkeypatch):
    UserManager().add_user("admin", PW, "admin")
    monkeypatch.setenv("FALCON_CLIENT_ID", "envclientid0000000000000001")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "env-secret")
    monkeypatch.setenv("FALCON_BASE_URL", DEAD_URL)
    at = _login(_app(), "admin")
    assert "Add a Falcon API profile to get started." not in [i.value for i in at.info]
    assert "Using credentials from the process environment" in _texts(at)

"""User authentication and management for Falcon Digest dashboard.

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

import contextlib
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timezone

from falcon_secrets import APP_DIR, _file_lock, write_private_file

logger = logging.getLogger("falcon_mcp.auth")

USERS_FILE = os.path.join(APP_DIR, ".falcon_users.json")
ROLES = ("admin", "viewer")
_PBKDF2_ITERATIONS = 600_000

# Failed-login throttling (process-wide), keyed by client + normalized username,
# so a remote attacker can't lock a user out from everyone else's address
_MAX_FREE_ATTEMPTS = 5
_LOCKOUT_BASE_SECONDS = 30
_LOCKOUT_MAX_SECONDS = 300
_MAX_TRACKED = 10_000
_failed_logins: dict[str, tuple[int, float]] = {}
_failed_lock = threading.Lock()
# Per-username failures across all clients: only ever slows attempts down, never blocks,
# so an attacker behind a shared/unknown address can't lock a real user out
_SLOWDOWN_MAX_SECONDS = 3.0
_user_failures: dict[str, tuple[int, float]] = {}

# Verified against when the username is unknown, so both paths cost one PBKDF2 run
_DUMMY_SALT = os.urandom(32)
_DUMMY_HASH = hashlib.pbkdf2_hmac("sha256", b"dummy-password", _DUMMY_SALT, _PBKDF2_ITERATIONS).hex()


class UsersFileError(Exception):
    """Raised when the users file exists but cannot be loaded or written."""


class _Abort(Exception):
    """Internal: abandon a user-file mutation without saving."""


def normalize_username(username: str) -> str:
    """Return the canonical (stripped, lowercase) form of a username."""
    return (username or "").strip().lower()


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if salt is None:
        salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return dk.hex(), salt.hex()


def _verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return hmac.compare_digest(dk.hex(), stored_hash)


def _throttle_key(username: str, client: str) -> str:
    return f"{client or '-'}|{normalize_username(username)}"


def _lockout_for(count: int, last: float, now: float) -> float:
    if count < _MAX_FREE_ATTEMPTS:
        return 0.0
    delay = min(_LOCKOUT_BASE_SECONDS * 2 ** (count - _MAX_FREE_ATTEMPTS), _LOCKOUT_MAX_SECONDS)
    return max(0.0, last + delay - now)


def lockout_remaining(username: str, client: str = "") -> float:
    """Return seconds until ``username`` may log in again from ``client`` (0 if not locked).

    Args:
        username: Username being attempted (normalized internally).
        client: Identifier of the requesting client, e.g. its IP address.
    """
    with _failed_lock:
        count, last = _failed_logins.get(_throttle_key(username, client), (0, 0.0))
    return _lockout_for(count, last, time.time())


def _prune(table: dict, now: float) -> None:
    if len(table) <= _MAX_TRACKED:
        return
    for k in [k for k, (_, t) in table.items() if now - t > _LOCKOUT_MAX_SECONDS * 2]:
        del table[k]
    while len(table) > _MAX_TRACKED:  # still full: drop the oldest
        del table[min(table, key=lambda k: table[k][1])]


def _bump(table: dict, key: str, now: float) -> int:
    count, last = table.get(key, (0, 0.0))
    if now - last > _LOCKOUT_MAX_SECONDS * 2:
        count = 0  # old failures are forgotten
    table[key] = (count + 1, now)
    _prune(table, now)
    return count + 1


def _reserve_attempt(key: str) -> bool:
    """Count an attempt before the password is checked; False if the key is locked out.

    Reserving first means a burst of parallel submissions can't all slip
    past the ``count < limit`` check.
    """
    now = time.time()
    with _failed_lock:
        count, last = _failed_logins.get(key, (0, 0.0))
        if _lockout_for(count, last, now) > 0:
            return False
        _bump(_failed_logins, key, now)
        return True


def _record_failure(key: str) -> None:
    """Record a failed attempt for ``key`` (used directly by tests and admin tooling)."""
    with _failed_lock:
        _bump(_failed_logins, key, time.time())


def _user_slowdown(username: str) -> float:
    """Return the delay to apply before verifying ``username`` (grows with recent failures)."""
    with _failed_lock:
        count, last = _user_failures.get(username, (0, 0.0))
    if time.time() - last > _LOCKOUT_MAX_SECONDS * 2 or count < _MAX_FREE_ATTEMPTS:
        return 0.0
    return min(0.25 * 2 ** (count - _MAX_FREE_ATTEMPTS), _SLOWDOWN_MAX_SECONDS)


def _clear_failures(key: str, username: str = "") -> None:
    with _failed_lock:
        _failed_logins.pop(key, None)
        if username:
            _user_failures.pop(username, None)


class UserManager:
    """Manage dashboard users stored in a local JSON file with PBKDF2 password hashes.

    If the users file exists but cannot be read or parsed, ``load_error`` is
    set and the manager fails closed: ``has_users()`` returns True and all
    writes are refused, so a damaged file never reopens first-run setup.
    """

    def __init__(self, path: str = USERS_FILE):
        self._path = path
        self._users: dict = {}
        self.load_error: str | None = None
        self._load()

    def _load(self) -> None:
        self.load_error = None
        if not os.path.exists(self._path):
            self._users = {}
            return
        try:
            with open(self._path, "r") as f:
                data = json.load(f)
            users = data.get("users") if isinstance(data, dict) else None
            if not isinstance(users, dict):
                raise ValueError("missing 'users' object")
            for name, info in users.items():
                if not (isinstance(name, str) and isinstance(info, dict)
                        and isinstance(info.get("password_hash"), str) and isinstance(info.get("salt"), str)
                        and info.get("role") in ROLES):
                    raise ValueError(f"malformed entry for user {name!r}")
                bytes.fromhex(info["salt"])
            self._users = users
        except (ValueError, OSError) as e:
            self.load_error = f"Cannot read users file {self._path}: {e}"
            logger.error(self.load_error)
            self._users = {}

    @contextlib.contextmanager
    def _mutation(self):
        """Lock the users file, re-read it, let the caller mutate, then save.

        Prevents two sessions from overwriting each other's changes.
        """
        with _file_lock(self._path + ".lock"):
            self._load()
            if self.load_error:
                raise UsersFileError(self.load_error)
            yield self._users
            self._save()

    def _save(self) -> None:
        if self.load_error:
            raise UsersFileError(self.load_error)
        write_private_file(self._path, json.dumps({"users": self._users}, indent=2).encode())

    def has_users(self) -> bool:
        """Return True if any user exists (or the users file is unreadable)."""
        return bool(self._users) or self.load_error is not None

    def list_users(self) -> list[dict]:
        """List users without password material."""
        return [
            {"username": u, "role": info.get("role", "viewer"), "created": info.get("created", "")}
            for u, info in self._users.items()
        ]

    def get_user(self, username: str) -> dict | None:
        """Return ``{"username", "role"}`` for an existing user, else None."""
        username = normalize_username(username)
        user = self._users.get(username)
        if not user:
            return None
        return {"username": username, "role": user.get("role", "viewer"), "epoch": user.get("epoch", 0)}

    def authenticate(self, username: str, password: str, client: str = "") -> dict | None:
        """Verify credentials.

        Unknown usernames are checked against a dummy hash so response time
        doesn't reveal which usernames exist. Repeated failures from the same
        client lock that client out for that username with exponential
        backoff (see ``lockout_remaining``); other clients are unaffected.

        Args:
            username: Username (case-insensitive).
            password: Password.
            client: Identifier of the requesting client, e.g. its IP address.

        Returns:
            ``{"username", "role"}`` on success, else None.
        """
        username = normalize_username(username)
        throttle_key = _throttle_key(username, client)
        if not _reserve_attempt(throttle_key):
            return None
        delay = _user_slowdown(username)
        if delay:
            time.sleep(delay)
        user = self._users.get(username)
        if user:
            ok = _verify_password(password or "", user["password_hash"], user["salt"])
        else:
            _verify_password(password or "", _DUMMY_HASH, _DUMMY_SALT.hex())
            ok = False
        if not ok:
            with _failed_lock:
                _bump(_user_failures, username, time.time())
            return None
        _clear_failures(throttle_key, username)
        return {"username": username, "role": user.get("role", "viewer"), "epoch": user.get("epoch", 0)}

    def add_user(self, username: str, password: str, role: str = "viewer",
                 require_no_users: bool = False) -> str | None:
        """Create a user.

        Args:
            username: Username (stored lowercase).
            password: Password (min 8 characters).
            role: ``admin`` or ``viewer``.
            require_no_users: Fail if any user already exists (first-run setup),
                so two concurrent setup submissions can't both create an admin.

        Returns:
            An error message, or None on success.
        """
        username = normalize_username(username)
        if not username or not password:
            return "Username and password are required."
        if len(username) < 3:
            return "Username must be at least 3 characters."
        if len(password) < 8:
            return "Password must be at least 8 characters."
        if role not in ROLES:
            return "Role must be 'admin' or 'viewer'."
        pw_hash, salt = _hash_password(password)  # slow; done before taking the lock
        try:
            with self._mutation() as users:
                if require_no_users and users:
                    raise _Abort("Setup has already been completed. Log in instead.")
                if username in users:
                    raise _Abort(f"User '{username}' already exists.")
                users[username] = {
                    "password_hash": pw_hash,
                    "salt": salt,
                    "role": role,
                    "epoch": 0,
                    "created": datetime.now(timezone.utc).isoformat(),
                }
        except _Abort as e:
            return str(e)
        return None

    def remove_user(self, username: str) -> str | None:
        """Delete a user (ending their sessions). The last admin can't be removed.

        Returns:
            An error message, or None on success.
        """
        username = normalize_username(username)
        try:
            with self._mutation() as users:
                if username not in users:
                    raise _Abort(f"User '{username}' not found.")
                admins = [u for u, info in users.items() if info.get("role") == "admin"]
                if users[username].get("role") == "admin" and len(admins) <= 1:
                    raise _Abort("Cannot remove the last admin user.")
                del users[username]
        except _Abort as e:
            return str(e)
        return None

    def change_password(self, username: str, new_password: str) -> str | None:
        """Set a new password and end the user's existing sessions.

        Returns:
            An error message, or None on success.
        """
        username = normalize_username(username)
        if len(new_password or "") < 8:
            return "Password must be at least 8 characters."
        pw_hash, salt = _hash_password(new_password)
        try:
            with self._mutation() as users:
                if username not in users:
                    raise _Abort(f"User '{username}' not found.")
                users[username]["password_hash"] = pw_hash
                users[username]["salt"] = salt
                users[username]["epoch"] = users[username].get("epoch", 0) + 1
        except _Abort as e:
            return str(e)
        return None

    def change_role(self, username: str, new_role: str) -> str | None:
        """Change a user's role and end their existing sessions. The last admin can't be demoted.

        Returns:
            An error message, or None on success.
        """
        username = normalize_username(username)
        if new_role not in ROLES:
            return "Role must be 'admin' or 'viewer'."
        try:
            with self._mutation() as users:
                if username not in users:
                    raise _Abort(f"User '{username}' not found.")
                if users[username].get("role") == "admin" and new_role == "viewer":
                    admins = [u for u, info in users.items() if info.get("role") == "admin"]
                    if len(admins) <= 1:
                        raise _Abort("Cannot demote the last admin user.")
                users[username]["role"] = new_role
                users[username]["epoch"] = users[username].get("epoch", 0) + 1
        except _Abort as e:
            return str(e)
        return None

    # ---- First-run setup token ----

    @property
    def setup_token_path(self) -> str:
        """Path of the one-time setup token file."""
        return self._path + ".setup"

    def get_or_create_setup_token(self) -> str:
        """Return the pending setup token, creating it if none exists.

        The token gates creation of the first admin account so that whoever
        happens to reach the dashboard first can't claim it.
        """
        try:
            with open(self.setup_token_path, "r") as f:
                token = json.load(f).get("token", "")
            if token:
                return token
        except (OSError, ValueError):
            pass
        with _file_lock(self._path + ".lock"):
            try:
                with open(self.setup_token_path, "r") as f:
                    existing = json.load(f).get("token", "")
                if existing:
                    return existing  # created by another session meanwhile
            except (OSError, ValueError):
                pass
            token = secrets.token_urlsafe(24)
            payload = {"token": token, "created": datetime.now(timezone.utc).isoformat()}
            write_private_file(self.setup_token_path, json.dumps(payload).encode())
            return token

    def verify_setup_token(self, token: str) -> bool:
        """Check a setup token in constant time."""
        try:
            with open(self.setup_token_path, "r") as f:
                expected = json.load(f).get("token", "")
        except (OSError, ValueError):
            return False
        return bool(expected) and hmac.compare_digest(expected, (token or "").strip())

    def consume_setup_token(self) -> None:
        """Delete the setup token after the first admin is created."""
        try:
            os.remove(self.setup_token_path)
        except OSError:
            pass

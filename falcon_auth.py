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

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timezone

from falcon_secrets import APP_DIR, write_private_file

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

# Verified against when the username is unknown, so both paths cost one PBKDF2 run
_DUMMY_SALT = os.urandom(32)
_DUMMY_HASH = hashlib.pbkdf2_hmac("sha256", b"dummy-password", _DUMMY_SALT, _PBKDF2_ITERATIONS).hex()


class UsersFileError(Exception):
    """Raised when the users file exists but cannot be loaded or written."""


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


def _record_failure(key: str) -> None:
    now = time.time()
    with _failed_lock:
        count, last = _failed_logins.get(key, (0, 0.0))
        if now - last > _LOCKOUT_MAX_SECONDS * 2:
            count = 0  # old failures are forgotten
        _failed_logins[key] = (count + 1, now)
        if len(_failed_logins) > _MAX_TRACKED:
            stale = [k for k, (_, t) in _failed_logins.items() if now - t > _LOCKOUT_MAX_SECONDS * 2]
            for k in stale:
                del _failed_logins[k]
            while len(_failed_logins) > _MAX_TRACKED:  # still full: drop the oldest
                del _failed_logins[min(_failed_logins, key=lambda k: _failed_logins[k][1])]


def _clear_failures(key: str) -> None:
    with _failed_lock:
        _failed_logins.pop(key, None)


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
            self._users = users
        except (ValueError, OSError) as e:
            self.load_error = f"Cannot read users file {self._path}: {e}"
            logger.error(self.load_error)
            self._users = {}

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
        return {"username": username, "role": user.get("role", "viewer")}

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
        if lockout_remaining(username, client) > 0:
            return None
        user = self._users.get(username)
        if user:
            ok = _verify_password(password or "", user["password_hash"], user["salt"])
        else:
            _verify_password(password or "", _DUMMY_HASH, _DUMMY_SALT.hex())
            ok = False
        if not ok:
            _record_failure(throttle_key)
            return None
        _clear_failures(throttle_key)
        return {"username": username, "role": user.get("role", "viewer")}

    def add_user(self, username: str, password: str, role: str = "viewer") -> str | None:
        """Create a user.

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
        if username in self._users:
            return f"User '{username}' already exists."
        if role not in ROLES:
            return "Role must be 'admin' or 'viewer'."
        pw_hash, salt = _hash_password(password)
        self._users[username] = {
            "password_hash": pw_hash,
            "salt": salt,
            "role": role,
            "created": datetime.now(timezone.utc).isoformat(),
        }
        self._save()
        return None

    def remove_user(self, username: str) -> str | None:
        """Delete a user. The last admin can't be removed.

        Returns:
            An error message, or None on success.
        """
        username = normalize_username(username)
        if username not in self._users:
            return f"User '{username}' not found."
        admins = [u for u, info in self._users.items() if info.get("role") == "admin"]
        if self._users[username].get("role") == "admin" and len(admins) <= 1:
            return "Cannot remove the last admin user."
        del self._users[username]
        self._save()
        return None

    def change_password(self, username: str, new_password: str) -> str | None:
        """Set a new password.

        Returns:
            An error message, or None on success.
        """
        username = normalize_username(username)
        if username not in self._users:
            return f"User '{username}' not found."
        if len(new_password) < 8:
            return "Password must be at least 8 characters."
        pw_hash, salt = _hash_password(new_password)
        self._users[username]["password_hash"] = pw_hash
        self._users[username]["salt"] = salt
        self._save()
        return None

    def change_role(self, username: str, new_role: str) -> str | None:
        """Change a user's role. The last admin can't be demoted.

        Returns:
            An error message, or None on success.
        """
        username = normalize_username(username)
        if username not in self._users:
            return f"User '{username}' not found."
        if new_role not in ROLES:
            return "Role must be 'admin' or 'viewer'."
        if self._users[username].get("role") == "admin" and new_role == "viewer":
            admins = [u for u, info in self._users.items() if info.get("role") == "admin"]
            if len(admins) <= 1:
                return "Cannot demote the last admin user."
        self._users[username]["role"] = new_role
        self._save()
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

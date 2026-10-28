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
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".falcon_users.json")
_PBKDF2_ITERATIONS = 600_000


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if salt is None:
        salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return dk.hex(), salt.hex()


def _verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return hmac.compare_digest(dk.hex(), stored_hash)


class UserManager:

    def __init__(self, path: str = USERS_FILE):
        self._path = path
        self._users: dict = {}
        self._load()

    def _load(self):
        if not os.path.isfile(self._path):
            self._users = {}
            return
        try:
            with open(self._path, "r") as f:
                data = json.load(f)
            self._users = data.get("users", {})
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load users file: {e}")
            self._users = {}

    def _save(self):
        payload = {"users": self._users}
        tmp_path = self._path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp_path, self._path)
        os.chmod(self._path, 0o600)

    def has_users(self) -> bool:
        return len(self._users) > 0

    def list_users(self) -> list[dict]:
        return [
            {"username": u, "role": info.get("role", "viewer"), "created": info.get("created", "")}
            for u, info in self._users.items()
        ]

    def authenticate(self, username: str, password: str) -> dict | None:
        user = self._users.get(username)
        if not user:
            return None
        if _verify_password(password, user["password_hash"], user["salt"]):
            return {"username": username, "role": user.get("role", "viewer")}
        return None

    def add_user(self, username: str, password: str, role: str = "viewer") -> str | None:
        username = username.strip().lower()
        if not username or not password:
            return "Username and password are required."
        if len(username) < 3:
            return "Username must be at least 3 characters."
        if len(password) < 8:
            return "Password must be at least 8 characters."
        if username in self._users:
            return f"User '{username}' already exists."
        if role not in ("admin", "viewer"):
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
        if username not in self._users:
            return f"User '{username}' not found."
        admins = [u for u, info in self._users.items() if info.get("role") == "admin"]
        if self._users[username].get("role") == "admin" and len(admins) <= 1:
            return "Cannot remove the last admin user."
        del self._users[username]
        self._save()
        return None

    def change_password(self, username: str, new_password: str) -> str | None:
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
        if username not in self._users:
            return f"User '{username}' not found."
        if new_role not in ("admin", "viewer"):
            return "Role must be 'admin' or 'viewer'."
        if self._users[username].get("role") == "admin" and new_role == "viewer":
            admins = [u for u, info in self._users.items() if info.get("role") == "admin"]
            if len(admins) <= 1:
                return "Cannot demote the last admin user."
        self._users[username]["role"] = new_role
        self._save()
        return None

    def generate_setup_token(self) -> str:
        token = secrets.token_urlsafe(32)
        meta_path = self._path + ".setup"
        with open(meta_path, "w") as f:
            json.dump({"token": token, "created": datetime.now(timezone.utc).isoformat()}, f)
        os.chmod(meta_path, 0o600)
        return token

    def verify_setup_token(self, token: str) -> bool:
        meta_path = self._path + ".setup"
        if not os.path.isfile(meta_path):
            return False
        try:
            with open(meta_path, "r") as f:
                data = json.load(f)
            valid = hmac.compare_digest(data.get("token", ""), token)
            if valid:
                os.remove(meta_path)
            return valid
        except (json.JSONDecodeError, OSError):
            return False

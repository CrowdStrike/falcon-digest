"""Credential management and data encryption for Falcon Digest.

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

import base64
import json
import logging
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("falcon_mcp.secrets")

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
KEYRING_SERVICE = "falcon-digest"
CONFIG_FILE = os.path.join(_APP_DIR, ".falcon_config.enc")
_KEY_FILE = os.path.join(_APP_DIR, ".falcon_config.key")
_PBKDF2_SALT = b"falcon-digest-config-v1"
_PBKDF2_ITERATIONS = 480_000

# ---------------------------------------------------------------------------
# Keyring helpers — graceful degradation when keyring is unavailable
# ---------------------------------------------------------------------------

_keyring = None
_keyring_available = False

try:
    import keyring as _keyring
    _keyring.get_password(KEYRING_SERVICE, "__probe__")
    _keyring_available = True
except Exception:
    _keyring_available = False
    logger.info("OS keychain not available — using file-based key storage")


def keyring_available() -> bool:
    return _keyring_available


# ---------------------------------------------------------------------------
# Encryption key management — one key for config + cache
# ---------------------------------------------------------------------------

def _get_or_create_key() -> bytes:
    """Get or create the master encryption key. Keychain first, file fallback."""
    # Try keychain
    if _keyring_available and _keyring:
        try:
            stored = _keyring.get_password(KEYRING_SERVICE, "encryption-key")
            if stored:
                return base64.urlsafe_b64decode(stored)
        except Exception:
            pass

    # Try key file
    if os.path.isfile(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            return f.read()

    # Generate new key
    key = os.urandom(32)

    # Store in keychain
    if _keyring_available and _keyring:
        try:
            _keyring.set_password(KEYRING_SERVICE, "encryption-key", base64.urlsafe_b64encode(key).decode())
            logger.info("Encryption key stored in OS keychain")
            return key
        except Exception:
            pass

    # Fall back to key file
    with open(_KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(_KEY_FILE, 0o600)
    logger.info("Encryption key stored in key file")
    return key


def _get_fernet() -> Fernet:
    key = _get_or_create_key()
    fernet_key = base64.urlsafe_b64encode(key)
    return Fernet(fernet_key)


# ---------------------------------------------------------------------------
# ConfigStore — encrypted configuration storage
# ---------------------------------------------------------------------------

_ENV_FIELDS = {
    "FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL",
    "LLM_ENDPOINT", "LLM_API_KEY", "LLM_PROVIDER", "LLM_MODEL",
}

CLOUD_REGIONS = {
    "US-1": "https://api.crowdstrike.com",
    "US-2": "https://api.us-2.crowdstrike.com",
    "US-3": "https://api.us-3.crowdstrike.com",
    "EU-1": "https://api.eu-1.crowdstrike.com",
    "GOV-1": "https://api.laggar.gcw.crowdstrike.com",
    "GOV-2": "https://api.us-gov-2.crowdstrike.mil",
}


class ConfigStore:
    """Encrypted configuration storage for all Falcon Digest settings."""

    def __init__(self, path: str = CONFIG_FILE):
        self._path = path
        self._data: dict = {
            "profiles": {},
            "active_profile": "",
            "llm": {
                "LLM_ENDPOINT": "",
                "LLM_API_KEY": "",
                "LLM_PROVIDER": "anthropic",
                "LLM_MODEL": "",
            },
        }
        self._load()

    def _load(self):
        if not os.path.isfile(self._path):
            return
        try:
            with open(self._path, "rb") as f:
                encrypted = f.read()
            f = _get_fernet()
            decrypted = f.decrypt(encrypted)
            self._data = json.loads(decrypted)
        except (InvalidToken, json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load config: {e}")

    def _save(self):
        f = _get_fernet()
        encrypted = f.encrypt(json.dumps(self._data).encode())
        tmp = self._path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(encrypted)
        os.replace(tmp, self._path)
        os.chmod(self._path, 0o600)

    def has_config(self) -> bool:
        return bool(self._data.get("profiles"))

    # ---- Profile management ----

    def list_profiles(self) -> list[dict]:
        results = []
        for name, p in self._data.get("profiles", {}).items():
            results.append({
                "name": name,
                "client_id": p.get("FALCON_CLIENT_ID", ""),
                "client_id_short": p.get("FALCON_CLIENT_ID", "")[-8:],
                "base_url": p.get("FALCON_BASE_URL", ""),
                "active": name == self._data.get("active_profile"),
            })
        return results

    def get_active_profile_name(self) -> str:
        return self._data.get("active_profile", "")

    def get_profile(self, name: str) -> dict | None:
        return self._data.get("profiles", {}).get(name)

    def save_profile(self, name: str, client_id: str, client_secret: str, base_url: str):
        if "profiles" not in self._data:
            self._data["profiles"] = {}
        self._data["profiles"][name] = {
            "FALCON_CLIENT_ID": client_id.strip(),
            "FALCON_CLIENT_SECRET": client_secret.strip(),
            "FALCON_BASE_URL": base_url.strip(),
        }
        if not self._data.get("active_profile"):
            self._data["active_profile"] = name
        self._save()

    def delete_profile(self, name: str):
        self._data.get("profiles", {}).pop(name, None)
        if self._data.get("active_profile") == name:
            remaining = list(self._data.get("profiles", {}).keys())
            self._data["active_profile"] = remaining[0] if remaining else ""
        self._save()

    def set_active_profile(self, name: str):
        if name in self._data.get("profiles", {}):
            self._data["active_profile"] = name
            self._save()

    # ---- LLM config ----

    def get_llm_config(self) -> dict:
        return dict(self._data.get("llm", {}))

    def save_llm_config(self, endpoint: str, api_key: str, provider: str = "anthropic", model: str = ""):
        self._data["llm"] = {
            "LLM_ENDPOINT": endpoint.strip(),
            "LLM_API_KEY": api_key.strip(),
            "LLM_PROVIDER": provider.strip().lower(),
            "LLM_MODEL": model.strip(),
        }
        self._save()

    # ---- Environment injection ----

    def inject_to_env(self):
        """Load active profile + LLM config into os.environ for FalconPy and LLM client."""
        profile_name = self._data.get("active_profile", "")
        profile = self._data.get("profiles", {}).get(profile_name, {})
        for key in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL"):
            val = profile.get(key, "")
            if val:
                os.environ[key] = val

        llm = self._data.get("llm", {})
        for key in ("LLM_ENDPOINT", "LLM_API_KEY", "LLM_PROVIDER", "LLM_MODEL"):
            val = llm.get(key, "")
            if val:
                os.environ[key] = val

    # ---- Migration from .env ----

    def migrate_from_env(self, env_path: str) -> bool:
        """One-time migration: read credentials from .env into encrypted store."""
        if not os.path.isfile(env_path):
            return False

        from dotenv import dotenv_values
        env = dotenv_values(env_path)

        client_id = env.get("FALCON_CLIENT_ID", "").strip()
        client_secret = env.get("FALCON_CLIENT_SECRET", "").strip()
        base_url = env.get("FALCON_BASE_URL", "https://api.crowdstrike.com").strip()

        if not client_id or not client_secret:
            return False

        # Already migrated?
        if self.has_config():
            return False

        self.save_profile("default", client_id, client_secret, base_url)

        llm_endpoint = env.get("LLM_ENDPOINT", "").strip()
        llm_key = env.get("LLM_API_KEY", "").strip()
        llm_provider = env.get("LLM_PROVIDER", "anthropic").strip()
        llm_model = env.get("LLM_MODEL", "").strip()
        if llm_endpoint:
            self.save_llm_config(llm_endpoint, llm_key, llm_provider, llm_model)

        # Blank out secrets in .env
        with open(env_path, "r") as f:
            lines = f.readlines()
        new_lines = []
        for line in lines:
            if line.strip().startswith("FALCON_CLIENT_SECRET=") and "=" in line:
                new_lines.append("FALCON_CLIENT_SECRET=\n")
            elif line.strip().startswith("LLM_API_KEY=") and "=" in line:
                k, _, v = line.partition("=")
                if v.strip():
                    new_lines.append("LLM_API_KEY=\n")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        with open(env_path, "w") as f:
            f.writelines(new_lines)
        os.chmod(env_path, 0o600)

        logger.info("Migrated credentials from .env to encrypted config store")
        return True


# Module-level singleton
config_store = ConfigStore()


# ---------------------------------------------------------------------------
# Cache encryption — uses the shared encryption key
# ---------------------------------------------------------------------------

def encrypt_cache(data: dict) -> bytes | None:
    """Serialize and encrypt cache data."""
    try:
        f = _get_fernet()
        return f.encrypt(json.dumps(data).encode())
    except Exception as e:
        logger.warning(f"Cache encryption failed: {e}")
        return None


def decrypt_cache(encrypted: bytes) -> dict | None:
    """Decrypt and deserialize cache data."""
    try:
        f = _get_fernet()
        decrypted = f.decrypt(encrypted)
        return json.loads(decrypted)
    except Exception as e:
        logger.warning(f"Cache decryption failed: {e}")
        return None

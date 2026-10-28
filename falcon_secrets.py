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

logger = logging.getLogger("falcon_mcp.secrets")

# All local state (config, key, users, cache) lives here. Override with
# FALCON_DIGEST_HOME to keep state outside the source tree (also used by tests).
APP_DIR = os.environ.get("FALCON_DIGEST_HOME") or os.path.dirname(os.path.abspath(__file__))
KEYRING_SERVICE = "falcon-digest"
CONFIG_FILE = os.path.join(APP_DIR, ".falcon_config.enc")
LEGACY_ENV_FILE = os.path.join(APP_DIR, ".env")
_KEY_FILE = os.path.join(APP_DIR, ".falcon_config.key")

_FALCON_KEYS = ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL")
_LLM_KEYS = ("LLM_ENDPOINT", "LLM_API_KEY", "LLM_PROVIDER", "LLM_MODEL")

CLOUD_REGIONS = {
    "US-1": "https://api.crowdstrike.com",
    "US-2": "https://api.us-2.crowdstrike.com",
    "US-3": "https://api.us-3.crowdstrike.com",
    "EU-1": "https://api.eu-1.crowdstrike.com",
    "GOV-1": "https://api.laggar.gcw.crowdstrike.com",
    "GOV-2": "https://api.us-gov-2.crowdstrike.mil",
}


class ConfigDecryptError(Exception):
    """Raised when an existing config file cannot be decrypted or read."""


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def write_private_file(path: str, data: bytes) -> None:
    """Atomically write bytes to a file readable only by the owner (0600).

    The temp file is created with mode 0600 before any data is written, so
    secrets are never briefly world-readable.

    Args:
        path: Destination file path.
        data: Bytes to write.
    """
    tmp_path = path + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)  # tmp may pre-exist with wider permissions
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


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
    """Return True if the OS keychain backend is usable in this process."""
    return _keyring_available


# ---------------------------------------------------------------------------
# Encryption key management — one key for config + cache
# ---------------------------------------------------------------------------

def _get_or_create_key() -> bytes:
    """Return the master encryption key, creating it on first use.

    Looks in the OS keychain first, then the key file. A new key is only
    generated when no encrypted config exists yet; otherwise a missing key
    means this process cannot see the key the config was written with, and
    generating a fresh one would orphan the existing config.

    Returns:
        The raw 32-byte key.

    Raises:
        ConfigDecryptError: If a config file exists but no key can be found.
    """
    if _keyring_available and _keyring:
        try:
            stored = _keyring.get_password(KEYRING_SERVICE, "encryption-key")
            if stored:
                return base64.urlsafe_b64decode(stored)
        except Exception:
            pass

    if os.path.isfile(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            return f.read()

    if os.path.isfile(CONFIG_FILE):
        raise ConfigDecryptError(
            f"Encrypted config exists at {CONFIG_FILE} but its encryption key was not found "
            "in the OS keychain or key file. Refusing to create a new key."
        )

    key = os.urandom(32)

    if _keyring_available and _keyring:
        try:
            _keyring.set_password(KEYRING_SERVICE, "encryption-key", base64.urlsafe_b64encode(key).decode())
            logger.info("Encryption key stored in OS keychain")
            return key
        except Exception:
            pass

    write_private_file(_KEY_FILE, key)
    logger.info("Encryption key stored in key file")
    return key


def _get_fernet() -> Fernet:
    """Return a Fernet instance for the master key."""
    return Fernet(base64.urlsafe_b64encode(_get_or_create_key()))


# ---------------------------------------------------------------------------
# ConfigStore — encrypted configuration storage
# ---------------------------------------------------------------------------

def _empty_config() -> dict:
    return {
        "profiles": {},
        "active_profile": "",
        "llm": {
            "LLM_ENDPOINT": "",
            "LLM_API_KEY": "",
            "LLM_PROVIDER": "anthropic",
            "LLM_MODEL": "",
        },
    }


class ConfigStore:
    """Encrypted configuration storage for Falcon API profiles and LLM settings.

    If the config file exists but cannot be decrypted, ``load_error`` is set
    and all writes are refused, so a process that can't see the right key
    never overwrites the real config.
    """

    def __init__(self, path: str = CONFIG_FILE):
        self._path = path
        self._data: dict = _empty_config()
        self.load_error: str | None = None
        self.reload()

    def reload(self) -> None:
        """Re-read the config from disk (picks up changes from other processes)."""
        self.load_error = None
        if not os.path.isfile(self._path):
            self._data = _empty_config()
            return
        try:
            with open(self._path, "rb") as f:
                encrypted = f.read()
            data = json.loads(_get_fernet().decrypt(encrypted))
            if not isinstance(data, dict):
                raise ValueError("config root is not an object")
            merged = _empty_config()
            merged.update(data)
            self._data = merged
        except (InvalidToken, ValueError, OSError, ConfigDecryptError) as e:
            msg = str(e) or type(e).__name__
            if isinstance(e, InvalidToken):
                msg = "the encryption key does not match this config file"
            self.load_error = f"Cannot read encrypted config ({msg})."
            logger.error(self.load_error)

    def _save(self) -> None:
        if self.load_error:
            raise ConfigDecryptError(self.load_error)
        encrypted = _get_fernet().encrypt(json.dumps(self._data).encode())
        write_private_file(self._path, encrypted)

    def has_config(self) -> bool:
        """Return True if at least one Falcon profile is stored."""
        return bool(self._data.get("profiles"))

    def has_llm_config(self) -> bool:
        """Return True if an LLM endpoint is stored."""
        return bool(self._data.get("llm", {}).get("LLM_ENDPOINT"))

    # ---- Profile management ----

    def list_profiles(self) -> list[dict]:
        """List profiles without secrets.

        Returns:
            Dicts with name, client_id, client_id_short, base_url and active.
        """
        results = []
        for name, p in self._data.get("profiles", {}).items():
            client_id = p.get("FALCON_CLIENT_ID", "")
            results.append({
                "name": name,
                "client_id": client_id,
                "client_id_short": client_id[-8:],
                "base_url": p.get("FALCON_BASE_URL", ""),
                "active": name == self._data.get("active_profile"),
            })
        return results

    def get_active_profile_name(self) -> str:
        """Return the name of the active profile, or an empty string."""
        return self._data.get("active_profile", "")

    def save_profile(self, name: str, client_id: str, client_secret: str, base_url: str) -> None:
        """Create or update a Falcon API profile.

        Args:
            name: Profile name.
            client_id: Falcon API client ID.
            client_secret: Falcon API client secret. Blank keeps the stored
                secret when updating an existing profile.
            base_url: Falcon cloud base URL.

        Raises:
            ValueError: If a required value is missing.
        """
        name = name.strip()
        client_id = client_id.strip()
        client_secret = client_secret.strip()
        existing = self._data.get("profiles", {}).get(name, {})
        if not client_secret:
            client_secret = existing.get("FALCON_CLIENT_SECRET", "")
        if not name or not client_id or not client_secret:
            raise ValueError("Profile name, Client ID, and Client Secret are required.")
        self._data.setdefault("profiles", {})[name] = {
            "FALCON_CLIENT_ID": client_id,
            "FALCON_CLIENT_SECRET": client_secret,
            "FALCON_BASE_URL": base_url.strip(),
        }
        if not self._data.get("active_profile"):
            self._data["active_profile"] = name
        self._save()

    def delete_profile(self, name: str) -> None:
        """Delete a profile. If it was active, the first remaining one becomes active."""
        self._data.get("profiles", {}).pop(name, None)
        if self._data.get("active_profile") == name:
            remaining = list(self._data.get("profiles", {}).keys())
            self._data["active_profile"] = remaining[0] if remaining else ""
        self._save()

    def set_active_profile(self, name: str) -> bool:
        """Make a profile active.

        Returns:
            True if the profile exists and is now active.
        """
        if name not in self._data.get("profiles", {}):
            return False
        self._data["active_profile"] = name
        self._save()
        return True

    # ---- LLM config ----

    def get_llm_config(self, include_secret: bool = False) -> dict:
        """Return LLM settings.

        Args:
            include_secret: Include the API key value. When False, the key is
                replaced by ``LLM_API_KEY_SET`` (bool) so it can't leak into UI.
        """
        llm = dict(self._data.get("llm", {}))
        if not include_secret:
            llm["LLM_API_KEY_SET"] = bool(llm.pop("LLM_API_KEY", ""))
        return llm

    def save_llm_config(self, endpoint: str, api_key: str | None, provider: str = "anthropic",
                        model: str = "") -> None:
        """Store LLM settings.

        Args:
            endpoint: LLM endpoint URL (blank disables chat).
            api_key: API key. ``None`` keeps the stored key; ``""`` clears it.
            provider: ``anthropic`` or ``openai``.
            model: Optional model override.
        """
        current = self._data.get("llm", {})
        self._data["llm"] = {
            "LLM_ENDPOINT": endpoint.strip(),
            "LLM_API_KEY": current.get("LLM_API_KEY", "") if api_key is None else api_key.strip(),
            "LLM_PROVIDER": (provider or "anthropic").strip().lower(),
            "LLM_MODEL": model.strip(),
        }
        self._save()

    # ---- Environment injection ----

    def inject_to_env(self) -> None:
        """Load the active profile and LLM settings into ``os.environ``.

        Values that are empty in the stored config are removed from the
        environment so stale credentials don't linger. If no config file
        exists, the environment is left untouched (env-var mode, e.g. an MCP
        server launched by an IDE with credentials in its environment).
        """
        if not os.path.isfile(self._path) or self.load_error:
            return
        profile = self._data.get("profiles", {}).get(self._data.get("active_profile", ""), {})
        llm = self._data.get("llm", {})
        for keys, source in ((_FALCON_KEYS, profile), (_LLM_KEYS, llm)):
            for key in keys:
                val = (source.get(key) or "").strip()
                if val:
                    os.environ[key] = val
                else:
                    os.environ.pop(key, None)

    # ---- Migration from .env ----

    def migrate_from_env(self, env_path: str = LEGACY_ENV_FILE) -> bool:
        """One-time import of credentials from a legacy ``.env`` file.

        On success the file is renamed to ``.env.migrated`` (0600) so it is
        no longer read anywhere; the user should delete it once verified.

        Args:
            env_path: Path to the legacy ``.env`` file.

        Returns:
            True if credentials were migrated.
        """
        if self.has_config() or self.load_error or not os.path.isfile(env_path):
            return False

        from dotenv import dotenv_values
        env = dotenv_values(env_path)

        def _get(key: str, default: str = "") -> str:
            return (env.get(key) or default).strip()

        client_id = _get("FALCON_CLIENT_ID")
        client_secret = _get("FALCON_CLIENT_SECRET")
        if not client_id or not client_secret:
            return False

        self.save_profile("default", client_id, client_secret,
                          _get("FALCON_BASE_URL", "https://api.crowdstrike.com"))

        llm_endpoint = _get("LLM_ENDPOINT")
        llm_key = _get("LLM_API_KEY")
        if llm_endpoint or llm_key:
            self.save_llm_config(llm_endpoint, llm_key, _get("LLM_PROVIDER", "anthropic"), _get("LLM_MODEL"))

        migrated_path = env_path + ".migrated"
        os.replace(env_path, migrated_path)
        try:
            os.chmod(migrated_path, 0o600)
        except OSError:
            pass
        logger.warning(
            "Migrated credentials from %s into the encrypted config store. The original file "
            "was renamed to %s and still contains plaintext secrets — delete it once verified.",
            env_path, migrated_path,
        )
        return True


# Module-level singleton
config_store = ConfigStore()


def load_config_into_env(env_path: str = LEGACY_ENV_FILE) -> None:
    """Migrate a legacy ``.env`` if needed, then inject the stored config into ``os.environ``.

    Safe to call repeatedly; every entry point (dashboard, MCP server, CLI,
    cache daemon) goes through this via ``crwd_mcp_server`` import.
    """
    if config_store.load_error:
        return
    try:
        config_store.migrate_from_env(env_path)
    except Exception as e:
        logger.error(f"Legacy .env migration failed: {e}")
    config_store.inject_to_env()


def refresh_env_from_store() -> None:
    """Reload the config from disk and re-inject it (used by long-running pollers)."""
    config_store.reload()
    config_store.inject_to_env()


# ---------------------------------------------------------------------------
# Cache encryption — uses the shared encryption key
# ---------------------------------------------------------------------------

def encrypt_cache(data: dict) -> bytes | None:
    """Serialize and encrypt cache data.

    Returns:
        Ciphertext, or None if encryption failed (callers must not fall back
        to writing plaintext).
    """
    try:
        return _get_fernet().encrypt(json.dumps(data).encode())
    except Exception as e:
        logger.error(f"Cache encryption failed: {e}")
        return None


def decrypt_cache(encrypted: bytes) -> dict | None:
    """Decrypt and deserialize cache data.

    Returns:
        The cache payload, or None if it isn't valid ciphertext for this key.
    """
    try:
        return json.loads(_get_fernet().decrypt(encrypted))
    except Exception as e:
        logger.debug(f"Cache decryption failed: {e}")
        return None

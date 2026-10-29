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
import contextlib
import json
import logging
import os
import re
import tempfile
import threading

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("falcon_mcp.secrets")

SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_APP_DIR = os.path.join(os.path.expanduser("~"), ".falcon-digest")

# All local state (config, key, users, cache) lives here — never in the source
# tree, so nothing that operates on the code (git, tests, tools) can touch it.
# Override with FALCON_DIGEST_HOME (tests point it at a temp dir).
APP_DIR = os.path.abspath(os.path.expanduser(os.environ.get("FALCON_DIGEST_HOME") or DEFAULT_APP_DIR))

# State file names, used for the one-time move out of the source tree and by
# the test-only cleanup helper. Only these are ever moved or removed.
STATE_FILES = (
    ".falcon_config.enc", ".falcon_config.key", ".falcon_config.lock", ".falcon_config.enc.lock",
    ".falcon_users.json", ".falcon_users.json.lock", ".falcon_users.json.setup",
    ".falcon_cache.json", ".env.migrated",
)
STATE_DIRS = (".falcon_cache_backups",)


def _is_within(path: str, parent: str) -> bool:
    path, parent = os.path.realpath(path), os.path.realpath(parent)
    return path == parent or path.startswith(parent.rstrip(os.sep) + os.sep)


def _refuse_unsafe_test_run() -> None:
    """Fail closed if test code is loaded while the data dir is not a temp dir.

    Tests set FALCON_DIGEST_HOME to a temp dir in tests/conftest.py. If test
    modules are imported any other way (e.g. ``python -c "import test_x"``),
    that never happens and the real data dir would be used — refuse instead.
    """
    import sys
    if "pytest" not in sys.modules and "PYTEST_CURRENT_TEST" not in os.environ:
        return
    import tempfile
    if not _is_within(APP_DIR, tempfile.gettempdir()):
        raise RuntimeError(
            f"Refusing to run tests against a non-temporary data directory ({APP_DIR}). "
            "Run tests only via `pytest` from the repo, which isolates FALCON_DIGEST_HOME."
        )


_refuse_unsafe_test_run()
os.makedirs(APP_DIR, mode=0o700, exist_ok=True)
KEYRING_SERVICE = "falcon-digest"
# One keychain entry per data directory, so separate installs/FALCON_DIGEST_HOMEs never share a key
KEYRING_ACCOUNT = "encryption-key:" + __import__("hashlib").sha256(os.path.realpath(APP_DIR).encode()).hexdigest()[:16]
CONFIG_FILE = os.path.join(APP_DIR, ".falcon_config.enc")
LEGACY_ENV_FILE = os.path.join(SOURCE_DIR, ".env")
_KEY_FILE = os.path.join(APP_DIR, ".falcon_config.key")
_KEY_LOCK_FILE = os.path.join(APP_DIR, ".falcon_config.lock")

_FALCON_KEYS = ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL")
_LLM_KEYS = ("LLM_ENDPOINT", "LLM_API_KEY", "LLM_PROVIDER", "LLM_MODEL", "LLM_LOCAL_MODE")

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

    Uses a unique temp file in the same directory (created 0600 by
    ``mkstemp``), so concurrent writers of the same path (e.g. dashboard and
    cache daemon) never share or truncate each other's temp file, and
    secrets are never briefly world-readable.

    Args:
        path: Destination file path.
        data: Bytes to write.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
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

class KeyUnavailableError(ConfigDecryptError):
    """Raised when the key store can't be read, so a new key must not be created."""


_fernet: Fernet | None = None
_fernet_lock = threading.Lock()


def _read_existing_key() -> bytes | None:
    """Return the stored key, or None if none exists.

    A key file in the data directory wins over the keychain; the keychain
    entry is specific to this data directory.

    Raises:
        KeyUnavailableError: If the keychain lookup itself failed, so it is
            unknown whether a key exists.
    """
    if os.path.isfile(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            return f.read()
    if _keyring_available and _keyring:
        try:
            stored = _keyring.get_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
        except Exception as e:
            raise KeyUnavailableError(f"OS keychain lookup failed ({type(e).__name__}); not creating a new key") from e
        if stored:
            return base64.urlsafe_b64decode(stored)
    return None


def _get_or_create_key() -> bytes:
    """Return the master encryption key, creating it on first use.

    Looks in the OS keychain first, then the key file. A new key is only
    generated when the key store was read successfully, holds no key, and no
    encrypted config exists yet. Creation is serialized with a lock file and
    the key is re-read afterwards, so two processes starting together end up
    with the same key.

    Returns:
        The raw 32-byte key.

    Raises:
        ConfigDecryptError: If a config exists but its key can't be found.
        KeyUnavailableError: If the keychain lookup failed.
    """
    key = _read_existing_key()
    if key:
        return key

    with _file_lock(_KEY_LOCK_FILE):
        key = _read_existing_key()  # another process may have created it meanwhile
        if key:
            return key
        if os.path.isfile(CONFIG_FILE):
            raise ConfigDecryptError(
                f"Encrypted config exists at {CONFIG_FILE} but its encryption key was not found "
                "in the OS keychain or key file. Refusing to create a new key."
            )
        key = os.urandom(32)
        stored_in_keychain = False
        if _keyring_available and _keyring:
            try:
                _keyring.set_password(KEYRING_SERVICE, KEYRING_ACCOUNT, base64.urlsafe_b64encode(key).decode())
                stored_in_keychain = True
                logger.info("Encryption key stored in OS keychain")
            except Exception:
                pass
        if not stored_in_keychain:
            write_private_file(_KEY_FILE, key)
            logger.info("Encryption key stored in key file")
        return _read_existing_key() or key


def _get_fernet() -> Fernet:
    """Return the Fernet instance for the master key (cached after first use)."""
    global _fernet
    if _fernet is None:
        with _fernet_lock:
            if _fernet is None:
                _fernet = Fernet(base64.urlsafe_b64encode(_get_or_create_key()))
    return _fernet


def _reset_key_cache() -> None:
    """Forget the cached Fernet instance (tests, or after the key store changes)."""
    global _fernet
    _fernet = None


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
            "LLM_LOCAL_MODE": "auto",
        },
    }


LLM_LOCAL_MODES = ("auto", "local", "full")

# Values present in the environment before this module touched it (IDE / MCP
# client supplied). With FALCON_DIGEST_USE_ENV=1 these win over the stored config.
_ENV_AT_START = {k: os.environ.get(k) for k in _FALCON_KEYS + _LLM_KEYS}


def _env_overrides_enabled() -> bool:
    return os.environ.get("FALCON_DIGEST_USE_ENV", "").strip().lower() in ("1", "true", "yes")


@contextlib.contextmanager
def _file_lock(lock_path: str):
    """Exclusive inter-process lock on ``lock_path`` (best effort on Windows)."""
    if fcntl is None:
        yield
        return
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class ConfigStore:
    """Encrypted configuration storage for Falcon API profiles and LLM settings.

    If the config file exists but cannot be decrypted, ``load_error`` is set
    and all writes are refused, so a process that can't see the right key
    never overwrites the real config. Every mutation re-reads the file under
    an inter-process lock first, so concurrent sessions/processes don't lose
    each other's changes.
    """

    def __init__(self, path: str = CONFIG_FILE):
        self._path = path
        self._lock = threading.RLock()
        self._data: dict = _empty_config()
        self.load_error: str | None = None
        self.migration_warning: str | None = None
        self.reload()

    def reload(self) -> None:
        """Re-read the config from disk (picks up changes from other processes)."""
        with self._lock:
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
                merged["llm"] = {**_empty_config()["llm"], **(data.get("llm") or {})}
                self._data = merged
            except KeyUnavailableError as e:
                self._set_load_error("the OS keychain could not be read", e)
            except ConfigDecryptError as e:
                self._set_load_error("its encryption key was not found", e)
            except InvalidToken as e:
                self._set_load_error("the encryption key does not match this config file", e)
            except (ValueError, OSError) as e:
                self._set_load_error("the file is damaged or unreadable", e)

    def _set_load_error(self, reason: str, exc: Exception) -> None:
        # User-facing text stays generic (no paths); details go to the server log
        self.load_error = f"Cannot read the encrypted config: {reason}."
        logger.error("Failed to load %s: %s", self._path, exc)

    @contextlib.contextmanager
    def _mutation(self):
        """Lock, re-read the latest config, let the caller mutate, then save."""
        with self._lock, _file_lock(self._path + ".lock"):
            self.reload()
            if self.load_error:
                raise ConfigDecryptError(self.load_error)
            yield self._data
            self._save()

    def _save(self) -> None:
        if self.load_error:
            raise ConfigDecryptError(self.load_error)
        encrypted = _get_fernet().encrypt(json.dumps(self._data).encode())
        write_private_file(self._path, encrypted)

    def exists(self) -> bool:
        """Return True if a config file exists (even one without profiles)."""
        return os.path.isfile(self._path)

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
        with self._lock:
            profiles = dict(self._data.get("profiles", {}))
            active = self._data.get("active_profile")
        results = []
        for name, p in profiles.items():
            client_id = p.get("FALCON_CLIENT_ID", "")
            results.append({
                "name": name,
                "client_id": client_id,
                "client_id_short": client_id[-8:],
                "base_url": p.get("FALCON_BASE_URL", ""),
                "active": name == active,
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
            ConfigDecryptError: If the existing config can't be read.
        """
        name = name.strip()
        client_id = client_id.strip()
        client_secret = client_secret.strip()
        with self._mutation() as data:
            existing = data.get("profiles", {}).get(name, {})
            if not client_secret:
                client_secret = existing.get("FALCON_CLIENT_SECRET", "")
            if not name or not client_id or not client_secret:
                raise ValueError("Profile name, Client ID, and Client Secret are required.")
            data.setdefault("profiles", {})[name] = {
                "FALCON_CLIENT_ID": client_id,
                "FALCON_CLIENT_SECRET": client_secret,
                "FALCON_BASE_URL": base_url.strip(),
            }
            if not data.get("active_profile"):
                data["active_profile"] = name

    def delete_profile(self, name: str) -> None:
        """Delete a profile. If it was active, the first remaining one becomes active."""
        with self._mutation() as data:
            data.get("profiles", {}).pop(name, None)
            if data.get("active_profile") == name:
                remaining = list(data.get("profiles", {}).keys())
                data["active_profile"] = remaining[0] if remaining else ""

    def set_active_profile(self, name: str) -> bool:
        """Make a profile active.

        Returns:
            True if the profile exists and is now active.
        """
        with self._mutation() as data:
            if name not in data.get("profiles", {}):
                return False
            data["active_profile"] = name
        return True

    # ---- LLM config ----

    def get_llm_config(self, include_secret: bool = False) -> dict:
        """Return LLM settings.

        Args:
            include_secret: Include the API key value. When False, the key is
                replaced by ``LLM_API_KEY_SET`` (bool) so it can't leak into UI.
        """
        llm = {**_empty_config()["llm"], **self._data.get("llm", {})}
        if not include_secret:
            llm["LLM_API_KEY_SET"] = bool(llm.pop("LLM_API_KEY", ""))
        return llm

    def save_llm_config(self, endpoint: str, api_key: str | None, provider: str = "anthropic",
                        model: str = "", local_mode: str | None = None) -> None:
        """Store LLM settings.

        Args:
            endpoint: LLM endpoint URL (blank disables chat).
            api_key: API key. ``None`` keeps the stored key; ``""`` clears it.
            provider: ``anthropic`` or ``openai``.
            model: Optional model override.
            local_mode: ``auto``, ``local`` or ``full``; ``None`` keeps the stored value.
        """
        with self._mutation() as data:
            current = {**_empty_config()["llm"], **data.get("llm", {})}
            mode = current["LLM_LOCAL_MODE"] if local_mode is None else local_mode.strip().lower()
            data["llm"] = {
                "LLM_ENDPOINT": endpoint.strip(),
                "LLM_API_KEY": current.get("LLM_API_KEY", "") if api_key is None else api_key.strip(),
                "LLM_PROVIDER": (provider or "anthropic").strip().lower(),
                "LLM_MODEL": model.strip(),
                "LLM_LOCAL_MODE": mode if mode in LLM_LOCAL_MODES else "auto",
            }

    # ---- Environment injection ----

    def inject_to_env(self) -> None:
        """Load the active profile and LLM settings into ``os.environ``.

        Values that are empty in the stored config are removed from the
        environment so stale credentials don't linger. If no config file
        exists, the environment is left untouched (env-var mode, e.g. an MCP
        server launched by an IDE with credentials in its environment). With
        ``FALCON_DIGEST_USE_ENV=1``, values that were already in the process
        environment at startup take precedence over the stored config.
        """
        with self._lock:
            if not os.path.isfile(self._path) or self.load_error:
                return
            profile = dict(self._data.get("profiles", {}).get(self._data.get("active_profile", ""), {}))
            llm = dict(self._data.get("llm", {}))
        use_env = _env_overrides_enabled()
        for keys, source in ((_FALCON_KEYS, profile), (_LLM_KEYS, llm)):
            for key in keys:
                if use_env and _ENV_AT_START.get(key):
                    os.environ[key] = _ENV_AT_START[key]
                    continue
                val = (source.get(key) or "").strip()
                if val:
                    os.environ[key] = val
                else:
                    os.environ.pop(key, None)

    # ---- Migration from .env ----

    def migrate_from_env(self, env_path: str = LEGACY_ENV_FILE) -> bool:
        """One-time import of credentials from a legacy ``.env`` file.

        The active profile and LLM settings are read with python-dotenv,
        exactly as the old runtime read them (``export``, quotes and inline
        comments behave the same). Commented-out ``#name`` profile blocks are
        imported too. If any value looks inconsistent, nothing is renamed and
        ``migration_warning`` explains why; otherwise ``.env`` is renamed to
        ``.env.migrated`` (0600) so it is no longer read anywhere.

        Args:
            env_path: Path to the legacy ``.env`` file.

        Returns:
            True if credentials were migrated.
        """
        if self.exists() or self.load_error or not os.path.isfile(env_path):
            return False

        from dotenv import dotenv_values
        env = {k: (v or "").strip() for k, v in dotenv_values(env_path).items()}
        with open(env_path, "r", errors="replace") as f:
            blocks = parse_legacy_env_profiles(f.read())

        profiles: dict[str, dict] = {}
        problems: list[str] = []
        active_name = ""

        def _unique(name: str) -> str:
            base, n = name, 2
            while name in profiles:
                name, n = f"{base} ({n})", n + 1
            return name

        # Active profile: dotenv's values are authoritative
        if env.get("FALCON_CLIENT_ID") or env.get("FALCON_CLIENT_SECRET"):
            active = {
                "FALCON_CLIENT_ID": env.get("FALCON_CLIENT_ID", ""),
                "FALCON_CLIENT_SECRET": env.get("FALCON_CLIENT_SECRET", ""),
                "FALCON_BASE_URL": env.get("FALCON_BASE_URL") or "https://api.crowdstrike.com",
            }
            problems += [f"active profile: {p}" for p in _profile_problems(active)]
            # Name it after the last uncommented block with the same client ID (dotenv: last wins)
            match = [b for b in blocks if b["active"] and b["values"].get("FALCON_CLIENT_ID") == active["FALCON_CLIENT_ID"]]
            active_block = match[-1] if match else None
            active_name = _unique((active_block["name"] if active_block else "") or "default")
            profiles[active_name] = active
        else:
            active_block = None

        for b in blocks:
            if b is active_block:
                continue  # taken from dotenv above
            values = {
                "FALCON_CLIENT_ID": b["values"].get("FALCON_CLIENT_ID", ""),
                "FALCON_CLIENT_SECRET": b["values"].get("FALCON_CLIENT_SECRET", ""),
                "FALCON_BASE_URL": b["values"].get("FALCON_BASE_URL") or "https://api.crowdstrike.com",
            }
            issues = _profile_problems(values)
            if issues:
                logger.warning("Skipping commented profile %r from %s: %s", b["name"] or "(unnamed)", env_path, "; ".join(issues))
                continue
            profiles[_unique(b["name"] or "imported")] = values

        llm = {k: env.get(k, "") for k in _LLM_KEYS}
        has_llm = bool(llm["LLM_ENDPOINT"] or llm["LLM_API_KEY"])
        if not profiles and not has_llm:
            return False
        if problems:
            self.migration_warning = (
                "Your legacy .env was not imported because some values look inconsistent ("
                + "; ".join(problems) + "). It was left in place; fix it or enter the profile in Settings."
            )
            logger.warning(self.migration_warning)
            return False

        with self._mutation() as data:
            data["profiles"] = profiles
            data["active_profile"] = active_name or next(iter(profiles), "")
            if has_llm:
                data["llm"] = {
                    "LLM_ENDPOINT": llm["LLM_ENDPOINT"],
                    "LLM_API_KEY": llm["LLM_API_KEY"],
                    "LLM_PROVIDER": (llm["LLM_PROVIDER"] or "anthropic").lower(),
                    "LLM_MODEL": llm["LLM_MODEL"],
                    "LLM_LOCAL_MODE": "auto",
                }

        # Keep the plaintext leftover in the data dir, never in the source tree
        migrated_path = os.path.join(os.path.dirname(os.path.abspath(self._path)), ".env.migrated")
        n = 2
        while os.path.exists(migrated_path):
            migrated_path = os.path.join(os.path.dirname(os.path.abspath(self._path)), f".env.migrated.{n}")
            n += 1
        os.replace(env_path, migrated_path)
        try:
            os.chmod(migrated_path, 0o600)
        except OSError:
            pass
        logger.warning(
            "Migrated %d CID profile(s)%s from %s into the encrypted config store. The original file "
            "was renamed to %s and still contains plaintext secrets — delete it once verified.",
            len(profiles), " and LLM settings" if has_llm else "", env_path, migrated_path,
        )
        return True


_LEGACY_VAR_RE = re.compile(r"^\s*#?\s*(?:export\s+)?(FALCON_CLIENT_ID|FALCON_CLIENT_SECRET|FALCON_BASE_URL)\s*=")
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


def _profile_problems(values: dict) -> list[str]:
    """Return reasons a migrated profile looks wrong (empty list if it looks fine)."""
    problems = []
    if not _ID_RE.match(values.get("FALCON_CLIENT_ID", "")):
        problems.append("client ID is missing or has unexpected characters")
    secret = values.get("FALCON_CLIENT_SECRET", "")
    if not secret or any(c.isspace() for c in secret) or "#" in secret or secret[:1] in "\"'":
        problems.append("client secret is missing or contains spaces, '#' or quotes")
    url = values.get("FALCON_BASE_URL", "")
    if not url.startswith("https://") or any(c.isspace() for c in url):
        problems.append("base URL is not an https URL")
    return problems


def _dotenv_line_value(line: str) -> tuple[str, str] | None:
    """Parse one ``KEY=value`` line (leading ``#`` removed) with python-dotenv's own parser."""
    import io
    from dotenv.parser import parse_stream
    for binding in parse_stream(io.StringIO(line)):
        if binding.key:
            return binding.key, (binding.value or "").strip()
    return None


def parse_legacy_env_profiles(text: str) -> list[dict]:
    """Discover CID profile blocks in the legacy ``.env`` comment/uncomment format.

    A block starts at a ``FALCON_CLIENT_ID`` line (commented out = inactive)
    and collects the ``FALCON_CLIENT_SECRET`` / ``FALCON_BASE_URL`` lines that
    follow, across blank and comment lines, until the next
    ``FALCON_CLIENT_ID``. The block's name is the comment line *directly*
    above its ``FALCON_CLIENT_ID`` line (``#prod``); otherwise it is unnamed.
    Values are parsed with python-dotenv's parser, so ``export``, quotes and
    inline comments behave exactly as dotenv does.

    Args:
        text: Contents of the ``.env`` file.

    Returns:
        Blocks as ``{"name", "active", "values"}`` in file order.
    """
    blocks: list[dict] = []
    current = None
    previous = ""
    for raw in text.splitlines():
        line = raw.strip()
        if _LEGACY_VAR_RE.match(line):
            commented = line.startswith("#")
            parsed = _dotenv_line_value(line.lstrip("#").strip())
            if parsed:
                key, value = parsed
                if key == "FALCON_CLIENT_ID":
                    name = ""
                    if previous.startswith("#") and "=" not in previous:
                        candidate = previous.lstrip("#").strip()
                        name = candidate if 0 < len(candidate) <= 64 else ""
                    current = {"name": name, "active": not commented, "values": {}}
                    blocks.append(current)
                if current is not None and key not in current["values"]:
                    current["values"][key] = value
        previous = line
    return blocks


def _move_legacy_state() -> None:
    """Move state files left in the source tree by older versions into APP_DIR (by name only).

    Nothing is overwritten: a file is moved only if APP_DIR doesn't already
    have one with that name.
    """
    if _is_within(APP_DIR, SOURCE_DIR) or _is_within(SOURCE_DIR, APP_DIR):
        return
    with _file_lock(os.path.join(APP_DIR, ".falcon_config.lock")):
        for name in STATE_FILES + STATE_DIRS:
            src, dst = os.path.join(SOURCE_DIR, name), os.path.join(APP_DIR, name)
            if os.path.lexists(src) and not os.path.lexists(dst):
                try:
                    os.replace(src, dst)
                    logger.warning("Moved %s from the source tree to the data directory %s", name, APP_DIR)
                except OSError as e:
                    logger.error("Could not move %s to %s: %s", name, APP_DIR, e)


_move_legacy_state()

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

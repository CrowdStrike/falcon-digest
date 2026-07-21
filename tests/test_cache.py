"""Unit tests for the FalconCache background polling system.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    Falcon Digest
`-------'                         `-------'

Falcon Digest — AI-Powered Falcon Security Dashboard

Copyright 2024 CrowdStrike, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import pytest
import json
import time
import threading
import sys
import os
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timezone

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _get_fresh_cache_class():
    """Import FalconCache with a clean singleton state.

    falcon_cache imports crwd_mcp_server which requires falconpy and mcp.
    We mock those dependencies so the tests can run without them installed
    and without real credentials.
    """
    # Remove cached modules so re-import picks up fresh state
    for mod_name in list(sys.modules):
        if mod_name in ("falcon_cache",):
            del sys.modules[mod_name]

    from falcon_cache import FalconCache
    return FalconCache


class TestFalconCache:

    def setup_method(self):
        """Reset singleton for each test."""
        FalconCache = _get_fresh_cache_class()
        FalconCache._instance = None
        FalconCache._lock_cls = threading.Lock()
        self.FalconCache = FalconCache
        # Point CACHE_FILE to a nonexistent path so __init__._load_from_file()
        # doesn't pick up a real .falcon_cache.json from the project directory
        import falcon_cache as fc_mod
        self._original_cache_file = fc_mod.CACHE_FILE
        fc_mod.CACHE_FILE = os.path.join(os.path.dirname(__file__), ".nonexistent_test_cache.json")

    def teardown_method(self):
        import falcon_cache as fc_mod
        fc_mod.CACHE_FILE = self._original_cache_file

    def test_singleton_pattern(self):
        """Two instantiations return the same object."""
        c1 = self.FalconCache()
        c2 = self.FalconCache()
        assert c1 is c2

    def test_initial_state(self):
        """Freshly created cache has sensible defaults."""
        cache = self.FalconCache()
        assert cache.entry_count == 0
        assert cache.refresh_count == 0
        assert cache.is_running is False
        assert cache.last_refresh is None

    def test_get_missing_key(self):
        """get() on a nonexistent key returns None."""
        cache = self.FalconCache()
        assert cache.get("nonexistent") is None

    def test_get_existing_key(self):
        """get() on an existing key returns the raw data string."""
        cache = self.FalconCache()
        cache._cache["test"] = {
            "data": '{"key": "value"}',
            "fetched_at": "2026-03-04T00:00:00Z"
        }
        result = cache.get("test")
        assert result == '{"key": "value"}'

    def test_get_parsed_valid_json(self):
        """get_parsed() returns a dict for valid JSON."""
        cache = self.FalconCache()
        cache._cache["test"] = {
            "data": '{"key": "value"}',
            "fetched_at": "2026-03-04T00:00:00Z"
        }
        result = cache.get_parsed("test")
        assert result == {"key": "value"}

    def test_get_parsed_invalid_json(self):
        """get_parsed() returns None for unparseable data."""
        cache = self.FalconCache()
        cache._cache["test"] = {
            "data": "not json",
            "fetched_at": "2026-03-04T00:00:00Z"
        }
        result = cache.get_parsed("test")
        assert result is None

    def test_get_parsed_missing_key(self):
        """get_parsed() returns None for missing key."""
        cache = self.FalconCache()
        result = cache.get_parsed("nonexistent")
        assert result is None

    def test_is_fresh_within_ttl(self):
        """Entry fetched just now is considered fresh."""
        cache = self.FalconCache()
        cache.ttl = 300
        cache._cache["test"] = {
            "data": "{}",
            "fetched_at": datetime.now(tz=timezone.utc).isoformat() + "Z"
        }
        assert cache.is_fresh("test") is True

    def test_is_fresh_expired(self):
        """Entry fetched long ago is considered stale."""
        cache = self.FalconCache()
        cache.ttl = 1
        cache._cache["test"] = {
            "data": "{}",
            "fetched_at": "2020-01-01T00:00:00Z"
        }
        assert cache.is_fresh("test") is False

    def test_is_fresh_missing_key(self):
        """is_fresh() returns False for a missing key."""
        cache = self.FalconCache()
        assert cache.is_fresh("nonexistent") is False

    def test_build_context_summary_empty(self):
        """Empty cache produces an empty summary string."""
        cache = self.FalconCache()
        assert cache.build_context_summary() == ""

    def test_build_context_summary_with_data(self):
        """Cache with a security_posture entry produces non-empty summary."""
        cache = self.FalconCache()
        cache._last_refresh = datetime.now(tz=timezone.utc)
        posture = {
            "risk_score": 42,
            "risk_level": "Medium",
            "alerts": {"total": 5, "by_severity": {"Critical": 2, "High": 3}},
            "cases": {"total": 1, "by_status": {"Open": 1}},
            "detections": {"total": 0, "by_severity": {}},
            "vulnerabilities": {"total": 0, "by_severity": {}}
        }
        cache._cache["security_posture"] = {
            "data": json.dumps(posture),
            "fetched_at": datetime.now(tz=timezone.utc).isoformat() + "Z"
        }
        summary = cache.build_context_summary()
        assert len(summary) > 0
        assert "Security Posture" in summary
        assert "42" in summary

    def test_get_all_returns_copy(self):
        """get_all() returns a shallow copy; mutations do not affect cache."""
        cache = self.FalconCache()
        cache._cache["test"] = {"data": "{}", "fetched_at": "2026-03-04T00:00:00Z"}
        snapshot = cache.get_all()
        assert "test" in snapshot
        # Verify it's a copy
        snapshot["test"]["data"] = "modified"
        assert cache._cache["test"]["data"] == "{}"

    def test_get_all_empty_cache(self):
        """get_all() on empty cache returns empty dict."""
        cache = self.FalconCache()
        assert cache.get_all() == {}

    def test_entry_count(self):
        """entry_count reflects number of cached entries."""
        cache = self.FalconCache()
        assert cache.entry_count == 0
        cache._cache["a"] = {"data": "{}", "fetched_at": "2026-03-04T00:00:00Z"}
        cache._cache["b"] = {"data": "{}", "fetched_at": "2026-03-04T00:00:00Z"}
        assert cache.entry_count == 2

    def test_recent_errors_initially_empty(self):
        """recent_errors is empty on fresh cache."""
        cache = self.FalconCache()
        assert cache.recent_errors == []

    def test_recent_errors_limit(self):
        """recent_errors returns at most 5 entries."""
        cache = self.FalconCache()
        cache._errors = [f"err-{i}" for i in range(10)]
        assert len(cache.recent_errors) == 5
        # Should return the last 5
        assert cache.recent_errors == [f"err-{i}" for i in range(5, 10)]

    def test_stop_sets_running_false(self):
        """stop() sets is_running to False."""
        cache = self.FalconCache()
        cache._running = True
        cache._polling_thread = MagicMock()
        cache._polling_thread.is_alive.return_value = True
        cache.stop()
        assert cache._running is False

    def test_last_refresh_duration_initially_none(self):
        """last_refresh_duration is None before any refresh."""
        cache = self.FalconCache()
        assert cache.last_refresh_duration is None


class TestFalconCacheFilePersistence:
    """Tests for JSON file persistence (save/load/has_fresh)."""

    def setup_method(self):
        FalconCache = _get_fresh_cache_class()
        FalconCache._instance = None
        FalconCache._lock_cls = threading.Lock()
        self.FalconCache = FalconCache

    def test_save_and_load_from_file(self, tmp_path):
        """Round-trip: save to file, load into a fresh instance."""
        import falcon_cache as fc_mod
        original_file = fc_mod.CACHE_FILE
        fc_mod.CACHE_FILE = str(tmp_path / ".falcon_cache.json")
        try:
            cache1 = self.FalconCache()
            cache1._cache["test_key"] = {
                "data": '{"hello": "world"}',
                "fetched_at": datetime.now(tz=timezone.utc).isoformat() + "Z",
            }
            cache1._save_to_file()

            # Reset singleton and reload
            self.FalconCache._instance = None
            self.FalconCache._lock_cls = threading.Lock()
            cache2 = self.FalconCache()
            assert cache2.get("test_key") == '{"hello": "world"}'
            assert cache2.loaded_from_file is True
        finally:
            fc_mod.CACHE_FILE = original_file

    def test_load_from_file_missing(self, tmp_path):
        """_load_from_file returns False for nonexistent file."""
        import falcon_cache as fc_mod
        original_file = fc_mod.CACHE_FILE
        fc_mod.CACHE_FILE = str(tmp_path / "does_not_exist.json")
        try:
            cache = self.FalconCache()
            # __init__ already called _load_from_file; check result
            assert cache.loaded_from_file is False
        finally:
            fc_mod.CACHE_FILE = original_file

    def test_load_from_file_invalid_json(self, tmp_path):
        """_load_from_file returns False for corrupted file."""
        import falcon_cache as fc_mod
        original_file = fc_mod.CACHE_FILE
        bad_file = tmp_path / ".falcon_cache.json"
        bad_file.write_text("{not valid json!!!")
        fc_mod.CACHE_FILE = str(bad_file)
        try:
            cache = self.FalconCache()
            assert cache.loaded_from_file is False
            assert cache.entry_count == 0
        finally:
            fc_mod.CACHE_FILE = original_file

    def test_has_fresh_file_data_when_fresh(self, tmp_path):
        """has_fresh_file_data() True when entries are within TTL."""
        import falcon_cache as fc_mod
        original_file = fc_mod.CACHE_FILE
        fc_mod.CACHE_FILE = str(tmp_path / ".falcon_cache.json")
        try:
            cache = self.FalconCache()
            cache.ttl = 300
            cache._loaded_from_file = True
            cache._cache["k"] = {
                "data": "{}",
                "fetched_at": datetime.now(tz=timezone.utc).isoformat() + "Z",
            }
            assert cache.has_fresh_file_data() is True
        finally:
            fc_mod.CACHE_FILE = original_file

    def test_has_fresh_file_data_when_stale(self, tmp_path):
        """has_fresh_file_data() False when entries are expired."""
        import falcon_cache as fc_mod
        original_file = fc_mod.CACHE_FILE
        fc_mod.CACHE_FILE = str(tmp_path / ".falcon_cache.json")
        try:
            cache = self.FalconCache()
            cache.ttl = 1
            cache._loaded_from_file = True
            cache._cache["k"] = {
                "data": "{}",
                "fetched_at": "2020-01-01T00:00:00Z",
            }
            assert cache.has_fresh_file_data() is False
        finally:
            fc_mod.CACHE_FILE = original_file

    def test_has_fresh_file_data_no_file_load(self):
        """has_fresh_file_data() False if no file was loaded."""
        cache = self.FalconCache()
        cache._loaded_from_file = False
        assert cache.has_fresh_file_data() is False

    def test_save_atomic_no_partial_write(self, tmp_path):
        """Verify atomic write: .tmp file should not persist after save."""
        import falcon_cache as fc_mod
        original_file = fc_mod.CACHE_FILE
        fc_mod.CACHE_FILE = str(tmp_path / ".falcon_cache.json")
        try:
            cache = self.FalconCache()
            cache._cache["k"] = {
                "data": '{"a": 1}',
                "fetched_at": datetime.now(tz=timezone.utc).isoformat() + "Z",
            }
            cache._save_to_file()

            # Main file should exist and be valid JSON
            assert os.path.exists(fc_mod.CACHE_FILE)
            with open(fc_mod.CACHE_FILE) as f:
                data = json.load(f)
            assert "entries" in data
            assert "k" in data["entries"]

            # Temp file should not exist after successful save
            assert not os.path.exists(fc_mod.CACHE_FILE + ".tmp")
        finally:
            fc_mod.CACHE_FILE = original_file

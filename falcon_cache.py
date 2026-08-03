#!/usr/bin/env python3
"""Background polling cache with file persistence for Falcon API data.

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

import logging
import os

import threading
import time
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

logger = logging.getLogger("falcon_mcp.cache")

from crwd_mcp_server import (
    search_alerts, search_cases, search_detections,
    search_vulnerabilities, search_threatgraph, get_security_posture,
    get_identity_protection, get_cloud_security, get_exposure_management,
    get_ngsiem_ingestion
)


CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".falcon_cache.json")
CACHE_BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".falcon_cache_backups")


def _get_cid_fingerprint() -> str:
    """Return a short fingerprint of current credentials for change detection."""
    import hashlib
    cid = os.getenv("FALCON_CLIENT_ID", "")
    # Use first 8 chars of hash so we don't store actual credentials
    return hashlib.sha256(cid.encode()).hexdigest()[:8] if cid else ""


class FalconCache:
    """Thread-safe singleton cache with background polling."""

    _instance = None
    _lock_cls = threading.Lock()

    def __new__(cls):
        with cls._lock_cls:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._cache = {}
        self._lock = threading.Lock()
        self._polling_thread = None
        self._running = False
        self.poll_interval = 300  # seconds between refreshes
        self.ttl = 300            # seconds before entry is stale
        self._last_refresh = None
        self._refresh_count = 0
        self._errors = []
        self._last_refresh_duration = None
        self._loaded_from_file = False
        self._cid_fingerprint = _get_cid_fingerprint()
        self._hours = 24  # default reporting window
        # Progress tracking for UI
        self._refreshing = False
        self._refresh_done = 0      # how many sources completed
        self._refresh_total = 0     # how many sources total
        self._refresh_current = {}  # {key: "pending"|"loading"|"done"|"error"}
        self._load_from_file()

    # ---------- lifecycle ----------

    def start(self, poll_interval: int = 300, ttl: int = 300):
        """Start background polling. Safe to call multiple times."""
        # If thread died but _running is still True, reset it
        if self._running and self._polling_thread and not self._polling_thread.is_alive():
            self._running = False
        if self._running:
            return
        self.poll_interval = poll_interval
        self.ttl = ttl
        self._running = True
        self._polling_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="falcon-cache-poller"
        )
        self._polling_thread.start()
        logger.info(f"Cache started (poll_interval={poll_interval}s, ttl={ttl}s)")

    def stop(self):
        self._running = False
        logger.info("Cache stopped")

    def force_refresh(self):
        """Trigger an immediate cache refresh in a background thread.
        Returns immediately; the refresh runs asynchronously.
        Skips if a refresh is already in progress.
        """
        if self._refreshing:
            logger.info("Force refresh skipped — already refreshing")
            return None
        logger.info("Force refresh requested")
        t = threading.Thread(target=self._refresh_all, daemon=True, name="falcon-cache-force-refresh")
        t.start()
        return t

    def set_hours(self, hours: int):
        """Update the reporting window and trigger a cache refresh.

        Called when the user changes the global hours selector in the dashboard.
        """
        if hours == self._hours:
            return
        logger.info("Reporting window changed: %dh → %dh — refreshing cache", self._hours, hours)
        self._hours = hours
        self.force_refresh()

    @property
    def is_running(self) -> bool:
        # Check if thread is actually alive
        if self._running and self._polling_thread and not self._polling_thread.is_alive():
            self._running = False
        return self._running

    @property
    def last_refresh(self):
        return self._last_refresh

    @property
    def refresh_count(self) -> int:
        return self._refresh_count

    @property
    def entry_count(self) -> int:
        with self._lock:
            return len(self._cache)

    @property
    def recent_errors(self) -> list:
        return list(self._errors[-5:])

    @property
    def last_refresh_duration(self) -> float:
        return self._last_refresh_duration

    @property
    def is_refreshing(self) -> bool:
        return self._refreshing

    @property
    def refresh_progress(self) -> float:
        """Return 0.0–1.0 fraction of current refresh cycle completed."""
        if self._refresh_total == 0:
            return 0.0
        return self._refresh_done / self._refresh_total

    @property
    def refresh_status(self) -> dict:
        """Per-source status dict: {key: 'pending'|'loading'|'done'|'error'}."""
        return dict(self._refresh_current)

    # ---------- polling ----------

    def _poll_loop(self):
        # Initial fetch immediately
        self._refresh_all()
        while self._running:
            time.sleep(self.poll_interval)
            if self._running:
                # Check for CID change before each refresh
                from dotenv import load_dotenv
                load_dotenv(override=True)
                self.check_cid_change()
                self._refresh_all()

    def _refresh_all(self):
        """Fetch all data sources in parallel using ThreadPoolExecutor."""
        start_time = time.time()
        self._errors = []

        # Human-friendly labels for progress display
        LABELS = {
            "security_posture": "Security Posture",
            "alerts_all": "All Alerts",
            "alerts_critical": "Critical Alerts",
            "alerts_high": "High Alerts",
            "cases_recent": "Cases",
            "detections_recent": "Detections",
            "vulnerabilities_critical": "Vulnerabilities",
            "threatgraph_edge_types": "ThreatGraph",
            "identity_protection": "Identity Protection",
            "cloud_security": "Cloud Security",
            "exposure_management": "Exposure Management",
        }

        def _run_coro(key, coro):
            """Run an async coroutine in its own event loop (one per thread)."""
            self._refresh_current[key] = "loading"
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(coro)
                return key, result
            except Exception as e:
                return key, e
            finally:
                loop.close()

        fetch_specs = {
            "security_posture": get_security_posture(hours=self._hours),
            "alerts_all": search_alerts(product="cao", hours=self._hours, limit=20),
            "alerts_critical": search_alerts(severity="Critical", hours=self._hours, limit=20),
            "alerts_high": search_alerts(severity="High", hours=self._hours, limit=20),
            "cases_recent": search_cases(hours=self._hours, limit=20),
            "detections_recent": search_detections(hours=self._hours, limit=20),
            "vulnerabilities_critical": search_vulnerabilities(severity="critical", limit=20),
            "threatgraph_edge_types": search_threatgraph(),
            "identity_protection": get_identity_protection(limit=20),
            "cloud_security": get_cloud_security(limit=100),
            "exposure_management": get_exposure_management(limit=20),
            "ngsiem_ingestion": get_ngsiem_ingestion(hours=self._hours),
        }

        # Initialize progress tracking
        self._refresh_total = len(fetch_specs)
        self._refresh_done = 0
        self._refresh_current = {k: "pending" for k in fetch_specs}
        self._refreshing = True

        now_ts = datetime.now(tz=timezone.utc).isoformat() + "Z"
        try:
            with ThreadPoolExecutor(max_workers=min(len(fetch_specs), 8)) as executor:
                futures = {
                    executor.submit(_run_coro, key, coro): key
                    for key, coro in fetch_specs.items()
                }
                for future in as_completed(futures):
                    key, result = future.result()
                    if isinstance(result, Exception):
                        self._errors.append(f"{key}: {result}")
                        logger.error(f"Error fetching {key}: {result}")
                        self._refresh_current[key] = "error"
                        with self._lock:
                            self._cache[key] = {
                                "data": json.dumps({"error": str(result)}),
                                "fetched_at": now_ts,
                            }
                    else:
                        self._refresh_current[key] = "done"
                        with self._lock:
                            self._cache[key] = {
                                "data": result,
                                "fetched_at": now_ts,
                            }
                    self._refresh_done += 1
        finally:
            self._refreshing = False

        self._last_refresh = datetime.now(tz=timezone.utc)
        self._refresh_count += 1

        elapsed = time.time() - start_time
        self._last_refresh_duration = elapsed
        logger.info(f"Cache refresh #{self._refresh_count} completed in {elapsed:.1f}s ({len(self._errors)} errors)")
        self._save_to_file()

    # ---------- file persistence ----------

    def _save_to_file(self):
        """Atomically write cache dict to JSON file with CID fingerprint."""
        try:
            with self._lock:
                snapshot = {k: dict(v) for k, v in self._cache.items()}
            # Wrap with metadata so we can detect CID changes
            payload = {
                "_meta": {"cid_fingerprint": self._cid_fingerprint},
                "entries": snapshot,
            }
            tmp_path = CACHE_FILE + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(payload, f)
            os.replace(tmp_path, CACHE_FILE)
            logger.debug(f"Cache saved to {CACHE_FILE} ({len(snapshot)} entries)")
        except Exception as e:
            logger.error(f"Failed to save cache file: {e}")

    def _load_from_file(self) -> bool:
        """Load cache from JSON file. Clears and backs up if CID changed."""
        try:
            with open(CACHE_FILE, "r") as f:
                data = json.load(f)

            # Handle new format with _meta
            if isinstance(data, dict) and "_meta" in data:
                file_fp = data["_meta"].get("cid_fingerprint", "")
                entries = data.get("entries", {})
                if file_fp and file_fp != self._cid_fingerprint:
                    logger.info(f"CID changed (cache: {file_fp}, current: {self._cid_fingerprint}) — backing up old cache")
                    self._backup_and_clear_file()
                    return False
                data = entries

            # Handle legacy format (flat dict without _meta)
            if isinstance(data, dict):
                with self._lock:
                    self._cache = data
                self._loaded_from_file = True
                logger.info(f"Cache loaded from {CACHE_FILE} ({len(data)} entries)")
                return True
        except FileNotFoundError:
            logger.debug(f"No cache file found at {CACHE_FILE}")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load cache file: {e}")
        return False

    def _backup_and_clear_file(self):
        """Move stale cache file to backup directory."""
        try:
            os.makedirs(CACHE_BACKUP_DIR, exist_ok=True)
            ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(CACHE_BACKUP_DIR, f"cache_{ts}.json")
            os.replace(CACHE_FILE, backup_path)
            logger.info(f"Old cache backed up to {backup_path}")
        except Exception as e:
            logger.warning(f"Failed to backup cache file: {e}")
            # Still try to remove it
            try:
                os.remove(CACHE_FILE)
            except Exception:
                pass

    def check_cid_change(self) -> bool:
        """Check if CID changed since cache was initialized. If so, clear everything.
        Returns True if CID changed and cache was cleared.
        """
        new_fp = _get_cid_fingerprint()
        if new_fp != self._cid_fingerprint:
            logger.info(f"CID change detected ({self._cid_fingerprint} -> {new_fp})")
            self._cid_fingerprint = new_fp
            with self._lock:
                self._cache.clear()
            self._loaded_from_file = False
            self._last_refresh = None
            self._refresh_count = 0
            self._backup_and_clear_file()
            # Also clear the MCP server client cache
            try:
                from crwd_mcp_server import clear_client_cache
                clear_client_cache()
            except Exception:
                pass
            return True
        return False

    @property
    def loaded_from_file(self) -> bool:
        return self._loaded_from_file

    def has_fresh_file_data(self) -> bool:
        """Check if file-loaded data has any entry within TTL."""
        if not self._loaded_from_file:
            return False
        with self._lock:
            now = datetime.now(tz=timezone.utc)
            for entry in self._cache.values():
                try:
                    fetched = datetime.fromisoformat(entry["fetched_at"].rstrip("Z")).replace(tzinfo=timezone.utc)
                    if (now - fetched).total_seconds() < self.ttl:
                        return True
                except (KeyError, ValueError):
                    continue
        return False

    # ---------- read ----------

    def get(self, key: str):
        """Get raw cached data string for a key, or None if missing."""
        with self._lock:
            entry = self._cache.get(key)
            if entry:
                logger.debug(f"Cache hit: {key}")
                return entry["data"]
        logger.debug(f"Cache miss: {key}")
        return None

    def get_parsed(self, key: str):
        """Get parsed JSON for a key, or None."""
        raw = self.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None

    def is_fresh(self, key: str) -> bool:
        """Check if a cache entry exists and is within TTL."""
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return False
            fetched = datetime.fromisoformat(entry["fetched_at"].rstrip("Z")).replace(tzinfo=timezone.utc)
            return (datetime.now(tz=timezone.utc) - fetched).total_seconds() < self.ttl

    def get_all(self) -> dict:
        """Snapshot of all cache entries."""
        with self._lock:
            return {k: dict(v) for k, v in self._cache.items()}

    # ---------- context for AI ----------

    def build_context_summary(self) -> str:
        """
        Build a compact text summary of all cached data.
        Injected as a system message so the AI can answer common questions
        without making tool calls.
        """
        if not self._cache:
            return ""

        lines = []

        if self._last_refresh:
            age = (datetime.now(tz=timezone.utc) - self._last_refresh).total_seconds()
            if age > self.ttl * 2:
                lines.append(f"WARNING: Cache data is {int(age/60)} minutes old (stale)")

        lines.append(f"=== FALCON DIGEST CACHED DATA (refreshed {self._last_refresh.strftime('%H:%M:%S UTC') if self._last_refresh else 'never'}) ===")
        lines.append("")

        # Security posture
        posture = self.get_parsed("security_posture")
        if posture and "error" not in posture:
            lines.append("## Security Posture (last 24h)")
            lines.append(f"Risk Score: {posture.get('risk_score', '?')}/100 ({posture.get('risk_level', '?')})")
            lines.append(f"Alerts: {posture.get('alerts', {}).get('total', 0)} | "
                         f"Cases: {posture.get('cases', {}).get('total', 0)} | "
                         f"Detections: {posture.get('detections', {}).get('total', 0)} | "
                         f"Vulnerabilities: {posture.get('vulnerabilities', {}).get('total', 0)} | "
                         f"Hosts: {posture.get('hosts', {}).get('total', 0)}")

            for source in ["alerts", "detections", "vulnerabilities"]:
                by_sev = posture.get(source, {}).get("by_severity", {})
                if by_sev:
                    sev_str = ", ".join(f"{k}: {v}" for k, v in by_sev.items())
                    lines.append(f"  {source.title()} by severity: {sev_str}")

            case_status = posture.get("cases", {}).get("by_status", {})
            if case_status:
                lines.append(f"  Cases by status: {', '.join(f'{k}: {v}' for k, v in case_status.items())}")

            # Host fleet details
            hosts = posture.get("hosts", {})
            by_platform = hosts.get("by_platform", {})
            if by_platform:
                plat_str = ", ".join(f"{k}: {v}" for k, v in by_platform.items())
                lines.append(f"  Hosts by platform: {plat_str}")
            stale = hosts.get("stale_count", 0)
            contained = hosts.get("contained_count", 0)
            if stale > 0:
                lines.append(f"  Stale hosts (not seen in 7+ days): {stale}")
            if contained > 0:
                lines.append(f"  Contained hosts (network isolated): {contained}")

            # Top attack tactics
            by_tactic = posture.get("alerts", {}).get("by_tactic", {})
            if by_tactic:
                tactic_str = ", ".join(f"{k}: {v}" for k, v in by_tactic.items())
                lines.append(f"  Top attack tactics: {tactic_str}")

            lines.append("")

        # Recent critical alerts
        for sev_key, sev_label in [("alerts_critical", "Critical"), ("alerts_high", "High")]:
            data = self.get_parsed(sev_key)
            if data and not isinstance(data, str) and "error" not in data:
                alert_list = data.get("alerts", [])
                if alert_list:
                    lines.append(f"## {sev_label} Alerts ({data.get('total_found', len(alert_list))} total, showing top {len(alert_list)})")
                    for a in alert_list[:5]:
                        lines.append(f"  - [{a.get('severity')}] {a.get('tactic', 'N/A')}/{a.get('technique', 'N/A')} "
                                     f"| {a.get('product')} | {a.get('status')} | {a.get('timestamp', '')[:19]}")
                    lines.append("")

        # Recent cases
        data = self.get_parsed("cases_recent")
        if data and not isinstance(data, str) and "error" not in data:
            case_list = data.get("cases", [])
            if case_list:
                lines.append(f"## Recent Cases ({data.get('total_found', len(case_list))} total, showing top {len(case_list)})")
                for c in case_list[:5]:
                    tags = ", ".join(c.get("tags", [])[:3]) or "N/A"
                    lines.append(f"  - [{c.get('severity')}] {c.get('status')} | "
                                 f"{c.get('title', 'N/A')[:60]} | Tags: {tags} | {c.get('created', '')[:19]}")
                lines.append("")

        # Recent detections
        data = self.get_parsed("detections_recent")
        if data and not isinstance(data, str) and "error" not in data:
            det_list = data.get("detections", [])
            if det_list:
                lines.append(f"## Recent Detections ({data.get('total_found', len(det_list))} total, showing top {len(det_list)})")
                for d in det_list[:5]:
                    lines.append(f"  - [{d.get('severity')}] {d.get('hostname', 'N/A')} | "
                                 f"{d.get('tactic', 'N/A')}/{d.get('technique', 'N/A')} | "
                                 f"{d.get('filename', 'N/A')} | {d.get('status')}")
                lines.append("")

        # Critical vulnerabilities
        data = self.get_parsed("vulnerabilities_critical")
        if data and not isinstance(data, str) and "error" not in data:
            vuln_list = data.get("vulnerabilities", [])
            if vuln_list:
                lines.append(f"## Critical Vulnerabilities ({data.get('total_found', len(vuln_list))} total, showing top {len(vuln_list)})")
                for v in vuln_list[:5]:
                    lines.append(f"  - {v.get('cve_id', 'N/A')} (CVSS {v.get('base_score', '?')}) | "
                                 f"{v.get('hostname', 'N/A')} | {v.get('app_name', 'N/A')} | {v.get('status')}")
                lines.append("")

        # ThreatGraph
        data = self.get_parsed("threatgraph_edge_types")
        if data and not isinstance(data, str) and "error" not in data:
            total = data.get("total_edge_types", 0)
            lines.append(f"## ThreatGraph ({total} edge types available)")
            lines.append("  IOC lookup supports: domain, ipv4, ipv6, md5, sha1, sha256")
            lines.append("")

        # Identity Protection
        data = self.get_parsed("identity_protection")
        if data and not isinstance(data, str) and "error" not in data:
            lines.append(f"## Identity Protection")
            lines.append(f"  Sensors: {data.get('total_sensors', 0)} | Risky entities: {data.get('total_risky', 0)}")
            by_status = data.get("by_status", {})
            if by_status:
                lines.append(f"  Sensors by status: {', '.join(f'{k}: {v}' for k, v in by_status.items())}")
            by_os = data.get("by_os", {})
            if by_os:
                lines.append(f"  Sensors by OS: {', '.join(f'{k}: {v}' for k, v in by_os.items())}")
            risky = data.get("risky_entities", [])
            if risky:
                lines.append(f"  Top risky identities:")
                for r in risky[:5]:
                    lines.append(f"    - {r.get('display_name', 'N/A')} ({r.get('type', '?')}) score={r.get('risk_score', 0)}")
            lines.append("")

        # Cloud Security
        data = self.get_parsed("cloud_security")
        if data and not isinstance(data, str) and "error" not in data:
            lines.append(f"## Cloud Security (CSPM)")
            lines.append(f"  Total risks: {data.get('total_risks', 0)} | IOMs: {data.get('iom_count', 'N/A')}")
            by_sev = data.get("risks_by_severity", {})
            if by_sev:
                lines.append(f"  Risks by severity: {', '.join(f'{k}: {v}' for k, v in by_sev.items())}")
            by_prov = data.get("risks_by_provider", {})
            if by_prov:
                lines.append(f"  Risks by provider: {', '.join(f'{k}: {v}' for k, v in by_prov.items())}")
            by_svc = data.get("risks_by_service", {})
            if by_svc:
                top_svc = dict(sorted(by_svc.items(), key=lambda x: x[1], reverse=True)[:5])
                lines.append(f"  Top risk categories: {', '.join(f'{k}: {v}' for k, v in top_svc.items())}")
            lines.append("")

        # Exposure Management
        data = self.get_parsed("exposure_management")
        if data and not isinstance(data, str) and "error" not in data:
            lines.append(f"## Exposure Management (External Attack Surface)")
            lines.append(f"  Total external assets: {data.get('total_assets', 0)}")
            by_crit = data.get("by_criticality", {})
            if by_crit:
                lines.append(f"  By criticality: {', '.join(f'{k}: {v}' for k, v in by_crit.items())}")
            by_type = data.get("by_asset_type", {})
            if by_type:
                lines.append(f"  By asset type: {', '.join(f'{k}: {v}' for k, v in by_type.items())}")
            assets = data.get("assets", [])
            if assets:
                lines.append(f"  Top assets:")
                for a in assets[:5]:
                    lines.append(f"    - {a.get('name', 'N/A')} ({a.get('asset_type', '?')}) {a.get('criticality', '')} {a.get('country', '')}")
            lines.append("")

        # NGSIEM Data Ingestion
        data = self.get_parsed("ngsiem_ingestion")
        if data and not isinstance(data, str) and "error" not in data:
            lines.append(f"## NGSIEM Data Ingestion (last 24h)")
            lines.append(f"  Total volume: {data.get('total_bytes_human', 'N/A')} | Events: {data.get('total_events_human', 'N/A')}")
            sources = data.get("sources", [])
            if sources:
                lines.append(f"  Top sources ({len(sources)} repos):")
                for s in sources[:5]:
                    lines.append(f"    - {s.get('repository', 'N/A')}: {s.get('ingest_bytes_human', '?')} / {s.get('ingest_events_human', '?')} events")
            lines.append("")

        lines.append("=== END CACHED DATA ===")

        return "\n".join(lines)


# ============ CID Profile Management ============

ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


def parse_env_profiles() -> list[dict]:
    """Parse .env file and extract CID credential profiles.

    The .env uses a comment/uncomment pattern:
        #profile_name
        #FALCON_CLIENT_ID=xxx    (commented = inactive)
        #FALCON_CLIENT_SECRET=xxx
        #FALCON_BASE_URL=xxx

    Active profile has uncommented FALCON_* lines.

    Returns list of dicts: [{"name": str, "client_id": str, "base_url": str, "active": bool}]
    """
    if not os.path.exists(ENV_FILE):
        return []

    with open(ENV_FILE, "r") as f:
        lines = f.readlines()

    profiles = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        # Look for a profile header comment: starts with # but is NOT a commented-out var
        # and does not mention LLM config (which is not a CID profile)
        if (line.startswith("#") and
                not line.startswith("#FALCON_") and
                not line.startswith("#LLM_") and
                "llm_endpoint" not in line.lower() and "llm_api_key" not in line.lower() and
                line.strip() and
                "=" not in line.split()[0]):
            profile_name = line.lstrip("#").strip()
            if not profile_name:
                i += 1
                continue

            # Scan ahead (up to 8 lines) for FALCON_CLIENT_ID/SECRET/BASE_URL
            # Skip over LLM_ lines and empty lines
            client_id = None
            client_secret = None
            base_url = None
            active = None
            line_start = i
            j = i + 1
            while j < len(lines) and j <= i + 8:
                l = lines[j].rstrip()
                if "FALCON_CLIENT_ID=" in l:
                    is_commented = l.lstrip().startswith("#")
                    val = l.lstrip("#").split("=", 1)[1].strip()
                    client_id = val
                    if active is None:
                        active = not is_commented
                elif "FALCON_CLIENT_SECRET=" in l:
                    is_commented = l.lstrip().startswith("#")
                    val = l.lstrip("#").split("=", 1)[1].strip()
                    client_secret = val
                elif "FALCON_BASE_URL=" in l:
                    is_commented = l.lstrip().startswith("#")
                    val = l.lstrip("#").split("=", 1)[1].strip()
                    base_url = val
                elif l.strip() == "" or "LLM_ENDPOINT" in l or "LLM_API_KEY" in l:
                    # Skip empty lines and LLM config lines
                    j += 1
                    continue
                elif l.startswith("#") and "=" not in l:
                    # Next profile header — stop scanning
                    break
                j += 1

            if client_id:
                profiles.append({
                    "name": profile_name,
                    "client_id": client_id,
                    "client_id_short": client_id[-8:] if len(client_id) >= 8 else client_id,
                    "base_url": base_url or "https://api.crowdstrike.com",
                    "active": bool(active),
                    "line_start": line_start,
                    "line_end": j - 1,
                })
            i = j
        else:
            i += 1

    return profiles


def switch_env_profile(target_name: str) -> bool:
    """Rewrite .env to activate the profile with `target_name` and comment out others.

    Returns True if profile was switched successfully.
    """
    if not os.path.exists(ENV_FILE):
        return False

    with open(ENV_FILE, "r") as f:
        lines = f.readlines()

    profiles = parse_env_profiles()
    if not profiles:
        return False

    target = None
    for p in profiles:
        if p["name"] == target_name:
            target = p
            break
    if not target:
        return False

    # Rewrite the file: comment out all FALCON_* lines, then uncomment the target profile's
    new_lines = []
    in_profile = None
    for i, line in enumerate(lines):
        stripped = line.rstrip()

        # Check if this line is a profile header
        is_header = False
        for p in profiles:
            if i == p["line_start"]:
                in_profile = p["name"]
                is_header = True
                break

        if is_header:
            new_lines.append(line)
            continue

        # For FALCON_ variable lines, comment/uncomment based on target
        if "FALCON_CLIENT_ID=" in stripped or "FALCON_CLIENT_SECRET=" in stripped or "FALCON_BASE_URL=" in stripped:
            # Get the raw key=value (strip any leading #)
            raw = stripped.lstrip("#")
            if in_profile == target_name:
                # Uncomment: write raw
                new_lines.append(raw + "\n")
            else:
                # Comment out: ensure it starts with #
                new_lines.append("#" + raw + "\n")
        else:
            new_lines.append(line)

    # Write atomically
    tmp_path = ENV_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        f.writelines(new_lines)
    os.replace(tmp_path, ENV_FILE)

    # Reload env vars
    from dotenv import load_dotenv
    load_dotenv(ENV_FILE, override=True)

    logger.info(f"Switched active CID profile to: {target_name}")
    return True


# Module-level convenience: import and use the singleton directly
cache = FalconCache()

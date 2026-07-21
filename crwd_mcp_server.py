#!/usr/bin/env python3
"""CrowdStrike Falcon MCP server with security operations tools.

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

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, Resource, Prompt, PromptMessage, PromptArgument
from falconpy import (
    Alerts, Hosts, CaseManagement, SpotlightVulnerabilities,
    ThreatGraph, Incidents, Discover, ExposureManagement,
    ZeroTrustAssessment, SensorUpdatePolicies, PreventionPolicies,
    NGSIEM, IdentityProtection, CloudSecurity, FlightControl
)
try:
    from falconpy import CloudSecurityDetections
except ImportError:
    CloudSecurityDetections = None
import asyncio
import os
import json
import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============ STRUCTURED LOGGING ============

logger = logging.getLogger("falcon_mcp")
logger.addHandler(logging.NullHandler())


# ============ CONFIGURATION VALIDATION ============

class ConfigError(Exception):
    """Raised when required configuration is missing."""
    pass


def validate_config():
    """Validate all required environment variables are set.

    Checks both Falcon API credentials and LLM configuration.
    Raises ConfigError with a clear message listing all missing values.
    """
    errors = []

    # Falcon API credentials
    if not os.getenv("FALCON_CLIENT_ID", "").strip():
        errors.append("FALCON_CLIENT_ID is not set")
    if not os.getenv("FALCON_CLIENT_SECRET", "").strip():
        errors.append("FALCON_CLIENT_SECRET is not set")

    # LLM configuration
    llm_endpoint = os.getenv("LLM_ENDPOINT", "").strip()
    llm_key = os.getenv("LLM_API_KEY", "").strip()
    if not llm_endpoint:
        errors.append("LLM_ENDPOINT is not set")
    if not llm_key:
        errors.append("LLM_API_KEY is not set")

    # LLM provider validation
    provider = os.getenv("LLM_PROVIDER", "anthropic").lower()
    if provider not in ("anthropic", "openai"):
        errors.append(f"LLM_PROVIDER '{provider}' is not supported (use 'anthropic' or 'openai')")

    if errors:
        raise ConfigError(
            "Required configuration missing in .env file:\n"
            + "\n".join(f"  - {e}" for e in errors)
            + "\n\nSee .env.example for details."
        )


# Initialize server
server = Server("falcon-digest")

# ============ HELPER FUNCTIONS ============

def sanitize_fql_value(value: str) -> str:
    """Sanitize a value for safe use in FQL filter strings.

    Strips/escapes injection characters. Only allows alphanumeric,
    dots, hyphens, underscores, colons, spaces, and @.
    """
    if not isinstance(value, str):
        return str(value)
    # Remove any characters not in the allowed set
    return re.sub(r"[^a-zA-Z0-9.\-_: @]", "", value)


def _is_crowdstrike_source(name: str) -> bool:
    """Return True if a source_product name belongs to CrowdStrike."""
    lower = (name or "").lower()
    return any(kw in lower for kw in ("falcon", "crowdstrike", "cs-"))


_client_cache = {}
_client_lock = threading.Lock()
_cached_credentials = {"client_id": None, "client_secret": None, "base_url": None}


def _credentials_changed() -> bool:
    """Check if .env credentials differ from what's cached."""
    current = {
        "client_id": os.getenv("FALCON_CLIENT_ID"),
        "client_secret": os.getenv("FALCON_CLIENT_SECRET"),
        "base_url": os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    }
    return current != _cached_credentials


def _update_cached_credentials():
    """Snapshot current credentials."""
    _cached_credentials["client_id"] = os.getenv("FALCON_CLIENT_ID")
    _cached_credentials["client_secret"] = os.getenv("FALCON_CLIENT_SECRET")
    _cached_credentials["base_url"] = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com")


def clear_client_cache():
    """Clear all cached Falcon API clients (e.g. after credential change)."""
    with _client_lock:
        _client_cache.clear()
        _update_cached_credentials()
    logger.info("Client cache cleared due to credential change")


def get_falcon_client(service_class):
    """Get or create a cached Falcon API client. Auto-clears on credential change."""
    with _client_lock:
        # Detect credential change — reload .env and clear stale clients
        if _credentials_changed():
            load_dotenv(override=True)
            _client_cache.clear()
            _update_cached_credentials()
            logger.info("Credentials changed — cleared client cache and reloaded .env")

        class_name = service_class.__name__
        if class_name not in _client_cache:
            logger.info(f"Creating new Falcon client: {class_name}")
            _client_cache[class_name] = service_class(
                client_id=os.getenv("FALCON_CLIENT_ID"),
                client_secret=os.getenv("FALCON_CLIENT_SECRET"),
                base_url=os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com"),
                user_agent="falcon-digest/1.0.0"
            )
        return _client_cache[class_name]


# Initialize credential snapshot on module load
_update_cached_credentials()


def _run_ngsiem_query(ngsiem_client, query_string: str, start: str = "24h",
                      repository: str = None, timeout_sec: int = 30) -> dict:
    """Run a LogScale async query: start job -> poll until done -> return events.

    Returns {"events": [...], "error": str|None}.
    """
    import time as _time

    if repository is None:
        repository = os.getenv("NGSIEM_REPOSITORY", "xdr")

    try:
        resp = ngsiem_client.start_search(
            repository=repository,
            query_string=query_string,
            start=start,
        )
        status_code = resp.get("status_code", 0) if isinstance(resp, dict) else 0
        if status_code == 403:
            return {"events": [], "error": "ngsiem:read scope not granted (403)"}

        # start_search returns "resources" (not "body")
        body = resp.get("resources", resp.get("body", resp)) if isinstance(resp, dict) else {}

        # Check for API-level errors
        if status_code >= 400:
            errors = body.get("errors", []) if isinstance(body, dict) else []
            err_msg = errors[0].get("message", str(resp)) if errors else str(resp)
            return {"events": [], "error": f"NGSIEM API error ({status_code}): {err_msg}"}

        # Extract job id from response
        job_id = body.get("id") or body.get("job_id") if isinstance(body, dict) else None

        # If results came back immediately
        if status_code == 200 and isinstance(body, dict) and body.get("done", False):
            events = body.get("events", body.get("results", []))
            return {"events": events, "error": None}

        if not job_id:
            return {"events": [], "error": f"No job_id in NGSIEM response: {resp}"}

        # Poll until done
        deadline = _time.time() + timeout_sec
        while _time.time() < deadline:
            _time.sleep(2)
            status_resp = ngsiem_client.get_search_status(
                repository=repository, id=job_id
            )
            status_body = status_resp.get("body", status_resp) if isinstance(status_resp, dict) else {}
            if status_body.get("done", False):
                events = status_body.get("events", status_body.get("results", []))
                return {"events": events, "error": None}

        # Timeout — attempt cleanup
        try:
            ngsiem_client.stop_search(repository=repository, id=job_id)
        except Exception:
            pass
        return {"events": [], "error": f"NGSIEM query timed out after {timeout_sec}s"}

    except Exception as e:
        return {"events": [], "error": str(e)}


# ============ EXISTING TOOL HANDLERS ============

async def search_alerts(product: str = "cao", severity: str = None, hours: int = 24, limit: int = 50) -> str:
    """Search CrowdStrike alerts (including CAO detections)"""
    logger.info(f"search_alerts called: product={product}, severity={severity}, hours={hours}, limit={limit}")
    try:
        falcon = get_falcon_client(Alerts)

        # Build FQL filter
        safe_product = sanitize_fql_value(product)
        filters = [f"product:'{safe_product}'"]

        # Add time filter
        time_ago = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
        filters.append(f"created_timestamp:>'{time_ago.isoformat()}Z'")

        # Add severity filter
        if severity:
            safe_severity = sanitize_fql_value(severity)
            filters.append(f"severity_name:'{safe_severity}'")

        filter_str = "+".join(filters)

        # Query alerts
        response = falcon.query_alerts(filter=filter_str, limit=limit)

        if response["status_code"] != 200:
            return json.dumps({"error": f"Error querying alerts: {response['body'].get('errors', 'Unknown error')}", "tool": "search_alerts", "status": "error"})

        alert_ids = response["body"]["resources"]

        if not alert_ids:
            return json.dumps({"total_found": 0, "query_filter": filter_str, "alerts": []})

        # Get alert details
        details_response = falcon.get_alerts(ids=alert_ids)

        if details_response["status_code"] != 200:
            return json.dumps({"error": f"Error getting alert details: {details_response['body'].get('errors', 'Unknown error')}", "tool": "search_alerts", "status": "error"})

        alerts = details_response["body"]["resources"]

        # Format results
        results = {
            "total_found": len(alerts),
            "query_filter": filter_str,
            "alerts": []
        }

        for alert in alerts[:limit]:
            results["alerts"].append({
                "id": alert.get("composite_id", "N/A"),
                "severity": alert.get("severity_name", "N/A"),
                "product": alert.get("product", "N/A"),
                "external_provider": alert.get("external_provider_name", "N/A"),
                "tactic": alert.get("tactic", "N/A"),
                "technique": alert.get("technique", "N/A"),
                "status": alert.get("status", "N/A"),
                "timestamp": alert.get("created_timestamp", "N/A"),
                "description": alert.get("description", "N/A")[:200]
            })

        return json.dumps(results, indent=2)

    except Exception as e:
        logger.error(f"search_alerts failed: {e}", exc_info=True)
        return json.dumps({"error": str(e), "tool": "search_alerts", "status": "error"})

async def search_hosts(platform: str = None, status: str = None, hostname: str = None, last_seen_within: int = None, limit: int = 50) -> str:
    """Search and count CrowdStrike hosts by platform, status, or hostname pattern"""
    logger.info(f"search_hosts called: platform={platform}, status={status}, hostname={hostname}, last_seen_within={last_seen_within}, limit={limit}")
    try:
        falcon = get_falcon_client(Hosts)

        filters = []
        if platform:
            filters.append(f"platform_name:'{sanitize_fql_value(platform)}'")
        if status:
            filters.append(f"status:'{sanitize_fql_value(status)}'")
        if hostname:
            filters.append(f"hostname:*'*{sanitize_fql_value(hostname)}*'")
        if last_seen_within is not None:
            cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=last_seen_within)).isoformat() + "Z"
            filters.append(f"last_seen:>'{cutoff}'")
        filter_str = "+".join(filters) if filters else ""

        # Query to get total count
        response = falcon.query_devices_by_filter(filter=filter_str, limit=limit, sort="last_seen.desc")

        if response["status_code"] != 200:
            return json.dumps({"error": f"Query failed: {response['body'].get('errors', 'Unknown')}", "tool": "search_hosts", "status": "error"})

        device_ids = response["body"]["resources"]
        total = response["body"].get("meta", {}).get("pagination", {}).get("total", len(device_ids))

        if not device_ids:
            return json.dumps({"total_hosts": total, "query_filter": filter_str, "hosts": []})

        # Get details for returned hosts
        details = falcon.get_device_details(ids=device_ids[:limit])

        if details["status_code"] != 200:
            return json.dumps({"error": f"Details failed: {details['body'].get('errors', 'Unknown')}", "tool": "search_hosts", "status": "error"})

        devices = details["body"]["resources"]

        results = {
            "total_hosts": total,
            "returned": len(devices),
            "query_filter": filter_str,
            "hosts": []
        }

        for device in devices[:limit]:
            results["hosts"].append({
                "hostname": device.get("hostname", "N/A"),
                "device_id": device.get("device_id", "N/A"),
                "platform": device.get("platform_name", "N/A"),
                "os_version": device.get("os_version", "N/A"),
                "status": device.get("status", "N/A"),
                "last_seen": device.get("last_seen", "N/A"),
                "local_ip": device.get("local_ip", "N/A"),
                "external_ip": device.get("external_ip", "N/A"),
                "agent_version": device.get("agent_version", "N/A"),
                "tags": device.get("tags", [])
            })

        return json.dumps(results, indent=2)

    except Exception as e:
        logger.error(f"search_hosts failed: {e}", exc_info=True)
        return json.dumps({"error": str(e), "tool": "search_hosts", "status": "error"})

async def get_host_details(hostname: str) -> str:
    """Get detailed information about a specific host"""
    logger.info(f"get_host_details called: hostname={hostname}")
    try:
        falcon = get_falcon_client(Hosts)

        safe_hostname = sanitize_fql_value(hostname)
        response = falcon.query_devices_by_filter(filter=f"hostname:'{safe_hostname}'")

        if response["status_code"] != 200:
            return json.dumps({"error": f"Error searching for host: {response['body'].get('errors', 'Unknown error')}", "tool": "get_host_details", "status": "error"})

        device_ids = response["body"]["resources"]

        if not device_ids:
            return json.dumps({"error": f"Host '{safe_hostname}' not found in Falcon", "tool": "get_host_details", "status": "error"})

        details = falcon.get_device_details(ids=device_ids)

        if details["status_code"] != 200:
            return json.dumps({"error": f"Error getting device details: {details['body'].get('errors', 'Unknown error')}", "tool": "get_host_details", "status": "error"})

        device = details["body"]["resources"][0]

        info = {
            "hostname": device.get("hostname", "N/A"),
            "agent_id": device.get("device_id", "N/A"),
            "platform": device.get("platform_name", "N/A"),
            "os_version": device.get("os_version", "N/A"),
            "status": device.get("status", "N/A"),
            "last_seen": device.get("last_seen", "N/A"),
            "local_ip": device.get("local_ip", "N/A"),
            "external_ip": device.get("external_ip", "N/A"),
            "mac_address": device.get("mac_address", "N/A"),
            "agent_version": device.get("agent_version", "N/A"),
            "tags": device.get("tags", [])
        }

        return json.dumps(info, indent=2)

    except Exception as e:
        logger.error(f"get_host_details failed: {e}", exc_info=True)
        return json.dumps({"error": str(e), "tool": "get_host_details", "status": "error"})

async def test_fql_filter(filter_string: str) -> str:
    """Test and validate an FQL filter string"""
    logger.info(f"test_fql_filter called: filter_string={filter_string}")
    try:
        issues = []

        if not filter_string:
            return json.dumps({"error": "Empty filter string", "tool": "test_fql_filter", "status": "error"})

        if filter_string.count("'") % 2 != 0:
            issues.append("Unbalanced single quotes")

        if filter_string.count('"') % 2 != 0:
            issues.append("Unbalanced double quotes")

        common_fields = [
            "product", "severity", "severity_name",
            "created_timestamp", "status", "tactic", "technique",
            "external_provider_name", "hostname"
        ]

        found_fields = [field for field in common_fields if field in filter_string]

        result = {
            "filter": filter_string,
            "valid": len(issues) == 0,
            "issues": issues if issues else None,
            "detected_fields": found_fields,
            "suggestion": "Filter looks good!" if len(issues) == 0 else "Fix the issues above"
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"test_fql_filter failed: {e}", exc_info=True)
        return json.dumps({"error": str(e), "tool": "test_fql_filter", "status": "error"})

async def list_available_products() -> str:
    """List available product types for filtering alerts"""
    logger.info("list_available_products called")
    products = {
        "available_products": [
            {
                "value": "cao",
                "name": "Cloud Automated Orchestration",
                "description": "CAO-generated detections"
            },
            {
                "value": "thirdparty",
                "name": "Third Party Integrations",
                "description": "Detections from external sources"
            },
            {
                "value": "epp",
                "name": "Endpoint Protection",
                "description": "Falcon sensor detections"
            },
            {
                "value": "idp",
                "name": "Identity Protection",
                "description": "Identity-based detections"
            }
        ],
        "example_filters": [
            "product:'cao'",
            "product:'thirdparty'+external_provider_name:'Corelight'",
            "product:'epp'+severity_name:'Critical'"
        ]
    }

    return json.dumps(products, indent=2)

# ============ NEW TOOL HANDLERS ============

async def search_cases(status: str = None, severity: str = None, hours: int = 72, limit: int = 50) -> str:
    """Search CrowdStrike cases by status, severity, and time range"""
    logger.info(f"search_cases called: status={status}, severity={severity}, hours={hours}, limit={limit}")
    try:
        falcon = get_falcon_client(CaseManagement)

        filters = []

        time_ago = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
        filters.append(f"created_timestamp:>'{time_ago.isoformat()}Z'")

        if status:
            safe_status = sanitize_fql_value(status)
            status_map = {"new": "new", "open": "open", "in_progress": "in_progress", "reopened": "reopened", "closed": "closed"}
            status_val = status_map.get(safe_status.lower(), safe_status.lower())
            filters.append(f"status:'{status_val}'")

        if severity:
            safe_severity = sanitize_fql_value(severity)
            # Cases API uses integer severity 0-100
            sev_ranges = {
                "critical": ("severity:>=75", None),
                "high":     ("severity:>=50", "severity:<75"),
                "medium":   ("severity:>=25", "severity:<50"),
                "low":      (None, "severity:<25"),
            }
            bounds = sev_ranges.get(safe_severity.lower())
            if bounds:
                if bounds[0]:
                    filters.append(bounds[0])
                if bounds[1]:
                    filters.append(bounds[1])

        filter_str = "+".join(filters) if filters else ""

        response = falcon.query_case_ids(filter=filter_str, limit=limit, sort="created_timestamp.desc")

        if response["status_code"] != 200:
            return json.dumps({"error": f"Query failed: {response['body'].get('errors', 'Unknown')}"})

        case_ids = response["body"]["resources"]

        if not case_ids:
            return json.dumps({"total_found": 0, "query_filter": filter_str, "cases": []})

        details = falcon.get_cases(body={"ids": case_ids})

        if details["status_code"] != 200:
            return json.dumps({"error": f"Details failed: {details['body'].get('errors', 'Unknown')}"})

        cases_data = details["body"]["resources"]

        results = {
            "total_found": len(cases_data),
            "query_filter": filter_str,
            "cases": []
        }

        for case in cases_data[:limit]:
            results["cases"].append({
                "id": case.get("id", "N/A"),
                "title": (case.get("title") or case.get("name") or "N/A")[:200],
                "description": (case.get("description", "N/A") or "N/A")[:200],
                "status": case.get("status", "N/A"),
                "severity": case.get("severity", "N/A"),
                "tags": case.get("tags", []),
                "created": case.get("created_time") or case.get("created_timestamp", "N/A"),
                "assigned_to": case.get("assigned_to_name") or case.get("assigned_to", "Unassigned")
            })

        return json.dumps(results, indent=2)

    except Exception as e:
        logger.error(f"search_cases failed: {e}", exc_info=True)
        return json.dumps({"error": str(e), "tool": "search_cases", "status": "error"})

async def search_detections(severity: str = None, status: str = None, hours: int = 24, limit: int = 50) -> str:
    """Search all detections via Alerts API (EPP, 3rd-party, IDP, CAO)

    Note: The legacy Detects API has been decommissioned. This uses the
    Alerts v2 API across all product types for a unified detection view.
    """
    logger.info(f"search_detections called: severity={severity}, status={status}, hours={hours}, limit={limit}")
    try:
        falcon = get_falcon_client(Alerts)

        filters = []

        time_ago = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
        filters.append(f"created_timestamp:>'{time_ago.isoformat()}Z'")

        if severity:
            safe_severity = sanitize_fql_value(severity)
            filters.append(f"severity_name:'{safe_severity.capitalize()}'")

        if status:
            safe_status = sanitize_fql_value(status)
            filters.append(f"status:'{safe_status}'")

        filter_str = "+".join(filters)

        response = falcon.query_alerts(filter=filter_str, limit=limit)

        if response["status_code"] != 200:
            return json.dumps({"error": f"Query failed: {response['body'].get('errors', 'Unknown')}"})

        alert_ids = response["body"]["resources"]
        _pagination_total = response["body"].get("meta", {}).get("pagination", {}).get("total", len(alert_ids))

        if not alert_ids:
            return json.dumps({"total_found": 0, "query_filter": filter_str, "detections": [],
                               "first_party": 0, "third_party": 0})

        details = falcon.get_alerts(ids=alert_ids)

        if details["status_code"] != 200:
            return json.dumps({"error": f"Details failed: {details['body'].get('errors', 'Unknown')}"})

        detections = details["body"]["resources"]

        # Count 1P vs 3P from the fetched details first (always accurate)
        _products_seen = {}
        for det in detections:
            p = det.get("product", "unknown")
            _products_seen[p] = _products_seen.get(p, 0) + 1
        logger.info(f"search_detections products breakdown: {_products_seen}")

        # Non-epp/non-3rdparty products (idp, cao, etc.) count as 1P (CrowdStrike-native)
        _1p_total = sum(c for p, c in _products_seen.items() if p != "thirdparty")
        _3p_total = _products_seen.get("thirdparty", 0)

        # Try to get accurate totals from API pagination (covers beyond fetched page)
        _time_filter = f"created_timestamp:>'{time_ago.isoformat()}Z'"
        _extra_filters = ""
        if severity:
            _extra_filters += f"+severity_name:'{sanitize_fql_value(severity).capitalize()}'"
        if status:
            _extra_filters += f"+status:'{sanitize_fql_value(status)}'"

        # 3P total from API
        _fql_3p = f"product:'thirdparty'+{_time_filter}{_extra_filters}"
        _resp_3p = falcon.query_alerts(filter=_fql_3p, limit=1)
        if _resp_3p["status_code"] == 200:
            _api_3p = _resp_3p["body"].get("meta", {}).get("pagination", {}).get("total", _3p_total)
            if _api_3p > _3p_total:
                _3p_total = _api_3p

        # 1P = total minus 3P
        if _pagination_total > _3p_total:
            _1p_total = _pagination_total - _3p_total

        results = {
            "total_found": _pagination_total,
            "query_filter": filter_str,
            "detections": [],
            "first_party": _1p_total,
            "third_party": _3p_total,
            "products_seen": _products_seen,
        }

        for det in detections[:limit]:
            product = det.get("product", "unknown")
            _vendors = det.get("source_vendors", [])
            _products = det.get("source_products", [])
            source_product = _products[0] if _products else ""
            provider = source_product or (_vendors[0] if _vendors else "")
            results["detections"].append({
                "id": det.get("composite_id", "N/A"),
                "severity": det.get("severity_name", "N/A"),
                "status": det.get("status", "N/A"),
                "hostname": det.get("hostname", "N/A"),
                "tactic": det.get("tactic", "N/A"),
                "technique": det.get("technique", "N/A"),
                "filename": det.get("filename", "N/A"),
                "cmdline": (det.get("cmdline", "N/A") or "N/A")[:200],
                "timestamp": det.get("created_timestamp", "N/A"),
                "description": (det.get("description", "N/A") or "N/A")[:200],
                "assigned_to": det.get("assigned_to_name", "Unassigned"),
                "product": product,
                "source": provider if (product == "thirdparty" and not _is_crowdstrike_source(provider)) else "CrowdStrike",
            })

        return json.dumps(results, indent=2)

    except Exception as e:
        logger.error(f"search_detections failed: {e}", exc_info=True)
        return json.dumps({"error": str(e), "tool": "search_detections", "status": "error"})

async def search_vulnerabilities(severity: str = None, status: str = None, limit: int = 50) -> str:
    """Search Spotlight vulnerabilities by severity and status"""
    logger.info(f"search_vulnerabilities called: severity={severity}, status={status}, limit={limit}")
    try:
        falcon = get_falcon_client(SpotlightVulnerabilities)

        filters = []

        if severity:
            safe_severity = sanitize_fql_value(severity)
            filters.append(f"cve.severity:'{safe_severity.upper()}'")

        if status:
            safe_status = sanitize_fql_value(status)
            filters.append(f"status:'{safe_status}'")

        # Default: last 30 days of vulns
        time_ago = datetime.now(tz=timezone.utc) - timedelta(days=30)
        filters.append(f"updated_timestamp:>'{time_ago.isoformat()}Z'")

        filter_str = "+".join(filters) if filters else f"updated_timestamp:>'{time_ago.isoformat()}Z'"

        response = falcon.query_vulnerabilities(filter=filter_str, limit=limit)

        if response["status_code"] != 200:
            return json.dumps({"error": f"Query failed: {response['body'].get('errors', 'Unknown')}"})

        vuln_ids = response["body"]["resources"]

        if not vuln_ids:
            return json.dumps({"total_found": 0, "query_filter": filter_str, "vulnerabilities": []})

        details = falcon.get_vulnerabilities(ids=vuln_ids)

        if details["status_code"] != 200:
            return json.dumps({"error": f"Details failed: {details['body'].get('errors', 'Unknown')}"})

        vulns = details["body"]["resources"]

        results = {
            "total_found": len(vulns),
            "query_filter": filter_str,
            "vulnerabilities": []
        }

        for vuln in vulns[:limit]:
            cve_info = vuln.get("cve", {})
            host_info = vuln.get("host_info", {})

            results["vulnerabilities"].append({
                "id": vuln.get("id", "N/A"),
                "cve_id": cve_info.get("id", "N/A"),
                "severity": cve_info.get("severity", "N/A"),
                "base_score": cve_info.get("base_score", "N/A"),
                "description": (cve_info.get("description", "N/A") or "N/A")[:200],
                "exploitability": cve_info.get("exploitability_score", "N/A"),
                "hostname": host_info.get("hostname", "N/A"),
                "os_version": host_info.get("os_version", "N/A"),
                "status": vuln.get("status", "N/A"),
                "created": vuln.get("created_timestamp", "N/A"),
                "app_name": vuln.get("app", {}).get("product_name_version", "N/A")
            })

        return json.dumps(results, indent=2)

    except Exception as e:
        logger.error(f"search_vulnerabilities failed: {e}", exc_info=True)
        return json.dumps({"error": str(e), "tool": "search_vulnerabilities", "status": "error"})

async def search_threatgraph(indicator_type: str = None, indicator_value: str = None, vertex_type: str = None, vertex_id: str = None, scope: str = "device", limit: int = 50) -> str:
    """Search CrowdStrike ThreatGraph for IOC activity or vertex details.

    Two modes:
      1. IOC lookup: provide indicator_type + indicator_value to find devices that
         communicated with a domain, IP, or ran a specific hash.
      2. Vertex lookup: provide vertex_type + vertex_id to get a vertex summary.
    """
    logger.info(f"search_threatgraph called: indicator_type={indicator_type}, indicator_value={indicator_value}, vertex_type={vertex_type}, vertex_id={vertex_id}")
    try:
        falcon = get_falcon_client(ThreatGraph)

        # Mode 1: IOC ran-on lookup
        if indicator_type and indicator_value:
            response = falcon.combined_ran_on_get(
                type=indicator_type,
                value=indicator_value,
                limit=limit
            )

            if response["status_code"] != 200:
                return json.dumps({"error": f"Query failed: {response['body'].get('errors', 'Unknown')}"})

            resources = response["body"].get("resources", [])

            results = {
                "query_type": "ioc_lookup",
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "total_found": len(resources),
                "devices": []
            }

            for r in resources[:limit]:
                results["devices"].append({
                    "device_id": r.get("device_id", "N/A"),
                    "object_id": r.get("object_id", "N/A"),
                    "edge_type": r.get("edge_type", "N/A"),
                    "direction": r.get("direction", "N/A"),
                    "scope": r.get("scope", "N/A"),
                    "timestamp": r.get("timestamp", "N/A")
                })

            return json.dumps(results, indent=2)

        # Mode 2: Vertex summary
        elif vertex_type and vertex_id:
            response = falcon.combined_summary_get(
                ids=vertex_id,
                vertex_type=vertex_type,
                scope=scope
            )

            if response["status_code"] != 200:
                return json.dumps({"error": f"Query failed: {response['body'].get('errors', 'Unknown')}"})

            resources = response["body"].get("resources", [])

            results = {
                "query_type": "vertex_summary",
                "vertex_type": vertex_type,
                "vertex_id": vertex_id,
                "total_found": len(resources),
                "vertices": []
            }

            for v in resources[:limit]:
                results["vertices"].append({
                    "id": v.get("id", "N/A"),
                    "vertex_type": v.get("vertex_type", vertex_type),
                    "scope": v.get("scope", "N/A"),
                    "timestamp": v.get("timestamp", "N/A"),
                    "properties": v.get("properties", {})
                })

            return json.dumps(results, indent=2)

        # Mode 3: List edge types (no params)
        else:
            response = falcon.get_edge_types()

            if response["status_code"] != 200:
                return json.dumps({"error": f"Query failed: {response['body'].get('errors', 'Unknown')}"})

            edge_types = response["body"].get("resources", [])

            return json.dumps({
                "query_type": "edge_types",
                "total_edge_types": len(edge_types),
                "edge_types": edge_types,
                "usage_hint": "Use indicator_type + indicator_value to look up IOC activity, "
                              "or vertex_type + vertex_id for vertex details."
            }, indent=2)

    except Exception as e:
        logger.error(f"search_threatgraph failed: {e}", exc_info=True)
        return json.dumps({"error": str(e), "tool": "search_threatgraph", "status": "error"})

async def get_security_posture(hours: int = 24) -> str:
    """Get executive security posture overview across all data sources"""
    logger.info(f"get_security_posture called: hours={hours}")
    posture = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat() + "Z",
        "lookback_hours": hours,
        "alerts": {"total": 0, "by_severity": {}, "by_tactic": {}, "by_time_bucket": {}, "tactic_timeline": [], "error": None},
        "cases": {"total": 0, "by_status": {}, "error": None},
        "detections": {"total": 0, "by_severity": {}, "error": None},
        "vulnerabilities": {"total": 0, "by_severity": {}, "error": None},
        "hosts": {"total": 0, "by_platform": {}, "stale_count": 0, "contained_count": 0, "error": None},
        "subscriptions": [],
        "crowdscore": {"current": None, "trend_7d": [], "error": None},
        "mttd_mttr": {"avg_seconds_to_triaged": None, "avg_seconds_to_resolved": None, "sample_size": 0, "error": None},
        "incidents": {"total": 0, "by_state": {}, "by_tactic": {}, "error": None},
        "sensor_health": {"rfm_count": 0, "total_managed": 0, "coverage_pct": None, "by_version": {}, "error": None},
        "asset_inventory": {"managed_hosts": 0, "unmanaged_hosts": 0, "iot_assets": 0, "accounts": 0, "applications": 0, "error": None},
        "external_attack_surface": {"total_assets": 0, "error": None},
        "api_scopes": [],
        "missing_scopes": []
    }

    time_ago = datetime.now(tz=timezone.utc) - timedelta(hours=hours)

    # --- Run all data-fetching sections in parallel via thread pool ---
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _fetch_alerts():
        try:
            falcon_alerts = get_falcon_client(Alerts)
            now_utc = datetime.now(tz=timezone.utc)
            result = {"by_severity": {}, "total": 0, "by_time_bucket": {}, "by_tactic": {}, "tactic_timeline": [],
                       "first_party": 0, "third_party": 0, "by_source": {}, "error": None}
            for sev in ["Critical", "High", "Medium", "Low"]:
                fql = f"severity_name:'{sev}'+created_timestamp:>'{time_ago.isoformat()}Z'"
                resp = falcon_alerts.query_alerts(filter=fql, limit=1)
                if resp["status_code"] == 200:
                    count = resp["body"].get("meta", {}).get("pagination", {}).get("total", len(resp["body"].get("resources", [])))
                    result["by_severity"][sev] = count
                    result["total"] += count
            for bucket_hours in [1, 4, 8, 24]:
                bucket_ago = now_utc - timedelta(hours=bucket_hours)
                fql = f"created_timestamp:>'{bucket_ago.isoformat()}Z'"
                resp = falcon_alerts.query_alerts(filter=fql, limit=1)
                if resp["status_code"] == 200:
                    count = resp["body"].get("meta", {}).get("pagination", {}).get("total", len(resp["body"].get("resources", [])))
                    result["by_time_bucket"][f"last_{bucket_hours}h"] = count
            fql_recent = f"created_timestamp:>'{time_ago.isoformat()}Z'"
            resp = falcon_alerts.query_alerts(filter=fql_recent, limit=100)
            if resp["status_code"] == 200:
                alert_ids = resp["body"].get("resources", [])
                if alert_ids:
                    detail_resp = falcon_alerts.get_alerts(ids=alert_ids[:100])
                    if detail_resp["status_code"] == 200:
                        tactic_counts = {}
                        for alert in detail_resp["body"].get("resources", []):
                            tactic = alert.get("tactic", "Unknown")
                            if tactic:
                                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                            ts = alert.get("created_timestamp") or alert.get("updated_timestamp", "")
                            if tactic and ts:
                                result["tactic_timeline"].append({
                                    "tactic": tactic,
                                    "timestamp": ts[:19],
                                    "severity": alert.get("severity_name", "Unknown"),
                                })
                            # Track 1P vs 3P
                            product = alert.get("product", "")
                            if product == "thirdparty":
                                _src_products = alert.get("source_products", [])
                                source = _src_products[0] if _src_products else (alert.get("source_vendors", []) or ["Unknown"])[0] or "Unknown"
                                if _is_crowdstrike_source(source):
                                    result["first_party"] += 1
                                else:
                                    result["third_party"] += 1
                                    result["by_source"][source] = result["by_source"].get(source, 0) + 1
                            else:
                                result["first_party"] += 1
                        result["by_tactic"] = dict(
                            sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                        )
            return ("alerts", result)
        except Exception as e:
            logger.error(f"get_security_posture alerts summary failed: {e}", exc_info=True)
            return ("alerts", {"total": 0, "by_severity": {}, "by_tactic": {}, "by_time_bucket": {}, "tactic_timeline": [], "error": str(e)})

    def _fetch_cases():
        try:
            falcon_cases = get_falcon_client(CaseManagement)
            result = {"total": 0, "by_status": {}, "error": None}
            for status_name in ["new", "open", "in_progress", "closed"]:
                fql = f"status:'{status_name}'+created_timestamp:>'{time_ago.isoformat()}Z'"
                resp = falcon_cases.query_case_ids(filter=fql, limit=1)
                if resp["status_code"] == 200:
                    count = resp["body"].get("meta", {}).get("pagination", {}).get("total", len(resp["body"].get("resources", [])))
                    result["by_status"][status_name.replace("_", " ").title()] = count
                    result["total"] += count
            return ("cases", result)
        except Exception as e:
            logger.error(f"get_security_posture cases summary failed: {e}", exc_info=True)
            return ("cases", {"total": 0, "by_status": {}, "error": str(e)})

    def _fetch_detections():
        try:
            falcon_det = get_falcon_client(Alerts)
            result = {"total": 0, "by_severity": {}, "first_party": 0, "third_party": 0,
                      "by_source": {}, "by_product": {}, "error": None}
            # Count by severity across ALL product types
            for sev in ["Critical", "High", "Medium", "Low"]:
                fql = f"severity_name:'{sev}'+created_timestamp:>'{time_ago.isoformat()}Z'"
                resp = falcon_det.query_alerts(filter=fql, limit=1)
                if resp["status_code"] == 200:
                    count = resp["body"].get("meta", {}).get("pagination", {}).get("total", len(resp["body"].get("resources", [])))
                    result["by_severity"][sev] = count
                    result["total"] += count
            # Count by product type
            _product_labels = {
                "epp": "Falcon EDR", "idp": "Identity Protection", "ngsiem": "NGSIEM",
                "cao": "CAO", "thirdparty": "Third-Party", "cspm": "Cloud Security",
                "xdr": "XDR", "fcs": "Cloud Security (FCS)", "data-protection": "Data Protection",
                "mobile": "Mobile", "automated-lead": "Automated Lead",
            }
            _time_fql = f"created_timestamp:>'{time_ago.isoformat()}Z'"
            for prod_code in _product_labels:
                fql_p = f"product:'{prod_code}'+{_time_fql}"
                resp_p = falcon_det.query_alerts(filter=fql_p, limit=1)
                if resp_p["status_code"] == 200:
                    cnt = resp_p["body"].get("meta", {}).get("pagination", {}).get("total", 0)
                    if cnt > 0:
                        result["by_product"][_product_labels[prod_code]] = cnt
            # 3P = thirdparty count; 1P = total - 3P
            result["third_party"] = result["by_product"].get("Third-Party", 0)
            result["first_party"] = max(0, result["total"] - result["third_party"])
            # Get 3rd-party vendor breakdown (sample top 100 to aggregate)
            _fql_3p = f"product:'thirdparty'+{_time_fql}"
            resp_3p_ids = falcon_det.query_alerts(filter=_fql_3p, limit=100)
            if resp_3p_ids["status_code"] == 200:
                ids_3p = resp_3p_ids["body"].get("resources", [])
                if ids_3p:
                    detail_3p = falcon_det.get_alerts(ids=ids_3p[:100])
                    if detail_3p["status_code"] == 200:
                        for a in detail_3p["body"].get("resources", []):
                            _src_products = a.get("source_products", [])
                            source = _src_products[0] if _src_products else (a.get("source_vendors", []) or ["Unknown"])[0] or "Unknown"
                            if not _is_crowdstrike_source(source):
                                result["by_source"][source] = result["by_source"].get(source, 0) + 1
            return ("detections", result)
        except Exception as e:
            logger.error(f"get_security_posture detections summary failed: {e}", exc_info=True)
            return ("detections", {"total": 0, "by_severity": {}, "error": str(e)})

    def _fetch_vulnerabilities():
        try:
            falcon_vulns = get_falcon_client(SpotlightVulnerabilities)
            result = {"total": 0, "by_severity": {}, "error": None}
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                fql = f"cve.severity:'{sev}'+updated_timestamp:>'{time_ago.isoformat()}Z'"
                resp = falcon_vulns.query_vulnerabilities(filter=fql, limit=1)
                if resp["status_code"] == 200:
                    count = resp["body"].get("meta", {}).get("pagination", {}).get("total", len(resp["body"].get("resources", [])))
                    result["by_severity"][sev.capitalize()] = count
                    result["total"] += count
            return ("vulnerabilities", result)
        except Exception as e:
            logger.error(f"get_security_posture vulnerabilities summary failed: {e}", exc_info=True)
            return ("vulnerabilities", {"total": 0, "by_severity": {}, "error": str(e)})

    def _fetch_hosts():
        try:
            falcon_hosts = get_falcon_client(Hosts)
            result = {"total": 0, "by_platform": {}, "stale_count": 0, "contained_count": 0, "error": None}
            resp = falcon_hosts.query_devices_by_filter(limit=1)
            if resp["status_code"] == 200:
                result["total"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            for platform in ["Windows", "Mac", "Linux"]:
                resp = falcon_hosts.query_devices_by_filter(filter=f"platform_name:'{platform}'", limit=1)
                if resp["status_code"] == 200:
                    count = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
                    if count > 0:
                        result["by_platform"][platform] = count
            stale_cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=7)).isoformat() + "Z"
            resp = falcon_hosts.query_devices_by_filter(filter=f"last_seen:<'{stale_cutoff}'", limit=1)
            if resp["status_code"] == 200:
                result["stale_count"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            resp = falcon_hosts.query_devices_by_filter(filter="status:'contained'", limit=1)
            if resp["status_code"] == 200:
                result["contained_count"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            return ("hosts", result)
        except Exception as e:
            logger.error(f"get_security_posture hosts summary failed: {e}", exc_info=True)
            return ("hosts", {"total": 0, "by_platform": {}, "stale_count": 0, "contained_count": 0, "error": str(e)})

    def _fetch_subscriptions():
        try:
            falcon_sub = get_falcon_client(Alerts)
            subs = []
            product_labels = {
                "epp": "Falcon EDR (Endpoint Protection)",
                "idp": "Falcon Identity Protection",
                "ngsiem": "Falcon NGSIEM (Next-Gen SIEM)",
                "cao": "Cloud Automated Orchestration",
                "mobile": "Falcon for Mobile",
                "thirdparty": "Third Party Integrations",
                "cspm": "Cloud Security Posture Mgmt",
                "xdr": "Falcon XDR",
                "fcs": "Falcon Cloud Security",
                "data-protection": "Falcon Data Protection",
                "automated-lead": "Automated Lead",
                "automated-lead-context": "Automated Lead Context",
            }
            for product_code, label in product_labels.items():
                resp = falcon_sub.query_alerts(filter=f"product:'{product_code}'", limit=1)
                if resp["status_code"] == 200:
                    total = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
                    if total > 0:
                        subs.append({"module": label, "status": "Active", "alerts": total})
            svc_checks = [
                ("Hosts / Device Management", lambda: get_falcon_client(Hosts).query_devices(limit=1)),
                ("Spotlight Vulnerabilities", lambda: get_falcon_client(SpotlightVulnerabilities).query_vulnerabilities(filter="cve.severity:'CRITICAL'", limit=1)),
                ("ThreatGraph", lambda: get_falcon_client(ThreatGraph).get_edge_types()),
                ("Cases / Triage", lambda: get_falcon_client(CaseManagement).query_case_ids(limit=1)),
                ("Exposure Management", lambda: get_falcon_client(ExposureManagement).query_external_assets(limit=1)),
            ]
            for svc_name, check_fn in svc_checks:
                try:
                    r = check_fn()
                    if r["status_code"] == 200:
                        subs.append({"module": svc_name, "status": "Active"})
                except Exception:
                    pass
            return ("subscriptions", subs)
        except Exception as e:
            logger.error(f"get_security_posture subscription probe failed: {e}", exc_info=True)
            return ("subscriptions", [])

    def _fetch_crowdscore():
        try:
            falcon_incidents = get_falcon_client(Incidents)
            result = {"current": None, "trend_7d": [], "error": None}
            cs_resp = falcon_incidents.crowdscore(sort="timestamp.desc", limit=168)
            if cs_resp["status_code"] == 200:
                scores = cs_resp["body"].get("resources", [])
                if scores:
                    result["current"] = scores[0].get("score", 0)
                    result["trend_7d"] = [
                        {"timestamp": s.get("timestamp", ""), "score": s.get("score", 0)}
                        for s in scores[:168]
                    ]
            elif cs_resp["status_code"] == 403:
                result["error"] = "403 Forbidden"
            return ("crowdscore", result)
        except Exception as e:
            logger.error(f"get_security_posture crowdscore failed: {e}", exc_info=True)
            return ("crowdscore", {"current": None, "trend_7d": [], "error": str(e)})

    def _fetch_mttd_mttr():
        try:
            falcon_mttd = get_falcon_client(Alerts)
            result = {"avg_seconds_to_triaged": None, "avg_seconds_to_resolved": None, "sample_size": 0, "error": None}
            fql = f"status:'closed'+created_timestamp:>'{time_ago.isoformat()}Z'"
            resp = falcon_mttd.query_alerts(filter=fql, limit=100)
            if resp["status_code"] == 200:
                ids = resp["body"].get("resources", [])
                if ids:
                    details = falcon_mttd.get_alerts(ids=ids[:100])
                    if details["status_code"] == 200:
                        triaged_times = []
                        resolved_times = []
                        for a in details["body"].get("resources", []):
                            t = a.get("seconds_to_triaged")
                            r = a.get("seconds_to_resolved")
                            if t is not None and t > 0:
                                triaged_times.append(t)
                            if r is not None and r > 0:
                                resolved_times.append(r)
                        if triaged_times:
                            result["avg_seconds_to_triaged"] = sum(triaged_times) // len(triaged_times)
                        if resolved_times:
                            result["avg_seconds_to_resolved"] = sum(resolved_times) // len(resolved_times)
                        result["sample_size"] = max(len(triaged_times), len(resolved_times))
            return ("mttd_mttr", result)
        except Exception as e:
            logger.error(f"get_security_posture mttd/mttr failed: {e}", exc_info=True)
            return ("mttd_mttr", {"avg_seconds_to_triaged": None, "avg_seconds_to_resolved": None, "sample_size": 0, "error": str(e)})

    def _fetch_incidents():
        try:
            falcon_inc = get_falcon_client(Incidents)
            result = {"total": 0, "by_state": {}, "by_tactic": {}, "error": None}
            fql = f"start:>'{time_ago.isoformat()}Z'"
            resp = falcon_inc.query_incidents(filter=fql, limit=1)
            if resp["status_code"] == 200:
                result["total"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
                for state in ["open", "closed", "reopened"]:
                    resp_s = falcon_inc.query_incidents(filter=f"{fql}+status:'{state}'", limit=1)
                    if resp_s["status_code"] == 200:
                        cnt = resp_s["body"].get("meta", {}).get("pagination", {}).get("total", 0)
                        if cnt > 0:
                            result["by_state"][state.title()] = cnt
                resp_ids = falcon_inc.query_incidents(filter=fql, limit=50)
                if resp_ids["status_code"] == 200:
                    inc_ids = resp_ids["body"].get("resources", [])
                    if inc_ids:
                        detail = falcon_inc.get_incidents(ids=inc_ids[:50])
                        if detail["status_code"] == 200:
                            tactic_map = {}
                            for inc in detail["body"].get("resources", []):
                                for t in inc.get("tactics", []):
                                    tactic_map[t] = tactic_map.get(t, 0) + 1
                            result["by_tactic"] = dict(
                                sorted(tactic_map.items(), key=lambda x: x[1], reverse=True)[:5]
                            )
            elif resp["status_code"] == 403:
                result["error"] = "403 Forbidden"
            return ("incidents", result)
        except Exception as e:
            logger.error(f"get_security_posture incidents failed: {e}", exc_info=True)
            return ("incidents", {"total": 0, "by_state": {}, "by_tactic": {}, "error": str(e)})

    def _fetch_sensor_health(host_total):
        try:
            falcon_sh = get_falcon_client(Hosts)
            result = {"rfm_count": 0, "total_managed": host_total, "coverage_pct": None, "by_version": {}, "error": None}
            resp = falcon_sh.query_devices_by_filter(filter="reduced_functionality_mode:'yes'", limit=1)
            if resp["status_code"] == 200:
                result["rfm_count"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            resp = falcon_sh.query_devices_by_filter(limit=200, sort="last_seen.desc")
            if resp["status_code"] == 200:
                ids = resp["body"].get("resources", [])
                if ids:
                    det = falcon_sh.get_device_details(ids=ids[:200])
                    if det["status_code"] == 200:
                        ver_counts = {}
                        for d in det["body"].get("resources", []):
                            v = d.get("agent_version", "Unknown")
                            ver_counts[v] = ver_counts.get(v, 0) + 1
                        result["by_version"] = dict(
                            sorted(ver_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                        )
            return ("sensor_health", result)
        except Exception as e:
            logger.error(f"get_security_posture sensor health failed: {e}", exc_info=True)
            return ("sensor_health", {"rfm_count": 0, "total_managed": 0, "coverage_pct": None, "by_version": {}, "error": str(e)})

    def _fetch_asset_inventory():
        try:
            falcon_disc = get_falcon_client(Discover)
            result = {"managed_hosts": 0, "unmanaged_hosts": 0, "iot_assets": 0, "accounts": 0, "applications": 0, "error": None}
            resp = falcon_disc.query_hosts(filter="entity_type:'managed'", limit=1)
            if resp["status_code"] == 200:
                result["managed_hosts"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            resp = falcon_disc.query_hosts(filter="entity_type:'unmanaged'", limit=1)
            if resp["status_code"] == 200:
                result["unmanaged_hosts"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            resp = falcon_disc.query_iot_hosts(limit=1)
            if resp["status_code"] == 200:
                result["iot_assets"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            resp = falcon_disc.query_accounts(limit=1)
            if resp["status_code"] == 200:
                result["accounts"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            resp = falcon_disc.query_applications(limit=1)
            if resp["status_code"] == 200:
                result["applications"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            return ("asset_inventory", result)
        except Exception as e:
            logger.error(f"get_security_posture asset inventory failed: {e}", exc_info=True)
            return ("asset_inventory", {"managed_hosts": 0, "unmanaged_hosts": 0, "iot_assets": 0, "accounts": 0, "applications": 0, "error": str(e)})

    def _fetch_external_attack_surface():
        try:
            falcon_em = get_falcon_client(ExposureManagement)
            result = {"total_assets": 0, "error": None}
            resp = falcon_em.query_external_assets(limit=1)
            if resp["status_code"] == 200:
                result["total_assets"] = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            elif resp["status_code"] == 403:
                result["error"] = "403 Forbidden"
            return ("external_attack_surface", result)
        except Exception as e:
            logger.error(f"get_security_posture external attack surface failed: {e}", exc_info=True)
            return ("external_attack_surface", {"total_assets": 0, "error": str(e)})

    def _probe_scope(scope_name, dashboard_section, check_fn):
        entry = {"scope": scope_name, "section": dashboard_section, "status": "Unknown"}
        try:
            r = check_fn()
            code = r.get("status_code", 0) if isinstance(r, dict) else 0
            if code == 403:
                entry["status"] = "Missing"
            else:
                entry["status"] = "Active"
        except Exception as e:
            if "403" in str(e):
                entry["status"] = "Missing"
            else:
                entry["status"] = "Error"
        return entry

    # Comprehensive API scope probe — test every scope the CISO dashboard needs
    scope_checks = [
        ("Alerts:read", "Alerts, Detections, MTTD/MTTR",
         lambda: get_falcon_client(Alerts).query_alerts(limit=1)),
        ("Hosts:read", "Host KPIs, Sensor Health",
         lambda: get_falcon_client(Hosts).query_devices_by_filter(limit=1)),
        ("Cases:read", "Cases by Status",
         lambda: get_falcon_client(CaseManagement).query_case_ids(limit=1)),
        ("Spotlight Vulnerabilities:read", "Vulnerability Counts",
         lambda: get_falcon_client(SpotlightVulnerabilities).query_vulnerabilities(filter="cve.severity:'CRITICAL'", limit=1)),
        ("ThreatGraph:read", "IOC Lookups",
         lambda: get_falcon_client(ThreatGraph).get_edge_types()),
        ("Incidents:read", "CrowdScore, Incidents Summary",
         lambda: get_falcon_client(Incidents).query_incidents(limit=1)),
        ("Discover:read", "Asset Inventory",
         lambda: get_falcon_client(Discover).query_hosts(limit=1)),
        ("Exposure Management:read", "External Attack Surface",
         lambda: get_falcon_client(ExposureManagement).query_external_assets(limit=1)),
        ("Zero Trust Assessment:read", "Zero Trust Scores",
         lambda: get_falcon_client(ZeroTrustAssessment).get_assessments_by_score(filter="score:>0", limit=1)),
        ("Sensor Update Policies:read", "Sensor Update Policies",
         lambda: get_falcon_client(SensorUpdatePolicies).query_policies(limit=1)),
        ("Prevention Policies:read", "Prevention Policies",
         lambda: get_falcon_client(PreventionPolicies).query_policies(limit=1)),
        ("NGSIEM:read", "Next-Gen SIEM (LogScale)",
         lambda: get_falcon_client(NGSIEM).list_saved_queries(search_domain="default")),
        ("Identity Protection:read", "Identity Threat Detection",
         lambda: get_falcon_client(IdentityProtection).query_sensors_by_filter(limit=1)),
        ("Cloud Security:read", "Cloud Security Posture (CSPM)",
         lambda: get_falcon_client(CloudSecurity).list_group_ids()),
    ]

    # Run ALL data sections + scope probes in parallel
    with ThreadPoolExecutor(max_workers=12) as executor:
        # Submit all data fetch tasks
        data_futures = [
            executor.submit(_fetch_alerts),
            executor.submit(_fetch_cases),
            executor.submit(_fetch_detections),
            executor.submit(_fetch_vulnerabilities),
            executor.submit(_fetch_hosts),
            executor.submit(_fetch_subscriptions),
            executor.submit(_fetch_crowdscore),
            executor.submit(_fetch_mttd_mttr),
            executor.submit(_fetch_incidents),
            executor.submit(_fetch_asset_inventory),
            executor.submit(_fetch_external_attack_surface),
        ]
        # Submit all scope probes
        scope_futures = [
            executor.submit(_probe_scope, sn, ds, fn)
            for sn, ds, fn in scope_checks
        ]

        # Collect data results
        for future in as_completed(data_futures):
            try:
                key, value = future.result()
                if key == "subscriptions":
                    posture[key] = value
                else:
                    posture[key] = value
            except Exception as e:
                logger.error(f"get_security_posture parallel fetch error: {e}", exc_info=True)

        # Collect scope results
        for future in as_completed(scope_futures):
            try:
                entry = future.result()
                posture["api_scopes"].append(entry)
                if entry["status"] == "Missing":
                    posture["missing_scopes"].append(entry["scope"])
            except Exception as e:
                logger.error(f"get_security_posture scope probe error: {e}", exc_info=True)

    # Sensor health needs host total — run after hosts are collected
    try:
        sh_key, sh_val = _fetch_sensor_health(posture["hosts"]["total"])
        posture["sensor_health"] = sh_val
    except Exception as e:
        logger.error(f"get_security_posture sensor health failed: {e}", exc_info=True)

    # Calculate overall risk score (simple weighted)
    critical_count = (
        posture["alerts"]["by_severity"].get("Critical", 0) +
        posture["detections"]["by_severity"].get("Critical", 0) +
        posture["vulnerabilities"]["by_severity"].get("Critical", 0)
    )
    high_count = (
        posture["alerts"]["by_severity"].get("High", 0) +
        posture["detections"]["by_severity"].get("High", 0) +
        posture["vulnerabilities"]["by_severity"].get("High", 0)
    )

    # Weighted risk score: considers all severity levels and data sources
    medium_count = (
        posture["alerts"]["by_severity"].get("Medium", 0) +
        posture["detections"]["by_severity"].get("Medium", 0) +
        posture["vulnerabilities"]["by_severity"].get("Medium", 0)
    )
    low_count = (
        posture["alerts"]["by_severity"].get("Low", 0) +
        posture["detections"]["by_severity"].get("Low", 0) +
        posture["vulnerabilities"]["by_severity"].get("Low", 0)
    )
    # Weighted formula with diminishing returns
    raw_score = (critical_count * 15) + (high_count * 8) + (medium_count * 3) + (low_count * 1)
    risk_score = min(100, int(100 * (1 - (1 / (1 + raw_score / 20)))))  # Sigmoid-like scaling
    posture["risk_score"] = risk_score
    posture["risk_level"] = (
        "Critical" if risk_score >= 75 else
        "High" if risk_score >= 50 else
        "Medium" if risk_score >= 25 else
        "Low"
    )

    # Use CrowdScore as primary risk if available and non-zero, fallback to computed score
    if posture["crowdscore"]["current"] is not None and posture["crowdscore"]["current"] > 0:
        posture["risk_score"] = posture["crowdscore"]["current"]
        cs = posture["crowdscore"]["current"]
        posture["risk_level"] = (
            "Critical" if cs >= 75 else "High" if cs >= 50 else "Medium" if cs >= 25 else "Low"
        )

    return json.dumps(posture, indent=2)


async def get_ngsiem_ingestion(hours: int = 24) -> str:
    """Query NGSIEM/LogScale data ingestion volume and top sources.

    Supports both single-CID and MSSP parent-CID (FlightControl) modes.
    """
    logger.info(f"get_ngsiem_ingestion called: hours={hours}")

    result = {
        "total_bytes": 0,
        "total_events": 0,
        "sources": [],
        "is_mssp": False,
        "children": [],
        "error": None,
    }

    logscale_query = "* | eventSize() | groupBy(#Vendor, function=[sum(_eventSize), count()])"
    start_str = f"{hours}h"
    # Query the xdr view (superset of third-party) for complete ingestion data.
    # Note: eventSize() measures stored event size which is ~70-80% of raw ingest
    # volume shown on Falcon's Data Ingestion page.
    ngsiem_repo = os.getenv("NGSIEM_REPOSITORY", "xdr")

    # --- Detect MSSP parent ---
    is_mssp = False
    child_cids = []
    child_names = {}

    try:
        fc = get_falcon_client(FlightControl)
        fc_resp = fc.query_children(limit=1000)
        fc_code = fc_resp.get("status_code", 0) if isinstance(fc_resp, dict) else 0
        if fc_code == 200:
            resources = fc_resp.get("body", {}).get("resources", [])
            if resources:
                is_mssp = True
                child_cids = resources[:20]  # cap at 20
                # Resolve child names
                try:
                    names_resp = fc.get_children(ids=child_cids)
                    if isinstance(names_resp, dict) and names_resp.get("status_code") == 200:
                        for child in names_resp.get("body", {}).get("resources", []):
                            cid = child.get("child_cid", "")
                            name = child.get("name", cid)
                            child_names[cid] = name
                except Exception:
                    pass
    except Exception:
        pass  # Not MSSP or FlightControl unavailable — fall through to single CID

    result["is_mssp"] = is_mssp

    # --- Aggregate source map ---
    source_map = {}  # source_name -> {"events": int, "bytes": int}

    if is_mssp:
        # Query each child CID's NGSIEM in parallel via asyncio.to_thread
        async def query_child(child_cid: str) -> dict:
            child_entry = {
                "cid": child_cid,
                "name": child_names.get(child_cid, child_cid),
                "total_bytes": 0,
                "total_events": 0,
                "error": None,
            }
            try:
                child_ngsiem = NGSIEM(
                    client_id=os.getenv("FALCON_CLIENT_ID"),
                    client_secret=os.getenv("FALCON_CLIENT_SECRET"),
                    base_url=os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com"),
                    member_cid=child_cid,
                    user_agent="falcon-digest/1.0.0",
                )
                qr = await asyncio.to_thread(
                    _run_ngsiem_query, child_ngsiem, logscale_query, start_str,
                    repository=ngsiem_repo, timeout_sec=15
                )
                if qr["error"]:
                    child_entry["error"] = qr["error"]
                for ev in qr["events"]:
                    src = ev.get("#Vendor", ev.get("#type", "unknown"))
                    ev_count = int(ev.get("_count", 0))
                    ev_bytes = int(ev.get("_sum", 0))
                    child_entry["total_events"] += ev_count
                    child_entry["total_bytes"] += ev_bytes
                    if src not in source_map:
                        source_map[src] = {"events": 0, "bytes": 0}
                    source_map[src]["events"] += ev_count
                    source_map[src]["bytes"] += ev_bytes
            except Exception as e:
                child_entry["error"] = str(e)
            return child_entry

        child_results = await asyncio.gather(
            *(query_child(cid) for cid in child_cids),
            return_exceptions=True,
        )
        for cr in child_results:
            if isinstance(cr, Exception):
                result["children"].append({
                    "cid": "unknown", "name": "unknown",
                    "total_bytes": 0, "total_events": 0, "error": str(cr),
                })
            else:
                result["children"].append(cr)
                result["total_bytes"] += cr["total_bytes"]
                result["total_events"] += cr["total_events"]

        # If ALL child queries failed (e.g. 403 scope), fall back to parent CID's own NGSIEM
        all_failed = all(c.get("error") for c in result["children"]) if result["children"] else False
        if all_failed and not source_map:
            logger.info("All MSSP child queries failed — falling back to parent CID NGSIEM")
            try:
                ngsiem = get_falcon_client(NGSIEM)
                qr = await asyncio.to_thread(
                    _run_ngsiem_query, ngsiem, logscale_query, start_str,
                    repository=ngsiem_repo
                )
                if qr["error"]:
                    result["error"] = qr["error"]
                else:
                    result["error"] = "MSSP child queries failed (scope not permitted); showing parent CID data"
                for ev in qr["events"]:
                    src = ev.get("#Vendor", ev.get("#type", "unknown"))
                    ev_count = int(ev.get("_count", 0))
                    ev_bytes = int(ev.get("_sum", 0))
                    result["total_events"] += ev_count
                    result["total_bytes"] += ev_bytes
                    if src not in source_map:
                        source_map[src] = {"events": 0, "bytes": 0}
                    source_map[src]["events"] += ev_count
                    source_map[src]["bytes"] += ev_bytes
            except Exception as e:
                result["error"] = f"MSSP child queries failed; parent fallback also failed: {e}"

    else:
        # Single CID mode
        try:
            ngsiem = get_falcon_client(NGSIEM)
            qr = await asyncio.to_thread(
                _run_ngsiem_query, ngsiem, logscale_query, start_str,
                repository=ngsiem_repo
            )
            if qr["error"]:
                result["error"] = qr["error"]
            for ev in qr["events"]:
                src = ev.get("#Vendor", ev.get("#type", "unknown"))
                ev_count = int(ev.get("_count", 0))
                ev_bytes = int(ev.get("_sum", 0))
                result["total_events"] += ev_count
                result["total_bytes"] += ev_bytes
                if src not in source_map:
                    source_map[src] = {"events": 0, "bytes": 0}
                source_map[src]["events"] += ev_count
                source_map[src]["bytes"] += ev_bytes
        except Exception as e:
            result["error"] = str(e)

    # Build sorted top sources
    sorted_sources = sorted(source_map.items(), key=lambda x: x[1]["bytes"], reverse=True)[:10]
    result["sources"] = [
        {"name": name, "events": vals["events"], "bytes": vals["bytes"]}
        for name, vals in sorted_sources
    ]

    # Flag partial errors in MSSP mode
    if is_mssp:
        errored = [c for c in result["children"] if c.get("error")]
        if errored and not result["error"]:
            result["error"] = f"{len(errored)} of {len(result['children'])} child queries had errors"

    return json.dumps(result, indent=2)


# ============ IDENTITY PROTECTION ============

async def get_identity_protection(limit: int = 50) -> str:
    """Get Identity Protection overview: sensor counts, entity types, and top risky identities."""
    result = await asyncio.to_thread(_get_identity_protection_sync, limit)
    return json.dumps(result, indent=2)


def _get_identity_protection_sync(limit: int) -> dict:
    result = {
        "total_sensors": 0,
        "by_status": {},
        "by_os": {},
        "risky_entities": [],
        "total_risky": 0,
        "error": None,
    }

    try:
        falcon_idp = get_falcon_client(IdentityProtection)
    except Exception as e:
        result["error"] = f"Failed to initialize Identity Protection client: {e}"
        return result

    # 1. Sensor count
    try:
        resp = falcon_idp.query_sensors_by_filter(limit=1)
        if resp["status_code"] == 403:
            result["error"] = "Identity Protection scope not available (403 Forbidden)"
            return result
        if resp["status_code"] == 200:
            result["total_sensors"] = resp.get("body", resp).get("meta", {}).get("pagination", {}).get("total", 0)
    except Exception as e:
        if "403" in str(e):
            result["error"] = "Identity Protection scope not available (403 Forbidden)"
            return result
        logger.error(f"Identity Protection sensor query failed: {e}", exc_info=True)

    # 2. Sensor status and OS aggregation
    agg_specs = [
        ("status", "by_status"),
        ("os_version", "by_os"),
    ]
    for agg_field, result_key in agg_specs:
        try:
            agg_resp = falcon_idp.get_sensor_aggregates(body=[{
                "name": result_key,
                "field": agg_field,
                "type": "terms",
                "size": 10,
            }])
            if agg_resp.get("status_code", 0) == 200:
                body = agg_resp.get("body", agg_resp)
                for agg in body.get("resources", []):
                    for bucket in agg.get("buckets", []):
                        key = bucket.get("label", bucket.get("key", "unknown"))
                        # Clean up status labels (e.g., "status.active" -> "Active")
                        if agg_field == "status" and "." in key:
                            key = key.split(".")[-1].replace("-", " ").title()
                        result[result_key][key] = bucket.get("count", bucket.get("doc_count", 0))
        except Exception as e:
            logger.warning(f"Identity Protection {agg_field} aggregation failed: {e}")

    # 3. GraphQL: top risky entities
    try:
        # Try extended query with AD account info first
        gql_query_extended = """{
  entities(first: %d, sortKey: RISK_SCORE, sortOrder: DESCENDING) {
    nodes {
      primaryDisplayName
      entityId
      riskScore
      riskFactors { type severity }
      secondaryDisplayName
      emailAddresses
      type
      accounts { ... on ActiveDirectoryAccountDescriptor { domain department jobTitle } }
      roles
      hasRole(type: ADMIN)
    }
    pageInfo { hasNextPage endCursor }
  }
}""" % min(limit, 100)

        gql_query_basic = """{
  entities(first: %d, sortKey: RISK_SCORE, sortOrder: DESCENDING) {
    nodes {
      primaryDisplayName
      entityId
      riskScore
      riskFactors { type severity }
      secondaryDisplayName
      emailAddresses
      type
    }
    pageInfo { hasNextPage endCursor }
  }
}""" % min(limit, 100)

        # Try extended first, fall back to basic if schema doesn't support it
        gql_resp = falcon_idp.graphql(body={"query": gql_query_extended})
        status = gql_resp.get("status_code", 0)
        _body = gql_resp.get("body", gql_resp)
        _has_errors = bool(_body.get("errors")) if isinstance(_body, dict) else False
        if status != 200 or _has_errors:
            logger.info("Extended IDP GraphQL query unsupported, falling back to basic query")
            gql_resp = falcon_idp.graphql(body={"query": gql_query_basic})
            status = gql_resp.get("status_code", 0)
        if status == 200:
            body = gql_resp.get("body", gql_resp)
            entities_data = body.get("resources", body)
            # Navigate GraphQL response
            if isinstance(entities_data, dict):
                nodes = entities_data.get("entities", {}).get("nodes", [])
            elif isinstance(entities_data, list) and entities_data:
                nodes = entities_data[0].get("entities", {}).get("nodes", []) if isinstance(entities_data[0], dict) else []
            else:
                nodes = []

            for node in nodes:
                risk_score = node.get("riskScore", 0)
                if risk_score and risk_score > 0:
                    result["total_risky"] += 1
                emails = node.get("emailAddresses", [])
                # Extract AD account info if available
                accounts = node.get("accounts", [])
                domain = ""
                department = ""
                job_title = ""
                for acct in (accounts or []):
                    if isinstance(acct, dict):
                        domain = acct.get("domain", "") or domain
                        department = acct.get("department", "") or department
                        job_title = acct.get("jobTitle", "") or job_title
                result["risky_entities"].append({
                    "display_name": node.get("primaryDisplayName", node.get("secondaryDisplayName", "N/A")),
                    "entity_id": node.get("entityId", ""),
                    "risk_score": risk_score or 0,
                    "type": node.get("type", "unknown"),
                    "email": emails[0] if emails else "",
                    "risk_factors": node.get("riskFactors", []),
                    "domain": domain,
                    "department": department,
                    "job_title": job_title,
                    "is_admin": bool(node.get("hasRole")),
                    "roles": node.get("roles", []) or [],
                })
        elif status == 403:
            logger.warning("Identity Protection GraphQL returned 403")
        else:
            logger.warning(f"Identity Protection GraphQL returned {status}")
    except Exception as e:
        logger.warning(f"Identity Protection GraphQL query failed: {e}")

    return result


# ============ CLOUD SECURITY ============

async def get_cloud_security(severity: str = None, cloud_provider: str = None, limit: int = 200) -> str:
    """Get Cloud Security posture: risk findings by severity, cloud provider, and service category."""
    result = await asyncio.to_thread(_get_cloud_security_sync, severity, cloud_provider, limit)
    return json.dumps(result, indent=2)


def _get_cloud_security_sync(severity: str, cloud_provider: str, limit: int) -> dict:
    result = {
        "total_risks": 0,
        "risks_by_severity": {},
        "risks_by_provider": {},
        "risks_by_service": {},
        "top_risks": [],
        "iom_count": None,
        "error": None,
    }

    try:
        falcon_cs = get_falcon_client(CloudSecurity)
    except Exception as e:
        result["error"] = f"Failed to initialize Cloud Security client: {e}"
        return result

    # Build FQL filter
    filters = []
    if severity:
        filters.append(f"severity:'{severity}'")
    if cloud_provider:
        filters.append(f"cloud_provider:'{cloud_provider}'")
    fql_filter = " + ".join(filters) if filters else None

    # 1. Combined cloud risks
    try:
        kwargs = {"limit": min(limit, 1000), "sort": "severity|desc"}
        if fql_filter:
            kwargs["filter"] = fql_filter
        resp = falcon_cs.combined_cloud_risks(**kwargs)

        if resp["status_code"] == 403:
            result["error"] = "Cloud Security scope not available (403 Forbidden)"
            return result

        if resp["status_code"] == 200:
            body = resp.get("body", resp)
            resources = body.get("resources", [])
            result["total_risks"] = body.get("meta", {}).get("pagination", {}).get("total", len(resources))

            # Client-side aggregation
            for r in resources:
                sev = r.get("severity", "Unknown")
                result["risks_by_severity"][sev] = result["risks_by_severity"].get(sev, 0) + 1

                provider = r.get("cloud_provider", "Unknown")
                result["risks_by_provider"][provider] = result["risks_by_provider"].get(provider, 0) + 1

                svc = r.get("service_category", "Unknown")
                result["risks_by_service"][svc] = result["risks_by_service"].get(svc, 0) + 1

            # Top risks for table
            for r in resources[:50]:
                result["top_risks"].append({
                    "severity": r.get("severity", ""),
                    "status": r.get("status", ""),
                    "cloud_provider": r.get("cloud_provider", ""),
                    "service_category": r.get("service_category", ""),
                    "asset_type": r.get("asset_type", ""),
                    "rule_name": r.get("rule_name", ""),
                    "account_name": r.get("account_name", ""),
                })
        else:
            result["error"] = f"Cloud Security API returned {resp['status_code']}"
    except Exception as e:
        result["error"] = f"Cloud Security query failed: {e}"
        logger.error(f"Cloud Security combined_cloud_risks failed: {e}", exc_info=True)

    # 2. IOM count (optional — separate service class)
    if CloudSecurityDetections is not None:
        try:
            falcon_csd = get_falcon_client(CloudSecurityDetections)
            iom_resp = falcon_csd.query_iom_entities(limit=1)
            if iom_resp.get("status_code", 0) == 200:
                result["iom_count"] = iom_resp.get("body", iom_resp).get("meta", {}).get("pagination", {}).get("total", 0)
        except Exception as e:
            logger.warning(f"Cloud Security IOM query failed: {e}")

    return result


# ============ EXPOSURE MANAGEMENT ============

async def get_exposure_management(limit: int = 100) -> str:
    """Get External Attack Surface Management overview: assets by criticality, type, triage status, and cloud provider."""
    result = await asyncio.to_thread(_get_exposure_management_sync, limit)
    return json.dumps(result, indent=2)


def _get_exposure_management_sync(limit: int) -> dict:
    result = {
        "total_assets": 0,
        "by_criticality": {},
        "by_asset_type": {},
        "by_triage_status": {},
        "by_cloud_provider": {},
        "assets": [],
        "error": None,
    }

    try:
        falcon_em = get_falcon_client(ExposureManagement)
    except Exception as e:
        result["error"] = f"Failed to initialize Exposure Management client: {e}"
        return result

    # 1. Total assets count
    try:
        resp = falcon_em.query_external_assets(limit=1)
        if resp["status_code"] == 403:
            result["error"] = "Exposure Management scope not available (403 Forbidden)"
            return result
        if resp["status_code"] == 200:
            result["total_assets"] = resp.get("body", resp).get("meta", {}).get("pagination", {}).get("total", 0)
    except Exception as e:
        if "403" in str(e):
            result["error"] = "Exposure Management scope not available (403 Forbidden)"
            return result
        logger.error(f"Exposure Management query failed: {e}", exc_info=True)

    # 2. Aggregations
    agg_fields = [
        ("criticality", "by_criticality"),
        ("asset_type", "by_asset_type"),
        ("triage.status", "by_triage_status"),
        ("cloud_provider", "by_cloud_provider"),
    ]

    use_aggregation_api = True
    for field_name, result_key in agg_fields:
        try:
            agg_resp = falcon_em.aggregate_external_assets(body=[{
                "name": result_key,
                "field": field_name,
                "type": "terms",
                "size": 20,
            }])
            if agg_resp.get("status_code", 0) == 200:
                body = agg_resp.get("body", agg_resp)
                for agg in body.get("resources", []):
                    for bucket in agg.get("buckets", []):
                        key = bucket.get("label", bucket.get("key", "unknown"))
                        result[result_key][key] = bucket.get("count", bucket.get("doc_count", 0))
            else:
                use_aggregation_api = False
                break
        except Exception as e:
            logger.warning(f"Exposure Management aggregation for {field_name} failed: {e}")
            use_aggregation_api = False
            break

    # 3. Top assets list
    try:
        query_resp = falcon_em.query_external_assets(limit=min(limit, 100), sort="criticality|desc")
        if query_resp.get("status_code", 0) == 200:
            body = query_resp.get("body", query_resp)
            asset_ids = body.get("resources", [])

            if asset_ids:
                detail_resp = falcon_em.get_external_assets(ids=asset_ids[:100])
                if detail_resp.get("status_code", 0) == 200:
                    detail_body = detail_resp.get("body", detail_resp)
                    for asset in detail_body.get("resources", []):
                        # Extract services list
                        services = []
                        ip_data = asset.get("ip", {})
                        dns_data = asset.get("dns_domain", {})
                        for svc in ip_data.get("services", []) + dns_data.get("services", []):
                            port = svc.get("port", "")
                            if port:
                                services.append(str(port))

                        # Get asset name
                        name = asset.get("asset_id", "")
                        if dns_data.get("fqdn"):
                            name = dns_data["fqdn"]
                        elif ip_data.get("ip_address"):
                            name = ip_data["ip_address"]

                        result["assets"].append({
                            "asset_id": asset.get("id", ""),
                            "asset_type": asset.get("asset_type", ""),
                            "name": name,
                            "criticality": asset.get("criticality", "Unassigned"),
                            "triage_status": asset.get("triage", {}).get("status", ""),
                            "cloud_provider": ip_data.get("cloud_provider", ""),
                            "services": services[:10],
                            "country": ip_data.get("location", {}).get("country_code", ""),
                            "discovery_date": asset.get("first_seen", "")[:10] if asset.get("first_seen") else "",
                        })

                        # If aggregation API failed, compute client-side
                        if not use_aggregation_api:
                            crit = asset.get("criticality", "Unassigned")
                            result["by_criticality"][crit] = result["by_criticality"].get(crit, 0) + 1
                            atype = asset.get("asset_type", "unknown")
                            result["by_asset_type"][atype] = result["by_asset_type"].get(atype, 0) + 1
                            tstatus = asset.get("triage", {}).get("status", "unknown")
                            result["by_triage_status"][tstatus] = result["by_triage_status"].get(tstatus, 0) + 1
                            cprov = ip_data.get("cloud_provider", "")
                            if cprov:
                                result["by_cloud_provider"][cprov] = result["by_cloud_provider"].get(cprov, 0) + 1
    except Exception as e:
        logger.error(f"Exposure Management asset details failed: {e}", exc_info=True)

    return result


# ============ MCP PROTOCOL HANDLERS ============

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """List available tools"""
    return [
        Tool(
            name="search_alerts",
            description="Search CrowdStrike alerts (including CAO detections)",
            inputSchema={
                "type": "object",
                "properties": {
                    "product": {
                        "type": "string",
                        "description": "Product type (epp, thirdparty, idp, ngsiem, cao, xdr, fcs, data-protection, mobile, cspm)",
                        "default": "cao"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (Critical, High, Medium, Low)",
                    },
                    "hours": {
                        "type": "number",
                        "description": "Look back period in hours",
                        "default": 24
                    },
                    "limit": {
                        "type": "number",
                        "description": "Max results to return",
                        "default": 50
                    }
                }
            }
        ),
        Tool(
            name="get_host_details",
            description="Get detailed information about a specific host",
            inputSchema={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Hostname to search for"
                    }
                },
                "required": ["hostname"]
            }
        ),
        Tool(
            name="test_fql_filter",
            description="Test and validate an FQL filter string",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter_string": {
                        "type": "string",
                        "description": "FQL filter to validate"
                    }
                },
                "required": ["filter_string"]
            }
        ),
        Tool(
            name="list_available_products",
            description="List available product types for filtering alerts",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="search_cases",
            description="Search CrowdStrike cases by status, severity, and time range",
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "description": "Filter by status (new, open, in_progress, reopened, closed)"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (critical, high, medium, low)"
                    },
                    "hours": {
                        "type": "number",
                        "description": "Look back period in hours",
                        "default": 72
                    },
                    "limit": {
                        "type": "number",
                        "description": "Max results to return",
                        "default": 50
                    }
                }
            }
        ),
        Tool(
            name="search_detections",
            description="Search endpoint detections (EPP alerts) by severity, status, and time range",
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (Critical, High, Medium, Low)"
                    },
                    "status": {
                        "type": "string",
                        "description": "Filter by status (new, in_progress, true_positive, false_positive, closed)"
                    },
                    "hours": {
                        "type": "number",
                        "description": "Look back period in hours",
                        "default": 24
                    },
                    "limit": {
                        "type": "number",
                        "description": "Max results to return",
                        "default": 50
                    }
                }
            }
        ),
        Tool(
            name="search_vulnerabilities",
            description="Search Spotlight vulnerabilities by severity and remediation status",
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "Filter by CVE severity (critical, high, medium, low)"
                    },
                    "status": {
                        "type": "string",
                        "description": "Filter by remediation status (open, closed)"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Max results to return",
                        "default": 50
                    }
                }
            }
        ),
        Tool(
            name="search_threatgraph",
            description="Search CrowdStrike ThreatGraph - look up IOC activity on devices (domains, IPs, hashes) or get vertex summaries. Call with no args to list edge types.",
            inputSchema={
                "type": "object",
                "properties": {
                    "indicator_type": {
                        "type": "string",
                        "description": "IOC type for ran-on lookup (domain, ipv4, ipv6, md5, sha1, sha256)"
                    },
                    "indicator_value": {
                        "type": "string",
                        "description": "IOC value to search for (e.g. 'evil.com', '1.2.3.4', hash)"
                    },
                    "vertex_type": {
                        "type": "string",
                        "description": "Vertex type for summary lookup (e.g. device, incident, indicator, user, process)"
                    },
                    "vertex_id": {
                        "type": "string",
                        "description": "Vertex ID to get summary for"
                    },
                    "scope": {
                        "type": "string",
                        "description": "Scope of request (device, customer, global, cspm, cwpp)",
                        "default": "device"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Max results to return",
                        "default": 50
                    }
                }
            }
        ),
        Tool(
            name="get_security_posture",
            description="Get executive security posture overview with counts and severity breakdown across alerts, cases, detections, and vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "number",
                        "description": "Look back period in hours",
                        "default": 24
                    }
                }
            }
        ),
        Tool(
            name="search_hosts",
            description="Search and count CrowdStrike hosts/devices. Returns total host count and details. Call with no filters to get total count of all hosts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "platform": {
                        "type": "string",
                        "description": "Filter by platform (Windows, Mac, Linux)"
                    },
                    "status": {
                        "type": "string",
                        "description": "Filter by status (normal, contained, containment_pending, lift_containment_pending)"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Filter by hostname pattern (partial match)"
                    },
                    "last_seen_within": {
                        "type": "number",
                        "description": "Only hosts seen within this many days (e.g. 7 for last week, 30 for last month)"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Max results to return",
                        "default": 50
                    }
                }
            }
        ),
        Tool(
            name="get_ngsiem_ingestion",
            description="Query NGSIEM/LogScale data ingestion metrics. Returns: total_bytes (total ingestion volume in bytes), total_events (total event count), sources (list of data sources with name, events count, and bytes per source — use this to answer 'how many data sources' and 'what is the ingestion size'), is_mssp (whether running in multi-tenant mode), children (per-tenant breakdown if MSSP). Call this tool to answer questions about data ingestion volume, number of data sources, ingestion size, or which vendors are sending data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "number",
                        "description": "Look-back period in hours (default 24)",
                        "default": 24
                    }
                }
            }
        ),
        Tool(
            name="get_identity_protection",
            description="Get Identity Protection overview: sensor counts by entity type and top risky identities ranked by risk score. Call this to answer questions about identity threats, risky users, or identity-based incidents.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "number",
                        "description": "Max risky entities to return",
                        "default": 50
                    }
                }
            }
        ),
        Tool(
            name="get_cloud_security",
            description="Get Cloud Security posture: risk findings by severity, cloud provider, and service category. Covers CSPM cloud risks and IOMs (Indicators of Misconfiguration). Call this to answer questions about cloud security risks, misconfigurations, or compliance.",
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (Critical, High, Medium, Low, Informational)"
                    },
                    "cloud_provider": {
                        "type": "string",
                        "description": "Filter by cloud provider (AWS, Azure, GCP)"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Max risk findings to return",
                        "default": 200
                    }
                }
            }
        ),
        Tool(
            name="get_exposure_management",
            description="Get External Attack Surface Management overview: external assets by criticality, type, triage status, and cloud provider. Shows internet-facing assets discovered by CrowdStrike. Call this to answer questions about external attack surface, internet-exposed assets, or asset inventory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "number",
                        "description": "Max assets to return",
                        "default": 100
                    }
                }
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool execution"""

    if name == "search_alerts":
        result = await search_alerts(
            product=arguments.get("product", "cao"),
            severity=arguments.get("severity"),
            hours=arguments.get("hours", 24),
            limit=arguments.get("limit", 50)
        )
    elif name == "get_host_details":
        result = await get_host_details(hostname=arguments["hostname"])
    elif name == "test_fql_filter":
        result = await test_fql_filter(filter_string=arguments["filter_string"])
    elif name == "list_available_products":
        result = await list_available_products()
    elif name == "search_cases":
        result = await search_cases(
            status=arguments.get("status"),
            severity=arguments.get("severity"),
            hours=arguments.get("hours", 72),
            limit=arguments.get("limit", 50)
        )
    elif name == "search_detections":
        result = await search_detections(
            severity=arguments.get("severity"),
            status=arguments.get("status"),
            hours=arguments.get("hours", 24),
            limit=arguments.get("limit", 50)
        )
    elif name == "search_vulnerabilities":
        result = await search_vulnerabilities(
            severity=arguments.get("severity"),
            status=arguments.get("status"),
            limit=arguments.get("limit", 50)
        )
    elif name == "search_threatgraph":
        result = await search_threatgraph(
            indicator_type=arguments.get("indicator_type"),
            indicator_value=arguments.get("indicator_value"),
            vertex_type=arguments.get("vertex_type"),
            vertex_id=arguments.get("vertex_id"),
            scope=arguments.get("scope", "device"),
            limit=arguments.get("limit", 50)
        )
    elif name == "get_security_posture":
        result = await get_security_posture(
            hours=arguments.get("hours", 24)
        )
    elif name == "search_hosts":
        result = await search_hosts(
            platform=arguments.get("platform"),
            status=arguments.get("status"),
            hostname=arguments.get("hostname"),
            last_seen_within=arguments.get("last_seen_within"),
            limit=arguments.get("limit", 50)
        )
    elif name == "get_ngsiem_ingestion":
        result = await get_ngsiem_ingestion(
            hours=arguments.get("hours", 24)
        )
    elif name == "get_identity_protection":
        result = await get_identity_protection(
            limit=arguments.get("limit", 50)
        )
    elif name == "get_cloud_security":
        result = await get_cloud_security(
            severity=arguments.get("severity"),
            cloud_provider=arguments.get("cloud_provider"),
            limit=arguments.get("limit", 200)
        )
    elif name == "get_exposure_management":
        result = await get_exposure_management(
            limit=arguments.get("limit", 100)
        )
    else:
        result = json.dumps({"error": f"Unknown tool: {name}", "tool": name, "status": "error"})

    return [TextContent(type="text", text=result)]

# ============ MCP RESOURCES ============

@server.list_resources()
async def handle_list_resources() -> list[Resource]:
    """List available resources"""
    return [
        Resource(
            uri="falcon://fql-cheatsheet",
            name="FQL Cheat Sheet",
            description="FQL (Falcon Query Language) syntax quick reference",
            mimeType="text/plain"
        ),
        Resource(
            uri="falcon://severity-definitions",
            name="Severity Definitions",
            description="CrowdStrike severity levels and their meanings",
            mimeType="text/plain"
        ),
        Resource(
            uri="falcon://mitre-attack-mapping",
            name="MITRE ATT&CK Mapping",
            description="MITRE ATT&CK tactics and techniques reference for CrowdStrike",
            mimeType="text/plain"
        ),
        Resource(
            uri="falcon://case-status-guide",
            name="Case Status Guide",
            description="Case and detection status codes and workflows",
            mimeType="text/plain"
        )
    ]

@server.read_resource()
async def handle_read_resource(uri: str) -> str:
    """Read resource content"""
    if uri == "falcon://fql-cheatsheet":
        return """# FQL (Falcon Query Language) Cheat Sheet

## Basic Operators
- field:'value'           - Exact match
- field:*value*           - Wildcard match
- field:>value            - Greater than
- field:<value            - Less than

## Combining Filters
- filter1+filter2         - AND (both must match)
- filter1,filter2         - OR (either can match)
- field:['val1','val2']   - IN (match any value)

## Common Alert Fields
- product                 - Product type (cao, thirdparty, epp, idp)
- external_provider_name  - 3rd party provider (Corelight, etc.)
- severity_name - Severity (Critical, High, Medium, Low)
- created_timestamp       - Alert creation time
- status                  - Alert status (new, in_progress, closed)
- tactic                  - MITRE ATT&CK tactic
- technique               - MITRE ATT&CK technique

## Time Filters
- created_timestamp:>'24h'                    - Last 24 hours
- created_timestamp:>'2024-02-24T00:00:00Z'   - Since specific date

## Example Filters
1. CAO Critical alerts from last 24h:
   product:'cao'+severity_name:'Critical'+created_timestamp:>'24h'

2. Corelight detections:
   product:'thirdparty'+external_provider_name:'Corelight'

3. New high/critical alerts:
   status:'new'+severity_name:['Critical','High']
"""

    elif uri == "falcon://severity-definitions":
        return """# CrowdStrike Severity Definitions

## Alert Severity Levels
| Level | Name | Description |
|-------|------|-------------|
| 5 | Critical | Confirmed active threat requiring immediate response |
| 4 | High | Strong indicators of malicious activity |
| 3 | Medium | Suspicious activity warranting investigation |
| 2 | Low | Minor anomaly or policy violation |
| 1 | Informational | Normal activity logged for awareness |

## Case Severity
- Critical: Requires immediate attention
- High: Important, address promptly
- Medium: Standard priority
- Low: Minor or informational

## Vulnerability Severity (CVSS-based)
| Rating | CVSS Score | Action |
|--------|-----------|--------|
| Critical | 9.0-10.0 | Patch immediately |
| High | 7.0-8.9 | Patch within 7 days |
| Medium | 4.0-6.9 | Patch within 30 days |
| Low | 0.1-3.9 | Patch in next cycle |

## Threat Intel Confidence
- High: Confirmed malicious, high-fidelity IOC
- Medium: Likely malicious, requires context
- Low: Possibly malicious, needs validation
- Unverified: Not yet assessed
"""

    elif uri == "falcon://mitre-attack-mapping":
        return """# MITRE ATT&CK Mapping for CrowdStrike Detections

## Tactics (Execution Order)
1. Reconnaissance - Gathering information
2. Resource Development - Building infrastructure
3. Initial Access - Getting into the network
4. Execution - Running malicious code
5. Persistence - Maintaining foothold
6. Privilege Escalation - Gaining higher permissions
7. Defense Evasion - Avoiding detection
8. Credential Access - Stealing credentials
9. Discovery - Exploring the environment
10. Lateral Movement - Moving through network
11. Collection - Gathering target data
12. Command and Control - Communicating with implants
13. Exfiltration - Stealing data
14. Impact - Disruption and destruction

## Common Techniques in CrowdStrike Detections
- T1059 - Command and Scripting Interpreter (PowerShell, Bash)
- T1053 - Scheduled Task/Job
- T1055 - Process Injection
- T1078 - Valid Accounts
- T1110 - Brute Force
- T1021 - Remote Services (RDP, SSH)
- T1486 - Data Encrypted for Impact (Ransomware)
- T1071 - Application Layer Protocol (C2)
- T1027 - Obfuscated Files or Information
- T1548 - Abuse Elevation Control Mechanism

## FQL Tactic Filters
- tactic:'InitialAccess'
- tactic:'Execution'
- tactic:'Persistence'
- tactic:'PrivilegeEscalation'
- tactic:'DefenseEvasion'
- tactic:'CredentialAccess'
- tactic:'LateralMovement'
- tactic:'CommandAndControl'
"""

    elif uri == "falcon://case-status-guide":
        return """# Case & Detection Status Guide

## Case Status Values
| Status | Description |
|--------|-------------|
| New | Newly created, not yet reviewed |
| Open | Active case, under investigation |
| In Progress | Actively being worked on |
| Reopened | Previously closed, new activity detected |
| Closed | Investigation complete, resolved |

## Detection Status Values
| Status | Description |
|--------|-------------|
| new | Not yet triaged |
| in_progress | Under investigation |
| true_positive | Confirmed malicious |
| false_positive | Benign activity misidentified |
| closed | Resolved and closed |
| ignored | Intentionally dismissed |

## Recommended Triage Workflow
1. **New** -> Review severity and context
2. **In Progress** -> Investigate IOCs, affected hosts, lateral movement
3. **True Positive** -> Contain, remediate, document
4. **False Positive** -> Tune detection, add exclusion if needed
5. **Closed** -> Verify remediation, update playbook

## FQL Status Filters
### Cases
- status:'new'                  - New cases
- status:'open'                 - Open cases
- status:'in_progress'          - In progress
- status:'closed'               - Closed

### Detections
- status:'new'                 - New detections
- status:'in_progress'         - Being investigated
- status:'true_positive'       - Confirmed threats
"""

    else:
        raise ValueError(f"Unknown resource: {uri}")

# ============ MCP PROMPTS ============

@server.list_prompts()
async def handle_list_prompts() -> list[Prompt]:
    """List available prompts"""
    return [
        Prompt(
            name="case-triage",
            description="Guided case triage workflow - reviews recent cases and provides prioritized response recommendations",
            arguments=[
                PromptArgument(
                    name="hours",
                    description="Look back period in hours (default: 24)",
                    required=False
                ),
                PromptArgument(
                    name="severity",
                    description="Focus on specific severity (critical, high, medium, low)",
                    required=False
                )
            ]
        ),
        Prompt(
            name="threat-hunt",
            description="Threat hunting workflow - search for indicators of compromise across the environment",
            arguments=[
                PromptArgument(
                    name="ioc",
                    description="Specific IOC to hunt for (IP, domain, hash, etc.)",
                    required=False
                ),
                PromptArgument(
                    name="tactic",
                    description="MITRE ATT&CK tactic to focus on",
                    required=False
                )
            ]
        ),
        Prompt(
            name="vulnerability-assessment",
            description="Vulnerability prioritization - analyze open vulnerabilities and recommend patching priorities",
            arguments=[
                PromptArgument(
                    name="severity",
                    description="Focus on specific severity (critical, high, medium, low)",
                    required=False
                )
            ]
        ),
        Prompt(
            name="executive-briefing",
            description="Generate an executive security summary with key metrics, risk posture, and recommendations",
            arguments=[
                PromptArgument(
                    name="hours",
                    description="Reporting period in hours (default: 24)",
                    required=False
                )
            ]
        ),
        Prompt(
            name="data-ingestion-analysis",
            description="Analyze NGSIEM/LogScale data ingestion - volume trends, top sources, and coverage gaps",
            arguments=[
                PromptArgument(
                    name="hours",
                    description="Look back period in hours (default: 24)",
                    required=False
                )
            ]
        )
    ]

@server.get_prompt()
async def handle_get_prompt(name: str, arguments: dict | None = None) -> list[PromptMessage]:
    """Get prompt content"""
    args = arguments or {}

    if name == "case-triage":
        hours = args.get("hours", "24")
        severity = args.get("severity", "")
        severity_clause = f" Focus specifically on {severity} severity cases." if severity else ""
        return [
            PromptMessage(
                role="user",
                content=TextContent(
                    type="text",
                    text=f"""Perform a case triage for the last {hours} hours.{severity_clause}

Steps:
1. Use get_security_posture to get an overview of current security state
2. Use search_cases to find recent cases
3. Use search_detections to find related endpoint detections
4. For any critical cases, check the affected hosts using get_host_details

Provide a prioritized list of cases to investigate with:
- Severity and risk assessment
- Affected hosts and scope
- Recommended response actions
- MITRE ATT&CK context"""
                )
            )
        ]

    elif name == "threat-hunt":
        ioc = args.get("ioc", "")
        tactic = args.get("tactic", "")
        context = []
        if ioc:
            context.append(f"Hunt for this specific IOC: {ioc}")
        if tactic:
            context.append(f"Focus on MITRE ATT&CK tactic: {tactic}")
        hunt_context = "\n".join(context) if context else "Perform a general threat hunting sweep."
        return [
            PromptMessage(
                role="user",
                content=TextContent(
                    type="text",
                    text=f"""Conduct a threat hunting investigation.

{hunt_context}

Steps:
1. Use search_threatgraph to find IOC activity across devices
2. Use search_detections to find related endpoint detections
3. Use search_alerts to find correlated alerts
4. Check any affected hosts with get_host_details

Provide:
- Indicators found and their confidence level
- Any matching detections or alerts in the environment
- Kill chain analysis
- Recommended containment actions"""
                )
            )
        ]

    elif name == "vulnerability-assessment":
        severity = args.get("severity", "critical")
        return [
            PromptMessage(
                role="user",
                content=TextContent(
                    type="text",
                    text=f"""Perform a vulnerability assessment focused on {severity} severity.

Steps:
1. Use search_vulnerabilities to find open vulnerabilities
2. Use get_security_posture for context on overall vulnerability landscape
3. Cross-reference with search_detections for any active exploitation

Provide:
- Top vulnerabilities ranked by risk (CVSS score + exploitability)
- Affected hosts and software
- Recommended patching priority order
- Any evidence of active exploitation"""
                )
            )
        ]

    elif name == "executive-briefing":
        hours = args.get("hours", "24")
        return [
            PromptMessage(
                role="user",
                content=TextContent(
                    type="text",
                    text=f"""Generate an executive security briefing for the last {hours} hours.

Steps:
1. Use get_security_posture to get comprehensive metrics
2. Use search_cases to get case details
3. Use search_detections for detection trends
4. Use search_vulnerabilities for vulnerability status
5. Use get_ngsiem_ingestion with hours={hours} to get data ingestion metrics

Produce a concise executive briefing with:
- Overall risk score and trend
- Key metrics: total alerts, cases, detections, vulnerabilities
- Severity distribution breakdown
- Data ingestion summary: total events ingested, top data sources, coverage status
- Top 3-5 critical items requiring attention
- Recommended actions for leadership"""
                )
            )
        ]

    elif name == "data-ingestion-analysis":
        hours = args.get("hours", "24")
        return [
            PromptMessage(
                role="user",
                content=TextContent(
                    type="text",
                    text=f"""Analyze NGSIEM/LogScale data ingestion for the last {hours} hours.

Steps:
1. Use get_ngsiem_ingestion with hours={hours} to retrieve ingestion metrics
2. Review the top data sources by event count
3. If MSSP mode is detected, review per-tenant ingestion breakdown

Provide:
- Total events ingested across all sources
- Top data sources ranked by event volume with percentage breakdown
- Any vendors with unusually low or zero event counts (potential coverage gaps)
- If MSSP: per-tenant ingestion summary highlighting any tenants with errors or missing data
- Recommendations for improving data source coverage or investigating anomalies
- Comparison context: are current ingestion levels consistent with expected baselines"""
                )
            )
        ]

    else:
        raise ValueError(f"Unknown prompt: {name}")

# ============ RUN SERVER ============

async def main():
    """Run the MCP server"""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="falcon-digest",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                )
            )
        )

if __name__ == "__main__":
    import sys
    try:
        validate_config()
    except ConfigError as e:
        print(f"\nError: {e}\n", file=sys.stderr)
        sys.exit(1)
    asyncio.run(main())

#!/usr/bin/env python3
"""QA validation script for Falcon Digest tool responses.

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

import sys
import os
import json
import inspect
import asyncio
import traceback

os.chdir(os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0
WARN = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  \033[92mPASS\033[0m  {name}")
    else:
        FAIL += 1
        print(f"  \033[91mFAIL\033[0m  {name}" + (f" — {detail}" if detail else ""))

def warn(name, detail=""):
    global WARN
    WARN += 1
    print(f"  \033[93mWARN\033[0m  {name}" + (f" — {detail}" if detail else ""))


print("\n" + "=" * 60)
print("  FALCON DIGEST — QA VALIDATION")
print("=" * 60)

# ============================================================
# 1. IMPORT CHECKS
# ============================================================
print("\n--- 1. IMPORT CHECKS ---")

try:
    from crwd_mcp_server import get_identity_protection
    check("Import get_identity_protection", True)
except Exception as e:
    check("Import get_identity_protection", False, str(e))

try:
    from crwd_mcp_server import get_cloud_security
    check("Import get_cloud_security", True)
except Exception as e:
    check("Import get_cloud_security", False, str(e))

try:
    from crwd_mcp_server import get_exposure_management
    check("Import get_exposure_management", True)
except Exception as e:
    check("Import get_exposure_management", False, str(e))

try:
    from falconpy import CloudSecurityDetections
    check("Import CloudSecurityDetections from falconpy", True)
except Exception as e:
    check("Import CloudSecurityDetections from falconpy", False, str(e))

try:
    from falconpy import IdentityProtection, CloudSecurity, ExposureManagement
    check("Import IdentityProtection, CloudSecurity, ExposureManagement", True)
except Exception as e:
    check("Import IdentityProtection, CloudSecurity, ExposureManagement", False, str(e))

# ============================================================
# 2. FUNCTION SIGNATURE CHECKS
# ============================================================
print("\n--- 2. FUNCTION SIGNATURE CHECKS ---")

sig = inspect.signature(get_identity_protection)
params = list(sig.parameters.keys())
check("get_identity_protection has 'limit' param", "limit" in params, f"params: {params}")

sig = inspect.signature(get_cloud_security)
params = list(sig.parameters.keys())
check("get_cloud_security has 'severity' param", "severity" in params, f"params: {params}")
check("get_cloud_security has 'cloud_provider' param", "cloud_provider" in params, f"params: {params}")
check("get_cloud_security has 'limit' param", "limit" in params, f"params: {params}")

sig = inspect.signature(get_exposure_management)
params = list(sig.parameters.keys())
check("get_exposure_management has 'limit' param", "limit" in params, f"params: {params}")

# Check they are all async
check("get_identity_protection is async", asyncio.iscoroutinefunction(get_identity_protection))
check("get_cloud_security is async", asyncio.iscoroutinefunction(get_cloud_security))
check("get_exposure_management is async", asyncio.iscoroutinefunction(get_exposure_management))

# ============================================================
# 3. SYNC HELPER CHECKS
# ============================================================
print("\n--- 3. SYNC HELPER CHECKS ---")

from crwd_mcp_server import _get_identity_protection_sync, _get_cloud_security_sync, _get_exposure_management_sync
check("_get_identity_protection_sync exists", callable(_get_identity_protection_sync))
check("_get_cloud_security_sync exists", callable(_get_cloud_security_sync))
check("_get_exposure_management_sync exists", callable(_get_exposure_management_sync))

# ============================================================
# 4. RETURN SHAPE VALIDATION (dry-run sync helpers)
# ============================================================
print("\n--- 4. RETURN SHAPE VALIDATION ---")

# Identity Protection
try:
    result = _get_identity_protection_sync(limit=5)
    check("Identity returns dict", isinstance(result, dict))
    for key in ["total_sensors", "by_status", "by_os", "risky_entities", "total_risky", "error"]:
        check(f"Identity has key '{key}'", key in result, f"keys: {list(result.keys())}")
    check("Identity risky_entities is list", isinstance(result.get("risky_entities"), list))
    check("Identity by_status is dict", isinstance(result.get("by_status"), dict))
    check("Identity by_os is dict", isinstance(result.get("by_os"), dict))
    if result.get("error"):
        warn(f"Identity returned error (expected if no scope)", result["error"])
    else:
        print(f"         Identity sensors: {result['total_sensors']}, status: {result['by_status']}, os: {list(result['by_os'].keys())}")
        if result["risky_entities"]:
            entity = result["risky_entities"][0]
            for ek in ["display_name", "entity_id", "risk_score", "type", "email", "risk_factors"]:
                check(f"Risky entity has '{ek}'", ek in entity, f"keys: {list(entity.keys())}")
except Exception as e:
    check("Identity sync helper runs without crash", False, str(e))
    traceback.print_exc()

# Cloud Security
try:
    result = _get_cloud_security_sync(severity=None, cloud_provider=None, limit=10)
    check("CloudSec returns dict", isinstance(result, dict))
    for key in ["total_risks", "risks_by_severity", "risks_by_provider", "risks_by_service", "top_risks", "iom_count", "error"]:
        check(f"CloudSec has key '{key}'", key in result, f"keys: {list(result.keys())}")
    check("CloudSec risks_by_severity is dict", isinstance(result.get("risks_by_severity"), dict))
    check("CloudSec top_risks is list", isinstance(result.get("top_risks"), list))
    if result.get("error"):
        warn(f"CloudSec returned error (expected if no scope)", result["error"])
    else:
        print(f"         CloudSec risks: {result['total_risks']}, IOMs: {result['iom_count']}, providers: {list(result['risks_by_provider'].keys())}")
        if result["top_risks"]:
            risk = result["top_risks"][0]
            for rk in ["severity", "status", "cloud_provider", "service_category", "rule_name", "account_name"]:
                check(f"Risk entry has '{rk}'", rk in risk, f"keys: {list(risk.keys())}")
except Exception as e:
    check("CloudSec sync helper runs without crash", False, str(e))
    traceback.print_exc()

# Exposure Management
try:
    result = _get_exposure_management_sync(limit=10)
    check("Exposure returns dict", isinstance(result, dict))
    for key in ["total_assets", "by_criticality", "by_asset_type", "by_triage_status", "by_cloud_provider", "assets", "error"]:
        check(f"Exposure has key '{key}'", key in result, f"keys: {list(result.keys())}")
    check("Exposure assets is list", isinstance(result.get("assets"), list))
    check("Exposure by_criticality is dict", isinstance(result.get("by_criticality"), dict))
    if result.get("error"):
        warn(f"Exposure returned error (expected if no scope)", result["error"])
    else:
        print(f"         Exposure assets: {result['total_assets']}, criticality: {result['by_criticality']}, types: {result['by_asset_type']}")
        if result["assets"]:
            asset = result["assets"][0]
            for ak in ["asset_id", "asset_type", "name", "criticality", "triage_status", "services", "country"]:
                check(f"Asset entry has '{ak}'", ak in asset, f"keys: {list(asset.keys())}")
except Exception as e:
    check("Exposure sync helper runs without crash", False, str(e))
    traceback.print_exc()

# ============================================================
# 5. JSON SERIALIZATION CHECK
# ============================================================
print("\n--- 5. JSON SERIALIZATION CHECK ---")

for func_name, func, kwargs in [
    ("get_identity_protection", get_identity_protection, {"limit": 5}),
    ("get_cloud_security", get_cloud_security, {"limit": 5}),
    ("get_exposure_management", get_exposure_management, {"limit": 5}),
]:
    try:
        raw = asyncio.get_event_loop().run_until_complete(func(**kwargs))
        check(f"{func_name} returns string", isinstance(raw, str))
        parsed = json.loads(raw)
        check(f"{func_name} returns valid JSON", isinstance(parsed, dict))
    except Exception as e:
        check(f"{func_name} JSON serialization", False, str(e))

# ============================================================
# 6. MCP TOOL REGISTRATION CHECK
# ============================================================
print("\n--- 6. MCP TOOL REGISTRATION CHECK ---")

import crwd_mcp_server as srv

# Check the handle_list_tools function exists and is decorated
check("handle_list_tools exists", hasattr(srv, "handle_list_tools"))
check("handle_call_tool exists", hasattr(srv, "handle_call_tool"))

# Read the source to verify tool registrations
with open("crwd_mcp_server.py", "r") as f:
    src = f.read()

check("Tool 'get_identity_protection' registered", 'name="get_identity_protection"' in src)
check("Tool 'get_cloud_security' registered", 'name="get_cloud_security"' in src)
check("Tool 'get_exposure_management' registered", 'name="get_exposure_management"' in src)

# Check dispatch
check("Dispatch 'get_identity_protection'", 'name == "get_identity_protection"' in src)
check("Dispatch 'get_cloud_security'", 'name == "get_cloud_security"' in src)
check("Dispatch 'get_exposure_management'", 'name == "get_exposure_management"' in src)

# Check docstring
check("Docstring says 13 tools", "13 tools" in src)

# ============================================================
# 7. DASHBOARD V2 STRUCTURE CHECK
# ============================================================
print("\n--- 7. DASHBOARD V2 STRUCTURE CHECK ---")

with open("mcp_dashboard_v2.py", "r") as f:
    v2 = f.read()

check("V2 imports get_identity_protection", "get_identity_protection" in v2)
check("V2 imports get_cloud_security", "get_cloud_security" in v2)
check("V2 imports get_exposure_management", "get_exposure_management" in v2)

# Tab variable names
check("V2 has tab_identity variable", "tab_identity" in v2)
check("V2 has tab_cloud variable", "tab_cloud" in v2)
check("V2 has tab_exposure variable", "tab_exposure" in v2)

# Tab labels in st.tabs
check("V2 tab label 'Identity'", '"Identity"' in v2)
check("V2 tab label 'Cloud Security'", '"Cloud Security"' in v2)
check("V2 tab label 'Exposure'", '"Exposure"' in v2)

# Tab order: Identity, Cloud Security, Exposure come after Vulnerabilities and before IOC Search
import re
tabs_match = re.search(r'st\.tabs\(\[(.*?)\]\)', v2, re.DOTALL)
if tabs_match:
    tabs_str = tabs_match.group(1)
    tab_labels = [t.strip().strip('"').strip("'") for t in tabs_str.split(",")]
    tab_labels = [t for t in tab_labels if t]
    print(f"         V2 tab order: {' | '.join(tab_labels)}")

    expected = ["Executive Summary", "Detections", "Cases", "Vulnerabilities",
                "Identity", "Cloud Security", "Exposure",
                "IOC Search", "Data Ingestion", "FQL Tools"]
    check("V2 has 10 tabs", len(tab_labels) == 10, f"got {len(tab_labels)}: {tab_labels}")
    check("V2 tab order correct", tab_labels == expected, f"got {tab_labels}")
else:
    check("V2 st.tabs() found", False, "Could not parse st.tabs")

# Tab content blocks
check("V2 'with tab_identity:' block", "with tab_identity:" in v2)
check("V2 'with tab_cloud:' block", "with tab_cloud:" in v2)
check("V2 'with tab_exposure:' block", "with tab_exposure:" in v2)

# Session state keys
check("V2 session 'identity_data'", '"identity_data"' in v2)
check("V2 session 'cloud_security_data'", '"cloud_security_data"' in v2)
check("V2 session 'exposure_data'", '"exposure_data"' in v2)

# CID change clears new keys
check("V2 CID-change clears identity_data", "identity_data" in v2.split("check_cid_change")[1][:500])
check("V2 CID-change clears cloud_security_data", "cloud_security_data" in v2.split("check_cid_change")[1][:500])
check("V2 CID-change clears exposure_data", "exposure_data" in v2.split("check_cid_change")[1][:500])

# FALCON_LINKS
check("V2 FALCON_LINKS has 'identity'", '"identity"' in v2.split("FALCON_LINKS")[1][:500])
check("V2 FALCON_LINKS has 'cloud_security'", '"cloud_security"' in v2.split("FALCON_LINKS")[1][:500])
check("V2 FALCON_LINKS has 'exposure'", '"exposure"' in v2.split("FALCON_LINKS")[1][:500])

# Chart types present
# Chart types: just check they exist in new tab blocks
check("V2 has Pie chart in new tabs", v2.count("go.Pie(") >= 2)  # at least 2 new pies (status + providers)
check("V2 has Bar chart in new tabs", v2.count("go.Bar(") >= 4)  # at least 4 new bars

# Tab section numbering
for i, name in [(5, "IDENTITY"), (6, "CLOUD SECURITY"), (7, "EXPOSURE"), (8, "IOC SEARCH"), (9, "DATA INGESTION"), (10, "FQL TOOLS")]:
    check(f"V2 TAB {i} comment: {name}", f"TAB {i}: {name}" in v2)

# ============================================================
# 8. DASHBOARD V1 STRUCTURE CHECK
# ============================================================
print("\n--- 8. DASHBOARD V1 STRUCTURE CHECK ---")

with open("mcp_dashboard.py", "r") as f:
    v1 = f.read()

check("V1 imports get_identity_protection", "get_identity_protection" in v1)
check("V1 imports get_cloud_security", "get_cloud_security" in v1)
check("V1 imports get_exposure_management", "get_exposure_management" in v1)

check("V1 has tab_identity variable", "tab_identity" in v1)
check("V1 has tab_cloud variable", "tab_cloud" in v1)
check("V1 has tab_exposure variable", "tab_exposure" in v1)

# Tab order
tabs_match = re.search(r'st\.tabs\(\[(.*?)\]\)', v1, re.DOTALL)
if tabs_match:
    tabs_str = tabs_match.group(1)
    tab_labels = [t.strip().strip('"').strip("'") for t in tabs_str.split(",")]
    tab_labels = [t for t in tab_labels if t]
    print(f"         V1 tab order: {' | '.join(tab_labels)}")

    expected = ["Executive Summary", "Detections", "Cases", "Vulnerabilities",
                "Identity", "Cloud Security", "Exposure",
                "IOC Search", "Data Ingestion", "FQL Tools", "Ask Vantage AI"]
    check("V1 has 11 tabs", len(tab_labels) == 11, f"got {len(tab_labels)}: {tab_labels}")
    check("V1 tab order correct", tab_labels == expected, f"got {tab_labels}")
    check("V1 'Ask Vantage AI' is last tab", tab_labels[-1] == "Ask Vantage AI")
else:
    check("V1 st.tabs() found", False, "Could not parse st.tabs")

# V1 uses use_container_width=True (not width="stretch")
identity_block = v1.split("with tab_identity:")[1].split("with tab_cloud:")[0]
check("V1 Identity uses use_container_width=True", "use_container_width=True" in identity_block)
check("V1 Identity does NOT use width='stretch'", 'width="stretch"' not in identity_block)

cloud_block = v1.split("with tab_cloud:")[1].split("with tab_exposure:")[0]
check("V1 CloudSec uses use_container_width=True", "use_container_width=True" in cloud_block)

exposure_block = v1.split("with tab_exposure:")[1].split("with tab_tg:")[0]
check("V1 Exposure uses use_container_width=True", "use_container_width=True" in exposure_block)

# FALCON_LINKS
check("V1 FALCON_LINKS has 'identity'", '"identity"' in v1.split("FALCON_LINKS")[1][:500])
check("V1 FALCON_LINKS has 'cloud_security'", '"cloud_security"' in v1.split("FALCON_LINKS")[1][:500])
check("V1 FALCON_LINKS has 'exposure'", '"exposure"' in v1.split("FALCON_LINKS")[1][:500])

# Tab section numbering
for i, name in [(5, "IDENTITY"), (6, "CLOUD SECURITY"), (7, "EXPOSURE"), (8, "IOC SEARCH"), (9, "DATA INGESTION"), (10, "FQL TOOLS"), (11, "AI CHAT")]:
    check(f"V1 TAB {i} comment: {name}", f"TAB {i}: {name}" in v1)

# ============================================================
# 9. EXISTING FUNCTIONALITY NOT BROKEN
# ============================================================
print("\n--- 9. EXISTING FUNCTIONALITY CHECK ---")

# Verify old functions still importable
for fn_name in ["search_alerts", "search_cases", "search_detections", "search_vulnerabilities",
                "search_threatgraph", "get_security_posture", "search_hosts",
                "get_host_details", "test_fql_filter", "list_available_products", "get_ngsiem_ingestion"]:
    try:
        fn = getattr(srv, fn_name)
        check(f"Existing function '{fn_name}' still exists", callable(fn))
    except AttributeError:
        check(f"Existing function '{fn_name}' still exists", False, "not found")

# Verify old tab variables still referenced in v2
for tab_var in ["tab_exec", "tab_detections", "tab_cases", "tab_vulns", "tab_tg", "tab_ingestion", "tab_fql"]:
    check(f"V2 still has '{tab_var}'", tab_var in v2)

# Verify old tab variables still referenced in v1
for tab_var in ["tab_exec", "tab_detections", "tab_cases", "tab_vulns", "tab_tg", "tab_ingestion", "tab_fql", "tab_chat"]:
    check(f"V1 still has '{tab_var}'", tab_var in v1)

# ============================================================
# 10. SCOPE PROBES CHECK
# ============================================================
print("\n--- 10. SCOPE PROBES CHECK ---")

check("Scope probe: Identity Protection", "Identity Protection:read" in src or "identity-protection" in src.lower())
check("Scope probe: Cloud Security", "Cloud Security:read" in src)
check("Scope probe: Exposure Management", "Exposure Management:read" in src)

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 60)
total = PASS + FAIL
print(f"  RESULTS: {PASS} passed, {FAIL} failed, {WARN} warnings out of {total} checks")
if FAIL == 0:
    print(f"  \033[92mALL CHECKS PASSED\033[0m")
else:
    print(f"  \033[91m{FAIL} CHECKS FAILED\033[0m")
print("=" * 60 + "\n")

sys.exit(1 if FAIL > 0 else 0)

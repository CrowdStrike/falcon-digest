#!/usr/bin/env python3
"""
Falcon Vantage — Dashboard
Bird's-eye view across your CrowdStrike Falcon environment.
"""

import streamlit as st
import streamlit.components.v1 as components
import asyncio
import html
import json
import logging
import os
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone
from dotenv import load_dotenv
from crwd_mcp_server import (
    get_host_details, test_fql_filter, list_available_products,
    search_cases, search_detections, search_vulnerabilities,
    search_threatgraph, get_security_posture, search_hosts,
    get_ngsiem_ingestion, get_identity_protection,
    get_cloud_security, get_exposure_management,
    validate_config, ConfigError
)
from mcp_api_client import call_llm, execute_tool, TOOL_DEFINITIONS
from falcon_cache import cache as falcon_cache, parse_env_profiles, switch_env_profile

load_dotenv()

_logger = logging.getLogger("falcon_mcp.dashboard")

# ============ PAGE CONFIG ============

st.set_page_config(
    page_title="Falcon Vantage",
    page_icon="https://www.crowdstrike.com/wp-content/uploads/2022/01/favicon.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============ CONFIGURATION CHECK ============

try:
    validate_config()
except ConfigError as e:
    st.error(
        "**Falcon Vantage cannot start — required configuration is missing.**\n\n"
        + str(e).replace("\n", "\n\n"),
        icon="\u274C"
    )
    st.info(
        "Copy `.env.example` to `.env` and fill in your credentials, "
        "then reload this page.\n\n"
        "```bash\ncp .env.example .env\n```",
        icon="\u2139\uFE0F"
    )
    st.stop()

# ============ THEME CSS ============

st.markdown("""
<style>
    /* Hide deploy button, menu, status — keep sidebar expand arrow */
    .stAppDeployButton,
    .stMainMenu,
    .stStatusWidget,
    .stToolbarActions {
        display: none !important;
    }
    /* Make header bar invisible but keep expand button clickable */
    .stAppHeader {
        background: transparent !important;
        pointer-events: none !important;
    }
    [data-testid="stExpandSidebarButton"] {
        pointer-events: auto !important;
    }
    /* Hide "Press Enter to submit form" instruction in chat input */
    [data-testid="InputInstructions"] {
        display: none !important;
    }
    /* Push main content up — remove default 6rem top padding */
    .stMainBlockContainer {
        padding-top: 1rem !important;
    }

    :root {
        --cs-red: #E8272C;
        --cs-bg: #F5F7FA;
        --cs-card-bg: #FFFFFF;
        --cs-sidebar-bg: #1B2A4A;
        --cs-sidebar-text: #E0E6EF;
        --cs-text: #1E1E2F;
        --cs-text-dim: #6B7280;
        --cs-border: #E2E8F0;
        --cs-green: #16A34A;
        --cs-orange: #EA580C;
        --cs-blue: #2563EB;
    }

    .stApp {
        background-color: var(--cs-bg);
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: var(--cs-sidebar-bg);
        color: var(--cs-sidebar-text);
    }
    section[data-testid="stSidebar"] .stMarkdown,
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] .stCaption,
    section[data-testid="stSidebar"] p {
        color: var(--cs-sidebar-text) !important;
    }
    /* Allow inline color overrides on spans (for scope red/green/yellow icons) */
    section[data-testid="stSidebar"] span[style] {
        color: inherit;
    }
    /* Sidebar buttons — dark background to match sidebar */
    section[data-testid="stSidebar"] .stButton > button {
        background-color: #243656 !important;
        color: #E0E6EF !important;
        border: 1px solid #3B5278 !important;
    }
    section[data-testid="stSidebar"] .stButton > button:hover {
        background-color: #2E4570 !important;
    }
    /* Sidebar expanders — force dark background on ALL inner elements */
    section[data-testid="stSidebar"] [data-testid="stExpander"] {
        background-color: #243656 !important;
        border: 1px solid #3B5278 !important;
        border-radius: 8px;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] details {
        background-color: #243656 !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] details > div {
        background-color: #243656 !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] summary,
    section[data-testid="stSidebar"] [data-testid="stExpander"] summary span,
    section[data-testid="stSidebar"] [data-testid="stExpander"] summary p,
    section[data-testid="stSidebar"] [data-testid="stExpander"] summary svg {
        color: #E0E6EF !important;
        fill: #E0E6EF !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        background-color: #243656 !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] * {
        background-color: transparent !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"],
    section[data-testid="stSidebar"] [data-testid="stExpander"] details,
    section[data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        background-color: #243656 !important;
    }

    /* KPI card */
    .kpi-card {
        background: var(--cs-card-bg);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        border: 1px solid var(--cs-border);
        box-shadow: 0 1px 3px rgba(0,0,0,0.06);
        margin-bottom: 10px;
    }
    .kpi-card .kpi-value {
        font-size: 2.5rem;
        font-weight: 700;
        margin: 5px 0;
    }
    .kpi-card .kpi-label {
        font-size: 0.8rem;
        color: var(--cs-text-dim);
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Status indicator */
    .status-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 6px;
    }
    .status-connected { background-color: #4ADE80; }
    .status-disconnected { background-color: #F87171; }

    /* Header */
    .main-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 0 20px 0;
    }
    .main-header h1 {
        color: var(--cs-text);
        font-size: 1.8rem;
        margin: 0;
    }

    /* Chat input border */
    [data-testid="stChatInput"] {
        border: 2px solid #CBD5E1 !important;
        border-radius: 12px !important;
    }
    [data-testid="stChatInput"]:focus-within {
        border-color: var(--cs-red) !important;
        box-shadow: 0 0 0 2px rgba(227, 37, 42, 0.15) !important;
    }

    /* Chat bubbles — !important needed to override sidebar text color */
    .chat-user {
        background: var(--cs-blue, #2563EB) !important;
        color: #fff !important;
        padding: 8px 12px;
        border-radius: 12px 12px 4px 12px;
        margin: 4px 0;
        font-size: 0.85rem;
        line-height: 1.4;
    }
    .chat-assistant {
        background: #F1F5F9 !important;
        color: #1E1E2F !important;
        padding: 8px 12px;
        border-radius: 12px 12px 12px 4px;
        margin: 4px 0;
        font-size: 0.85rem;
        line-height: 1.4;
    }
    .chat-assistant strong, .chat-assistant b {
        color: #1E1E2F !important;
    }
    .chat-user strong, .chat-user b {
        color: #fff !important;
    }
    .chat-tool {
        background: #FEF9C3 !important;
        color: #92400E !important;
        padding: 4px 10px;
        border-radius: 8px;
        margin: 4px 0;
        font-size: 0.8rem;
        font-style: italic;
    }
</style>
""", unsafe_allow_html=True)

# ============ BACKGROUND DATA CACHE ============

# Detect CID change — clear all session state and cache if credentials switched
if falcon_cache.check_cid_change():
    _logger.info("CID change detected — clearing session state")
    for key in ["posture_data", "detections_data", "cases_data", "vulns_data",
                 "tg_edge_types", "ingestion_data", "identity_data",
                 "cloud_security_data", "exposure_data", "cache_started",
                 "_cache_sync_count"]:
        st.session_state.pop(key, None)

if "cache_started" not in st.session_state:
    try:
        if falcon_cache.has_fresh_file_data():
            # Instant load from daemon-populated cache file
            st.session_state.cache_loaded_from_file = True
            falcon_cache.start(poll_interval=300, ttl=300)
        else:
            st.session_state.cache_loaded_from_file = False
            falcon_cache.start(poll_interval=300, ttl=300)
            # Wait for initial cache load with progress
            _init_progress = st.empty()
            _init_status = st.empty()
            while falcon_cache.is_refreshing or falcon_cache.entry_count == 0:
                pct = falcon_cache.refresh_progress
                _init_progress.progress(pct, text=f"Loading Falcon data... {int(pct * 100)}%")
                # Show which source is currently loading
                status = falcon_cache.refresh_status
                loading = [k for k, v in status.items() if v == "loading"]
                if loading:
                    _init_status.caption(f"Fetching: {', '.join(loading)}")
                time.sleep(0.3)
                if not falcon_cache.is_refreshing and falcon_cache.entry_count > 0:
                    break
            _init_progress.empty()
            _init_status.empty()
    except Exception:
        _logger.warning("Failed to start cache", exc_info=True)
    st.session_state.cache_started = True
elif not falcon_cache.is_running:
    # Cache was started before but thread may have died; restart it
    try:
        falcon_cache.start(poll_interval=300, ttl=300)
    except Exception:
        _logger.warning("Failed to restart cache", exc_info=True)

# Sync session state from cache when background refresh has newer data
# This is what makes auto-refresh and cache polling actually update the tabs
_CACHE_SESSION_KEYS = {
    "security_posture": "posture_data",
    "detections_recent": "detections_data",
    "cases_recent": "cases_data",
    "vulnerabilities_critical": "vulns_data",
    "threatgraph_edge_types": "tg_edge_types",
    "ngsiem_ingestion": "ingestion_data",
    "identity_protection": "identity_data",
    "cloud_security": "cloud_security_data",
    "exposure_management": "exposure_data",
}

_last_synced = st.session_state.get("_cache_sync_count", -1)
if falcon_cache.refresh_count > _last_synced and falcon_cache.refresh_count > 0:
    for cache_key, session_key in _CACHE_SESSION_KEYS.items():
        parsed = falcon_cache.get_parsed(cache_key)
        if parsed and not isinstance(parsed, str) and "error" not in parsed:
            st.session_state[session_key] = parsed
    st.session_state["_cache_sync_count"] = falcon_cache.refresh_count

# ============ HELPER FUNCTIONS ============

def get_falcon_console_url() -> str:
    """Derive Falcon console URL from FALCON_BASE_URL env var."""
    base = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com")
    return base.replace("://api.", "://falcon.").rstrip("/")

FALCON_CONSOLE = get_falcon_console_url()

FALCON_LINKS = {
    "detections": f"{FALCON_CONSOLE}/unified-detections",
    "cases": f"{FALCON_CONSOLE}/xdr/cases",
    "vulnerabilities": f"{FALCON_CONSOLE}/spotlight/vulnerabilities",
    "hosts": f"{FALCON_CONSOLE}/hosts/hosts",
    "threatgraph": f"{FALCON_CONSOLE}/threatgraph",
    "dashboard": f"{FALCON_CONSOLE}/activity/dashboard",
    "identity": f"{FALCON_CONSOLE}/identity-protection/overview",
    "cloud_security": f"{FALCON_CONSOLE}/cloud-security/overview",
    "exposure": f"{FALCON_CONSOLE}/exposure-management/assets",
}


def falcon_link(section: str, label: str = None) -> str:
    """Return a markdown link to the Falcon console section."""
    url = FALCON_LINKS.get(section, FALCON_CONSOLE)
    text = label or "Open in Falcon"
    return f"[{text}]({url})"


def falcon_detection_url(composite_id: str) -> str:
    """Return a direct URL to a specific detection in the Falcon console."""
    return f"{FALCON_CONSOLE}/unified-detections/{composite_id}"


def falcon_case_url(case_id: str) -> str:
    """Return a direct URL to a specific case in the Falcon console."""
    return f"{FALCON_CONSOLE}/xdr/cases/{case_id}"


def severity_hex(severity: str) -> str:
    s = severity.lower() if severity else ""
    if "critical" in s:
        return "#DC2626"
    elif "high" in s:
        return "#EA580C"
    elif "medium" in s:
        return "#CA8A04"
    elif "low" in s:
        return "#16A34A"
    return "#2563EB"


def format_bytes(b: int) -> str:
    """Convert integer bytes to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(b) < 1024:
            return f"{b:,.1f} {unit}" if unit != "B" else f"{b:,} B"
        b /= 1024
    return f"{b:,.1f} EB"


def render_kpi_card(label: str, value, color: str = "#E8272C", trend=None):
    trend_html = ""
    if trend is not None:
        if trend > 0:
            trend_html = f'<span style="color: #DC2626; font-size: 0.8rem;"> +{trend}</span>'
        elif trend < 0:
            trend_html = f'<span style="color: #16A34A; font-size: 0.8rem;"> {trend}</span>'
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">{label}</div>
        <div class="kpi-value" style="color: {color};">{value}{trend_html}</div>
    </div>
    """, unsafe_allow_html=True)


SCOPE_TAB_MAP = {
    "Alerts:read": "Exec Summary / Detections",
    "Hosts:read": "Exec Summary",
    "Cases:read": "Cases",
    "Spotlight Vulnerabilities:read": "Vulnerabilities",
    "ThreatGraph:read": "IOC Search",
    "Incidents:read": "Exec Summary",
    "Discover:read": "Exec Summary",
    "Exposure Management:read": "Exposure",
    "Zero Trust Assessment:read": "Exec Summary",
    "Sensor Update Policies:read": "Exec Summary",
    "Prevention Policies:read": "Exec Summary",
    "NGSIEM:read": "Data Ingestion",
    "Identity Protection:read": "Identity",
    "Cloud Security:read": "Cloud Security",
    "MSSP:read": "Exec Summary",
}


def render_scope_hint(scope_name: str):
    """Show scope status from posture data if available."""
    posture = st.session_state.get("posture_data")
    if posture:
        scopes = posture.get("api_scopes", [])
        for s in scopes:
            if s["scope"] == scope_name:
                if s["status"] == "Missing":
                    st.error(f"**{scope_name}** scope is **not enabled** on this API client.")
                elif s["status"] == "Error":
                    st.warning(f"**{scope_name}** scope could not be verified.")
                else:
                    st.info(f"**{scope_name}** scope is active — the error may be transient.")
                return
    # Fallback if posture data not available yet
    st.info(f"Ensure the **{scope_name}** API scope is enabled for this API client.")


def safe_json_parse(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def export_buttons(data, prefix: str):
    col1, col2 = st.columns([1, 1])
    with col1:
        st.download_button(
            "Export JSON",
            data=json.dumps(data, indent=2),
            file_name=f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            key=f"json_{prefix}"
        )
    with col2:
        if isinstance(data, dict):
            for key in ["alerts", "cases", "incidents", "detections", "vulnerabilities", "devices"]:
                if key in data and isinstance(data[key], list):
                    df = pd.DataFrame(data[key])
                    st.download_button(
                        "Export CSV",
                        data=df.to_csv(index=False),
                        file_name=f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        key=f"csv_{prefix}"
                    )
                    break


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# Auto-scroll JS snippet for chat containers
_SCROLL_JS = """
<script>
    const frame = window.frameElement;
    if (frame) {
        let el = frame.closest('[data-testid="stVerticalBlockBorderWrapper"]');
        if (!el) {
            el = frame.parentElement;
            while (el) {
                const style = window.getComputedStyle(el);
                if (style.overflowY === 'auto' || style.overflowY === 'scroll') break;
                el = el.parentElement;
            }
        }
        if (el) el.scrollTop = el.scrollHeight;
    }
</script>
"""


def stream_to_chat(container, text, label="Vantage AI"):
    """Stream text word-by-word into a chat container with typewriter effect."""
    escaped = html.escape(text)
    with container:
        placeholder = st.empty()
        streamed = ""
        words = escaped.split(' ')
        for i, word in enumerate(words):
            streamed += word + (' ' if i < len(words) - 1 else '')
            placeholder.markdown(
                f'<div class="chat-assistant"><strong>{label}:</strong> {streamed}▌</div>',
                unsafe_allow_html=True
            )
            time.sleep(0.02)
        # Final render without cursor
        placeholder.markdown(
            f'<div class="chat-assistant"><strong>{label}:</strong> {escaped}</div>',
            unsafe_allow_html=True
        )
        # Auto-scroll to bottom
        components.html(_SCROLL_JS, height=0)



# ============ SIDEBAR ============

with st.sidebar:
    st.markdown("### Falcon Vantage")

    st.markdown(
        '<span class="status-dot status-connected"></span> **Falcon API Connected**',
        unsafe_allow_html=True
    )

    # --- CID Profile Selector ---
    env_profiles = parse_env_profiles()
    if len(env_profiles) > 1:
        profile_names = [p["name"] for p in env_profiles]
        active_idx = next((i for i, p in enumerate(env_profiles) if p["active"]), 0)
        selected_profile = st.selectbox(
            "CID Profile",
            profile_names,
            index=active_idx,
            format_func=lambda n: next(
                (f"{p['name']}  ({p['client_id_short']})" for p in env_profiles if p["name"] == n), n
            ),
            key="cid_profile_select",
        )
        if selected_profile != env_profiles[active_idx]["name"]:
            if switch_env_profile(selected_profile):
                # Clear caches and session state
                from crwd_mcp_server import clear_client_cache
                try:
                    clear_client_cache()
                except Exception:
                    pass
                falcon_cache.check_cid_change()
                for key in ["posture_data", "detections_data", "cases_data", "vulns_data",
                             "tg_edge_types", "ingestion_data", "identity_data",
                             "cloud_security_data", "exposure_data",
                             "_cache_sync_count"]:
                    st.session_state.pop(key, None)
                falcon_cache.force_refresh()
                time.sleep(0.2)
                _cid_prog = st.empty()
                _cid_stat = st.empty()
                while falcon_cache.is_refreshing:
                    pct = falcon_cache.refresh_progress
                    _cid_prog.progress(pct, text=f"Switching CID... {int(pct * 100)}%")
                    status = falcon_cache.refresh_status
                    loading = [k for k, v in status.items() if v == "loading"]
                    if loading:
                        _cid_stat.caption(f"Fetching: {', '.join(loading)}")
                    time.sleep(0.3)
                _cid_prog.empty()
                _cid_stat.empty()
                st.rerun()
    else:
        st.caption("Credentials loaded from .env")

    # Subscriptions + API Scopes — render from session state or cache
    _posture_for_sidebar = st.session_state.get("posture_data")
    if not _posture_for_sidebar:
        _cached_posture = falcon_cache.get_parsed("security_posture")
        if _cached_posture and "error" not in _cached_posture:
            _posture_for_sidebar = _cached_posture

    if _posture_for_sidebar:
        subs = _posture_for_sidebar.get("subscriptions", [])
        if subs:
            with st.expander(f"Subscriptions ({len(subs)})", expanded=False):
                for s in subs:
                    icon = '<span style="color: #4ADE80;">&#x2713;</span>'
                    alert_info = f" ({s['alerts']} alerts)" if "alerts" in s else ""
                    st.markdown(
                        f'{icon} **{s["module"]}**{alert_info}',
                        unsafe_allow_html=True
                    )

        api_scopes = _posture_for_sidebar.get("api_scopes", [])
        missing = _posture_for_sidebar.get("missing_scopes", [])
        if api_scopes:
            _status_order = {"Missing": 0, "Error": 1, "Active": 2}
            sorted_scopes = sorted(api_scopes, key=lambda e: _status_order.get(e.get("status", "Active"), 2))
            affected_tabs = sorted({
                SCOPE_TAB_MAP.get(e["scope"], e.get("section", "Unknown"))
                for e in api_scopes if e.get("status") in ("Missing", "Error")
            })
            scope_label = f"API Scopes ({len(api_scopes) - len(missing)}/{len(api_scopes)} active)"
            if missing:
                summary = f"{len(missing)} missing — {', '.join(affected_tabs)} tabs affected"
            else:
                summary = None
            with st.expander(scope_label, expanded=len(missing) > 0):
                if summary:
                    st.caption(f":red[{summary}]")
                for entry in sorted_scopes:
                    status = entry.get("status", "Unknown")
                    tab_name = SCOPE_TAB_MAP.get(entry["scope"], entry.get("section", ""))
                    if status == "Active":
                        st.markdown(
                            f'<span style="color:#4ADE80;">&#x2713;</span> '
                            f'**{entry["scope"]}** — {tab_name}',
                            unsafe_allow_html=True
                        )
                    elif status == "Missing":
                        st.markdown(
                            f'<span style="color:#EF4444;">&#x2717; '
                            f'<b>{entry["scope"]}</b> — {tab_name} tab</span>',
                            unsafe_allow_html=True
                        )
                    else:
                        st.markdown(
                            f'<span style="color:#FBBF24;">&#x26A0; '
                            f'<b>{entry["scope"]}</b> — {tab_name}</span>',
                            unsafe_allow_html=True
                        )
                if affected_tabs:
                    st.divider()
                    tabs_str = ", ".join(affected_tabs)
                    st.caption(f":red[Affected tabs: {tabs_str}]")
                    st.caption("Enable missing scopes in Falcon Console > API Clients & Keys.")

    _sidebar_chat_ph = st.empty()

    st.divider()

    if falcon_cache.is_running:
        st.markdown(
            '<span class="status-dot status-connected"></span> **Data Cache Active**',
            unsafe_allow_html=True
        )
        cache_meta = []
        cache_meta.append(f"Entries: {falcon_cache.entry_count}")
        cache_meta.append(f"Refreshes: {falcon_cache.refresh_count}")
        if falcon_cache.last_refresh:
            cache_meta.append(f"Last: {falcon_cache.last_refresh.strftime('%H:%M:%S')}")
        if falcon_cache.last_refresh_duration is not None:
            cache_meta.append(f"Duration: {falcon_cache.last_refresh_duration:.1f}s")
        st.caption(" | ".join(cache_meta))
        if st.session_state.get("cache_loaded_from_file") and falcon_cache.refresh_count == 0:
            st.caption("Data: Stale (from cache file)")
        else:
            st.caption("Data: Live")
        errs = falcon_cache.recent_errors
        if errs:
            with st.expander(f"Cache Errors ({len(errs)})"):
                for e in errs:
                    st.caption(e)
        # Cache restart button
        if st.button("Refresh Cache Now", key="cache_refresh_btn", width="stretch"):
            falcon_cache.force_refresh()
            time.sleep(0.2)  # let the thread start
            _prog = st.empty()
            _stat = st.empty()
            while falcon_cache.is_refreshing:
                pct = falcon_cache.refresh_progress
                _prog.progress(pct, text=f"Refreshing... {int(pct * 100)}%")
                status = falcon_cache.refresh_status
                loading = [k for k, v in status.items() if v == "loading"]
                if loading:
                    _stat.caption(f"Fetching: {', '.join(loading)}")
                time.sleep(0.3)
            _prog.empty()
            _stat.empty()
            st.rerun()
    else:
        st.markdown(
            '<span class="status-dot status-disconnected"></span> **Data Cache Inactive**',
            unsafe_allow_html=True
        )
        if st.button("Start Cache", key="cache_start_btn", width="stretch"):
            falcon_cache.start(poll_interval=300, ttl=300)
            st.rerun()

    st.divider()

    auto_refresh = st.toggle("Auto-refresh", value=False)
    if auto_refresh:
        refresh_interval = st.slider("Refresh interval (sec)", 30, 300, 60)
        st.caption(f"Refreshing every {refresh_interval}s")

    cache_interval = st.slider("Cache poll interval (sec)", 60, 600, 300, key="cache_poll")
    if falcon_cache.is_running and falcon_cache.poll_interval != cache_interval:
        falcon_cache.poll_interval = cache_interval
        falcon_cache.ttl = cache_interval

    st.divider()

    with st.expander("Severity Definitions"):
        st.markdown("""
        - **Critical** - Active threat, immediate response
        - **High** - Strong malicious indicators
        - **Medium** - Suspicious, needs investigation
        - **Low** - Minor anomaly
        - **Info** - Logged for awareness
        """)

    with st.expander("Case Status"):
        st.markdown("""
        | Status | Description |
        |--------|-------------|
        | New | Not yet reviewed |
        | Open | Under investigation |
        | In Progress | Actively worked |
        | Reopened | Re-opened |
        | Closed | Resolved |
        """)

    with st.expander("FQL Quick Reference"):
        st.code("field:'value'          # Exact match")
        st.code("field:>value           # Greater than")
        st.code("filter1+filter2        # AND")
        st.code("filter1,filter2        # OR")
        st.code("field:['v1','v2']      # IN")

    with st.expander("Help"):
        st.markdown("""
**Tabs**
- **Executive Summary** — Risk score, KPIs, severity charts, and critical items at a glance
- **Detections** — Search and filter endpoint detections (EPP)
- **Cases** — Browse and filter CrowdStrike cases
- **Vulnerabilities** — Spotlight vulnerability data with CVE details
- **ThreatGraph** — IOC search
- **FQL Tools** — Validate FQL filters, look up hosts, browse products

**AI Chat** *(floating panel)*
- Click "Open AI Chat" in the sidebar to open the floating assistant
- Drag the header bar to reposition the panel anywhere on screen
- Click X or "Close AI Chat" to dismiss
- Responses stream in word-by-word with auto-scroll

**Cache Daemon** *(optional, for faster startup)*
- Run `python falcon_cache_daemon.py` to keep data warm in the background
- The dashboard loads cached data instantly when the daemon is running

**Tips**
- Export data as JSON or CSV from any tab
- Adjust the cache poll interval in the sidebar
        """)

    st.divider()
    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

# ============ CHAT STATE ============

if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []
if "chat_open" not in st.session_state:
    st.session_state.chat_open = False

# ============ HEADER ============

st.markdown("""
<div class="main-header">
    <h1>Falcon Vantage</h1>
</div>
""", unsafe_allow_html=True)

# ============ FULL-WIDTH TABS ============

tab_exec, tab_detections, tab_cases, tab_ingestion, tab_vulns, tab_tg, tab_identity, tab_cloud, tab_exposure, tab_fql = st.tabs([
    "Executive Summary",
    "Detections",
    "Cases",
    "Data Ingestion",
    "Vulnerabilities",
    "IOC Search",
    "Identity",
    "Cloud Security",
    "Exposure",
    "FQL Tools"
])

# ============ TAB 1: EXECUTIVE SUMMARY ============

with tab_exec:
    st.subheader("Security Posture Overview")
    hdr_left, hdr_right = st.columns([3, 1])
    with hdr_left:
        st.caption(f"{falcon_link('dashboard', 'View Falcon Dashboard')}")
    with hdr_right:
        exec_hours = st.selectbox("Reporting period", [6, 12, 24, 48, 72, 168], index=2,
                                  format_func=lambda x: f"Last {x}h" if x < 168 else "Last 7d",
                                  key="exec_hours", label_visibility="collapsed")

    # Auto-load on first visit: try cache, fallback to live API
    if "posture_data" not in st.session_state:
        cached = falcon_cache.get_parsed("security_posture")
        if cached and "error" not in cached:
            st.session_state["posture_data"] = cached
        else:
            with st.spinner("Loading security posture..."):
                result = run_async(get_security_posture(hours=exec_hours))
                data = safe_json_parse(result)
                if data and "error" not in data:
                    st.session_state["posture_data"] = data

    data = st.session_state.get("posture_data")

    # ---- CRITICAL ACTIONS PANEL ----
    if data and "error" not in data:
        critical_dets = data.get("alerts", {}).get("by_severity", {}).get("Critical", 0)
        critical_vulns = data.get("vulnerabilities", {}).get("by_severity", {}).get("Critical", 0)
        open_cases = data.get("cases", {}).get("by_status", {}).get("New", 0) + data.get("cases", {}).get("by_status", {}).get("Open", 0)
        contained_hosts = data.get("hosts", {}).get("contained_count", 0)
        stale_hosts = data.get("hosts", {}).get("stale_count", 0)

        if critical_dets > 0 or critical_vulns > 0 or open_cases > 0 or contained_hosts > 0:
            action_items = []
            if critical_dets > 0:
                action_items.append(f'<strong>{critical_dets}</strong> critical detection{"s" if critical_dets != 1 else ""} need triage')
            if critical_vulns > 0:
                action_items.append(f'<strong>{critical_vulns}</strong> critical vulnerability{"ies" if critical_vulns != 1 else "y"} to remediate')
            if open_cases > 0:
                action_items.append(f'<strong>{open_cases}</strong> open case{"s" if open_cases != 1 else ""} awaiting action')
            if contained_hosts > 0:
                action_items.append(f'<strong>{contained_hosts}</strong> host{"s" if contained_hosts != 1 else ""} currently contained')

            st.markdown(
                '<span style="color:#DC2626; font-weight:700;">Action Required:</span> '
                + ' &bull; '.join(f'<span style="color:#DC2626;">{item}</span>' for item in action_items),
                unsafe_allow_html=True
            )

    if data:
        # CrowdScore gauge or fallback Risk Score
        crowdscore = data.get("crowdscore", {})
        cs_current = crowdscore.get("current")
        if cs_current is not None and cs_current > 0:
            cs_col1, cs_col2 = st.columns([1, 2])
            with cs_col1:
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number", value=cs_current,
                    gauge={"axis": {"range": [0, 100]},
                           "bar": {"color": severity_hex(data.get("risk_level", "low"))},
                           "steps": [
                               {"range": [0, 25], "color": "#DCFCE7"},
                               {"range": [25, 50], "color": "#FEF9C3"},
                               {"range": [50, 75], "color": "#FED7AA"},
                               {"range": [75, 100], "color": "#FECACA"}
                           ]},
                    title={"text": "CrowdScore"}
                ))
                fig_gauge.update_layout(height=200, margin=dict(l=20, r=20, t=40, b=20))
                st.plotly_chart(fig_gauge, width="stretch")
            with cs_col2:
                trend = crowdscore.get("trend_7d", [])
                if trend:
                    df_trend = pd.DataFrame(trend)
                    df_trend["timestamp"] = pd.to_datetime(df_trend["timestamp"], errors="coerce")
                    fig_spark = px.line(df_trend, x="timestamp", y="score")
                    fig_spark.update_layout(height=200, margin=dict(l=20, r=20, t=30, b=20),
                                            xaxis_title="", yaxis_title="CrowdScore")
                    fig_spark.update_traces(line_color="#E8272C")
                    st.plotly_chart(fig_spark, width="stretch")

        k1, k2, k3, k4, k5 = st.columns(5)
        with k1:
            render_kpi_card("Risk Score", data.get("risk_score", 0), severity_hex(data.get("risk_level", "low")))
        with k2:
            render_kpi_card("Alerts", data["alerts"]["total"], "#2563EB")
        with k3:
            render_kpi_card("Cases", data["cases"]["total"], "#EA580C")
        with k4:
            render_kpi_card("Vulnerabilities", data["vulnerabilities"]["total"], "#7C3AED")
        with k5:
            render_kpi_card("Hosts", data.get("hosts", {}).get("total", 0), "#0891B2")

        # MTTD / MTTR
        mttd_data = data.get("mttd_mttr", {})
        if mttd_data.get("sample_size", 0) > 0:
            st.markdown("**Response Time Metrics**")
            m1, m2, m3 = st.columns(3)
            with m1:
                triaged_sec = mttd_data.get("avg_seconds_to_triaged")
                if triaged_sec:
                    render_kpi_card("MTTD (Avg)", f"{triaged_sec // 3600}h {(triaged_sec % 3600) // 60}m", "#2563EB")
            with m2:
                resolved_sec = mttd_data.get("avg_seconds_to_resolved")
                if resolved_sec:
                    render_kpi_card("MTTR (Avg)", f"{resolved_sec // 3600}h {(resolved_sec % 3600) // 60}m", "#16A34A")
            with m3:
                render_kpi_card("Sample Size", mttd_data["sample_size"], "#6B7280")

        # Incidents summary
        inc_data = data.get("incidents", {})
        if inc_data.get("total", 0) > 0:
            st.markdown("**Incidents**")
            i1, i2 = st.columns(2)
            with i1:
                render_kpi_card("Total Incidents", inc_data["total"], "#DC2626")
                by_state = inc_data.get("by_state", {})
                if by_state:
                    fig = go.Figure(data=[go.Pie(labels=list(by_state.keys()), values=list(by_state.values()), hole=0.4)])
                    fig.update_layout(height=200, margin=dict(l=0, r=0, t=0, b=0), showlegend=True)
                    st.plotly_chart(fig, width="stretch")
            with i2:
                by_tactic = inc_data.get("by_tactic", {})
                if by_tactic:
                    st.markdown("**Top MITRE Tactics (Incidents)**")
                    fig = go.Figure(data=[go.Bar(
                        x=list(by_tactic.values()), y=list(by_tactic.keys()),
                        orientation="h", marker_color="#E8272C"
                    )])
                    fig.update_layout(height=200, margin=dict(l=20, r=20, t=10, b=20),
                                      plot_bgcolor="#FFFFFF", paper_bgcolor="rgba(0,0,0,0)")
                    st.plotly_chart(fig, width="stretch")

        # Sensor Health
        sh = data.get("sensor_health", {})
        if sh.get("total_managed", 0) > 0:
            st.markdown("**Sensor Health**")
            s1, s2, s3 = st.columns(3)
            with s1:
                render_kpi_card("RFM Hosts", sh.get("rfm_count", 0), "#DC2626" if sh.get("rfm_count", 0) > 0 else "#16A34A")
            with s2:
                total = sh.get("total_managed", 1)
                stale = data.get("hosts", {}).get("stale_count", 0)
                active = total - stale
                pct = round(active / total * 100, 1) if total > 0 else 0
                render_kpi_card("Coverage", f"{pct}%", "#16A34A" if pct > 90 else "#EA580C")
            with s3:
                by_ver = sh.get("by_version", {})
                if by_ver:
                    st.markdown("**Top Sensor Versions**")
                    for ver, cnt in list(by_ver.items())[:3]:
                        st.caption(f"`{ver}` — {cnt} hosts")

        # Asset Inventory (Discover)
        assets = data.get("asset_inventory", {})
        has_asset_data = any(assets.get(k, 0) > 0 for k in ["managed_hosts", "unmanaged_hosts", "iot_assets", "accounts"])
        if has_asset_data:
            st.markdown("**Asset Inventory (Discover)**")
            a1, a2, a3, a4, a5 = st.columns(5)
            with a1:
                render_kpi_card("Managed", assets.get("managed_hosts", 0), "#16A34A")
            with a2:
                render_kpi_card("Unmanaged", assets.get("unmanaged_hosts", 0), "#EA580C")
            with a3:
                render_kpi_card("IoT", assets.get("iot_assets", 0), "#2563EB")
            with a4:
                render_kpi_card("Accounts", assets.get("accounts", 0), "#7C3AED")
            with a5:
                render_kpi_card("Applications", assets.get("applications", 0), "#0891B2")

        # External Attack Surface
        eas = data.get("external_attack_surface", {})
        if eas.get("total_assets", 0) > 0:
            st.markdown("**External Attack Surface**")
            render_kpi_card("Internet-Facing Assets", eas["total_assets"], "#DC2626")

        # Row 1: Severity Distribution + Cases by Status
        row1_col1, row1_col2 = st.columns(2)

        with row1_col1:
            st.markdown("**Severity Distribution**")
            categories = []
            for sev, count in data["alerts"].get("by_severity", {}).items():
                categories.append({"Source": "Alerts", "Severity": sev, "Count": count})
            for sev, count in data["vulnerabilities"].get("by_severity", {}).items():
                categories.append({"Source": "Vulnerabilities", "Severity": sev, "Count": count})

            if categories:
                df_sev = pd.DataFrame(categories)
                color_map = {"Critical": "#DC2626", "High": "#EA580C", "Medium": "#CA8A04",
                             "Low": "#16A34A", "Informational": "#2563EB"}
                fig_bar = px.bar(df_sev, x="Source", y="Count", color="Severity",
                                 color_discrete_map=color_map, barmode="stack")
                fig_bar.update_layout(
                    plot_bgcolor="#FFFFFF", paper_bgcolor="rgba(0,0,0,0)",
                    margin=dict(l=20, r=20, t=10, b=20), height=220,
                    legend=dict(orientation="h", y=-0.2), font=dict(color="#1E1E2F")
                )
                st.plotly_chart(fig_bar, width="stretch")

        with row1_col2:
            st.markdown("**Cases by Status**")
            case_status = data["cases"].get("by_status", {})
            if case_status:
                status_colors = {"New": "#2563EB", "Open": "#EA580C", "In Progress": "#CA8A04", "Reopened": "#7C3AED", "Closed": "#16A34A"}
                fig_cases = go.Figure(data=[go.Bar(
                    x=list(case_status.values()), y=list(case_status.keys()),
                    orientation="h",
                    marker_color=[status_colors.get(s, "#6B7280") for s in case_status.keys()],
                    text=list(case_status.values()), textposition="auto"
                )])
                fig_cases.update_layout(
                    plot_bgcolor="#FFFFFF", paper_bgcolor="rgba(0,0,0,0)",
                    margin=dict(l=20, r=20, t=10, b=20), height=220,
                    xaxis_title="Count", font=dict(color="#1E1E2F")
                )
                st.plotly_chart(fig_cases, width="stretch")
            else:
                st.info("No case status data available")

        # Row 1b: Detection Time Buckets + Tactics Timechart
        row1b_col1, row1b_col2 = st.columns(2)

        with row1b_col1:
            st.markdown("**Detections by Time Window**")
            time_buckets = data.get("alerts", {}).get("by_time_bucket", {})
            if time_buckets:
                bucket_labels = {"last_1h": "Last 1h", "last_4h": "Last 4h", "last_8h": "Last 8h", "last_24h": "Last 24h"}
                bucket_data = []
                for key in ["last_1h", "last_4h", "last_8h", "last_24h"]:
                    if key in time_buckets:
                        bucket_data.append({"Window": bucket_labels.get(key, key), "Count": time_buckets[key]})
                if bucket_data:
                    fig_buckets = go.Figure(data=[go.Bar(
                        x=[b["Window"] for b in bucket_data],
                        y=[b["Count"] for b in bucket_data],
                        marker_color=["#DC2626", "#EA580C", "#CA8A04", "#2563EB"],
                        text=[b["Count"] for b in bucket_data],
                        textposition="auto"
                    )])
                    fig_buckets.update_layout(
                        plot_bgcolor="#FFFFFF", paper_bgcolor="rgba(0,0,0,0)",
                        margin=dict(l=20, r=20, t=10, b=20), height=220,
                        yaxis_title="Detections", font=dict(color="#1E1E2F")
                    )
                    st.plotly_chart(fig_buckets, width="stretch")
            else:
                st.info("No time-bucketed data available")

        with row1b_col2:
            st.markdown("**Attack Tactics Timeline**")
            tactic_timeline = data.get("alerts", {}).get("tactic_timeline", [])
            if tactic_timeline:
                df_timeline = pd.DataFrame(tactic_timeline)
                df_timeline["timestamp"] = pd.to_datetime(df_timeline["timestamp"], errors="coerce")
                df_timeline = df_timeline.dropna(subset=["timestamp"])
                if not df_timeline.empty:
                    # Bin into hourly buckets and count per tactic
                    df_timeline["hour"] = df_timeline["timestamp"].dt.floor("h")
                    df_grouped = df_timeline.groupby(["hour", "tactic"]).size().reset_index(name="count")
                    fig_tl = px.bar(
                        df_grouped, x="hour", y="count", color="tactic",
                        barmode="stack",
                    )
                    fig_tl.update_layout(
                        plot_bgcolor="#FFFFFF", paper_bgcolor="rgba(0,0,0,0)",
                        margin=dict(l=20, r=20, t=10, b=20), height=220,
                        xaxis_title="Time", yaxis_title="Detections",
                        legend=dict(orientation="h", y=-0.3), font=dict(color="#1E1E2F")
                    )
                    st.plotly_chart(fig_tl, width="stretch")
                else:
                    st.info("No tactic timeline data available")
            else:
                st.info("No tactic timeline data available")

        # Row 2: Top Critical Detections + Top Critical Vulnerabilities
        row2_col1, row2_col2 = st.columns(2)

        with row2_col1:
            st.markdown(f"**Critical/High Detections** &nbsp; {falcon_link('detections')}")
            cached_dets = falcon_cache.get_parsed("detections_recent")
            top_dets = []
            if cached_dets and isinstance(cached_dets, dict) and "detections" in cached_dets:
                for d in cached_dets["detections"]:
                    sev = (d.get("severity") or "").lower()
                    if sev in ("critical", "high"):
                        top_dets.append(d)
            if top_dets:
                det_rows = []
                for d in top_dets[:5]:
                    det_rows.append({
                        "Severity": d.get("severity", "N/A"),
                        "Tactic": d.get("tactic", "N/A"),
                        "Hostname": d.get("hostname", "N/A"),
                        "Status": d.get("status", "N/A"),
                    })
                st.dataframe(pd.DataFrame(det_rows), width="stretch", hide_index=True, height=210)
            else:
                st.info("No critical/high detections found")

        with row2_col2:
            st.markdown(f"**Critical Vulnerabilities** &nbsp; {falcon_link('vulnerabilities')}")
            critical_vulns = falcon_cache.get_parsed("vulnerabilities_critical")
            if critical_vulns and isinstance(critical_vulns, dict) and "vulnerabilities" in critical_vulns:
                vuln_rows = []
                for v in critical_vulns["vulnerabilities"][:5]:
                    vuln_rows.append({
                        "CVE": v.get("cve_id", "N/A"),
                        "CVSS": v.get("base_score", "N/A"),
                        "Host": v.get("hostname", "N/A"),
                        "App": v.get("app_name", "N/A"),
                    })
                st.dataframe(pd.DataFrame(vuln_rows), width="stretch", hide_index=True, height=210)
            else:
                st.info("No critical vulnerabilities found")

        # API errors (if any)
        errors = []
        for source in ["cases", "detections", "vulnerabilities"]:
            if data.get(source, {}).get("error"):
                errors.append(f"**{source.title()}**: {data[source]['error']}")
        if errors:
            with st.expander("API Errors", expanded=False):
                for err in errors:
                    st.warning(err)

        export_buttons(data, "security_posture")

# ============ TAB 2: DETECTIONS ============

with tab_detections:
    st.subheader("Detections")
    st.caption(f"Search Falcon endpoint detections | {falcon_link('detections', 'Open in Falcon')}")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        det_severity = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low", "Informational"], key="det_sev")
        det_severity_val = None if det_severity == "All" else det_severity.lower()
    with col2:
        det_status = st.selectbox("Status", ["All", "new", "in_progress", "true_positive", "false_positive", "closed"], key="det_status")
        det_status_val = None if det_status == "All" else det_status
    with col3:
        det_hours = st.selectbox("Reporting period", [6, 12, 24, 48, 72, 168], index=2,
                                 format_func=lambda x: f"Last {x}h" if x < 168 else "Last 7d",
                                 key="det_hours")
    with col4:
        det_limit = st.number_input("Max Results", min_value=1, max_value=500, value=50, key="det_limit")

    if st.button("Search", type="primary", key="search_detections_btn"):
        with st.spinner("Searching detections..."):
            result = run_async(search_detections(
                severity=det_severity_val, status=det_status_val,
                hours=int(det_hours), limit=int(det_limit)
            ))
            data = safe_json_parse(result)
            if data and "error" not in data:
                st.session_state["detections_data"] = data
            elif data and "error" in data:
                st.error(data["error"])
            else:
                st.error(result)

    # Auto-load on first visit: try cache, fallback to live API
    if "detections_data" not in st.session_state:
        cached = falcon_cache.get_parsed("detections_recent")
        if cached and cached.get("detections"):
            st.session_state["detections_data"] = cached
        else:
            with st.spinner("Loading detections..."):
                result = run_async(search_detections(hours=24, limit=50))
                data = safe_json_parse(result)
                if data and "error" not in data:
                    st.session_state["detections_data"] = data

    detections_data = st.session_state.get("detections_data")
    if detections_data:
        st.success(f"Found {detections_data['total_found']} results")

        with st.expander("FQL Filter Used"):
            st.code(detections_data.get("query_filter", ""), language="text")

        items = detections_data.get("detections", [])
        if items:
            for item in items:
                item["falcon_link"] = falcon_detection_url(item.get("id", ""))
            df = pd.DataFrame(items)
            # Ensure View in Falcon is the first column
            if "falcon_link" in df.columns:
                cols = ["falcon_link"] + [c for c in df.columns if c != "falcon_link"]
                df = df[cols]
            st.dataframe(
                df,
                width="stretch",
                hide_index=True,
                column_config={
                    "falcon_link": st.column_config.LinkColumn("View in Falcon", display_text="Open"),
                    "severity": st.column_config.TextColumn("Severity", width="small"),
                    "status": st.column_config.TextColumn("Status", width="small"),
                    "hostname": st.column_config.TextColumn("Hostname"),
                    "tactic": st.column_config.TextColumn("MITRE Tactic"),
                    "technique": st.column_config.TextColumn("MITRE Technique"),
                    "description": st.column_config.TextColumn("Description", width="large"),
                    "timestamp": st.column_config.TextColumn("Timestamp"),
                    "id": None,
                }
            )
            export_buttons(detections_data, "detections")
        else:
            st.info("No detections found matching criteria")

# ============ TAB 3: CASES ============

with tab_cases:
    st.subheader("CrowdStrike Cases")
    st.caption(f"{falcon_link('cases', 'Open in Falcon')}")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        case_status = st.selectbox("Status", ["All", "New", "Open", "In Progress", "Reopened", "Closed"], key="case_status")
        case_status_val = None if case_status == "All" else case_status.lower().replace(" ", "_")
    with col2:
        case_severity = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"], key="case_sev")
        case_severity_val = None if case_severity == "All" else case_severity.lower()
    with col3:
        case_hours = st.selectbox("Reporting period", [6, 12, 24, 48, 72, 168], index=4,
                                  format_func=lambda x: f"Last {x}h" if x < 168 else "Last 7d",
                                  key="case_hours")
    with col4:
        case_limit = st.number_input("Max Results", min_value=1, max_value=500, value=50, key="case_limit")

    if st.button("Search Cases", type="primary", key="search_cases_btn"):
        with st.spinner("Searching cases..."):
            result = run_async(search_cases(
                status=case_status_val, severity=case_severity_val,
                hours=int(case_hours), limit=int(case_limit)
            ))
            data = safe_json_parse(result)
            if data and "error" not in data:
                st.session_state["cases_data"] = data
            elif data and "error" in data:
                st.error(data["error"])
            else:
                st.error(result)

    # Auto-load on first visit: try cache, fallback to live API
    if "cases_data" not in st.session_state:
        cached = falcon_cache.get_parsed("cases_recent")
        if cached and "error" not in cached:
            st.session_state["cases_data"] = cached
        else:
            with st.spinner("Loading cases..."):
                result = run_async(search_cases(hours=72, limit=50))
                data = safe_json_parse(result)
                if data and "error" not in data:
                    st.session_state["cases_data"] = data

    cases_data = st.session_state.get("cases_data")
    if cases_data:
        st.success(f"Found {cases_data['total_found']} cases")

        if cases_data.get("cases"):
            display_items = []
            for case in cases_data["cases"]:
                item = dict(case)
                item["tags"] = ", ".join(case.get("tags", []))
                item["falcon_link"] = falcon_case_url(item.get("id", ""))
                display_items.append(item)

            df = pd.DataFrame(display_items)
            # Ensure View in Falcon is the first column
            if "falcon_link" in df.columns:
                cols = ["falcon_link"] + [c for c in df.columns if c != "falcon_link"]
                df = df[cols]
            st.dataframe(
                df,
                width="stretch",
                hide_index=True,
                column_config={
                    "falcon_link": st.column_config.LinkColumn("View in Falcon", display_text="Open"),
                    "severity": st.column_config.TextColumn("Severity", width="small"),
                    "status": st.column_config.TextColumn("Status", width="small"),
                    "title": st.column_config.TextColumn("Title"),
                    "assigned_to": st.column_config.TextColumn("Assigned To"),
                    "description": st.column_config.TextColumn("Description", width="large"),
                    "tags": st.column_config.TextColumn("Tags"),
                    "id": None,
                }
            )
            export_buttons(cases_data, "cases")
        else:
            st.info("No cases found matching criteria")

# ============ TAB 4: VULNERABILITIES ============

with tab_vulns:
    st.subheader("Spotlight Vulnerabilities")
    st.caption(f"{falcon_link('vulnerabilities', 'Open in Falcon')}")

    col1, col2, col3 = st.columns(3)
    with col1:
        vuln_severity = st.selectbox("CVE Severity", ["All", "Critical", "High", "Medium", "Low"], key="vuln_sev")
        vuln_severity_val = None if vuln_severity == "All" else vuln_severity.lower()
    with col2:
        vuln_status = st.selectbox("Status", ["All", "open", "closed"], key="vuln_status")
        vuln_status_val = None if vuln_status == "All" else vuln_status
    with col3:
        vuln_limit = st.number_input("Max Results", min_value=1, max_value=500, value=50, key="vuln_limit")

    if st.button("Search Vulnerabilities", type="primary", key="search_vulns_btn"):
        with st.spinner("Searching vulnerabilities..."):
            result = run_async(search_vulnerabilities(
                severity=vuln_severity_val, status=vuln_status_val,
                limit=int(vuln_limit)
            ))
            data = safe_json_parse(result)
            if data and "error" not in data:
                st.session_state["vulns_data"] = data
            elif data and "error" in data:
                st.error(data["error"])
            else:
                st.error(result)

    # Auto-load on first visit: try cache, fallback to live API
    if "vulns_data" not in st.session_state:
        cached = falcon_cache.get_parsed("vulnerabilities_critical")
        if cached and "error" not in cached:
            st.session_state["vulns_data"] = cached
        else:
            with st.spinner("Loading vulnerabilities..."):
                result = run_async(search_vulnerabilities(severity="critical", limit=50))
                data = safe_json_parse(result)
                if data and "error" not in data:
                    st.session_state["vulns_data"] = data

    vulns_data = st.session_state.get("vulns_data")
    if vulns_data:
        st.success(f"Found {vulns_data['total_found']} vulnerabilities")

        if vulns_data.get("vulnerabilities"):
            df = pd.DataFrame(vulns_data["vulnerabilities"])
            st.dataframe(
                df,
                width="stretch",
                hide_index=True,
                column_config={
                    "cve_id": st.column_config.TextColumn("CVE ID"),
                    "severity": st.column_config.TextColumn("Severity", width="small"),
                    "base_score": st.column_config.NumberColumn("CVSS Score", format="%.1f"),
                    "hostname": st.column_config.TextColumn("Hostname"),
                    "app_name": st.column_config.TextColumn("Application"),
                    "status": st.column_config.TextColumn("Status", width="small"),
                    "description": st.column_config.TextColumn("Description", width="large"),
                }
            )
            export_buttons(vulns_data, "vulnerabilities")
        else:
            st.info("No vulnerabilities found matching criteria")

# ============ TAB 5: IDENTITY PROTECTION ============

with tab_identity:
    st.subheader("Identity Protection")
    st.caption(f"Identity threat detection and risk assessment | {falcon_link('identity', 'Open in Falcon')}")

    # Auto-load on first visit
    if "identity_data" not in st.session_state:
        with st.spinner("Loading Identity Protection data..."):
            raw = run_async(get_identity_protection(limit=50))
            data = safe_json_parse(raw)
            if data:
                st.session_state["identity_data"] = data

    if st.button("Refresh", key="refresh_identity", type="secondary"):
        with st.spinner("Loading Identity Protection data..."):
            raw = run_async(get_identity_protection(limit=50))
            data = safe_json_parse(raw)
            if data:
                st.session_state["identity_data"] = data
            st.rerun()

    idp_data = st.session_state.get("identity_data")
    if idp_data:
        if idp_data.get("error"):
            st.warning(f"Identity Protection: {idp_data['error']}")
            render_scope_hint("Identity Protection:read")
        else:
            # KPI row
            k1, k2, k3 = st.columns(3)
            with k1:
                render_kpi_card("Identity Sensors", f"{idp_data.get('total_sensors', 0):,}", color="#7C3AED")
            with k2:
                render_kpi_card("Risky Entities", str(idp_data.get("total_risky", 0)), color="#E8272C")
            with k3:
                by_status = idp_data.get("by_status", {})
                active_count = by_status.get("Active", 0)
                render_kpi_card("Active Sensors", str(active_count), color="#16A34A")

            st.markdown("---")

            # Charts row: sensor status + OS distribution
            by_status = idp_data.get("by_status", {})
            by_os = idp_data.get("by_os", {})

            if by_status or by_os:
                chart_col1, chart_col2 = st.columns(2)
                with chart_col1:
                    if by_status:
                        st.markdown("**Sensors by Status**")
                        status_colors = {"Active": "#16A34A", "Inactive": "#DC2626", "Limited Func": "#CA8A04"}
                        fig = go.Figure(go.Pie(
                            labels=list(by_status.keys()),
                            values=list(by_status.values()),
                            hole=0.4,
                            marker_colors=[status_colors.get(s, "#7C3AED") for s in by_status.keys()],
                        ))
                        fig.update_layout(
                            height=350,
                            margin=dict(l=10, r=10, t=10, b=10),
                            plot_bgcolor="rgba(0,0,0,0)",
                            paper_bgcolor="rgba(0,0,0,0)",
                            font=dict(color="#FAFAFA"),
                        )
                        st.plotly_chart(fig, width="stretch")
                with chart_col2:
                    if by_os:
                        st.markdown("**Sensors by OS**")
                        fig = go.Figure(go.Bar(
                            x=list(by_os.keys()),
                            y=list(by_os.values()),
                            marker_color="#2563EB",
                            text=list(by_os.values()),
                            textposition="auto",
                        ))
                        fig.update_layout(
                            height=350,
                            margin=dict(l=10, r=10, t=10, b=40),
                            plot_bgcolor="rgba(0,0,0,0)",
                            paper_bgcolor="rgba(0,0,0,0)",
                            font=dict(color="#FAFAFA"),
                        )
                        st.plotly_chart(fig, width="stretch")

            # Table: Top risky entities
            risky = idp_data.get("risky_entities", [])
            if risky:
                st.markdown("**Top Risky Identities**")
                df = pd.DataFrame(risky)
                display_cols = {}
                if "display_name" in df.columns:
                    display_cols["display_name"] = st.column_config.TextColumn("Name")
                if "type" in df.columns:
                    display_cols["type"] = st.column_config.TextColumn("Type", width="small")
                if "risk_score" in df.columns:
                    display_cols["risk_score"] = st.column_config.NumberColumn("Risk Score", format="%.0f")
                if "email" in df.columns:
                    display_cols["email"] = st.column_config.TextColumn("Email")
                display_cols["entity_id"] = None
                display_cols["risk_factors"] = None
                st.dataframe(df, width="stretch", hide_index=True, column_config=display_cols)

                with st.expander("Risk Factor Details"):
                    for entity in risky[:10]:
                        factors = entity.get("risk_factors", [])
                        if factors:
                            st.markdown(f"**{entity.get('display_name', 'N/A')}** (score: {entity.get('risk_score', 'N/A')})")
                            factor_rows = [{"Type": f.get("type", ""), "Severity": f.get("severity", "")} for f in factors]
                            st.dataframe(pd.DataFrame(factor_rows), hide_index=True, width="stretch")

                export_buttons(idp_data, "identity")
            elif not by_status and not by_os:
                st.info("No identity data found")
    else:
        st.info("Identity Protection data not loaded. It will load automatically or click Refresh.")

# ============ TAB 6: CLOUD SECURITY ============

with tab_cloud:
    st.subheader("Cloud Security Posture")
    st.caption(f"CSPM risk findings and misconfigurations | {falcon_link('cloud_security', 'Open in Falcon')}")

    # Filter controls
    cs_col1, cs_col2, cs_col3 = st.columns(3)
    with cs_col1:
        cs_severity = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low", "Informational"], key="cs_sev")
        cs_severity_val = None if cs_severity == "All" else cs_severity
    with cs_col2:
        cs_provider = st.selectbox("Cloud Provider", ["All", "AWS", "Azure", "GCP"], key="cs_provider")
        cs_provider_val = None if cs_provider == "All" else cs_provider
    with cs_col3:
        cs_limit = st.number_input("Max Results", min_value=1, max_value=1000, value=200, key="cs_limit")

    if st.button("Search Cloud Risks", type="primary", key="search_cloud_btn"):
        with st.spinner("Searching cloud security risks..."):
            raw = run_async(get_cloud_security(
                severity=cs_severity_val, cloud_provider=cs_provider_val, limit=int(cs_limit)
            ))
            data = safe_json_parse(raw)
            if data:
                st.session_state["cloud_security_data"] = data

    # Auto-load on first visit
    if "cloud_security_data" not in st.session_state:
        with st.spinner("Loading Cloud Security data..."):
            raw = run_async(get_cloud_security(limit=200))
            data = safe_json_parse(raw)
            if data:
                st.session_state["cloud_security_data"] = data

    cs_data = st.session_state.get("cloud_security_data")
    if cs_data:
        if cs_data.get("error"):
            st.warning(f"Cloud Security: {cs_data['error']}")
            render_scope_hint("Cloud Security:read")
        else:
            # KPI row
            k1, k2, k3, k4 = st.columns(4)
            sev = cs_data.get("risks_by_severity", {})
            with k1:
                render_kpi_card("Total Risks", f"{cs_data.get('total_risks', 0):,}", color="#E8272C")
            with k2:
                render_kpi_card("Critical", str(sev.get("Critical", 0)), color="#DC2626")
            with k3:
                render_kpi_card("High", str(sev.get("High", 0)), color="#EA580C")
            with k4:
                iom_label = f"{cs_data['iom_count']:,}" if cs_data.get("iom_count") is not None else "N/A"
                render_kpi_card("IOMs", iom_label, color="#7C3AED")

            st.markdown("---")

            # Chart row: severity bar + provider donut
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                if sev:
                    st.markdown("**Risks by Severity**")
                    sev_order = ["Critical", "High", "Medium", "Low", "Informational"]
                    sev_colors = ["#DC2626", "#EA580C", "#CA8A04", "#16A34A", "#6366F1"]
                    present = [(s, sev_order.index(s)) for s in sev_order if s in sev]
                    fig = go.Figure(go.Bar(
                        x=[s for s, _ in present],
                        y=[sev.get(s, 0) for s, _ in present],
                        marker_color=[sev_colors[i] for _, i in present],
                        text=[sev.get(s, 0) for s, _ in present],
                        textposition="auto",
                    ))
                    fig.update_layout(
                        height=350, margin=dict(l=10, r=10, t=10, b=40),
                        xaxis_title="", yaxis_title="Count",
                        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#FAFAFA"),
                    )
                    st.plotly_chart(fig, width="stretch")

            with chart_col2:
                providers = cs_data.get("risks_by_provider", {})
                if providers:
                    st.markdown("**Risks by Cloud Provider**")
                    provider_colors = {"AWS": "#FF9900", "Azure": "#0078D4", "GCP": "#4285F4"}
                    fig = go.Figure(go.Pie(
                        labels=list(providers.keys()),
                        values=list(providers.values()),
                        hole=0.4,
                        marker_colors=[provider_colors.get(p, "#7C3AED") for p in providers.keys()],
                    ))
                    fig.update_layout(
                        height=350, margin=dict(l=10, r=10, t=10, b=10),
                        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#FAFAFA"),
                    )
                    st.plotly_chart(fig, width="stretch")

            # Service category bar chart
            services = cs_data.get("risks_by_service", {})
            if services:
                st.markdown("**Top Risk Categories**")
                sorted_svc = sorted(services.items(), key=lambda x: x[1], reverse=True)[:15]
                fig = go.Figure(go.Bar(
                    y=[s[0] for s in reversed(sorted_svc)],
                    x=[s[1] for s in reversed(sorted_svc)],
                    orientation="h",
                    marker_color="#2563EB",
                    text=[s[1] for s in reversed(sorted_svc)],
                    textposition="auto",
                ))
                fig.update_layout(
                    height=max(300, len(sorted_svc) * 35 + 80),
                    margin=dict(l=10, r=10, t=10, b=40),
                    plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#FAFAFA"),
                )
                st.plotly_chart(fig, width="stretch")

            # Data table: top risks
            risks = cs_data.get("top_risks", [])
            if risks:
                with st.expander("Risk Details"):
                    df = pd.DataFrame(risks)
                    st.dataframe(df, width="stretch", hide_index=True, column_config={
                        "severity": st.column_config.TextColumn("Severity", width="small"),
                        "status": st.column_config.TextColumn("Status", width="small"),
                        "cloud_provider": st.column_config.TextColumn("Provider", width="small"),
                        "service_category": st.column_config.TextColumn("Service"),
                        "asset_type": st.column_config.TextColumn("Asset Type"),
                        "rule_name": st.column_config.TextColumn("Rule", width="large"),
                        "account_name": st.column_config.TextColumn("Account"),
                    })
                export_buttons(cs_data, "cloud_security")
    else:
        st.info("Cloud Security data not loaded. It will load automatically or click Refresh.")

# ============ TAB 7: EXPOSURE MANAGEMENT ============

with tab_exposure:
    st.subheader("External Attack Surface")
    st.caption(f"Internet-facing assets discovered by Falcon | {falcon_link('exposure', 'Open in Falcon')}")

    # Auto-load on first visit
    if "exposure_data" not in st.session_state:
        with st.spinner("Loading Exposure Management data..."):
            raw = run_async(get_exposure_management(limit=100))
            data = safe_json_parse(raw)
            if data:
                st.session_state["exposure_data"] = data

    if st.button("Refresh", key="refresh_exposure", type="secondary"):
        with st.spinner("Loading Exposure Management data..."):
            raw = run_async(get_exposure_management(limit=100))
            data = safe_json_parse(raw)
            if data:
                st.session_state["exposure_data"] = data
            st.rerun()

    em_data = st.session_state.get("exposure_data")
    if em_data:
        if em_data.get("error"):
            st.warning(f"Exposure Management: {em_data['error']}")
            render_scope_hint("Exposure Management:read")
        else:
            # KPI row
            k1, k2, k3, k4 = st.columns(4)
            crit = em_data.get("by_criticality", {})
            with k1:
                render_kpi_card("Total Assets", f"{em_data.get('total_assets', 0):,}", color="#2563EB")
            with k2:
                render_kpi_card("Critical", str(crit.get("Critical", 0)), color="#DC2626")
            with k3:
                render_kpi_card("High", str(crit.get("High", 0)), color="#EA580C")
            with k4:
                asset_types = em_data.get("by_asset_type", {})
                render_kpi_card("Asset Types", str(len(asset_types)), color="#0891B2")

            st.markdown("---")

            # Chart row: criticality bar + asset type donut
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                if crit:
                    st.markdown("**Assets by Criticality**")
                    crit_order = ["Critical", "High", "Medium", "Low", "Unassigned"]
                    crit_colors = ["#DC2626", "#EA580C", "#CA8A04", "#16A34A", "#9CA3AF"]
                    present = [(c, crit_order.index(c)) for c in crit_order if c in crit]
                    fig = go.Figure(go.Bar(
                        x=[c for c, _ in present],
                        y=[crit.get(c, 0) for c, _ in present],
                        marker_color=[crit_colors[i] for _, i in present],
                        text=[crit.get(c, 0) for c, _ in present],
                        textposition="auto",
                    ))
                    fig.update_layout(
                        height=350, margin=dict(l=10, r=10, t=10, b=40),
                        xaxis_title="", yaxis_title="Count",
                        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#FAFAFA"),
                    )
                    st.plotly_chart(fig, width="stretch")

            with chart_col2:
                asset_types = em_data.get("by_asset_type", {})
                if asset_types:
                    st.markdown("**Assets by Type**")
                    fig = go.Figure(go.Pie(
                        labels=list(asset_types.keys()),
                        values=list(asset_types.values()),
                        hole=0.4,
                        marker_colors=["#E8272C", "#2563EB", "#16A34A", "#D97706", "#7C3AED",
                                       "#0891B2", "#DB2777", "#65A30D"],
                    ))
                    fig.update_layout(
                        height=350, margin=dict(l=10, r=10, t=10, b=10),
                        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#FAFAFA"),
                    )
                    st.plotly_chart(fig, width="stretch")

            # Triage status + cloud provider row
            triage = em_data.get("by_triage_status", {})
            cloud = em_data.get("by_cloud_provider", {})

            if triage or cloud:
                t_col1, t_col2 = st.columns(2)
                with t_col1:
                    if triage:
                        st.markdown("**Assets by Triage Status**")
                        fig = go.Figure(go.Bar(
                            x=list(triage.keys()),
                            y=list(triage.values()),
                            marker_color="#7C3AED",
                            text=list(triage.values()),
                            textposition="auto",
                        ))
                        fig.update_layout(
                            height=300, margin=dict(l=10, r=10, t=10, b=40),
                            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                            font=dict(color="#FAFAFA"),
                        )
                        st.plotly_chart(fig, width="stretch")
                with t_col2:
                    if cloud:
                        st.markdown("**Assets by Cloud Provider**")
                        provider_colors = {"AWS": "#FF9900", "Azure": "#0078D4", "GCP": "#4285F4"}
                        fig = go.Figure(go.Pie(
                            labels=list(cloud.keys()),
                            values=list(cloud.values()),
                            hole=0.4,
                            marker_colors=[provider_colors.get(p, "#7C3AED") for p in cloud.keys()],
                        ))
                        fig.update_layout(
                            height=300, margin=dict(l=10, r=10, t=10, b=10),
                            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                            font=dict(color="#FAFAFA"),
                        )
                        st.plotly_chart(fig, width="stretch")

            # Assets data table
            assets = em_data.get("assets", [])
            if assets:
                with st.expander("Asset Details"):
                    df = pd.DataFrame(assets)
                    if "services" in df.columns:
                        df["services"] = df["services"].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
                    st.dataframe(df, width="stretch", hide_index=True, column_config={
                        "name": st.column_config.TextColumn("Asset", width="large"),
                        "asset_type": st.column_config.TextColumn("Type", width="small"),
                        "criticality": st.column_config.TextColumn("Criticality", width="small"),
                        "triage_status": st.column_config.TextColumn("Triage", width="small"),
                        "cloud_provider": st.column_config.TextColumn("Cloud", width="small"),
                        "services": st.column_config.TextColumn("Services"),
                        "country": st.column_config.TextColumn("Country", width="small"),
                        "discovery_date": st.column_config.TextColumn("Discovered"),
                        "asset_id": None,
                    })
                export_buttons(em_data, "exposure")
    else:
        st.info("Exposure Management data not loaded. It will load automatically or click Refresh.")

# ============ TAB 8: IOC SEARCH ============

with tab_tg:
    st.subheader("IOC Search")
    st.caption(f"Find which devices communicated with a domain, IP, or executed a specific hash | {falcon_link('threatgraph', 'Open in Falcon')}")

    col1, col2, col3 = st.columns([1, 2, 1])
    with col1:
        tg_type = st.selectbox("IOC Type", ["domain", "ipv4", "ipv6", "md5", "sha1", "sha256"], key="tg_type")
    with col2:
        tg_value = st.text_input("IOC Value", placeholder="e.g. evil.com, 1.2.3.4, or file hash", key="tg_value")
    with col3:
        tg_limit = st.number_input("Max Results", min_value=1, max_value=100, value=20, key="tg_limit")

    if st.button("Search IOC", type="primary", key="search_tg_btn"):
        if tg_value:
            with st.spinner(f"Searching for {tg_type}: {tg_value}..."):
                result = run_async(search_threatgraph(
                    indicator_type=tg_type, indicator_value=tg_value, limit=int(tg_limit)
                ))
                data = safe_json_parse(result)
                if data and "error" not in data:
                    st.session_state["tg_data"] = data
                elif data and "error" in data:
                    st.error(data["error"])
                else:
                    st.error(result)
        else:
            st.warning("Enter an IOC value to search")

    tg_data = st.session_state.get("tg_data")
    if tg_data and tg_data.get("query_type") == "ioc_lookup":
        st.success(f"Found {tg_data['total_found']} device interactions for "
                   f"{tg_data.get('indicator_type')}: {tg_data.get('indicator_value')}")
        if tg_data.get("devices"):
            df = pd.DataFrame(tg_data["devices"])
            st.dataframe(df, width="stretch", hide_index=True, column_config={
                "device_id": st.column_config.TextColumn("Device ID", width="large"),
                "edge_type": st.column_config.TextColumn("Edge Type", width="small"),
                "direction": st.column_config.TextColumn("Direction", width="small"),
                "timestamp": st.column_config.TextColumn("Timestamp"),
            })
            export_buttons(tg_data, "ioc_search")
        else:
            st.info("No device interactions found for this IOC")

# ============ TAB 9: DATA INGESTION ============

with tab_ingestion:
    st.subheader("NGSIEM Data Ingestion")
    ing_left, ing_mid, ing_right = st.columns([3, 1, 1])
    with ing_left:
        st.caption("LogScale ingestion volume and top data sources")
    with ing_right:
        ing_hours = st.selectbox("Reporting period", [6, 12, 24, 48, 72, 168], index=2,
                                 format_func=lambda x: f"Last {x}h" if x < 168 else "Last 7d",
                                 key="ing_hours", label_visibility="collapsed")

    # Auto-load on first visit
    if "ingestion_data" not in st.session_state:
        with st.spinner("Querying NGSIEM ingestion data..."):
            raw = run_async(get_ngsiem_ingestion(hours=ing_hours))
            ing_parsed = safe_json_parse(raw)
            if ing_parsed:
                st.session_state["ingestion_data"] = ing_parsed

    # Manual refresh
    if st.button("Refresh", key="refresh_ingestion", type="secondary"):
        with st.spinner("Querying NGSIEM ingestion data..."):
            raw = run_async(get_ngsiem_ingestion(hours=ing_hours))
            ing_parsed = safe_json_parse(raw)
            if ing_parsed:
                st.session_state["ingestion_data"] = ing_parsed
            st.rerun()

    ing_data = st.session_state.get("ingestion_data")

    if ing_data:
        top_error = ing_data.get("error")
        sources = ing_data.get("sources", [])
        is_mssp = ing_data.get("is_mssp", False)
        children = ing_data.get("children", [])

        # Mode indicator (top right, subtle)
        mode_label = "MSSP Multi-Tenant" if is_mssp else "Single CID"
        st.caption(f"Mode: **{mode_label}**")

        # Partial-results warning
        if top_error and sources:
            st.warning(f"Partial results: {top_error}")
        elif top_error and not sources:
            st.warning(f"Could not query NGSIEM: {top_error}")
            render_scope_hint("NGSIEM:read")

        # ---- KPI ROW ----
        if sources or ing_data.get("total_events", 0) > 0:
            k1, k2, k3 = st.columns(3)
            with k1:
                render_kpi_card("Total Volume", format_bytes(ing_data.get("total_bytes", 0)), color="#7C3AED")
            with k2:
                render_kpi_card("Total Events", f"{ing_data.get('total_events', 0):,}", color="#2563EB")
            with k3:
                render_kpi_card("Data Sources", str(len(sources)), color="#0891B2")

            st.markdown("---")

            # ---- TOP SOURCES BAR CHART ----
            if sources:
                st.markdown("**Top Data Sources by Volume**")
                # Reverse for horizontal bar display (largest at top)
                chart_sources = list(reversed(sources))
                vendor_colors = [
                    "#E8272C", "#2563EB", "#16A34A", "#D97706", "#7C3AED",
                    "#0891B2", "#DB2777", "#65A30D", "#EA580C", "#6366F1",
                    "#0D9488", "#C026D3", "#CA8A04", "#DC2626", "#4F46E5",
                ]
                bar_colors = [vendor_colors[i % len(vendor_colors)] for i in range(len(chart_sources))]
                fig = go.Figure(go.Bar(
                    x=[s.get("bytes", 0) for s in chart_sources],
                    y=[s["name"] for s in chart_sources],
                    orientation="h",
                    text=[format_bytes(s.get("bytes", 0)) for s in chart_sources],
                    textposition="auto",
                    hovertemplate="<b>%{y}</b><br>Volume: %{text}<br>Events: %{customdata:,}<extra></extra>",
                    customdata=[s["events"] for s in chart_sources],
                    marker_color=bar_colors,
                ))
                fig.update_layout(
                    xaxis_title="Volume Ingested (bytes)",
                    yaxis_title="",
                    height=max(300, len(chart_sources) * 40 + 100),
                    margin=dict(l=10, r=10, t=10, b=40),
                    xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.1)"),
                    yaxis=dict(showgrid=False),
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#FAFAFA"),
                )
                st.plotly_chart(fig, width="stretch")

                # Source details expander
                with st.expander("Source Details"):
                    src_rows = [
                        {"Source": s["name"], "Events": f"{s['events']:,}", "Volume": format_bytes(s.get("bytes", 0))}
                        for s in sources
                    ]
                    st.dataframe(pd.DataFrame(src_rows), hide_index=True, width="stretch")

            # ---- MSSP PER-TENANT BREAKDOWN ----
            if is_mssp and children:
                st.markdown("---")
                st.markdown("**Per-Tenant Ingestion Breakdown**")

                # Sort children by bytes descending for chart (ascending for horizontal bar)
                sorted_children = sorted(children, key=lambda c: c.get("total_bytes", 0))
                has_child_data = any(c.get("total_bytes", 0) > 0 for c in children)

                if has_child_data:
                    # Volume chart by child CID
                    fig_children = go.Figure(go.Bar(
                        x=[c.get("total_bytes", 0) for c in sorted_children],
                        y=[c.get("name", c.get("cid", "?")) for c in sorted_children],
                        orientation="h",
                        text=[format_bytes(c.get("total_bytes", 0)) for c in sorted_children],
                        textposition="auto",
                        marker_color=[
                            "#16A34A" if not c.get("error") else "#DC2626"
                            for c in sorted_children
                        ],
                        hovertemplate="<b>%{y}</b><br>Volume: %{text}<br>Events: %{customdata:,}<extra></extra>",
                        customdata=[c.get("total_events", 0) for c in sorted_children],
                    ))
                    fig_children.update_layout(
                        xaxis_title="Volume Ingested (bytes)",
                        yaxis_title="",
                        height=max(300, len(sorted_children) * 35 + 100),
                        margin=dict(l=10, r=10, t=10, b=40),
                        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.1)"),
                        yaxis=dict(showgrid=False),
                        plot_bgcolor="rgba(0,0,0,0)",
                        paper_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#FAFAFA"),
                    )
                    st.plotly_chart(fig_children, width="stretch")
                else:
                    st.info("Per-tenant ingestion data not available (child CID queries require **ngsiem:write** scope on each tenant).")

                with st.expander("Tenant Details"):
                    tenant_rows = [
                        {
                            "Tenant": c.get("name", c.get("cid", "?")),
                            "CID": c.get("cid", ""),
                            "Volume": format_bytes(c.get("total_bytes", 0)),
                            "Events": f"{c.get('total_events', 0):,}",
                            "Status": "Error" if c.get("error") else "OK",
                        }
                        for c in sorted(children, key=lambda c: c.get("total_bytes", 0), reverse=True)
                    ]
                    st.dataframe(pd.DataFrame(tenant_rows), hide_index=True, width="stretch")

                errored = [c for c in children if c.get("error")]
                if errored:
                    st.warning(f"{len(errored)} tenant(s) had query errors. Check Tenant Details for status.")

            export_buttons(ing_data, "ingestion")

        elif not top_error:
            st.info("No ingestion data available for the selected period.")
    else:
        st.info("Ingestion data not loaded yet. It will load automatically or click Refresh.")

# ============ TAB 10: FQL TOOLS ============

with tab_fql:
    st.subheader("FQL Tools")

    fql_tab1, fql_tab2, fql_tab3 = st.tabs(["Validate FQL", "Host Lookup", "Product Browser"])

    with fql_tab1:
        filter_input = st.text_area(
            "FQL Filter",
            placeholder="product:'cao'+severity_name:'Critical'",
            height=100, key="fql_input"
        )
        if st.button("Validate", type="primary", key="validate_fql_btn"):
            if filter_input:
                with st.spinner("Validating..."):
                    result = run_async(test_fql_filter(filter_string=filter_input))
                    data = safe_json_parse(result)
                    if data:
                        if data["valid"]:
                            st.success("Filter is valid!")
                        else:
                            st.error("Filter has issues")
                            for issue in data.get("issues", []):
                                st.warning(issue)
                        st.write("**Detected Fields:**", ", ".join(data.get("detected_fields", [])) or "None")
                        st.info(data.get("suggestion", ""))
            else:
                st.warning("Enter a filter to validate")

        st.markdown("**Example Filters**")
        for ex in ["product:'cao'", "product:'cao'+severity_name:'Critical'",
                    "product:'3rdparty'+external_provider_name:'Corelight'",
                    "status:'new'+severity_name:['Critical','High']"]:
            st.code(ex, language="text")

    with fql_tab2:
        hostname = st.text_input("Hostname", placeholder="e.g. DESKTOP-ABC123", key="host_input")
        if st.button("Get Host Details", type="primary", key="host_lookup_btn"):
            if hostname:
                with st.spinner(f"Looking up {hostname}..."):
                    result = run_async(get_host_details(hostname=hostname))
                    data = safe_json_parse(result)
                    if data and "hostname" in data:
                        st.success(f"Host found: {data['hostname']}")
                        c1, c2, c3 = st.columns(3)
                        with c1:
                            st.metric("Platform", data["platform"])
                            st.metric("Status", data["status"])
                            st.write("**OS:**", data["os_version"])
                        with c2:
                            st.write("**Agent ID:**", data["agent_id"])
                            st.write("**Agent Version:**", data["agent_version"])
                            st.write("**Last Seen:**", data["last_seen"])
                        with c3:
                            st.write("**Local IP:**", data["local_ip"])
                            st.write("**External IP:**", data["external_ip"])
                            st.write("**MAC:**", data["mac_address"])
                        if data.get("tags"):
                            st.write("**Tags:**", ", ".join(data["tags"]))
                    else:
                        st.error(result)
            else:
                st.warning("Enter a hostname")

    with fql_tab3:
        if st.button("Load Products", type="primary", key="load_products_btn"):
            with st.spinner("Loading..."):
                result = run_async(list_available_products())
                data = safe_json_parse(result)
                if data:
                    for product in data.get("available_products", []):
                        with st.expander(f"{product['name']} ({product['value']})"):
                            st.write(product["description"])
                            st.code(f"product:'{product['value']}'", language="text")
                    st.markdown("**Example Filters**")
                    for ex in data.get("example_filters", []):
                        st.code(ex, language="text")

# ============ SIDEBAR: chat ============

# Chat — in sidebar via placeholder
with _sidebar_chat_ph.container():
    if not st.session_state.chat_open:
        if st.button("Open AI Chat", key="chat_fab_toggle", type="primary"):
            st.session_state.chat_open = True
            st.rerun()
    else:
        st.markdown(
            '<div style="background:#1B2A4A;color:#fff;padding:8px 12px;'
            'font-weight:600;font-size:0.9rem;border-radius:8px 8px 0 0;'
            'margin-bottom:4px;">Ask Vantage AI</div>',
            unsafe_allow_html=True
        )

        chat_container = st.container(height=350)
        with chat_container:
            if not st.session_state.chat_messages:
                st.caption("Ask a question about your security environment.")
            for msg in st.session_state.chat_messages:
                if msg["role"] == "user":
                    st.markdown(
                        f'<div class="chat-user"><strong>You:</strong> {html.escape(msg["content"])}</div>',
                        unsafe_allow_html=True
                    )
                elif msg["role"] == "assistant":
                    st.markdown(
                        f'<div class="chat-assistant"><strong>Vantage AI:</strong> {html.escape(msg["content"])}</div>',
                        unsafe_allow_html=True
                    )
                elif msg["role"] == "tool_call":
                    st.markdown(
                        f'<div class="chat-tool">Using {html.escape(msg.get("tool_name", "tool"))}...</div>',
                        unsafe_allow_html=True
                    )
            if st.session_state.chat_messages:
                components.html(_SCROLL_JS, height=0)

        with st.form("chat_form", clear_on_submit=True):
            user_input = st.text_input(
                "Message", placeholder="Ask about your security...",
                label_visibility="collapsed", key="chat_v2_input"
            )
            submitted = st.form_submit_button("Send", type="primary", width="stretch")

        pending_msg = st.session_state.pop("chat_pending", None)
        active_input = pending_msg or (user_input if submitted else None)

        if active_input:
            st.session_state.chat_messages.append({"role": "user", "content": active_input})
            with chat_container:
                st.markdown(
                    f'<div class="chat-user"><strong>You:</strong> {html.escape(active_input)}</div>',
                    unsafe_allow_html=True
                )
                components.html(_SCROLL_JS, height=0)

            api_messages = [{"role": "user", "content": active_input}]
            try:
                with st.spinner("Vantage AI is thinking..."):
                    response = call_llm(api_messages, TOOL_DEFINITIONS)
                    max_iterations = 10
                    iteration = 0
                    while response.get("stop_reason") == "tool_use" and iteration < max_iterations:
                        iteration += 1
                        tool_calls = [b for b in response.get("content", []) if b.get("type") == "tool_use"]
                        tool_results = []
                        for tc in tool_calls:
                            st.session_state.chat_messages.append({
                                "role": "tool_call", "tool_name": tc["name"],
                                "input": tc["input"], "result": None
                            })
                            with chat_container:
                                st.markdown(
                                    f'<div class="chat-tool">Using {html.escape(tc["name"])}...</div>',
                                    unsafe_allow_html=True
                                )
                                components.html(_SCROLL_JS, height=0)
                            result = execute_tool(tc["name"], tc["input"])
                            st.session_state.chat_messages[-1]["result"] = result
                            tool_results.append({
                                "type": "tool_result", "tool_use_id": tc["id"], "content": result
                            })
                        api_messages.append({"role": "assistant", "content": response["content"]})
                        api_messages.append({"role": "user", "content": tool_results})
                        response = call_llm(api_messages, TOOL_DEFINITIONS)

                    final_text = ""
                    for block in response.get("content", []):
                        if block.get("type") == "text":
                            final_text += block.get("text", "")
                    if final_text:
                        stream_to_chat(chat_container, final_text)
                        st.session_state.chat_messages.append({"role": "assistant", "content": final_text})

            except Exception as e:
                _logger.error("LLM error: %s", e, exc_info=True)
                err_msg = "Sorry, I'm having trouble connecting to Vantage AI right now. Please try again in a moment."
                stream_to_chat(chat_container, err_msg)
                st.session_state.chat_messages.append({"role": "assistant", "content": err_msg})

        bc1, bc2 = st.columns(2)
        with bc1:
            if st.button("Close", key="close_chat_v2"):
                st.session_state.chat_open = False
                st.rerun()
        with bc2:
            if st.session_state.chat_messages:
                if st.button("Clear", key="clear_chat_v2"):
                    st.session_state.chat_messages = []
                    st.rerun()

# ============ FOOTER ============

st.divider()
st.caption(f"Falcon Vantage v2.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if auto_refresh:
    import time
    time.sleep(refresh_interval)
    st.rerun()

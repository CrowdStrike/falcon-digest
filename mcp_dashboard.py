#!/usr/bin/env python3
"""
Falcon Digest — Dashboard (v1)
Ask your Falcon data anything.
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
from datetime import datetime
from dotenv import load_dotenv
from crwd_mcp_server import (
    get_host_details, test_fql_filter, list_available_products,
    search_cases, search_detections, search_vulnerabilities,
    search_threatgraph, get_security_posture, get_ngsiem_ingestion,
    get_identity_protection, get_cloud_security, get_exposure_management,
    validate_config, ConfigError
)
from mcp_api_client import call_llm, execute_tool, TOOL_DEFINITIONS
from falcon_cache import cache as falcon_cache, parse_env_profiles, switch_env_profile

load_dotenv()

_logger = logging.getLogger("falcon_mcp.dashboard")

# ============ PAGE CONFIG ============

st.set_page_config(
    page_title="Falcon Digest",
    page_icon="https://www.crowdstrike.com/wp-content/uploads/2022/01/favicon.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============ CONFIGURATION CHECK ============

try:
    validate_config()
except ConfigError as e:
    st.error(
        "**Falcon Digest cannot start — required configuration is missing.**\n\n"
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
    /* Push main content up — remove default 6rem top padding */
    .stMainBlockContainer {
        padding-top: 1rem !important;
    }

    :root {
        --cs-red: #EC0000;
        --cs-bg: #F8F8F8;
        --cs-card-bg: #FFFFFF;
        --cs-sidebar-bg: #3D474F;
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
        background-color: #4A545C !important;
        color: #E0E6EF !important;
        border: 1px solid #5C666E !important;
    }
    section[data-testid="stSidebar"] .stButton > button:hover {
        background-color: #5C666E !important;
    }
    /* Sidebar expanders — force dark background on ALL inner elements */
    section[data-testid="stSidebar"] [data-testid="stExpander"] {
        background-color: #4A545C !important;
        border: 1px solid #5C666E !important;
        border-radius: 8px;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] details {
        background-color: #4A545C !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] details > div {
        background-color: #4A545C !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] summary,
    section[data-testid="stSidebar"] [data-testid="stExpander"] summary span,
    section[data-testid="stSidebar"] [data-testid="stExpander"] summary p,
    section[data-testid="stSidebar"] [data-testid="stExpander"] summary svg {
        color: #E0E6EF !important;
        fill: #E0E6EF !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        background-color: #4A545C !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"] * {
        background-color: transparent !important;
    }
    section[data-testid="stSidebar"] [data-testid="stExpander"],
    section[data-testid="stSidebar"] [data-testid="stExpander"] details,
    section[data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        background-color: #4A545C !important;
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
    .kpi-card .kpi-delta {
        font-size: 0.75rem;
        font-weight: 600;
        margin-top: 2px;
    }
    .kpi-delta.up { color: #DC2626; }
    .kpi-delta.down { color: #16A34A; }
    .kpi-delta.neutral { color: #6B7280; }
    .kpi-delta.up-good { color: #16A34A; }
    .kpi-delta.down-bad { color: #DC2626; }

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

    /* Chat styling */
    .chat-user {
        background-color: #EFF6FF;
        color: #1E1E2F;
        border-radius: 12px 12px 4px 12px;
        padding: 12px 16px;
        margin: 8px 0;
        border-left: 3px solid var(--cs-blue);
    }
    .chat-assistant {
        background-color: #FFFFFF;
        color: #1E1E2F;
        border-radius: 12px 12px 12px 4px;
        padding: 12px 16px;
        margin: 8px 0;
        border-left: 3px solid var(--cs-red);
        border-top: 1px solid var(--cs-border);
        border-right: 1px solid var(--cs-border);
        border-bottom: 1px solid var(--cs-border);
    }

    /* Header */
    .main-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 0 20px 0;
    }
    .main-header h1 {
        color: #EC0000;
        font-size: 1.8rem;
        margin: 0;
    }

    /* Section headers */
    .section-header {
        font-size: 1.05rem;
        font-weight: 700;
        color: var(--cs-text);
        margin: 0 0 8px 0;
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
    # api.crowdstrike.com → falcon.crowdstrike.com
    # api.us-2.crowdstrike.com → falcon.us-2.crowdstrike.com
    return base.replace("://api.", "://falcon.").rstrip("/")

FALCON_CONSOLE = get_falcon_console_url()

# Falcon console deep link paths
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
    """Return an HTML link to the Falcon console section (red color)."""
    url = FALCON_LINKS.get(section, FALCON_CONSOLE)
    text = label or "Open in Falcon"
    return f'<a href="{url}" target="_blank" style="color: #EC0000; text-decoration: none; font-weight: 600;">{text} &#x2197;</a>'


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
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(b) < 1024:
            return f"{b:,.1f} {unit}" if unit != "B" else f"{b:,} B"
        b /= 1024
    return f"{b:,.1f} EB"


def render_kpi_card(label: str, value, color: str = "#E8272C", delta=None, delta_invert: bool = False):
    """Render a KPI card with optional delta badge.

    Args:
        delta: Numeric change value. Positive shows ▲, negative shows ▼.
        delta_invert: If True, positive is bad (red) and negative is good (green).
                      Use for metrics where "more = worse" (e.g. critical count).
    """
    delta_html = ""
    if delta is not None and delta != 0:
        arrow = "&#9650;" if delta > 0 else "&#9660;"
        sign = "+" if delta > 0 else ""
        if delta_invert:
            css_cls = "up" if delta > 0 else "down"  # up=red(bad), down=green(good)
        else:
            css_cls = "up-good" if delta > 0 else "down-bad"  # up=green(good), down=red(bad)
        delta_html = f'<div class="kpi-delta {css_cls}">{arrow} {sign}{delta}</div>'
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">{label}</div>
        <div class="kpi-value" style="color: {color};">{value}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


# ============ CENTRALIZED COLOR PALETTES ============

_CS_FALCON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 144 144"><g fill="#EC0000"><path d="M114.7,97.69c-2.33-.23-6.45-.81-11.62,1.8-5.16,2.6-7.19,2.72-9.73,2.44.74,1.36,2.25,3.23,7,3.57,4.74.33,7.01.48,4.52,6.39.06-1.79-.36-5.24-5.07-4.63-4.71.61-5.81,4.85-.76,6.96-1.64.33-5.12.53-7.61-5.98-1.72.75-4.38,2.25-9.2-1.47,1.68.61,3.75.65,3.75.65-4.28-2.04-8.36-5.84-10.98-9.42,2.07,1.54,4.36,3.08,6.68,3.37-2.73-3.34-9.06-10.01-16.8-16.87,4.98,3.25,10.98,8.39,20.81,7.23,9.83-1.16,16.43-3.41,29,5.96"/><path d="M72.64,95.37c-6.16-2.67-7.48-3.21-15.41-5.22-7.92-2.01-15.72-6.2-20.93-12.74,3.67,2.69,11.18,8.11,18.88,7.52-1.17-1.71-3.33-3.05-5.91-4.4,2.92.7,11.73,2.95,23.37,14.84"/><path d="M59.22,72.56c-1.59-4.56-4.46-10.39-18.05-19.07-6.62-4.37-16.34-9.86-29.14-23.85.91,3.77,4.96,13.58,25.34,26.31,6.69,4.57,15.33,7.39,21.86,16.6"/><path d="M60.06,79.17c-1.67-3.86-5.03-8.81-18.2-15.87-6.07-3.4-16.45-8.64-25.78-18.59.85,3.59,5.18,11.48,23.82,21.34,5.16,2.84,13.89,5.51,20.17,13.12"/><path d="M109.89,89.35c4.87.74,4.62,1.77,4.67,3.55-2.07-2.26-4.67-3.55-4.67-3.55M72.84,59.23c-25.67-7.35-35.88-16.62-43.78-26.32,3.61,11.17,12.21,15.17,21.4,22.67,9.19,7.5,9.71,11.53,12.42,15.96,6.03,9.87,6.99,11.5,12.97,15.81,7.05,4.68,15.58,1.51,24.94,2.98,9.36,1.47,17.09,8.6,18.77,11.34,1.96-3.5-2.72-8.54-3.99-9.81.68-4.58-10.16-6.6-14.27-8.17-.81-.31-2.8-.77-1.07-4.88,2.33-5.68,4.76-10.62-27.39-19.59"/></g></svg>'

SEVERITY_COLORS = {
    "Critical": "#DC2626", "High": "#EA580C", "Medium": "#CA8A04",
    "Low": "#16A34A", "Informational": "#6366F1", "Unknown": "#9CA3AF",
}
STATUS_COLORS = {
    "New": "#2563EB", "Open": "#EA580C", "In Progress": "#CA8A04",
    "Reopened": "#7C3AED", "Closed": "#16A34A",
    "Active": "#16A34A", "Inactive": "#DC2626", "Unknown": "#9CA3AF",
}
PROVIDER_COLORS = {"AWS": "#FF9900", "Azure": "#0078D4", "GCP": "#4285F4"}
CHART_PALETTE = [
    "#E8272C", "#2563EB", "#16A34A", "#D97706", "#7C3AED",
    "#0891B2", "#DB2777", "#65A30D", "#EA580C", "#6366F1",
]


# ============ STANDARDIZED CHART THEME ============

CHART_THEME = dict(
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, -apple-system, sans-serif", color="#374151", size=12),
    margin=dict(l=20, r=20, t=10, b=20),
    xaxis=dict(showgrid=True, gridcolor="rgba(0,0,0,0.06)", zeroline=False),
    yaxis=dict(showgrid=True, gridcolor="rgba(0,0,0,0.06)", zeroline=False),
    hoverlabel=dict(bgcolor="#1E293B", font_color="#F8FAFC", font_size=12),
)
CHART_HEIGHT_SM = 240
CHART_HEIGHT_MD = 320


def apply_chart_theme(fig, height=CHART_HEIGHT_MD, **overrides):
    """Apply the standardized chart theme to a Plotly figure."""
    layout = dict(CHART_THEME, height=height, **overrides)
    fig.update_layout(**layout)
    return fig


def render_section_header(title):
    """Render a lightweight section header."""
    st.markdown(f'<div class="section-header">{title}</div>', unsafe_allow_html=True)


def render_empty_state(module_name, hint=None):
    """Render a consistent empty state with optional scope hint."""
    msg = f"No {module_name} data available for the selected period."
    if hint:
        msg += f" {hint}"
    st.info(msg)


def compute_sla_compliance(detections_list):
    """Compute SLA compliance % from a list of detection dicts.

    SLA thresholds (time to resolution):
        Critical: <4h, High: <24h, Medium: <7d, Low: <30d.
    Returns (pct, met, total) or None if insufficient data.
    """
    sla_thresholds = {
        "critical": 4 * 3600, "high": 24 * 3600,
        "medium": 7 * 86400, "low": 30 * 86400,
    }
    met = total = 0
    for d in detections_list:
        sev = (d.get("severity") or "").lower()
        status = (d.get("status") or "").lower()
        if status not in ("closed", "true_positive", "false_positive"):
            continue
        threshold = sla_thresholds.get(sev)
        if threshold is None:
            continue
        total += 1
        # Approximate: if resolved exists, compare to created
        created = d.get("timestamp") or d.get("created")
        resolved = d.get("resolved") or d.get("closed_timestamp")
        if created and resolved:
            try:
                t_created = pd.to_datetime(created, utc=True)
                t_resolved = pd.to_datetime(resolved, utc=True)
                delta_sec = (t_resolved - t_created).total_seconds()
                if delta_sec <= threshold:
                    met += 1
            except Exception:
                met += 1  # Assume compliant if we can't parse
        else:
            met += 1  # No timing data, assume compliant
    if total == 0:
        return None
    return round(met / total * 100, 1), met, total


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
}

# Maps tab labels to the subscription module names that gate them.
# Tabs not listed here are always shown.
# A tab is shown if ANY of its required subscription modules are active.
SUB_TAB_MAP = {
    "Data Ingestion": ["Falcon NGSIEM (Next-Gen SIEM)"],
    "Identity": ["Falcon Identity Protection"],
    "Cloud Security": ["Cloud Security Posture Mgmt", "Falcon Cloud Security"],
    "Exposure": ["Exposure Management"],
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


def stream_to_chat(container, text, label="Falcon Digest"):
    """Stream text word-by-word into a chat container with typewriter effect."""
    text = html.escape(text)
    with container:
        placeholder = st.empty()
        streamed = ""
        words = text.split(' ')
        for i, word in enumerate(words):
            streamed += word + (' ' if i < len(words) - 1 else '')
            placeholder.markdown(
                f'<div class="chat-assistant"><strong>{label}:</strong> {streamed}▌</div>',
                unsafe_allow_html=True
            )
            time.sleep(0.02)
        # Final render without cursor
        placeholder.markdown(
            f'<div class="chat-assistant"><strong>{label}:</strong> {text}</div>',
            unsafe_allow_html=True
        )
        # Auto-scroll to bottom
        components.html(_SCROLL_JS, height=0)


# ============ SIDEBAR ============

with st.sidebar:
    st.markdown(f'<div style="display:flex; align-items:center; gap:8px;"><span style="display:inline-flex; align-items:center; height:24px; width:24px;">{_CS_FALCON_SVG}</span><h3 style="color: #EC0000; margin: 0; padding: 0; line-height: 1;">Falcon Digest</h3></div>', unsafe_allow_html=True)

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
            with st.expander(scope_label, expanded=False):
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
            time.sleep(0.2)
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

    auto_refresh = st.toggle("Auto-refresh", value=True)
    if auto_refresh:
        refresh_interval = st.slider("Refresh interval (sec)", 30, 300, 60)
        st.caption(f"Refreshing every {refresh_interval}s")

    cache_interval = st.slider("Cache poll interval (sec)", 60, 600, 300, key="cache_poll")
    if falcon_cache.is_running and falcon_cache.poll_interval != cache_interval:
        falcon_cache.poll_interval = cache_interval
        falcon_cache.ttl = cache_interval

    st.divider()

    with st.expander("FQL Quick Reference"):
        st.code("field:'value'          # Exact match")
        st.code("field:>value           # Greater than")
        st.code("filter1+filter2        # AND")
        st.code("filter1,filter2        # OR")
        st.code("field:['v1','v2']      # IN")

    with st.expander("Help"):
        st.markdown("""
**Tabs**
- **Executive Summary** — Risk score, KPIs, severity charts
- **Detections** — Search endpoint detections (EPP)
- **Cases** — Browse CrowdStrike cases
- **Vulnerabilities** — Spotlight vulnerability data
- **ThreatGraph** — IOC search
- **FQL Tools** — Validate FQL filters, look up hosts
- **Ask Falcon Digest** — Natural-language Q&A
        """)

    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

# ============ HEADER ============

st.markdown(f"""
<div class="main-header">
    <span style="display:inline-block; height:36px; width:36px;">{_CS_FALCON_SVG}</span>
    <h1>Falcon Digest</h1>
</div>
""", unsafe_allow_html=True)

# ============ GLOBAL REPORTING PERIOD ============

def _on_global_hours_change():
    new_hours = st.session_state.get("global_hours", 24)
    # Update cache reporting window — triggers background refresh with new hours
    falcon_cache.set_hours(new_hours)
    # Clear time-dependent session data so tabs pick up fresh cache
    for _key in ["posture_data", "detections_data", "cases_data", "ingestion_data"]:
        st.session_state.pop(_key, None)

# Right-aligned period selector above tabs
_period_spacer, _period_ts, _period_col = st.columns([4, 1, 1])
with _period_ts:
    _last_refresh = falcon_cache.last_refresh
    if _last_refresh:
        _now = datetime.now(_last_refresh.tzinfo) if _last_refresh.tzinfo else datetime.now()
        _ago_sec = (_now - _last_refresh).total_seconds()
        if _ago_sec < 60:
            _ago_str = f"{int(_ago_sec)}s ago"
        elif _ago_sec < 3600:
            _ago_str = f"{int(_ago_sec // 60)}m ago"
        else:
            _ago_str = _last_refresh.strftime("%H:%M")
        st.markdown(f'<div style="text-align:right; padding-top:8px; font-size:0.8rem; color:#6B7280;">Updated {_ago_str}</div>', unsafe_allow_html=True)
with _period_col:
    st.selectbox("Period", [6, 12, 24, 48, 72, 168], index=5,
                 format_func=lambda x: f"Last {x}h" if x < 168 else "Last 7d",
                 key="global_hours", on_change=_on_global_hours_change,
                 label_visibility="collapsed")

# ============ TABS ============

# Determine which subscription-gated tabs to show based on cached posture data.
_ALL_TAB_LABELS = [
    "Executive Summary",
    "Detections",
    "Cases",
    "Data Ingestion",
    "Identity",
    "Cloud Security",
    "Exposure",
    "Vulnerabilities",
    "IOC Search",
    "FQL Tools",
    "Ask Falcon Digest",
]

_active_modules: set[str] | None = None
_cached_posture = falcon_cache.get_parsed("security_posture")
if _cached_posture and isinstance(_cached_posture, dict):
    _subs = _cached_posture.get("subscriptions")
    if isinstance(_subs, list) and len(_subs) > 0:
        _active_modules = {s.get("module", "") for s in _subs if isinstance(s, dict)}

if _active_modules is not None:
    _visible_tabs = [
        label for label in _ALL_TAB_LABELS
        if label not in SUB_TAB_MAP
        or any(mod in _active_modules for mod in SUB_TAB_MAP[label])
    ]
else:
    # No subscription data yet (first run) — show all tabs
    _visible_tabs = list(_ALL_TAB_LABELS)

_tab_objects = st.tabs(_visible_tabs)
_tabs = dict(zip(_visible_tabs, _tab_objects))

# Always-visible tabs
tab_exec = _tabs["Executive Summary"]
tab_detections = _tabs["Detections"]
tab_cases = _tabs["Cases"]
tab_vulns = _tabs["Vulnerabilities"]
tab_tg = _tabs["IOC Search"]
tab_fql = _tabs["FQL Tools"]
tab_chat = _tabs["Ask Falcon Digest"]

# Subscription-gated tabs (None if not subscribed)
tab_ingestion = _tabs.get("Data Ingestion")
tab_identity = _tabs.get("Identity")
tab_cloud = _tabs.get("Cloud Security")
tab_exposure = _tabs.get("Exposure")

# ============ TAB 1: EXECUTIVE SUMMARY ============

with tab_exec:
    st.subheader("Security Posture Overview")
    st.markdown(f"<small>{falcon_link('dashboard', 'View Falcon Dashboard')}</small>", unsafe_allow_html=True)

    exec_hours = st.session_state.get("global_hours", 168)

    # Auto-load on first visit or after hours change
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
                fig_gauge.update_layout(height=CHART_HEIGHT_SM, margin=dict(l=20, r=20, t=40, b=20),
                                       plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                                       font=dict(family="Inter, -apple-system, sans-serif", color="#374151", size=12))
                st.plotly_chart(fig_gauge, width="stretch")
            with cs_col2:
                trend = crowdscore.get("trend_7d", [])
                if trend:
                    df_trend = pd.DataFrame(trend)
                    df_trend["timestamp"] = pd.to_datetime(df_trend["timestamp"], errors="coerce")
                    fig_spark = px.line(df_trend, x="timestamp", y="score")
                    apply_chart_theme(fig_spark, height=CHART_HEIGHT_SM,
                                      xaxis_title="", yaxis_title="CrowdScore")
                    fig_spark.update_traces(line_color="#E8272C")
                    st.plotly_chart(fig_spark, width="stretch")

        # Compute deltas from time buckets (recent vs expected rate)
        _buckets = data.get("alerts", {}).get("by_time_bucket", {})
        _last_8h = _buckets.get("last_8h", 0)
        _last_24h = _buckets.get("last_24h", 0)
        # Delta: alerts in the last 8h vs the expected 8h rate (24h / 3)
        _alert_delta = round(_last_8h - _last_24h / 3) if _last_24h > 0 else None

        k1, k2, k3, k4, k5 = st.columns(5)
        with k1:
            render_kpi_card("Risk Score", data.get("risk_score", 0), severity_hex(data.get("risk_level", "low")))
        with k2:
            render_kpi_card("Alerts", data["alerts"]["total"], "#2563EB",
                            delta=_alert_delta, delta_invert=True)
        with k3:
            render_kpi_card("Cases", data["cases"]["total"], "#EA580C")
        with k4:
            render_kpi_card("Vulnerabilities", data["vulnerabilities"]["total"], "#7C3AED")
        with k5:
            # SLA compliance from cached detections
            _cached_dets = falcon_cache.get_parsed("detections_recent")
            _sla = None
            if _cached_dets and isinstance(_cached_dets, dict):
                _sla = compute_sla_compliance(_cached_dets.get("detections", []))
            if _sla:
                _pct, _met, _tot = _sla
                _sla_color = "#16A34A" if _pct >= 90 else "#EA580C" if _pct >= 70 else "#DC2626"
                render_kpi_card("SLA Compliance", f"{_pct}%", _sla_color)
            else:
                render_kpi_card("SLA Compliance", "N/A", "#6B7280")

        # Detection source breakdown (1P vs 3P)
        _alerts_data = data.get("alerts", {})
        _dets_data = data.get("detections", {})
        _1p_alerts = _alerts_data.get("first_party", 0)
        _3p_alerts = _alerts_data.get("third_party", 0)
        _1p_dets = _dets_data.get("first_party", 0)
        _3p_dets = _dets_data.get("third_party", 0)
        if _1p_alerts or _3p_alerts or _1p_dets or _3p_dets:
            _src_k1, _src_k2, _src_k3, _src_k4 = st.columns(4)
            with _src_k1:
                render_kpi_card("CrowdStrike Alerts", str(_1p_alerts), "#2563EB")
            with _src_k2:
                render_kpi_card("3rd-Party Alerts", str(_3p_alerts),
                                "#7C3AED" if _3p_alerts > 0 else "#6B7280")
            with _src_k3:
                render_kpi_card("CrowdStrike Detections", str(_1p_dets), "#2563EB")
            with _src_k4:
                render_kpi_card("3rd-Party Detections", str(_3p_dets),
                                "#7C3AED" if _3p_dets > 0 else "#6B7280")

            # Charts row: Detections by Product + Cases by Status + 3P Detection Sources
            _det_sources = _dets_data.get("by_source", {})
            _det_sources = {k: v for k, v in _det_sources.items() if k != "Unknown"}
            _chart_r1, _chart_r2, _chart_r3 = st.columns(3)

            with _chart_r1:
                render_section_header("Detections by Product")
                _by_product = data.get("detections", {}).get("by_product", {})
                if _by_product:
                    fig = go.Figure(go.Pie(
                        labels=list(_by_product.keys()),
                        values=list(_by_product.values()),
                        hole=0.4,
                        marker_colors=CHART_PALETTE[:len(_by_product)],
                    ))
                    apply_chart_theme(fig, CHART_HEIGHT_SM)
                    st.plotly_chart(fig, width="stretch")
                else:
                    _det_sev = data.get("detections", {}).get("by_severity", {})
                    if _det_sev:
                        st.caption("Showing severity (refresh cache for product breakdown)")
                        fig = go.Figure(go.Pie(
                            labels=list(_det_sev.keys()),
                            values=list(_det_sev.values()),
                            hole=0.4,
                            marker_colors=[SEVERITY_COLORS.get(s, "#6B7280") for s in _det_sev.keys()],
                        ))
                        apply_chart_theme(fig, CHART_HEIGHT_SM)
                        st.plotly_chart(fig, width="stretch")

            with _chart_r2:
                render_section_header("Cases by Status")
                case_status = data["cases"].get("by_status", {})
                if case_status:
                    fig = go.Figure(go.Pie(
                        labels=list(case_status.keys()),
                        values=list(case_status.values()),
                        hole=0.4,
                        marker_colors=[STATUS_COLORS.get(s, "#6B7280") for s in case_status.keys()],
                    ))
                    apply_chart_theme(fig, CHART_HEIGHT_SM)
                    st.plotly_chart(fig, width="stretch", key="exec_cases_status")

            with _chart_r3:
                if _det_sources:
                    render_section_header("3rd-Party Detection Sources")
                    fig = go.Figure(go.Pie(
                        labels=list(_det_sources.keys()),
                        values=list(_det_sources.values()),
                        hole=0.4,
                        marker_colors=CHART_PALETTE[:len(_det_sources)],
                    ))
                    apply_chart_theme(fig, CHART_HEIGHT_SM)
                    st.plotly_chart(fig, width="stretch")

        # MTTD / MTTR
        mttd_data = data.get("mttd_mttr", {})
        if mttd_data.get("sample_size", 0) > 0:
            render_section_header("Response Time Metrics")
            _mttd_cards = []
            triaged_sec = mttd_data.get("avg_seconds_to_triaged")
            if triaged_sec:
                _mttd_cards.append(("MTTD (Avg)", f"{triaged_sec // 3600}h {(triaged_sec % 3600) // 60}m", "#2563EB"))
            resolved_sec = mttd_data.get("avg_seconds_to_resolved")
            if resolved_sec:
                _mttd_cards.append(("MTTR (Avg)", f"{resolved_sec // 3600}h {(resolved_sec % 3600) // 60}m", "#16A34A"))
            _mttd_cards.append(("Sample Size", mttd_data["sample_size"], "#6B7280"))
            _mttd_cols = st.columns(len(_mttd_cards))
            for col, (label, value, color) in zip(_mttd_cols, _mttd_cards):
                with col:
                    render_kpi_card(label, value, color)

        # Incidents summary
        inc_data = data.get("incidents", {})
        if inc_data.get("total", 0) > 0:
            render_section_header("Incidents")
            i1, i2 = st.columns(2)
            with i1:
                render_kpi_card("Total Incidents", inc_data["total"], "#DC2626")
                by_state = inc_data.get("by_state", {})
                if by_state:
                    fig = go.Figure(data=[go.Pie(
                        labels=list(by_state.keys()), values=list(by_state.values()), hole=0.4,
                        marker_colors=[STATUS_COLORS.get(s, "#6B7280") for s in by_state.keys()],
                    )])
                    apply_chart_theme(fig, height=CHART_HEIGHT_SM, showlegend=True)
                    st.plotly_chart(fig, width="stretch")
            with i2:
                by_tactic = inc_data.get("by_tactic", {})
                if by_tactic:
                    st.markdown("**Top MITRE Tactics (Incidents)**")
                    fig = go.Figure(data=[go.Bar(
                        x=list(by_tactic.values()), y=list(by_tactic.keys()),
                        orientation="h", marker_color="#E8272C"
                    )])
                    apply_chart_theme(fig, height=CHART_HEIGHT_SM)
                    st.plotly_chart(fig, width="stretch")

        # Sensor Health
        sh = data.get("sensor_health", {})
        if sh.get("total_managed", 0) > 0:
            by_ver = sh.get("by_version", {})
            _sh_title_l, _sh_title_r = st.columns([3, 2])
            with _sh_title_l:
                render_section_header("Sensor Health")
            with _sh_title_r:
                if by_ver:
                    render_section_header("Top Sensor Versions")
            s1, s2, s3, s4 = st.columns([1, 1, 1, 2])
            with s1:
                render_kpi_card("RFM Hosts", sh.get("rfm_count", 0), "#DC2626" if sh.get("rfm_count", 0) > 0 else "#16A34A")
            with s2:
                total = sh.get("total_managed", 1)
                stale = data.get("hosts", {}).get("stale_count", 0)
                active = total - stale
                pct = round(active / total * 100, 1) if total > 0 else 0
                render_kpi_card("Coverage", f"{pct}%", "#16A34A" if pct > 90 else "#EA580C")
            with s3:
                render_kpi_card("Sensor Versions", len(by_ver), "#2563EB")
            with s4:
                if by_ver:
                    total_sampled = sum(by_ver.values())
                    ver_rows = []
                    for ver, cnt in list(by_ver.items())[:3]:
                        pct = round(cnt / total_sampled * 100, 1) if total_sampled > 0 else 0
                        ver_rows.append({"Version": ver, "Hosts": cnt, "%": f"{pct}%"})
                    row_height = 35
                    header_height = 38
                    table_h = header_height + len(ver_rows) * row_height + 2
                    st.dataframe(ver_rows, width="content", hide_index=True, height=table_h)

        # Asset Inventory (Discover)
        assets = data.get("asset_inventory", {})
        has_asset_data = any(assets.get(k, 0) > 0 for k in ["managed_hosts", "unmanaged_hosts", "iot_assets", "accounts"])
        if has_asset_data:
            render_section_header("Asset Inventory (Discover)")
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
            render_section_header("External Attack Surface")
            render_kpi_card("Internet-Facing Assets", eas["total_assets"], "#DC2626")

        # Row 1b: Detection Time Buckets + Tactics Timechart
        row1b_col1, row1b_col2 = st.columns(2)

        with row1b_col1:
            render_section_header("Detections by Time Window")
            time_buckets = data.get("alerts", {}).get("by_time_bucket", {})
            if time_buckets:
                bucket_labels = {"last_1h": "Last 1h", "last_4h": "Last 4h", "last_8h": "Last 8h", "last_24h": "Last 24h"}
                bucket_colors = {"last_1h": "#DC2626", "last_4h": "#EA580C", "last_8h": "#CA8A04", "last_24h": "#2563EB"}
                _tb_cols = st.columns(len([k for k in ["last_1h", "last_4h", "last_8h", "last_24h"] if k in time_buckets]) or 1)
                _col_idx = 0
                for key in ["last_1h", "last_4h", "last_8h", "last_24h"]:
                    if key in time_buckets:
                        with _tb_cols[_col_idx]:
                            render_kpi_card(bucket_labels.get(key, key), str(time_buckets[key]),
                                            color=bucket_colors.get(key, "#6B7280"))
                        _col_idx += 1
            else:
                st.info("No time-bucketed data available")

        with row1b_col2:
            render_section_header("Attack Tactics Timeline")
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
                    apply_chart_theme(fig_tl, height=CHART_HEIGHT_SM,
                                      xaxis_title="Time", yaxis_title="Detections",
                                      legend=dict(orientation="h", y=-0.3))
                    st.plotly_chart(fig_tl, width="stretch")
                else:
                    st.info("No tactic timeline data available")
            else:
                st.info("No tactic timeline data available")

        # Row 2: Top Critical Detections + Top Critical Vulnerabilities
        row2_col1, row2_col2 = st.columns(2)

        with row2_col1:
            render_section_header("Critical/High Detections")
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
            render_section_header("Critical Vulnerabilities")
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
    st.markdown(f"<small>Search Falcon endpoint detections | {falcon_link('detections', 'Open in Falcon')}</small>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        det_severity = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low", "Informational"], key="det_sev")
        det_severity_val = None if det_severity == "All" else det_severity.lower()
    with col2:
        det_status = st.selectbox("Status", ["All", "new", "in_progress", "true_positive", "false_positive", "closed"], key="det_status")
        det_status_val = None if det_status == "All" else det_status
    with col3:
        det_limit = st.number_input("Max Results", min_value=1, max_value=500, value=50, key="det_limit")
    det_hours = st.session_state.get("global_hours", 168)

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
                result = run_async(search_detections(hours=int(det_hours), limit=50))
                data = safe_json_parse(result)
                if data and "error" not in data:
                    st.session_state["detections_data"] = data

    detections_data = st.session_state.get("detections_data")
    if detections_data:
        items = detections_data.get("detections", [])

        # KPI row: total, first-party, third-party, critical
        _first_party = detections_data.get("first_party", sum(1 for d in items if d.get("product") != "thirdparty"))
        _third_party = detections_data.get("third_party", sum(1 for d in items if d.get("product") == "thirdparty"))
        _critical = sum(1 for d in items if str(d.get("severity", "")).lower() == "critical")
        k1, k2, k3, k4 = st.columns(4)
        with k1:
            render_kpi_card("Total Detections", str(detections_data.get("total_found", len(items))), color="#E8272C")
        with k2:
            render_kpi_card("CrowdStrike (1P)", str(_first_party), color="#2563EB")
        with k3:
            render_kpi_card("Third-Party (3P)", str(_third_party),
                            color="#7C3AED" if _third_party > 0 else "#6B7280")
        with k4:
            render_kpi_card("Critical", str(_critical),
                            color="#DC2626" if _critical > 0 else "#16A34A")

        # KPI row 2: Detection status + top targeted host
        if items:
            _det_df = pd.DataFrame(items)
            _status_counts = _det_df["status"].value_counts().to_dict()
            _valid_hosts = _det_df[~_det_df["hostname"].isin(["N/A", "n/a", "", "Unknown"])]
            _host_counts = _valid_hosts["hostname"].value_counts() if not _valid_hosts.empty else pd.Series(dtype=int)
            _status_cards = [(s.replace("_", " ").title(), str(c),
                              STATUS_COLORS.get(s.replace("_", " ").title(), "#6B7280"))
                             for s, c in list(_status_counts.items())[:5]]
            if not _host_counts.empty:
                _status_cards.append(("Top Host", str(_host_counts.index[0]),
                                      "#2563EB"))
            _sk_cols = st.columns(len(_status_cards))
            for col, (label, value, color) in zip(_sk_cols, _status_cards):
                with col:
                    render_kpi_card(label, value, color)

        with st.expander("FQL Filter Used"):
            st.code(detections_data.get("query_filter", ""), language="text")
            _ps = detections_data.get("products_seen", {})
            if _ps:
                st.caption(f"Product types in results: {_ps}")

        if items:
            # _det_df already created in KPI row 2 above

            # --- Charts row 1: Severity donut + Source donut + 3P vendor ---
            _det_chart1, _det_chart2, _det_chart3 = st.columns(3)

            with _det_chart1:
                render_section_header("Severity Distribution")
                # Prefer full API counts from security posture over small sample
                _posture = st.session_state.get("posture_data", {})
                _posture_sev = _posture.get("detections", {}).get("by_severity", {}) if _posture else {}
                _sev_counts = _posture_sev if _posture_sev else _det_df["severity"].value_counts().to_dict()
                if _sev_counts:
                    _sev_order = ["Critical", "High", "Medium", "Low", "Informational"]
                    _ordered_sev = {s: _sev_counts[s] for s in _sev_order if s in _sev_counts and _sev_counts[s] > 0}
                    _ordered_sev.update({s: c for s, c in _sev_counts.items() if s not in _ordered_sev and c > 0})
                    fig = go.Figure(go.Pie(
                        labels=list(_ordered_sev.keys()),
                        values=list(_ordered_sev.values()),
                        hole=0.4,
                        marker_colors=[SEVERITY_COLORS.get(s, "#6B7280") for s in _ordered_sev.keys()],
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_SM)
                    st.plotly_chart(fig, width="stretch")

            with _det_chart2:
                render_section_header("Detection Sources")
                if "source" in _det_df.columns:
                    _source_counts = _det_df["source"].value_counts().to_dict()
                    if _source_counts:
                        fig = go.Figure(go.Pie(
                            labels=list(_source_counts.keys()),
                            values=list(_source_counts.values()),
                            hole=0.4,
                            marker_colors=CHART_PALETTE[:len(_source_counts)],
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_SM)
                        st.plotly_chart(fig, width="stretch")

            with _det_chart3:
                # Show 3rd-party vendor breakdown if any exist
                if "source" in _det_df.columns:
                    _3p_df = _det_df[_det_df["product"] == "thirdparty"] if "product" in _det_df.columns else pd.DataFrame()
                    if not _3p_df.empty:
                        render_section_header("Detections by 3rd-Party Vendor")
                        _vendor_counts = _3p_df["source"].value_counts().to_dict()
                        if _vendor_counts:
                            fig = go.Figure(go.Pie(
                                labels=list(_vendor_counts.keys()),
                                values=list(_vendor_counts.values()),
                                hole=0.4,
                                marker_colors=CHART_PALETTE[:len(_vendor_counts)],
                            ))
                            apply_chart_theme(fig, height=CHART_HEIGHT_SM)
                            st.plotly_chart(fig, width="stretch")
                    else:
                        render_section_header("Detections by Product Type")
                        if "product" in _det_df.columns:
                            _prod_labels = {"epp": "Falcon EDR", "idp": "Identity Protection",
                                            "ngsiem": "NGSIEM", "cao": "CAO", "mobile": "Mobile",
                                            "cspm": "Cloud Security", "thirdparty": "Third-Party",
                                            "xdr": "XDR", "fcs": "Cloud Security", "data-protection": "Data Protection",
                                            "automated-lead": "Automated Lead", "unknown": "Unknown"}
                            _prod_counts = _det_df["product"].value_counts().to_dict()
                            _labeled = {_prod_labels.get(k, k): v for k, v in _prod_counts.items()}
                            if _labeled:
                                fig = go.Figure(go.Pie(
                                    labels=list(_labeled.keys()),
                                    values=list(_labeled.values()),
                                    hole=0.4,
                                    marker_colors=CHART_PALETTE[:len(_labeled)],
                                ))
                                apply_chart_theme(fig, height=CHART_HEIGHT_SM)
                                st.plotly_chart(fig, width="stretch")

            # --- Tables row: Tactics + Techniques ---
            _det_tbl1, _det_tbl2 = st.columns(2)

            with _det_tbl1:
                render_section_header("MITRE ATT&CK Tactics")
                _tactic_counts = _det_df["tactic"].value_counts().head(10).reset_index()
                _tactic_counts.columns = ["Tactic", "Count"]
                if not _tactic_counts.empty:
                    st.dataframe(_tactic_counts, hide_index=True, width="stretch")

            with _det_tbl2:
                render_section_header("MITRE ATT&CK Techniques")
                _tech_counts = _det_df["technique"].value_counts().head(10).reset_index()
                _tech_counts.columns = ["Technique", "Count"]
                if not _tech_counts.empty:
                    st.dataframe(_tech_counts, hide_index=True, width="stretch")

            # --- Detection timeline (if timestamp data available) ---
            if "timestamp" in _det_df.columns:
                _det_df["_ts"] = pd.to_datetime(_det_df["timestamp"], errors="coerce")
                _det_ts = _det_df.dropna(subset=["_ts"])
                if not _det_ts.empty:
                    render_section_header("Detection Timeline")
                    _det_ts["_hour"] = _det_ts["_ts"].dt.floor("h")
                    _timeline = _det_ts.groupby(["_hour", "severity"]).size().reset_index(name="count")
                    fig = px.area(_timeline, x="_hour", y="count", color="severity",
                                  color_discrete_map=SEVERITY_COLORS)
                    apply_chart_theme(fig, height=CHART_HEIGHT_SM,
                                      xaxis_title="Time", yaxis_title="Detections",
                                      legend=dict(orientation="h", y=-0.25))
                    st.plotly_chart(fig, width="stretch")

            # --- Data table ---
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
                    "source": st.column_config.TextColumn("Source", width="small"),
                    "hostname": st.column_config.TextColumn("Hostname"),
                    "tactic": st.column_config.TextColumn("MITRE Tactic"),
                    "technique": st.column_config.TextColumn("MITRE Technique"),
                    "description": st.column_config.TextColumn("Description", width="large"),
                    "timestamp": st.column_config.TextColumn("Timestamp"),
                    "id": None,
                    "product": None,
                }
            )
            export_buttons(detections_data, "detections")
        else:
            st.info("No detections found matching criteria")

# ============ TAB 3: CASES ============

with tab_cases:
    st.subheader("CrowdStrike Cases")
    st.markdown(f"<small>{falcon_link('cases', 'Open in Falcon')}</small>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        case_status = st.selectbox("Status", ["All", "New", "Open", "In Progress", "Reopened", "Closed"], key="case_status")
        case_status_val = None if case_status == "All" else case_status.lower().replace(" ", "_")
    with col2:
        case_severity = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"], key="case_sev")
        case_severity_val = None if case_severity == "All" else case_severity.lower()
    with col3:
        case_limit = st.number_input("Max Results", min_value=1, max_value=500, value=50, key="case_limit")
    case_hours = st.session_state.get("global_hours", 168)

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
                result = run_async(search_cases(hours=int(case_hours), limit=50))
                data = safe_json_parse(result)
                if data and "error" not in data:
                    st.session_state["cases_data"] = data

    cases_data = st.session_state.get("cases_data")
    if cases_data:
        st.success(f"Found {cases_data['total_found']} cases")

        if cases_data.get("cases"):
            _cases_list = cases_data["cases"]
            _cases_df = pd.DataFrame(_cases_list)

            # --- Charts row: Status distribution + Severity distribution + Assigned To ---
            _case_ch1, _case_ch2, _case_ch3 = st.columns(3)

            with _case_ch1:
                render_section_header("Cases by Status")
                # Prefer full API counts from security posture over small sample
                _posture = st.session_state.get("posture_data", {})
                _posture_cs = _posture.get("cases", {}).get("by_status", {}) if _posture else {}
                _cs_counts = _posture_cs if _posture_cs else _cases_df["status"].value_counts().to_dict()
                if _cs_counts:
                    fig = go.Figure(go.Pie(
                        labels=list(_cs_counts.keys()),
                        values=list(_cs_counts.values()),
                        hole=0.4,
                        marker_colors=[STATUS_COLORS.get(s.replace("_", " ").title(), "#6B7280") for s in _cs_counts.keys()],
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_SM)
                    st.plotly_chart(fig, width="stretch", key="cases_tab_status")

            with _case_ch2:
                render_section_header("Cases by Severity")
                if "severity" in _cases_df.columns:
                    # Case severity is numeric — map to named buckets
                    def _case_sev_label(val):
                        try:
                            v = int(val)
                        except (ValueError, TypeError):
                            return str(val)
                        if v >= 80:
                            return "Critical"
                        if v >= 60:
                            return "High"
                        if v >= 40:
                            return "Medium"
                        if v >= 20:
                            return "Low"
                        return "Informational"
                    _cases_df["_sev_label"] = _cases_df["severity"].apply(_case_sev_label)
                    _csev_counts = _cases_df["_sev_label"].value_counts().to_dict()
                    if _csev_counts:
                        fig = go.Figure(go.Pie(
                            labels=list(_csev_counts.keys()),
                            values=list(_csev_counts.values()),
                            hole=0.4,
                            marker_colors=[SEVERITY_COLORS.get(s, "#6B7280") for s in _csev_counts.keys()],
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_SM)
                        st.plotly_chart(fig, width="stretch")

            with _case_ch3:
                render_section_header("Assigned To")
                if "assigned_to" in _cases_df.columns:
                    _assign_counts = _cases_df["assigned_to"].value_counts().head(10)
                    if not _assign_counts.empty:
                        fig = go.Figure(go.Bar(
                            x=_assign_counts.values, y=_assign_counts.index,
                            orientation="h", marker_color="#0891B2",
                            text=_assign_counts.values, textposition="auto",
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_SM, yaxis=dict(autorange="reversed"))
                        st.plotly_chart(fig, width="stretch")

            # --- Data table ---
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
    st.markdown(f"<small>{falcon_link('vulnerabilities', 'Open in Falcon')}</small>", unsafe_allow_html=True)

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
            _vulns_list = vulns_data["vulnerabilities"]
            _vulns_df = pd.DataFrame(_vulns_list)

            # --- Charts row: Severity donut + CVSS histogram + Top Apps ---
            _vc1, _vc2, _vc3 = st.columns(3)

            with _vc1:
                render_section_header("Severity Distribution")
                # Prefer full API counts from security posture over small sample
                # (default fetch is pre-filtered to critical-only, which skews the chart)
                _posture = st.session_state.get("posture_data", {})
                _posture_vsev = _posture.get("vulnerabilities", {}).get("by_severity", {}) if _posture else {}
                if _posture_vsev:
                    _vsev = _posture_vsev
                elif "severity" in _vulns_df.columns:
                    # Normalize uppercase severity (CRITICAL) to title-case (Critical)
                    _vulns_df["_sev_label"] = _vulns_df["severity"].apply(lambda s: str(s).title() if s else "Unknown")
                    _vsev = _vulns_df["_sev_label"].value_counts().to_dict()
                else:
                    _vsev = {}
                if _vsev:
                    _sev_order = ["Critical", "High", "Medium", "Low", "Informational"]
                    _ordered = {s: _vsev[s] for s in _sev_order if s in _vsev and _vsev[s] > 0}
                    _ordered.update({s: c for s, c in _vsev.items() if s not in _ordered and c > 0})
                    fig = go.Figure(go.Pie(
                        labels=list(_ordered.keys()),
                        values=list(_ordered.values()),
                        hole=0.4,
                        marker_colors=[SEVERITY_COLORS.get(s, "#6B7280") for s in _ordered.keys()],
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_SM)
                    st.plotly_chart(fig, width="stretch")

            with _vc2:
                render_section_header("CVSS Score Distribution")
                if "base_score" in _vulns_df.columns:
                    _scores = pd.to_numeric(_vulns_df["base_score"], errors="coerce").dropna()
                    if not _scores.empty:
                        fig = go.Figure(go.Histogram(
                            x=_scores, nbinsx=10,
                            marker_color="#7C3AED",
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_SM,
                                          xaxis_title="CVSS Score", yaxis_title="Count")
                        st.plotly_chart(fig, width="stretch")

            with _vc3:
                render_section_header("Top Affected Applications")
                if "app_name" in _vulns_df.columns:
                    _app_counts = _vulns_df["app_name"].value_counts().head(8)
                    if not _app_counts.empty:
                        fig = go.Figure(go.Bar(
                            x=_app_counts.values, y=_app_counts.index,
                            orientation="h", marker_color="#EA580C",
                            text=_app_counts.values, textposition="auto",
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_SM, yaxis=dict(autorange="reversed"))
                        st.plotly_chart(fig, width="stretch")

            # --- Vulnerability aging (if created timestamp available) ---
            if "created" in _vulns_df.columns:
                _vulns_df["_created"] = pd.to_datetime(_vulns_df["created"], errors="coerce")
                _vulns_valid = _vulns_df.dropna(subset=["_created"])
                if not _vulns_valid.empty:
                    _vc4, _vc5 = st.columns(2)
                    with _vc4:
                        render_section_header("Vulnerability Age Distribution")
                        _now = pd.Timestamp.now(tz="UTC")
                        _ts_col = _vulns_valid["_created"]
                        if _ts_col.dt.tz is None:
                            _ts_col = _ts_col.dt.tz_localize("UTC")
                        else:
                            _ts_col = _ts_col.dt.tz_convert("UTC")
                        _days = (_now - _ts_col).dt.days
                        _days = _days.dropna()
                        if not _days.empty:
                            _bins = [0, 7, 30, 90, 180, 9999]
                            _labels = ["0-7d", "8-30d", "31-90d", "91-180d", "180+d"]
                            _buckets = pd.cut(_days, bins=_bins, labels=_labels, right=True)
                            _age_counts = _buckets.value_counts().reindex(_labels, fill_value=0)
                            _age_colors = ["#16A34A", "#2563EB", "#CA8A04", "#EA580C", "#DC2626"]
                            fig = go.Figure(go.Bar(
                                x=_age_counts.index.tolist(),
                                y=_age_counts.values.tolist(),
                                marker_color=_age_colors,
                                text=_age_counts.values.tolist(),
                                textposition="auto",
                            ))
                            apply_chart_theme(fig, height=CHART_HEIGHT_SM,
                                              xaxis_title="Age", yaxis_title="Vulnerabilities")
                            st.plotly_chart(fig, width="stretch")

                    with _vc5:
                        render_section_header("Top Affected Hosts")
                        if "hostname" in _vulns_df.columns:
                            _host_counts = _vulns_df["hostname"].value_counts().head(8)
                            if not _host_counts.empty:
                                fig = go.Figure(go.Bar(
                                    x=_host_counts.values, y=_host_counts.index,
                                    orientation="h", marker_color="#DC2626",
                                    text=_host_counts.values, textposition="auto",
                                ))
                                apply_chart_theme(fig, height=CHART_HEIGHT_SM, yaxis=dict(autorange="reversed"))
                                st.plotly_chart(fig, width="stretch")

            # --- Data table ---
            df = pd.DataFrame(_vulns_list)
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

if tab_identity is not None:
 with tab_identity:
    st.subheader("Identity Protection")
    st.markdown(f"<small>Identity threat detection and risk assessment | {falcon_link('identity', 'Open in Falcon')}</small>", unsafe_allow_html=True)

    idp_hours = st.session_state.get("global_hours", 168)

    # Auto-load on first visit: try cache, fallback to live API
    if "identity_data" not in st.session_state:
        cached = falcon_cache.get_parsed("identity_protection")
        if cached and not isinstance(cached, str) and "error" not in cached:
            st.session_state["identity_data"] = cached
        else:
            with st.spinner("Loading Identity Protection data..."):
                raw = run_async(get_identity_protection(limit=50))
                data = safe_json_parse(raw)
                if data:
                    st.session_state["identity_data"] = data

    idp_data = st.session_state.get("identity_data")
    if idp_data:
        if idp_data.get("error"):
            st.warning(f"Identity Protection: {idp_data['error']}")
            render_scope_hint("Identity Protection:read")
        else:
            # KPI row
            k1, k2, k3, k4, k5 = st.columns(5)
            with k1:
                render_kpi_card("Identity Sensors", f"{idp_data.get('total_sensors', 0):,}", color="#7C3AED")
            with k2:
                render_kpi_card("Risky Entities", str(idp_data.get("total_risky", 0)), color="#E8272C")
            with k3:
                by_status = idp_data.get("by_status", {})
                active_count = by_status.get("Active", 0)
                render_kpi_card("Active Sensors", str(active_count), color="#16A34A")
            with k4:
                inactive_count = by_status.get("Inactive", 0)
                render_kpi_card("Inactive Sensors", str(inactive_count),
                                color="#DC2626" if inactive_count > 0 else "#16A34A")
            with k5:
                _high_risk = sum(1 for e in idp_data.get("risky_entities", [])
                                 if (e.get("risk_score") or 0) >= 70)
                render_kpi_card("High-Risk Users", str(_high_risk),
                                color="#DC2626" if _high_risk > 0 else "#16A34A")

            st.markdown("---")

            # Charts row: sensor status + OS distribution + entity types
            by_status = idp_data.get("by_status", {})
            by_os = idp_data.get("by_os", {})
            risky = idp_data.get("risky_entities", [])

            # Build entity type counts from risky entities
            entity_types = {}
            for e in risky:
                t = e.get("type", "Unknown")
                entity_types[t] = entity_types.get(t, 0) + 1

            if by_status or by_os or entity_types:
                chart_col1, chart_col2, chart_col3 = st.columns(3)
                with chart_col1:
                    if by_status:
                        render_section_header("Sensors by Status")
                        fig = go.Figure(go.Pie(
                            labels=list(by_status.keys()),
                            values=list(by_status.values()),
                            hole=0.4,
                            marker_colors=[STATUS_COLORS.get(s, "#7C3AED") for s in by_status.keys()],
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                        st.plotly_chart(fig, width="stretch")
                with chart_col2:
                    if by_os:
                        render_section_header("Sensors by OS")
                        fig = go.Figure(go.Pie(
                            labels=list(by_os.keys()),
                            values=list(by_os.values()),
                            hole=0.4,
                            marker_colors=CHART_PALETTE[:len(by_os)],
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                        st.plotly_chart(fig, width="stretch")
                with chart_col3:
                    if entity_types:
                        render_section_header("Risky Entities by Type")
                        fig = go.Figure(go.Pie(
                            labels=list(entity_types.keys()),
                            values=list(entity_types.values()),
                            hole=0.4,
                            marker_colors=CHART_PALETTE[:len(entity_types)],
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                        st.plotly_chart(fig, width="stretch")

            # Top risky users bar chart + risk factor severity heatmap
            risky = idp_data.get("risky_entities", [])
            if risky:
                _user_chart1, _user_chart2 = st.columns(2)

                with _user_chart1:
                    render_section_header("Top Risky Users by Score")
                    _top_users = sorted(risky, key=lambda e: e.get("risk_score", 0), reverse=True)[:15]
                    _names = [e.get("display_name", "N/A")[:25] for e in _top_users]
                    _scores = [e.get("risk_score", 0) for e in _top_users]
                    _colors = ["#DC2626" if s >= 70 else "#EA580C" if s >= 40 else "#CA8A04" for s in _scores]
                    fig = go.Figure(go.Bar(
                        x=_scores, y=_names, orientation="h",
                        marker_color=_colors,
                        text=_scores, textposition="auto",
                    ))
                    apply_chart_theme(fig, height=max(CHART_HEIGHT_MD, len(_top_users) * 28),
                                      yaxis=dict(autorange="reversed"))
                    st.plotly_chart(fig, width="stretch")

                with _user_chart2:
                    render_section_header("Identity Risk Factors by Severity")
                    _sev_counts = {}
                    for entity in risky:
                        for f in entity.get("risk_factors", []):
                            sev = f.get("severity", "Unknown")
                            _sev_counts[sev] = _sev_counts.get(sev, 0) + 1
                    if _sev_counts:
                        _sev_order = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]
                        _present_sev = [s for s in _sev_order if s in _sev_counts]
                        fig = go.Figure(go.Pie(
                            labels=_present_sev,
                            values=[_sev_counts[s] for s in _present_sev],
                            hole=0.4,
                            marker_colors=[SEVERITY_COLORS.get(s, "#6B7280") for s in _present_sev],
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                        st.plotly_chart(fig, width="stretch")

            # Risk factor distribution + Risk score histogram
            risky = idp_data.get("risky_entities", [])
            if risky:
                _rf_chart1, _rf_chart2 = st.columns(2)

                with _rf_chart1:
                    render_section_header("Top Identity Risk Factor Types")
                    _factor_counts = {}
                    for entity in risky:
                        for f in entity.get("risk_factors", []):
                            ft = f.get("type", "Unknown")
                            _factor_counts[ft] = _factor_counts.get(ft, 0) + 1
                    if _factor_counts:
                        _sorted_factors = sorted(_factor_counts.items(), key=lambda x: x[1], reverse=True)[:12]
                        fig = go.Figure(go.Bar(
                            x=[c for _, c in _sorted_factors],
                            y=[t for t, _ in _sorted_factors],
                            orientation="h", marker_color="#E8272C",
                            text=[c for _, c in _sorted_factors],
                            textposition="auto",
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD, yaxis=dict(autorange="reversed"))
                        st.plotly_chart(fig, width="stretch")

                with _rf_chart2:
                    render_section_header("Identity Risk Score Distribution")
                    _scores = [e.get("risk_score", 0) for e in risky if e.get("risk_score") is not None]
                    if _scores:
                        fig = go.Figure(go.Histogram(
                            x=_scores, nbinsx=10,
                            marker_color="#7C3AED",
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD,
                                          xaxis_title="Risk Score", yaxis_title="Entity Count")
                        st.plotly_chart(fig, width="stretch")

            # Department + domain breakdown (user-centric data)
            risky = idp_data.get("risky_entities", [])
            if risky:
                _dept_counts = {}
                _domain_counts = {}
                _admin_count = 0
                for e in risky:
                    dept = e.get("department", "")
                    if dept:
                        _dept_counts[dept] = _dept_counts.get(dept, 0) + 1
                    domain = e.get("domain", "")
                    if domain:
                        _domain_counts[domain] = _domain_counts.get(domain, 0) + 1
                    if e.get("is_admin"):
                        _admin_count += 1

                if _dept_counts or _domain_counts:
                    _dept_col, _domain_col = st.columns(2)

                    with _dept_col:
                        if _dept_counts:
                            render_section_header("Risky Users by Department")
                            _sorted_dept = sorted(_dept_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                            fig = go.Figure(go.Pie(
                                labels=[d for d, _ in _sorted_dept],
                                values=[c for _, c in _sorted_dept],
                                hole=0.4,
                                marker_colors=CHART_PALETTE[:len(_sorted_dept)],
                            ))
                            apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                            st.plotly_chart(fig, width="stretch")

                    with _domain_col:
                        if _domain_counts:
                            render_section_header("Risky Users by Domain")
                            _sorted_domain = sorted(_domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                            fig = go.Figure(go.Pie(
                                labels=[d for d, _ in _sorted_domain],
                                values=[c for _, c in _sorted_domain],
                                hole=0.4,
                                marker_colors=CHART_PALETTE[:len(_sorted_domain)],
                            ))
                            apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                            st.plotly_chart(fig, width="stretch")

                # Admin users callout
                if _admin_count > 0:
                    st.warning(
                        f"**Privileged Account Risk:** {_admin_count} admin/privileged account(s) "
                        f"found among risky entities. Privileged accounts with high risk scores "
                        f"require immediate attention."
                    )

            # Table: Top risky entities
            risky = idp_data.get("risky_entities", [])
            if risky:
                render_section_header("Top Risky Identities")
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
                if "department" in df.columns:
                    display_cols["department"] = st.column_config.TextColumn("Department", width="small")
                if "domain" in df.columns:
                    display_cols["domain"] = st.column_config.TextColumn("Domain", width="small")
                if "job_title" in df.columns:
                    display_cols["job_title"] = st.column_config.TextColumn("Job Title", width="small")
                if "is_admin" in df.columns:
                    display_cols["is_admin"] = st.column_config.CheckboxColumn("Admin", width="small")
                display_cols["entity_id"] = None
                display_cols["risk_factors"] = None
                display_cols["roles"] = None
                st.dataframe(df, width="stretch", hide_index=True, column_config=display_cols)

                render_section_header("Risk Factor Details (Top 10 Users)")
                for entity in risky[:10]:
                    factors = entity.get("risk_factors", [])
                    if factors:
                        _admin_tag = " &#128272;" if entity.get("is_admin") else ""
                        _dept_tag = f" | {entity.get('department')}" if entity.get("department") else ""
                        st.markdown(
                            f"**{entity.get('display_name', 'N/A')}** "
                            f"(score: {entity.get('risk_score', 'N/A')}{_dept_tag}){_admin_tag}",
                            unsafe_allow_html=True
                        )
                        factor_rows = [{"Type": f.get("type", ""), "Severity": f.get("severity", "")} for f in factors]
                        st.dataframe(pd.DataFrame(factor_rows), hide_index=True, width="stretch")

                export_buttons(idp_data, "identity")
            elif not by_status and not by_os:
                st.info("No identity data found")
    else:
        render_empty_state("Identity Protection", "Data will load automatically.")

# ============ TAB 6: CLOUD SECURITY ============

if tab_cloud is not None:
 with tab_cloud:
    st.subheader("Cloud Security Posture")
    st.markdown(f"<small>CSPM risk findings and misconfigurations | {falcon_link('cloud_security', 'Open in Falcon')}</small>", unsafe_allow_html=True)

    cs_hours = st.session_state.get("global_hours", 168)

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

    # Auto-load on first visit: try cache, fallback to live API
    if "cloud_security_data" not in st.session_state:
        cached = falcon_cache.get_parsed("cloud_security")
        if cached and not isinstance(cached, str) and "error" not in cached:
            st.session_state["cloud_security_data"] = cached
        else:
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
            k1, k2, k3, k4, k5 = st.columns(5)
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
            with k5:
                _providers = cs_data.get("risks_by_provider", {})
                render_kpi_card("Cloud Providers", str(len(_providers)), color="#0891B2")

            st.markdown("---")

            # Chart row: severity bar + provider donut + service donut
            chart_col1, chart_col2, chart_col3 = st.columns(3)

            with chart_col1:
                if sev:
                    render_section_header("Cloud Misconfigurations by Severity")
                    sev_order = ["Critical", "High", "Medium", "Low", "Informational"]
                    present = [s for s in sev_order if s in sev]
                    fig = go.Figure(go.Pie(
                        labels=present,
                        values=[sev.get(s, 0) for s in present],
                        hole=0.4,
                        marker_colors=[SEVERITY_COLORS.get(s, "#6B7280") for s in present],
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                    st.plotly_chart(fig, width="stretch")

            with chart_col2:
                providers = cs_data.get("risks_by_provider", {})
                if providers:
                    render_section_header("Misconfigurations by Provider")
                    fig = go.Figure(go.Pie(
                        labels=list(providers.keys()),
                        values=list(providers.values()),
                        hole=0.4,
                        marker_colors=[PROVIDER_COLORS.get(p, "#7C3AED") for p in providers.keys()],
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                    st.plotly_chart(fig, width="stretch")

            with chart_col3:
                services = cs_data.get("risks_by_service", {})
                if services:
                    render_section_header("Top Cloud Service Categories")
                    sorted_svc = sorted(services.items(), key=lambda x: x[1], reverse=True)[:8]
                    fig = go.Figure(go.Pie(
                        labels=[s[0] for s in sorted_svc],
                        values=[s[1] for s in sorted_svc],
                        hole=0.4,
                        marker_colors=CHART_PALETTE[:len(sorted_svc)],
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                    st.plotly_chart(fig, width="stretch")

            # Row 2: top failing CSPM rules + top affected cloud accounts
            risks = cs_data.get("top_risks", [])
            if risks:
                _cs_chart1, _cs_chart2 = st.columns(2)

                with _cs_chart1:
                    render_section_header("Top Failing CSPM Rules")
                    _rule_counts = {}
                    for r in risks:
                        rule = r.get("rule_name", "Unknown")
                        if rule:
                            _rule_counts[rule] = _rule_counts.get(rule, 0) + 1
                    if _rule_counts:
                        _sorted_rules = sorted(_rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                        fig = go.Figure(go.Bar(
                            x=[c for _, c in _sorted_rules],
                            y=[r[:50] for r, _ in _sorted_rules],
                            orientation="h", marker_color="#DC2626",
                            text=[c for _, c in _sorted_rules],
                            textposition="auto",
                        ))
                        apply_chart_theme(fig, height=max(CHART_HEIGHT_MD, len(_sorted_rules) * 30),
                                          yaxis=dict(autorange="reversed"))
                        st.plotly_chart(fig, width="stretch")

                with _cs_chart2:
                    render_section_header("Top Affected Cloud Accounts")
                    _acct_counts = {}
                    for r in risks:
                        acct = r.get("account_name", "Unknown")
                        if acct:
                            _acct_counts[acct] = _acct_counts.get(acct, 0) + 1
                    if _acct_counts:
                        _sorted_accts = sorted(_acct_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                        fig = go.Figure(go.Pie(
                            labels=[a[:30] for a, _ in _sorted_accts],
                            values=[c for _, c in _sorted_accts],
                            hole=0.4,
                            marker_colors=CHART_PALETTE[:len(_sorted_accts)],
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                        st.plotly_chart(fig, width="stretch")

            # Row 3: finding status + severity-by-provider grouped bar
            if risks:
                _cs_chart3, _cs_chart4 = st.columns(2)

                with _cs_chart3:
                    render_section_header("Cloud Finding Status")
                    _status_counts = {}
                    for r in risks:
                        s = r.get("status", "Unknown")
                        _status_counts[s] = _status_counts.get(s, 0) + 1
                    if _status_counts:
                        fig = go.Figure(go.Pie(
                            labels=list(_status_counts.keys()),
                            values=list(_status_counts.values()),
                            hole=0.4,
                            marker_colors=[STATUS_COLORS.get(s, "#7C3AED") for s in _status_counts.keys()],
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                        st.plotly_chart(fig, width="stretch")

                with _cs_chart4:
                    render_section_header("Cloud Severity by Provider")
                    _prov_sev = {}
                    for r in risks:
                        prov = r.get("cloud_provider", "Unknown")
                        sev = r.get("severity", "Unknown")
                        if prov not in _prov_sev:
                            _prov_sev[prov] = {}
                        _prov_sev[prov][sev] = _prov_sev[prov].get(sev, 0) + 1
                    if _prov_sev:
                        _sev_order = ["Critical", "High", "Medium", "Low", "Informational"]
                        _providers = sorted(_prov_sev.keys())
                        fig = go.Figure()
                        for sev_name in _sev_order:
                            vals = [_prov_sev.get(p, {}).get(sev_name, 0) for p in _providers]
                            if any(v > 0 for v in vals):
                                fig.add_trace(go.Bar(
                                    name=sev_name, y=_providers, x=vals,
                                    orientation="h",
                                    marker_color=SEVERITY_COLORS.get(sev_name, "#6B7280"),
                                ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD,
                                          barmode="stack", xaxis_title="Count", yaxis_title="")
                        st.plotly_chart(fig, width="stretch")

            # Row 4: cloud resource type distribution
            if risks:
                _asset_type_counts = {}
                for r in risks:
                    at = r.get("asset_type", "Unknown")
                    if at:
                        _asset_type_counts[at] = _asset_type_counts.get(at, 0) + 1
                if _asset_type_counts:
                    render_section_header("Findings by Cloud Resource Type")
                    _sorted_at = sorted(_asset_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                    fig = go.Figure(go.Pie(
                        labels=[a for a, _ in _sorted_at],
                        values=[c for _, c in _sorted_at],
                        hole=0.4,
                        marker_colors=CHART_PALETTE[:len(_sorted_at)],
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                    st.plotly_chart(fig, width="stretch")

            # Data table: CSPM findings (always visible)
            risks = cs_data.get("top_risks", [])
            if risks:
                render_section_header("Cloud Security Findings")
                df = pd.DataFrame(risks)
                st.dataframe(df, width="stretch", hide_index=True, column_config={
                    "severity": st.column_config.TextColumn("Severity", width="small"),
                    "status": st.column_config.TextColumn("Status", width="small"),
                    "cloud_provider": st.column_config.TextColumn("Provider", width="small"),
                    "service_category": st.column_config.TextColumn("Service"),
                    "asset_type": st.column_config.TextColumn("Resource Type"),
                    "rule_name": st.column_config.TextColumn("CSPM Rule", width="large"),
                    "account_name": st.column_config.TextColumn("Cloud Account"),
                })
                export_buttons(cs_data, "cloud_security")
    else:
        render_empty_state("Cloud Security", "Data will load automatically.")

# ============ TAB 7: EXPOSURE MANAGEMENT ============

if tab_exposure is not None:
 with tab_exposure:
    st.subheader("External Attack Surface")
    st.markdown(f"<small>Internet-facing assets discovered by Falcon | {falcon_link('exposure', 'Open in Falcon')}</small>", unsafe_allow_html=True)

    em_hours = st.session_state.get("global_hours", 168)

    # Auto-load on first visit: try cache, fallback to live API
    if "exposure_data" not in st.session_state:
        cached = falcon_cache.get_parsed("exposure_management")
        if cached and not isinstance(cached, str) and "error" not in cached:
            st.session_state["exposure_data"] = cached
        else:
            with st.spinner("Loading Exposure Management data..."):
                raw = run_async(get_exposure_management(limit=100))
                data = safe_json_parse(raw)
                if data:
                    st.session_state["exposure_data"] = data

    em_data = st.session_state.get("exposure_data")
    if em_data:
        if em_data.get("error"):
            st.warning(f"Exposure Management: {em_data['error']}")
            render_scope_hint("Exposure Management:read")
        else:
            # KPI row
            k1, k2, k3, k4, k5 = st.columns(5)
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
            with k5:
                _em_countries = set(a.get("country", "") for a in em_data.get("assets", []) if a.get("country"))
                render_kpi_card("Countries", str(len(_em_countries)), color="#7C3AED")

            st.markdown("---")

            # Chart row: criticality bar + asset type donut + triage status
            chart_col1, chart_col2, chart_col3 = st.columns(3)

            with chart_col1:
                if crit:
                    render_section_header("Assets by Criticality")
                    crit_order = ["Critical", "High", "Medium", "Low", "Unassigned"]
                    crit_colors_map = {**SEVERITY_COLORS, "Unassigned": "#9CA3AF"}
                    present = [c for c in crit_order if c in crit]
                    fig = go.Figure(go.Pie(
                        labels=present,
                        values=[crit.get(c, 0) for c in present],
                        hole=0.4,
                        marker_colors=[crit_colors_map.get(c, "#6B7280") for c in present],
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                    st.plotly_chart(fig, width="stretch")

            with chart_col2:
                asset_types = em_data.get("by_asset_type", {})
                if asset_types:
                    render_section_header("Assets by Type")
                    fig = go.Figure(go.Pie(
                        labels=list(asset_types.keys()),
                        values=list(asset_types.values()),
                        hole=0.4,
                        marker_colors=CHART_PALETTE[:len(asset_types)],
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                    st.plotly_chart(fig, width="stretch")

            with chart_col3:
                triage = em_data.get("by_triage_status", {})
                if triage:
                    render_section_header("Triage Status Funnel")
                    fig = go.Figure(go.Funnel(
                        y=list(triage.keys()),
                        x=list(triage.values()),
                        marker_color=CHART_PALETTE[:len(triage)],
                        textinfo="value+percent initial",
                    ))
                    apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                    st.plotly_chart(fig, width="stretch")

            # Cloud provider row (if data available)
            cloud = em_data.get("by_cloud_provider", {})
            if cloud:
                render_section_header("Assets by Cloud Provider")
                fig = go.Figure(go.Pie(
                    labels=list(cloud.keys()),
                    values=list(cloud.values()),
                    hole=0.4,
                    marker_colors=[PROVIDER_COLORS.get(p, "#7C3AED") for p in cloud.keys()],
                ))
                apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                st.plotly_chart(fig, width="stretch")

            # Row 2: geographic distribution + top services/ports
            assets = em_data.get("assets", [])
            if assets:
                _em_chart1, _em_chart2 = st.columns(2)

                with _em_chart1:
                    _country_counts = {}
                    for a in assets:
                        country = a.get("country", "")
                        if country:
                            _country_counts[country] = _country_counts.get(country, 0) + 1
                    if _country_counts:
                        render_section_header("Assets by Country")
                        _sorted_countries = sorted(_country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                        fig = go.Figure(go.Pie(
                            labels=[co for co, _ in _sorted_countries],
                            values=[c for _, c in _sorted_countries],
                            hole=0.4,
                            marker_colors=CHART_PALETTE[:len(_sorted_countries)],
                        ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD)
                        st.plotly_chart(fig, width="stretch")

                with _em_chart2:
                    _svc_counts = {}
                    for a in assets:
                        services = a.get("services", [])
                        if isinstance(services, list):
                            for svc in services:
                                if svc:
                                    _svc_counts[str(svc)] = _svc_counts.get(str(svc), 0) + 1
                    if _svc_counts:
                        render_section_header("Top Services / Open Ports")
                        _sorted_svcs = sorted(_svc_counts.items(), key=lambda x: x[1], reverse=True)[:12]
                        fig = go.Figure(go.Bar(
                            x=[c for _, c in _sorted_svcs],
                            y=[s for s, _ in _sorted_svcs],
                            orientation="h", marker_color="#EA580C",
                            text=[c for _, c in _sorted_svcs],
                            textposition="auto",
                        ))
                        apply_chart_theme(fig, height=max(CHART_HEIGHT_MD, len(_sorted_svcs) * 28),
                                          yaxis=dict(autorange="reversed"))
                        st.plotly_chart(fig, width="stretch")

            # Row 3: discovery timeline + criticality by type heatmap
            if assets:
                _em_chart3, _em_chart4 = st.columns(2)

                with _em_chart3:
                    _disc_dates = [a.get("discovery_date") for a in assets if a.get("discovery_date")]
                    if _disc_dates:
                        render_section_header("Discovery Timeline")
                        _dates_parsed = pd.to_datetime(_disc_dates, errors="coerce").dropna()
                        if len(_dates_parsed) > 0:
                            _date_df = pd.DataFrame({"date": _dates_parsed})
                            _date_df["day"] = _date_df["date"].dt.date
                            _daily = _date_df.groupby("day").size().reset_index(name="count")
                            fig = go.Figure(go.Scatter(
                                x=_daily["day"], y=_daily["count"],
                                mode="lines+markers", fill="tozeroy",
                                marker_color="#7C3AED", line_color="#7C3AED",
                            ))
                            apply_chart_theme(fig, height=CHART_HEIGHT_MD,
                                              xaxis_title="Date", yaxis_title="Assets Discovered")
                            st.plotly_chart(fig, width="stretch")

                with _em_chart4:
                    # Criticality by asset type cross-tab
                    _type_crit = {}
                    for a in assets:
                        at = a.get("asset_type", "Unknown")
                        cr = a.get("criticality", "Unassigned")
                        if at not in _type_crit:
                            _type_crit[at] = {}
                        _type_crit[at][cr] = _type_crit[at].get(cr, 0) + 1
                    if _type_crit:
                        render_section_header("Criticality by Asset Type")
                        _crit_order = ["Critical", "High", "Medium", "Low", "Unassigned"]
                        _at_names = sorted(_type_crit.keys())
                        _crit_colors = {**SEVERITY_COLORS, "Unassigned": "#9CA3AF"}
                        fig = go.Figure()
                        for crit_name in _crit_order:
                            vals = [_type_crit.get(at, {}).get(crit_name, 0) for at in _at_names]
                            if any(v > 0 for v in vals):
                                fig.add_trace(go.Bar(
                                    name=crit_name, y=_at_names, x=vals,
                                    orientation="h",
                                    marker_color=_crit_colors.get(crit_name, "#6B7280"),
                                ))
                        apply_chart_theme(fig, height=CHART_HEIGHT_MD,
                                          barmode="stack", xaxis_title="Count", yaxis_title="")
                        st.plotly_chart(fig, width="stretch")

            # Assets data table (always visible, not in expander)
            assets = em_data.get("assets", [])
            if assets:
                render_section_header("Asset Details")
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
        render_empty_state("Exposure Management", "Data will load automatically.")

# ============ TAB 8: IOC SEARCH ============

with tab_tg:
    st.subheader("IOC Search")
    st.markdown(f"<small>Find which devices communicated with a domain, IP, or executed a specific hash | {falcon_link('threatgraph', 'Open in Falcon')}</small>", unsafe_allow_html=True)

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

if tab_ingestion is not None:
 with tab_ingestion:
    st.subheader("NGSIEM Data Ingestion")
    st.caption("LogScale ingestion volume and top data sources")

    ing_hours = st.session_state.get("global_hours", 24)

    # Auto-load on first visit: try cache, fallback to live API
    if "ingestion_data" not in st.session_state:
        cached = falcon_cache.get_parsed("ngsiem_ingestion")
        if cached and not isinstance(cached, str) and "error" not in cached:
            st.session_state["ingestion_data"] = cached
        else:
            with st.spinner("Querying NGSIEM ingestion data..."):
                raw = run_async(get_ngsiem_ingestion(hours=int(ing_hours)))
                ing_parsed = safe_json_parse(raw)
                if ing_parsed:
                    st.session_state["ingestion_data"] = ing_parsed

    ing_data = st.session_state.get("ingestion_data")

    if ing_data:
        top_error = ing_data.get("error")
        sources = ing_data.get("sources", [])
        is_mssp = ing_data.get("is_mssp", False)
        children = ing_data.get("children", [])

        # Mode indicator
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
                render_section_header("Top Data Sources by Volume")
                chart_sources = list(reversed(sources))
                bar_colors = [CHART_PALETTE[i % len(CHART_PALETTE)] for i in range(len(chart_sources))]
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
                apply_chart_theme(fig,
                                  height=max(300, len(chart_sources) * 40 + 100),
                                  xaxis_title="Volume Ingested (bytes)", yaxis_title="",
                                  yaxis=dict(showgrid=False))
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
                render_section_header("Per-Tenant Ingestion Breakdown")

                sorted_children = sorted(children, key=lambda c: c.get("total_bytes", 0))
                has_child_data = any(c.get("total_bytes", 0) > 0 for c in children)

                if has_child_data:
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
                    apply_chart_theme(fig_children,
                                      height=max(300, len(sorted_children) * 35 + 100),
                                      xaxis_title="Volume Ingested (bytes)", yaxis_title="",
                                      yaxis=dict(showgrid=False))
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
        render_empty_state("Ingestion", "Data will load automatically.")

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
                    "product:'thirdparty'+external_provider_name:'Corelight'",
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

# ============ TAB 11: AI CHAT ============

with tab_chat:
    st.subheader("Ask Falcon Digest")
    st.caption("Powered by CrowdStrike Falcon Platform with full MCP tool access")

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    st.markdown("**Quick Actions**")
    prompt_cols = st.columns(5)
    guided_prompts = [
        "Triage critical cases from the last 24h",
        "Show my security posture overview",
        "What are the top vulnerabilities I should patch?",
        "Hunt for suspicious IOCs in the last 7 days",
        "Generate an executive security briefing"
    ]
    for idx, (col, prompt_text) in enumerate(zip(prompt_cols, guided_prompts)):
        with col:
            if st.button(prompt_text, key=f"guided_{idx}", width="stretch"):
                st.session_state.chat_pending = prompt_text

    # Fixed-height scrollable chat window
    chat_container = st.container(height=500)
    with chat_container:
        if not st.session_state.chat_messages:
            st.markdown(
                '<div style="text-align:center; color:#9CA3AF; padding:40px 0;">'
                'Ask a question or use a Quick Action above to get started.</div>',
                unsafe_allow_html=True
            )
        for msg in st.session_state.chat_messages:
            if msg["role"] == "user":
                st.markdown(f'<div class="chat-user"><strong>You:</strong> {html.escape(msg["content"])}</div>', unsafe_allow_html=True)
            elif msg["role"] == "assistant":
                st.markdown(f'<div class="chat-assistant"><strong>Falcon Digest:</strong> {html.escape(msg["content"])}</div>', unsafe_allow_html=True)
            elif msg["role"] == "tool_call":
                with st.expander(f"Tool: {msg['tool_name']}", expanded=False):
                    st.json(msg.get("input", {}))
                    if msg.get("result"):
                        parsed = safe_json_parse(msg["result"])
                        if parsed:
                            st.json(parsed)
                        else:
                            st.text(msg["result"])

        # Auto-scroll is handled after new messages are sent (below)

    chat_input = st.chat_input("Ask about your security environment...")
    pending_msg = st.session_state.pop("chat_pending", None)
    active_input = pending_msg or chat_input

    if active_input:
        st.session_state.chat_messages.append({"role": "user", "content": active_input})
        with chat_container:
            st.markdown(f'<div class="chat-user"><strong>You:</strong> {html.escape(active_input)}</div>', unsafe_allow_html=True)
            components.html(_SCROLL_JS, height=0)
        api_messages = [{"role": "user", "content": active_input}]

        try:
            with st.spinner("Falcon Digest is thinking..."):
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
                    # Stream the response word-by-word into the chat container
                    stream_to_chat(chat_container, final_text)
                    st.session_state.chat_messages.append({"role": "assistant", "content": final_text})

        except Exception as e:
            _logger.error("LLM error: %s", e, exc_info=True)
            err_msg = "Sorry, I'm having trouble connecting to Falcon Digest right now. Please try again in a moment."
            stream_to_chat(chat_container, err_msg)
            st.session_state.chat_messages.append({
                "role": "assistant",
                "content": err_msg
            })

    if st.session_state.chat_messages:
        if st.button("Clear Chat", key="clear_chat"):
                st.session_state.chat_messages = []
                st.rerun()

# ============ FOOTER ============

st.divider()
st.caption(f"Falcon Digest v1.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if auto_refresh:
    _last_refresh = st.session_state.get("_last_auto_refresh", 0)
    _now = time.time()
    if _now - _last_refresh >= refresh_interval:
        st.session_state["_last_auto_refresh"] = _now
        # Clear cached data so tabs re-fetch on next run
        for _key in ["posture_data", "ingestion_data", "identity_data",
                      "cloud_security_data", "exposure_data"]:
            st.session_state.pop(_key, None)
        st.rerun()

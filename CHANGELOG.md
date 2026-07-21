# Changelog

## Chart Audit Fixes — 2026-03-19

### Color Mapping
- Added `Unknown` key to `SEVERITY_COLORS` (#9CA3AF) — fixes Identity Risk Factors, Cloud Severity by Provider charts showing fallback gray
- Added `Unknown` key to `STATUS_COLORS` (#9CA3AF) — fixes Cloud Finding Status chart using wrong fallback color
- Incidents by State pie chart now uses `STATUS_COLORS` mapping instead of default Plotly colors

### Data Source Fixes (sample → full API counts)
- Vulnerability Severity Distribution now uses posture `by_severity` data (full API counts) instead of pre-filtered critical-only 50-item sample
- Cases by Status chart now uses posture `by_status` data (full API counts) instead of 50-item sample
- Both charts fall back to sample data if posture data is not yet cached

### Bug Fixes
- Fixed `StreamlitDuplicateElementId` crash: Cases by Status pie chart appears in both Executive Summary and Cases tab with identical data — added unique `key` params (`exec_cases_status`, `cases_tab_status`)

## Product-Type Detection Breakdown & Fixes — 2026-03-19

### Server (crwd_mcp_server.py)
- Fixed product field values: `3rdparty` → `thirdparty` (correct API value) across all FQL filters
- Added `by_product` breakdown to `_fetch_detections()` in security posture — queries count per product type (epp, idp, ngsiem, thirdparty, cao, xdr, fcs, data-protection, mobile, cspm)
- Added `products_seen` to `search_detections()` response for debugging
- Updated product label map with all discovered product types (ngsiem, xdr, fcs, data-protection, automated-lead)
- Fixed `total_found` to use API pagination metadata instead of fetched page size

### Executive Summary Tab
- Replaced "Severity Distribution" stacked bar (alerts+vulns, showed 100% one color) with "Detections by Product" donut chart — groups by product type (Falcon EDR, NGSIEM, Identity Protection, Third-Party, etc.)

### Detections Tab
- Detection Status funnel → KPI cards (one per status)
- Top Targeted Hosts bar → "Top Host" KPI card (filters out N/A hostnames)
- MITRE ATT&CK Tactics/Techniques bar charts → tables with count columns
- 3P KPI now uses API-provided totals (not limited to fetched page)

### Bug Fixes
- Fixed 3P detection count always showing 0 (wrong FQL filter value `3rdparty` → `thirdparty`)
- Fixed `use_container_width` deprecation warnings → `width="stretch"`
- Fixed `TypeError: can't subtract offset-naive and offset-aware datetimes` in refresh badge
- Auto-refresh now enabled by default (60s interval)

## 1st-Party / 3rd-Party Source Tracking — 2026-03-14

### Server (crwd_mcp_server.py)
- Removed `product:'epp'` filter from `search_detections()` — now returns ALL detections (EDR, 3P, IDP, etc.)
- Added `product` and `source` fields to each detection result
- `_fetch_detections()` in security posture: removed epp filter, added `first_party`, `third_party`, `by_source` fields
- `_fetch_alerts()` in security posture: added `first_party`, `third_party`, `by_source` fields using `product` and `external_provider_name`

### Executive Summary Tab
- Added 1P/3P KPI row: CrowdStrike Alerts, 3rd-Party Alerts, CrowdStrike Detections, 3rd-Party Detections
- Added Alert Sources (3rd-Party) donut chart from `by_source` data
- Added Detection Sources (3rd-Party) donut chart from `by_source` data

### Detections Tab
- Added 4 KPI cards: Total, CrowdStrike (1P), Third-Party (3P), Critical
- Added Detection Sources donut chart
- Added Detections by 3rd-Party Vendor donut chart
- Added Source column to data table

## Identity, Cloud Security & Exposure Tab Enhancements — 2026-03-14

### Server (crwd_mcp_server.py)
- Extended Identity Protection GraphQL query with AD account fields: `domain`, `department`, `jobTitle`, `roles`, `hasRole(type: ADMIN)`
- Added graceful fallback: tries extended query first, falls back to basic if schema doesn't support new fields
- Enriched `risky_entities[]` with: `domain`, `department`, `job_title`, `is_admin`, `roles`

### Identity Tab (added 4 charts + user-centric data)
- Expanded KPI row from 3 → 5 columns: added Inactive Sensors, High-Risk Users (score ≥ 70)
- Added Top Risky Users by Score horizontal bar chart (top 15, color-coded by risk tier)
- Added Risk Factors by Severity bar chart (cross-tabulated severity distribution)
- Added Risky Users by Department horizontal bar chart (from AD account data)
- Added Risky Users by Domain horizontal bar chart (from AD account data)
- Added Privileged Account Risk alert panel (counts admin accounts among risky entities)
- Expanded data table with Department, Domain, Job Title, Admin columns
- Moved Risk Factor Details out of expander — always visible with department/admin tags

### Cloud Security Tab (added 5 charts)
- Expanded KPI row from 4 → 5 columns: added Cloud Providers count
- Added Top Failing Rules horizontal bar chart (top 10 by occurrence)
- Added Top Affected Accounts horizontal bar chart (top 10)
- Added Risk Status Distribution donut chart
- Added Severity by Cloud Provider grouped bar chart (multi-cloud comparison)
- Added Risks by Asset Type bar chart (top 10)
- Moved Risk Details table out of expander — always visible

### Exposure Tab (added 4 charts)
- Expanded KPI row from 4 → 5 columns: added Countries count
- Added Assets by Country horizontal bar chart (geographic distribution, top 10)
- Added Top Services / Open Ports horizontal bar chart (top 12, parsed from asset services)
- Added Discovery Timeline area chart (daily asset discovery trend)
- Added Criticality by Asset Type stacked bar chart (cross-tab)
- Moved Asset Details table out of expander — always visible

### Stats
- Total `apply_chart_theme()` calls: 49 (up from 36)
- Total `render_section_header()` calls: 58 (up from 42)

## P0 Dashboard Charts & KPI Enhancements — 2026-03-14

### CSS
- Added `.kpi-delta` classes for delta badges on KPI cards (`.up`, `.down`, `.neutral`, `.up-good`, `.down-bad`)

### Constants & Helpers
- Enhanced `render_kpi_card()` with optional `delta` and `delta_invert` parameters for trend badges
- Added `compute_sla_compliance()` helper to compute SLA % from detection timing data

### Executive Summary Tab
- Added 5th KPI column: SLA Compliance % (color-coded green/orange/red by threshold)
- Added alert rate delta badge on Alerts KPI (compares last 8h rate to 24h average)
- KPI row now 5 columns: Risk Score, Alerts (+delta), Cases, Vulnerabilities, SLA Compliance

### Detections Tab (previously table-only — added 7 charts)
- Severity Distribution donut chart
- Detection Status funnel (New → In Progress → True Positive → Closed)
- Top Targeted Hosts horizontal bar chart (top 10)
- MITRE ATT&CK Tactics horizontal bar chart (top 10)
- MITRE ATT&CK Techniques horizontal bar chart (top 10)
- Detection Timeline stacked area chart (hourly, colored by severity)
- All charts use `apply_chart_theme()` and centralized `SEVERITY_COLORS`/`STATUS_COLORS`

### Cases Tab (previously table-only — added 3 charts)
- Cases by Status donut chart
- Cases by Severity bar chart
- Assigned To workload horizontal bar chart (top 10)

### Vulnerabilities Tab (previously table-only — added 5 charts)
- Severity Distribution donut chart
- CVSS Score Distribution histogram
- Top Affected Applications horizontal bar chart (top 8)
- Vulnerability Age Distribution bar chart (0-7d, 8-30d, 31-90d, 91-180d, 180+d buckets)
- Top Affected Hosts horizontal bar chart (top 8)

### Identity Tab (added 2 charts)
- Top Risk Factor Types horizontal bar chart (aggregated across all risky entities, top 12)
- Risk Score Distribution histogram

### Exposure Tab
- Changed Assets by Criticality from bar chart to donut chart for visual consistency
- Changed Assets by Triage Status from bar chart to funnel chart (shows remediation pipeline)

### Stats
- Total `apply_chart_theme()` calls: 36 (up from 12)
- Total `render_section_header()` calls: 42 (up from 23)
- Tabs with zero charts: 0 (was 4: Detections, Cases, Vulnerabilities, IOC Search)

## Dashboard Beautification — 2026-03-13

### CSS
- Added `.section-panel` and `.section-title` CSS classes for framed section headers with red bottom border

### Constants & Helpers
- Added centralized color palettes: `SEVERITY_COLORS`, `STATUS_COLORS`, `PROVIDER_COLORS`, `CHART_PALETTE`
- Added `CHART_THEME` dict and `apply_chart_theme()` for standardized Plotly chart styling (transparent bg, Inter font, readable #374151 text color, consistent gridlines)
- Added `CHART_HEIGHT_SM` (240px) and `CHART_HEIGHT_MD` (320px) constants
- Added `render_section_header()` helper for framed section titles

### Executive Summary Tab
- Replaced 10 `st.markdown("**...**")` section headers with `render_section_header()`
- Migrated 7 charts to `apply_chart_theme()` with consistent height/font/colors
- Replaced inline `color_map` / `status_colors` dicts with `SEVERITY_COLORS` / `STATUS_COLORS`
- CrowdScore gauge and sparkline now use transparent background and theme font

### Identity Tab
- Replaced `st.markdown("**...**")` headers with `render_section_header()`
- Migrated 3 charts from `font=dict(color="#FAFAFA")` (invisible on light backgrounds) to `apply_chart_theme()`
- Replaced inline `status_colors` and `type_colors` with `STATUS_COLORS` and `CHART_PALETTE`

### Cloud Security Tab
- Replaced 3 section headers with `render_section_header()`
- Migrated 3 charts: replaced `font=dict(color="#FAFAFA")` with theme, replaced inline `sev_colors`/`provider_colors`/`svc_colors` with centralized palettes
- Used `SEVERITY_COLORS` for severity bar chart colors

### Exposure Tab
- Replaced 4 section headers with `render_section_header()`
- Migrated 4 charts from `font=dict(color="#FAFAFA")` to `apply_chart_theme()`
- Replaced inline `crit_colors` list with `SEVERITY_COLORS` + Unassigned fallback
- Replaced inline asset type palette with `CHART_PALETTE`
- Replaced inline `provider_colors` with `PROVIDER_COLORS`

### Data Ingestion Tab
- Replaced 2 section headers with `render_section_header()`
- Migrated 2 charts: fixed `gridcolor="rgba(255,255,255,0.1)"` (invisible on light bg) via `apply_chart_theme()`
- Replaced `vendor_colors` list with `CHART_PALETTE`

### Bug Fixes
- Fixed all chart text being `#FAFAFA` (near-white, invisible on light backgrounds) across Identity, Cloud, Exposure, and Ingestion tabs
- Fixed grid lines using `rgba(255,255,255,0.1)` (invisible on light backgrounds) in Ingestion charts

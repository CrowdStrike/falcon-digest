# CrowdStrike Falcon MCP Server

AI-powered security operations platform for CrowdStrike Falcon. Built on [FalconPy](https://github.com/CrowdStrike/falconpy) (CrowdStrike's official Python SDK) and the [Model Context Protocol](https://modelcontextprotocol.io) (MCP). Includes an MCP server, an 11-tab Streamlit dashboard ("Falcon Vantage"), and a CLI client for querying Falcon security data using natural language.

## Features

- **Built on FalconPy** — Uses CrowdStrike's official Python SDK for all Falcon platform interactions (12 service classes, read-only)
- **13 MCP Tools** — search alerts, detections, cases, vulnerabilities, hosts, ThreatGraph IOCs, security posture, NGSIEM ingestion, identity protection, cloud security, exposure management, FQL validation, and more
- **4 MCP Resources** — FQL cheatsheet, severity definitions, MITRE ATT&CK mapping, case status guide
- **5 MCP Prompts** — case triage, threat hunting, vulnerability assessment, executive briefing, identity risk review
- **11-Tab Dashboard** — Executive summary, detections, cases, vulnerabilities, identity, cloud security, exposure, IOC search, data ingestion, FQL tools, AI chat
- **Multi-Provider LLM Support** — Anthropic and OpenAI API formats, selectable via `LLM_PROVIDER` env var
- **Background Cache** — pre-fetches all Falcon data sources for instant dashboard loads with file persistence
- **CLI Chat Client** — interactive terminal-based Q&A with full tool access

## Quick Start

### Prerequisites

- Python 3.10+
- CrowdStrike Falcon API credentials (API Clients & Keys in your Falcon console)
- [CrowdStrike FalconPy](https://github.com/CrowdStrike/falconpy) (>=1.6.0, installed via requirements.txt)
- *(Optional)* An LLM endpoint (Anthropic or OpenAI compatible) for AI chat features

### Installation

```bash
git clone <repo-url> && cd crwd_mcp
bash setup.sh
```

The setup script will:
1. Check Python version
2. Create and activate a virtual environment
3. Install dependencies
4. Walk you through Falcon cloud region selection and `.env` configuration
5. Optionally run the test suite
6. Optionally start the cache daemon

### Manual Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit .env with your credentials
```

### Running

```bash
source venv/bin/activate

# Dashboard (11-tab layout with AI Chat)
streamlit run mcp_dashboard.py

# MCP server (stdio — for IDE/editor integration)
python crwd_mcp_server.py

# CLI client (interactive chat)
python mcp_api_client.py

# CLI client (single query)
python mcp_api_client.py "show security posture"

# Cache daemon (keeps data warm for instant dashboard loads)
python falcon_cache_daemon.py [poll_interval_seconds]
```

## Architecture

```
crwd_mcp_server.py        MCP server: 13 tools, 4 resources, 5 prompts
mcp_api_client.py          LLM API client with tool execution + CLI chat
mcp_dashboard.py           Streamlit dashboard (11-tab UI with AI Chat)
falcon_cache.py            Background polling cache with file persistence
falcon_cache_daemon.py     Standalone cache daemon process
tests/                     pytest unit tests (mock-based)
  conftest.py              Shared fixtures
  test_server_tools.py     Tool tests
  test_fql_security.py     FQL injection prevention tests
  test_cache.py            Cache tests
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `search_alerts` | Search alerts by product, severity, time range |
| `get_host_details` | Get device info by hostname |
| `test_fql_filter` | Validate FQL filter syntax |
| `list_available_products` | List Falcon product types with examples |
| `search_cases` | Query cases by status, severity, time |
| `search_detections` | Query all detections (EDR, 3P, IDP, NGSIEM, etc.) |
| `search_vulnerabilities` | Query Spotlight vulnerabilities |
| `search_threatgraph` | IOC lookups and edge type listing |
| `get_security_posture` | Executive security overview with risk score |
| `search_hosts` | Search/count hosts by platform, status, recency |
| `get_ngsiem_ingestion` | LogScale data ingestion volume and top sources |
| `get_identity_protection` | Risky entities, risk scores, AD account data |
| `get_cloud_security` | CSPM risks by severity, provider, service |
| `get_exposure_management` | External attack surface assets |

## Required API Scopes

| Scope | Dashboard Section |
|-------|-------------------|
| `alerts:read` | Detections, severity charts, MTTD/MTTR, 1P/3P tracking |
| `hosts:read` | Host KPIs, Sensor Health (RFM, versions) |
| `cases:read` | Cases by status/severity |
| `spotlight-vulnerabilities:read` | Vulnerability counts by severity |
| `threatgraph:read` | IOC lookups |
| `incidents:read` | CrowdScore gauge, Incidents summary |
| `discover:read` | Asset Inventory (managed, unmanaged, IoT, accounts, apps) |
| `exposure-management:read` | External Attack Surface |
| `identity-protection:read` | Identity Protection (risky entities, sensors) |
| `cloud-security:read` | Cloud Security (CSPM risks) |

Missing scopes are detected and shown in the sidebar so you know what to enable.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FALCON_CLIENT_ID` | Yes | Falcon API client ID |
| `FALCON_CLIENT_SECRET` | Yes | Falcon API client secret |
| `FALCON_BASE_URL` | Yes | Falcon cloud base URL (see `.env.example` for regions) |
| `LLM_ENDPOINT` | No | LLM endpoint URL for AI chat |
| `LLM_API_KEY` | No | API key for the LLM endpoint |
| `LLM_PROVIDER` | No | `anthropic` (default) or `openai` |
| `LLM_MODEL` | No | Model override (defaults: `claude-4-6-opus` / `gpt-4o`) |

The `.env` file supports multiple CID profiles using a comment/uncomment pattern. The dashboard sidebar includes a profile switcher.

## Testing

```bash
# Run all tests (no API credentials needed)
python -m pytest tests/ -v

# Run specific test files
python -m pytest tests/test_server_tools.py -v
python -m pytest tests/test_fql_security.py -v
python -m pytest tests/test_cache.py -v
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

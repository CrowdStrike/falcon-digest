# Building Local Dashboards with FalconPy using AI

Extract, visualize, and query your CrowdStrike Falcon security data locally. Built on [FalconPy](https://github.com/CrowdStrike/falconpy) (CrowdStrike's official Python SDK) with an 11-tab Streamlit dashboard, AI-powered natural language chat, and an MCP server for tool integration.

## Features

### Platform
- **Built on FalconPy** — CrowdStrike's official Python SDK for all Falcon platform interactions (12 service classes, read-only)
- **Read-Only Access** — All API operations are strictly read-only; no RTR, no response actions, no write operations
- **13 MCP Tools** — Search alerts, detections, cases, vulnerabilities, hosts, ThreatGraph IOCs, security posture, NGSIEM ingestion, identity protection, cloud security, exposure management, FQL validation, and more
- **4 MCP Resources** — FQL cheatsheet, severity definitions, MITRE ATT&CK mapping, case status guide
- **5 MCP Prompts** — Case triage, threat hunting, vulnerability assessment, executive briefing, identity risk review
- **Background Cache** — Pre-fetches all Falcon data sources for instant dashboard loads with file persistence

### Dashboard
- **11-Tab Dashboard** — Executive summary, detections, cases, vulnerabilities, identity, cloud security, exposure, IOC search, data ingestion, FQL tools, AI chat
- **Non-Blocking Chat UI** — Chat tab runs as a Streamlit fragment so the rest of the dashboard stays interactive during LLM processing

### AI Chat
- **Multi-Provider LLM Support** — Anthropic and OpenAI API formats, configurable in Settings; works with local models via Ollama
- **Local LLM via Ollama** — Run fully offline with self-hosted models (Qwen, Llama, Mistral, etc.) — no data leaves your machine
- **Cache-First AI Chat** — LLM answers from pre-fetched Falcon data with cache age reporting; cross-referenced "Top Affected Hosts" rollup across alerts, detections, and vulnerabilities
- **Response Grounding** — Post-inference validation cross-references LLM output against cached data, flags unverifiable claims
- **CLI Chat Client** — Interactive terminal-based Q&A with full tool access

## Quick Start

### Prerequisites

- Python 3.10+
- CrowdStrike Falcon API credentials (API Clients & Keys in your Falcon console)
- [CrowdStrike FalconPy](https://github.com/CrowdStrike/falconpy) (>=1.6.0, installed via requirements.txt)
- *(Optional)* An LLM endpoint for AI chat: cloud (Anthropic/OpenAI compatible) or local via [Ollama](https://ollama.com)

### Installation

```bash
git clone <repo-url> && cd crwd_mcp
bash setup.sh
```

The setup script will:
1. Check Python version
2. Create and activate a virtual environment
3. Install dependencies
4. Optionally run the test suite
5. Optionally start the cache daemon

### Manual Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Running

```bash
source venv/bin/activate

# Dashboard (11-tab layout with AI Chat)
streamlit run mcp_dashboard.py

# On first launch:
# 1. Create an admin account (setup wizard)
# 2. Enter Falcon API credentials in the Settings page
# 3. Optionally configure LLM settings for AI chat

# MCP server (stdio — for IDE/editor integration)
python crwd_mcp_server.py

# CLI client (interactive chat)
python mcp_api_client.py

# CLI client (single query)
python mcp_api_client.py "show security posture"

# Cache daemon (keeps data warm for instant dashboard loads)
python falcon_cache_daemon.py [poll_interval_seconds]
```

## Local LLM with Ollama

Run the AI chat features entirely offline using [Ollama](https://ollama.com) — no API keys, no cloud dependency, no data leaving your machine.

### Setup

1. **Install Ollama**

   Download from [ollama.com/download](https://ollama.com/download) or:
   ```bash
   # macOS (Homebrew)
   brew install ollama

   # Linux
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. **Pull a model**

   ```bash
   # Lightweight (3B) — works on 8GB+ RAM, good for quick answers
   ollama pull llama3.2:3b

   # Recommended (7-8B) — better reasoning, needs 16GB+ RAM
   ollama pull llama3.1:8b

   # Best quality (14B+) — needs 32GB+ RAM
   ollama pull mistral-small
   ```

3. **Start Ollama** (runs in background)

   ```bash
   ollama serve
   ```

4. **Configure LLM in Settings**

   After logging into the dashboard, open **Settings** from the sidebar and enter:
   - **LLM Endpoint**: `http://localhost:11434`
   - **Provider**: `openai` (Ollama exposes an OpenAI-compatible API)
   - **Model Override**: `llama3.2:3b` (or whichever model you pulled)
   - **LLM API Key**: leave blank (not needed for Ollama)

5. **Run the dashboard or CLI as usual**

   ```bash
   streamlit run mcp_dashboard.py
   # or
   python mcp_api_client.py
   ```

### Performance Notes

| Model Size | RAM/VRAM Needed | Response Time (GPU) | Response Time (CPU-only) |
|-----------|----------------|---------------------|--------------------------|
| 3B | 8 GB | ~5-10s | ~30-60s |
| 7-8B | 16 GB | ~10-20s | ~60-120s |
| 14B | 32 GB | ~20-40s | not recommended |

- GPU-accelerated inference (CUDA, ROCm, Metal) is significantly faster than CPU-only
- The cache-first approach means the model answers from pre-fetched data — no live API calls needed during chat
- Larger models produce more accurate and well-structured responses but require more memory and are slower

## Security

- **Read-Only Access** — All Falcon API operations are strictly read-only. No RTR, no response actions, no write operations.
- **Mandatory Authentication** — On first launch, create an admin account. All dashboard access requires login. Passwords are hashed with PBKDF2-SHA256 (600k iterations) and stored in `.falcon_users.json`. Admins can add/remove users and change roles from the sidebar.
- **Encrypted Configuration** — All credentials (Falcon API, LLM keys) are stored in `.falcon_config.enc`, encrypted with Fernet (AES-128-CBC + HMAC-SHA256). No plaintext secrets on disk.
- **OS Keychain Integration** — The encryption key is stored in the OS keychain (macOS Keychain, Linux Secret Service) via the `keyring` library. Falls back to a local key file (`.falcon_config.key`, chmod 0600) if keychain is unavailable.
- **Encrypted Cache** — `.falcon_cache.json` is encrypted at rest using the same Fernet key.
- **No .env Required** — All configuration is entered via the dashboard Settings UI. Legacy `.env` files are automatically migrated to encrypted storage on first run.
- **FQL Injection Prevention** — All user-supplied values are sanitized through a character whitelist (`sanitize_fql_value()`) before interpolation into FQL filter strings.
- **XSS Protection** — API-sourced values rendered via `unsafe_allow_html=True` are escaped with `html.escape()`.
- **Error Sanitization** — API error messages are stripped of internal file paths and truncated before display to prevent information leakage.
- **File Permissions** — All sensitive files (`.falcon_config.enc`, `.falcon_config.key`, `.falcon_cache.json`, `.falcon_users.json`) are automatically set to `0600` (owner read/write only).
- **No Credentials in Code** — All secrets live in encrypted storage or OS keychain (all gitignored). No credentials are logged or included in LLM context.

## Architecture

```
crwd_mcp_server.py        MCP server: 13 tools, 4 resources, 5 prompts
mcp_api_client.py          LLM API client with tool execution + CLI chat
mcp_dashboard.py           Streamlit dashboard (11-tab UI with AI Chat)
falcon_cache.py            Background polling cache with encrypted file persistence
falcon_auth.py             User authentication (PBKDF2 hashed passwords)
falcon_secrets.py          Encrypted config store (ConfigStore) and cache encryption
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

## Configuration

All configuration is managed through the dashboard **Settings** page (no `.env` file needed):

| Setting | Required | Description |
|---------|----------|-------------|
| Falcon Client ID | Yes | Falcon API client ID (from Falcon Console > API Clients & Keys) |
| Falcon Client Secret | Yes | Falcon API client secret |
| Cloud Region | Yes | Your CrowdStrike cloud (US-1, US-2, US-3, EU-1, GOV-1, GOV-2) |
| LLM Endpoint | No | LLM endpoint URL (`http://localhost:11434` for Ollama, or cloud endpoint) |
| LLM API Key | No | API key for the LLM endpoint (not needed for Ollama) |
| LLM Provider | No | `anthropic` (default) or `openai` (use `openai` for Ollama) |
| LLM Model | No | Model name override (e.g. `llama3.2:3b`, `gpt-4o`) |

Settings are stored encrypted in `.falcon_config.enc`. Multiple CID profiles are supported — switch between them from the sidebar.

> **Legacy .env migration:** If you have an existing `.env` file, credentials are automatically migrated to encrypted storage on first startup and secrets are blanked from the `.env` file.

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

MIT License — see [LICENSE](LICENSE).

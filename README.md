# Building Local Dashboards with FalconPy using AI

Extract, visualize, and query your CrowdStrike Falcon security data locally. Built on [FalconPy](https://github.com/CrowdStrike/falconpy) (CrowdStrike's official Python SDK) with an 11-tab Streamlit dashboard, AI-powered natural language chat, and an MCP server for tool integration.

## Features

### Platform
- **Built on FalconPy** — CrowdStrike's official Python SDK for all Falcon platform interactions (12 service classes, read-only)
- **Read-Only Access** — All API operations are strictly read-only; no RTR, no response actions, no write operations
- **13 MCP Tools** — Search alerts, detections, cases, vulnerabilities, hosts, ThreatGraph IOCs, security posture, NGSIEM ingestion, identity protection, cloud security, exposure management, FQL validation, and more
- **4 MCP Resources** — FQL cheatsheet, severity definitions, MITRE ATT&CK mapping, case status guide
- **5 MCP Prompts** — Case triage, threat hunting, vulnerability assessment, executive briefing, identity risk review
- **Background Cache** — Pre-fetches all Falcon data sources for instant dashboard loads, persisted to an encrypted cache file

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
# 1. Copy the one-time setup token printed in this terminal
#    (also stored in ~/.falcon-digest/.falcon_users.json.setup)
# 2. Create the admin account in the browser using that token
# 3. Enter Falcon API credentials in the Settings page
# 4. Optionally configure LLM settings for AI chat

# MCP server (stdio — for IDE/editor integration)
python crwd_mcp_server.py

# CLI client (interactive chat)
python mcp_api_client.py

# CLI client (single query)
python mcp_api_client.py "show security posture"

# Cache daemon (keeps data warm for instant dashboard loads; reads the same encrypted config)
python falcon_cache_daemon.py [poll_interval_seconds]
```

The dashboard only listens on `127.0.0.1` by default (see `.streamlit/config.toml`). To reach it from other machines, change `server.address` deliberately and put it behind TLS / a reverse proxy.

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
   - **Model type**: `Auto` (default) treats loopback, private-network and `.local` endpoints as small local models. Choose `Local small model` or `Full model (tools)` to override, e.g. for a large model on a private-IP gateway.

   The LLM is optional — the dashboard works with Falcon credentials alone. Until an endpoint is set, the AI Chat tab asks you to configure it in Settings.

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
- **Mandatory Authentication** — All dashboard access requires login. Passwords are hashed with PBKDF2-SHA256 (600k iterations, per-user salt) and stored in `.falcon_users.json`. Usernames are case-insensitive, and repeated failed logins trigger a temporary lockout with backoff, counted per client address. When Streamlit can't see the client IP (localhost, or behind a reverse proxy) the lockout is per browser session, plus a per-username slow-down that never hard-blocks the account. If you put the dashboard behind a reverse proxy, per-IP lockout depends on the proxy passing client addresses.
- **Protected First-Run Setup** — Creating the first admin requires a one-time setup token, printed to the terminal running `streamlit run` and stored in `~/.falcon-digest/.falcon_users.json.setup` (0600, or under `$FALCON_DIGEST_HOME`). The token is deleted after use. If `.falcon_users.json` exists but is corrupt or unreadable, the dashboard refuses to start instead of reopening setup.
- **Roles** — Only admins can open Settings, manage users, and switch CID profiles; viewers can only view. Roles are re-checked on every page load and inside interactive panels and callbacks (including AI chat), so removing or demoting a user takes effect immediately.
- **Sessions** — Changing a user's password or role, or removing the user, ends that user's existing sessions. Sessions expire after 8 hours of inactivity. Logout clears all session data, so the next user in the same browser sees nothing from the previous one.
- **Secrets Stay Server-Side** — Stored secrets (Falcon client secret, LLM API key) are never sent back to the browser. Leave a secret field blank in Settings to keep the existing value.
- **Encrypted Configuration** — Credentials are stored in `.falcon_config.enc`, encrypted with Fernet (AES-128-CBC + HMAC-SHA256). The encryption key is kept in the OS keychain (service `falcon-digest`, via the `keyring` library) when available, under an account name derived from the data directory path, so separate installs and `FALCON_DIGEST_HOME` directories never share or overwrite each other's key. If `.falcon_config.key` exists in the data directory it is used in preference to the keychain. Otherwise the key is written to `.falcon_config.key` (0600) **next to the ciphertext** — in that mode the encryption only guards against casual disclosure (e.g. backups or syncs of just the config file), not against someone who can read the app directory as the same OS user.
- **Fail Closed on Decrypt Errors** — If the config file exists but can't be decrypted (for example, a process that can't reach the keychain, or a lost key), the app shows an error and refuses to overwrite it rather than silently resetting your settings.
- **Encrypted Cache** — `.falcon_cache.json` is encrypted with the same key. If encryption fails, the cache is not written to disk. A plaintext cache left by an older version is re-encrypted on first load, and cache backups in `.falcon_cache_backups/` (made when the CID changes) are encrypted and pruned to the newest 5.
- **Localhost by Default** — `.streamlit/config.toml` binds the dashboard to `127.0.0.1`. Streamlit reads this file from the current directory, so start `streamlit run` from the repo root (or pass `--server.address 127.0.0.1`); started elsewhere, it listens on all interfaces.
- **FQL Injection Prevention** — All user-supplied values are sanitized through a character whitelist (`sanitize_fql_value()`) before interpolation into FQL filter strings.
- **XSS Protection** — API-sourced values rendered via `unsafe_allow_html=True` are escaped with `html.escape()`.
- **Error Sanitization** — API error messages are stripped of internal file paths and truncated before display to prevent information leakage.
- **File Permissions** — Sensitive files (`.falcon_config.enc`, `.falcon_config.key`, `.falcon_cache.json`, `.falcon_users.json`) are created with `0600` (owner read/write only) and written atomically.
- **No Credentials in Code** — Secrets live in the encrypted config or the process environment, never in source. All data files are gitignored. No credentials are logged or included in LLM context.

## Architecture

```
crwd_mcp_server.py        MCP server: 13 tools, 4 resources, 5 prompts
mcp_api_client.py          LLM API client with tool execution + CLI chat
mcp_dashboard.py           Streamlit dashboard (11-tab UI with AI Chat)
falcon_cache.py            Background polling cache with encrypted file persistence
falcon_auth.py             User authentication (PBKDF2 hashed passwords, setup token, lockout)
falcon_secrets.py          Encrypted config store (ConfigStore), key management, cache encryption
falcon_cache_daemon.py     Standalone cache daemon process
.streamlit/config.toml     Streamlit settings (binds to 127.0.0.1)
tests/                     pytest unit tests (mock-based)
  conftest.py              Shared fixtures (isolated data dir, no real keychain)
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

All configuration is entered in the dashboard **Settings** page (admins only):

| Setting | Required | Description |
|---------|----------|-------------|
| Falcon Client ID | Yes | Falcon API client ID (from Falcon Console > API Clients & Keys) |
| Falcon Client Secret | Yes | Falcon API client secret |
| Cloud Region | Yes | Your CrowdStrike cloud (US-1, US-2, US-3, EU-1, GOV-1, GOV-2) |
| LLM Endpoint | No | LLM endpoint URL (`http://localhost:11434` for Ollama, or cloud endpoint). Leave blank to run without AI chat |
| LLM API Key | No | API key for the LLM endpoint (not needed for Ollama) |
| LLM Provider | No | `anthropic` (default) or `openai` (use `openai` for Ollama) |
| LLM Model | No | Model name override (e.g. `llama3.2:3b`, `gpt-4o`) |
| Model type | No | `Auto` (default), `Local small model` (simplified prompt, no tools) or `Full model (tools)`. Env var `LLM_LOCAL_MODE=auto\|local\|full`. Each chat turn is capped at 120 s in total |

Settings are stored encrypted in `.falcon_config.enc`. Multiple CID profiles are supported — admins can switch between them from the sidebar. Switching changes the active CID for the whole dashboard process, so every open session sees the new tenant.

**Data directory** — `.falcon_config.enc`, `.falcon_config.key`, `.falcon_users.json`, and `.falcon_cache.json` live in `~/.falcon-digest/` (created 0700), never in the source tree, so git operations, tests and other tools working on the code can't touch them. Set `FALCON_DIGEST_HOME` to use a different directory. State files left in the project directory by earlier versions are moved there on first start (by name; nothing is overwritten). The test suite always uses a temporary directory and refuses to run against a non-temporary one.

**Environment-variable mode** — If no encrypted config file exists, the MCP server, CLI client, cache daemon and dashboard read `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL`, and `LLM_*` from the process environment (for example, set by an IDE's MCP server config). In the dashboard, Settings can then be used to create a stored config.

**Env vars vs stored config** — By default, once `.falcon_config.enc` exists it takes precedence over the environment. Set `FALCON_DIGEST_USE_ENV=1` to let `FALCON_*` / `LLM_*` variables already present in the process environment win — for example, an MCP server launched by an IDE for a different CID than the dashboard's active profile.

> **Upgrading from a `.env` file:** On first start, if there is no encrypted config, `.env` is imported into the encrypted store. The active profile and the `LLM_*` settings are read with python-dotenv, exactly as earlier versions did (so `export`, quotes and inline comments behave the same), and commented-out `#name` profile blocks from the old multi-profile layout are imported as additional profiles. If anything looks inconsistent, `.env` is left in place and a warning is logged instead. On success `.env` is moved to `~/.falcon-digest/.env.migrated` (0600), out of the source tree. Delete it once you've confirmed the dashboard works — it still contains your plaintext secrets. A plaintext `.falcon_cache.json` from an older version is re-encrypted on first load, and existing cache backups are encrypted and pruned to the newest 5.

## Testing

```bash
# Run all tests (no API credentials needed)
python -m pytest tests/ -v

# Run specific test files
python -m pytest tests/test_server_tools.py -v
python -m pytest tests/test_fql_security.py -v
python -m pytest tests/test_cache.py -v
```

## Contributing safely

Local state (`.env*`, `.falcon_*` config/key/users/cache files) is gitignored. To also block commits and pushes that would include those files, common secret formats, or the real Falcon client IDs, secrets, profile names and usernames configured on your machine, enable the bundled hooks once per clone:

```bash
git config core.hooksPath scripts/git-hooks
```

Run the same check manually with `python scripts/check_sensitive.py --staged` or `--range origin/main..HEAD`. Hits show only a label and length, never the value. To check your real config values the hook decrypts the local config, which may need keychain access; set `FALCON_DIGEST_HOOK_SKIP_CONFIG=1` to skip that part.

The tests never read or move a `.env` or state files in your checkout: under pytest, legacy files are only looked up in the temporary data directory.

## License

MIT License — see [LICENSE](LICENSE).

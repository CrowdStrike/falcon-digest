# Contributing to Falcon Digest

Welcome! We're glad you want to contribute to Falcon Digest.

## How You Can Contribute

- **Bug Reports** — Open a GitHub Issue describing the bug, steps to reproduce, and expected behavior.
- **Feature Requests** — Open a GitHub Issue describing the use case and proposed solution.
- **Pull Requests** — Fork the repo, make your changes, and submit a PR.

## Pull Request Guidelines

### Branch Targeting

- Target the **dev** branch for all PRs.
- The **main** branch is protected and only updated by maintainers.

### Requirements

Before submitting a PR:

1. **Tests pass** — Run `python -m pytest tests/ -v` and ensure all tests pass.
2. **No credentials** — Never commit `.env` files, `.falcon_*` state files, API keys, or secrets. Enable the bundled hooks (see below) to block this automatically.
3. **No internal references** — No internal URLs, IPs, hostnames, or employee information.
4. **FQL safety** — Any new user input flowing into FQL queries must use `sanitize_fql_value()`.

### What to Include

- Clear description of what the PR does and why.
- Reference any related issues.
- Note any breaking changes.

## Development Setup

```bash
git clone <repo-url>
cd falcon-digest
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
git config core.hooksPath scripts/git-hooks   # block commits/pushes containing credentials
python -m pytest tests/ -v                     # no credentials needed; tests use a temp data dir
```

To run the dashboard against a real tenant:

1. `streamlit run mcp_dashboard.py`
2. Copy the one-time setup token printed in the terminal and create the admin account.
3. Enter your Falcon API credentials (and optional LLM settings) in **Settings**. They are stored encrypted in `.falcon_config.enc`.

For headless or MCP use without the dashboard, use env-var mode: when no `.falcon_config.enc` exists, `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL` and the optional `LLM_*` variables are read from the process environment. Local state (config, key, users, cache) lives in `~/.falcon-digest/` by default, never in the source tree; set `FALCON_DIGEST_HOME` to use another directory. Run tests only via `pytest` — the suite isolates its data directory and refuses to run against a non-temporary one.

## Restrictions

Pull requests will not be accepted if they contain:

- Hardcoded credentials or secrets
- Compiled binaries
- Inappropriate language or comments
- Non-owned intellectual property
- Code that performs write/response actions via Falcon APIs (this project is read-only)

## Approval

At least one maintainer approval is required before merging. All PRs undergo code review.

## Questions?

Open a GitHub Discussion or Issue — we're happy to help.

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
2. **No credentials** — Never commit `.env` files, API keys, or secrets.
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
cp .env.example .env  # Add your Falcon API credentials
python -m pytest tests/ -v
```

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

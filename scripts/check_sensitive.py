#!/usr/bin/env python3
"""Block commits/pushes that would publish local credentials or tenant data.

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

Checks, for staged changes (``--staged``) or a commit range (``--range A..B``):

1. File paths: local state files (.env*, .falcon_*, keys, backups, dev notes).
2. Generic secret formats (private keys, cloud/API tokens).
3. The real values configured on THIS machine — Falcon client IDs/secrets,
   CID profile names, LLM API keys, dashboard usernames — read from the local
   .env / .env.migrated, the encrypted config store and the users file.
   Values are never printed; a hit shows only its label and length.

Reading the encrypted config may need the OS keychain. Set
FALCON_DIGEST_HOOK_SKIP_CONFIG=1 to skip it (the other checks still run).

Install as git hooks with:  git config core.hooksPath scripts/git-hooks
"""

import argparse
import json
import os
import re
import subprocess
import sys

REPO = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip() or "."

FORBIDDEN_PATHS = [
    (re.compile(r"(^|/)\.env(\.(?!example$)[^/]+)?$"), "local .env file"),
    (re.compile(r"(^|/)\.falcon_[^/]*(/|$)"), "Falcon Digest local state (config/key/users/cache/backups)"),
    (re.compile(r"\.(key|pem|p12|pfx)$|(^|/)id_rsa"), "key material"),
    (re.compile(r"\.(bak\w*|log|pid)$"), "backup/log/pid file"),
    (re.compile(r"(^|/)(context\.md|CLAUDE\.md|PUBLISH_REQUEST\.\w+|HANDOFF_GUIDE\.txt|generate_deck\.py)$"), "local dev notes"),
    (re.compile(r"(^|/)\.claude/"), "Claude Code session data"),
]

GENERIC_SECRETS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "GitHub token"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic API key"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"), "OpenAI API key"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    (re.compile(r"(?i)(?:FALCON_CLIENT_SECRET|LLM_API_KEY|JIRA_PERSONAL_TOKEN|PASSWORD)[ \t]*[=:][ \t]*['\"]?(?!<|\$|not-needed|test|dummy|example|xxx)[A-Za-z0-9+/=_-]{16,}"), "credential assignment"),
]

# Generic words that are fine to appear even if used as a profile/user name
_COMMON = {"default", "admin", "viewer", "test", "prod", "production", "staging", "local", "anthropic", "openai",
           "not-needed", "localhost"}
_PLACEHOLDER = re.compile(r"^(?:<.*>|\$\{?\w+\}?|https?://api\.(?:[\w-]+\.)?crowdstrike\.(?:com|mil)/?|https?://(?:localhost|127\.0\.0\.1)(?::\d+)?/?)$")


def _git(*args: str) -> str:
    return subprocess.run(["git", "-C", REPO, *args], capture_output=True, text=True, errors="replace").stdout


def _add(needles: dict, value, label: str, min_len: int = 6) -> None:
    value = (value or "").strip().strip("'\"")
    if len(value) < min_len or value.lower() in _COMMON or _PLACEHOLDER.match(value):
        return
    needles.setdefault(value, label)


def _local_values() -> dict:
    """Collect real values configured on this machine (never printed)."""
    needles: dict[str, str] = {}
    env_line = re.compile(r"^#?\s*([A-Z_]+)\s*=\s*(.*)$")
    # Same rule as falcon_secrets.APP_DIR, computed here so a missing data dir is never created
    data_dir = os.path.abspath(os.path.expanduser(os.environ.get("FALCON_DIGEST_HOME") or "~/.falcon-digest"))
    for path in (os.path.join(REPO, ".env"), os.path.join(REPO, ".env.migrated"), os.path.join(data_dir, ".env.migrated")):
        name = os.path.basename(path)
        if not os.path.isfile(path):
            continue
        for line in open(path, errors="replace"):
            m = env_line.match(line.strip())
            if m and re.search(r"CLIENT_ID|SECRET|API_KEY|TOKEN|PASSWORD|ENDPOINT", m.group(1)):
                _add(needles, m.group(2), f"{name}:{m.group(1)}", 8)
            elif line.strip().startswith("#") and "=" not in line:
                _add(needles, line.strip().lstrip("#").strip(), f"{name}:profile name", 5)

    # Encrypted config store (profile names, client IDs, secrets, LLM key/endpoint).
    # Importing falcon_secrets only reads: legacy files are moved by the app, not on import.
    config_file = os.path.join(data_dir, ".falcon_config.enc")
    try:
        if os.path.isfile(config_file) and os.environ.get("FALCON_DIGEST_HOOK_SKIP_CONFIG") != "1":
            sys.path.insert(0, REPO)
            from falcon_secrets import ConfigStore
            store = ConfigStore(config_file)
            for p in store.list_profiles():
                _add(needles, p["name"], "config:profile name", 5)
                _add(needles, p["client_id"], "config:client id", 8)
            data = getattr(store, "_data", {})
            for p in data.get("profiles", {}).values():
                _add(needles, p.get("FALCON_CLIENT_SECRET"), "config:client secret", 8)
            llm = data.get("llm", {})
            _add(needles, llm.get("LLM_API_KEY"), "config:LLM key", 8)
            _add(needles, llm.get("LLM_ENDPOINT"), "config:LLM endpoint", 8)
    except Exception as e:  # missing deps or unreadable config: still run the other checks
        print(f"  (note: encrypted config not checked: {type(e).__name__})", file=sys.stderr)

    users = os.path.join(data_dir, ".falcon_users.json")
    if os.path.isfile(users):
        try:
            for u in json.load(open(users)).get("users", {}):
                _add(needles, u, "users:username", 4)
        except Exception:
            pass
    return needles


def _mask(value: str) -> str:
    return f"{len(value)} chars"


def _changes(args) -> list[tuple[str, str]]:
    """Return (path, added_text) pairs to check."""
    if args.staged:
        paths = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR").split()
        diff = _git("diff", "--cached", "-U0", "--no-color")
    else:
        paths = _git("diff", "--name-only", "--diff-filter=ACMR", args.range).split()
        diff = _git("log", "-p", "-U0", "--no-color", "--format=%n+COMMIT_MSG %B", args.range)
    added: dict[str, list[str]] = {}
    current = "<commit message>"
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else current
        elif line.startswith("+COMMIT_MSG ") or (line.startswith("+") and not line.startswith("+++")):
            added.setdefault(current if not line.startswith("+COMMIT_MSG ") else "<commit message>", []).append(
                line[len("+COMMIT_MSG "):] if line.startswith("+COMMIT_MSG ") else line[1:])
        elif line.startswith("diff --git"):
            current = "<commit message>"
    result = [(p, "") for p in paths]
    result += [(p, "\n".join(lines)) for p, lines in added.items()]
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--staged", action="store_true", help="check staged changes (pre-commit)")
    g.add_argument("--range", help="check commits in A..B (pre-push / audit)")
    args = ap.parse_args()

    problems = []
    changes = _changes(args)
    for path, _ in changes:
        for pat, why in FORBIDDEN_PATHS:
            if path and pat.search(path):
                problems.append(f"{path}: {why} must not be committed")
    needles = _local_values()
    for path, text in changes:
        if not text:
            continue
        for pat, why in GENERIC_SECRETS:
            for m in pat.finditer(text):
                problems.append(f"{path}: looks like a {why} ({_mask(m.group(0))})")
        for value, label in needles.items():
            if value in text:
                problems.append(f"{path}: contains a real local value [{label}] ({_mask(value)})")

    if problems:
        print("\nBlocked: these changes would publish local credentials or tenant data:\n", file=sys.stderr)
        for p in sorted(set(problems)):
            print(f"  - {p}", file=sys.stderr)
        print("\nRemove them (and rewrite any commits that contain them) before committing/pushing.\n", file=sys.stderr)
        return 1
    print(f"check_sensitive: OK ({len(changes)} paths/chunks checked against {len(needles)} local values)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

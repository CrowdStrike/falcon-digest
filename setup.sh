#!/usr/bin/env bash
# Falcon Digest — Setup Script
# Usage: bash setup.sh

set -e

echo "========================================"
echo "  CrowdStrike Falcon MCP — Setup"
echo "========================================"
echo ""

# ------ 1. Check Python 3.10+ ------
echo "[1/6] Checking Python version..."

PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        major=$("$candidate" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo 0)
        minor=$("$candidate" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo 0)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON="$candidate"
            echo "  Found $candidate $version"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "  ERROR: Python 3.10+ is required but not found."
    echo "  Install it from https://www.python.org/downloads/"
    exit 1
fi

# ------ 2. Create / activate venv ------
echo ""
echo "[2/6] Setting up virtual environment..."

if [ ! -d "venv" ]; then
    $PYTHON -m venv venv
    echo "  Created venv/"
else
    echo "  venv/ already exists"
fi

source venv/bin/activate
echo "  Activated venv ($(python --version))"

# ------ 3. Install dependencies ------
echo ""
echo "[3/6] Installing dependencies..."
pip install -q -r requirements.txt
echo "  Done — all packages installed"

# ------ 4. Configuration ------
echo ""
echo "[4/6] Configuration"
echo "  Credentials are no longer stored in .env. They are entered in the"
echo "  dashboard Settings page and saved to an encrypted config file."
if [ -f ".env" ]; then
    echo ""
    echo "  Found an existing .env — on first dashboard start its Falcon/LLM"
    echo "  values are imported into the encrypted config and the file is"
    echo "  renamed to .env.migrated. Delete .env.migrated once the dashboard"
    echo "  works, because it still contains your plaintext secret."
fi

# ------ 5. Run tests (optional) ------
echo ""
echo "[5/6] Run test suite?"
read -r -p "  Run pytest now? [y/N] " run_tests
if [[ "$run_tests" =~ ^[Yy]$ ]]; then
    echo ""
    python -m pytest tests/ -q
    echo ""
fi

# ------ 6. Start cache daemon (optional) ------
echo ""
echo "[6/6] Cache daemon"
read -r -p "  Start the cache daemon in the background? [y/N] " start_daemon
if [[ "$start_daemon" =~ ^[Yy]$ ]]; then
    bash daemon.sh start 300
fi

# ------ Done ------
echo ""
echo "========================================"
echo "  Setup complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo ""
echo "  # Activate the virtual environment"
echo "  source venv/bin/activate"
echo ""
echo "  # Run the dashboard (listens on 127.0.0.1 only, see .streamlit/config.toml)"
echo "  streamlit run mcp_dashboard.py"
echo ""
echo "  # First launch:"
echo "  #   1. Copy the one-time setup token printed in this terminal"
echo "  #      (also stored in .falcon_users.json.setup)"
echo "  #   2. Create the admin account in the browser using that token"
echo "  #   3. Enter Falcon API credentials (and optionally LLM settings) in Settings"
echo ""
echo "  # Run MCP server (stdio, for IDE/editor integration)"
echo "  python crwd_mcp_server.py"
echo ""
echo "  # Run CLI client (interactive chat)"
echo "  python mcp_api_client.py"
echo ""
echo "  # Cache daemon"
echo "  bash daemon.sh start          # Start (5-min poll)"
echo "  bash daemon.sh start 60       # Start (1-min poll)"
echo "  bash daemon.sh stop            # Stop"
echo "  bash daemon.sh status          # Check status"
echo ""

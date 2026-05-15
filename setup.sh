#!/usr/bin/env bash
# CrowdStrike Falcon MCP — Setup Script
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

# ------ 4. Environment variables ------
echo ""
echo "[4/6] Checking environment configuration..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "  Created .env from .env.example"
    else
        cat > .env <<'ENVEOF'
FALCON_CLIENT_ID=
FALCON_CLIENT_SECRET=
FALCON_BASE_URL=
LLM_ENDPOINT=
LLM_API_KEY=
ENVEOF
        echo "  Created blank .env"
    fi

    echo ""
    echo "  Let's configure your CrowdStrike cloud region."
    echo ""
    echo "  Select your Falcon cloud:"
    echo "    1) US-1  (api.crowdstrike.com)"
    echo "    2) US-2  (api.us-2.crowdstrike.com)"
    echo "    3) EU-1  (api.eu-1.crowdstrike.com)"
    echo "    4) GOV-1 (api.laggar.gcw.crowdstrike.com)"
    echo "    5) Other (enter custom URL)"
    echo ""
    read -r -p "  Choice [1-5]: " cloud_choice

    case "$cloud_choice" in
        1) FALCON_URL="https://api.crowdstrike.com" ;;
        2) FALCON_URL="https://api.us-2.crowdstrike.com" ;;
        3) FALCON_URL="https://api.eu-1.crowdstrike.com" ;;
        4) FALCON_URL="https://api.laggar.gcw.crowdstrike.com" ;;
        5)
            read -r -p "  Enter Falcon API base URL: " FALCON_URL
            ;;
        *) FALCON_URL="https://api.crowdstrike.com"
            echo "  Defaulting to US-1"
            ;;
    esac

    # Write the chosen base URL into .env
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|^FALCON_BASE_URL=.*|FALCON_BASE_URL=$FALCON_URL|" .env
    else
        sed -i "s|^FALCON_BASE_URL=.*|FALCON_BASE_URL=$FALCON_URL|" .env
    fi
    echo "  Set FALCON_BASE_URL=$FALCON_URL"

    echo ""
    echo "  *** Please edit .env and fill in your API credentials: ***"
    echo "    FALCON_CLIENT_ID      (required)"
    echo "    FALCON_CLIENT_SECRET   (required)"
    echo ""
    echo "  AI chat is optional. To enable it, also set:"
    echo "    LLM_ENDPOINT   (any Anthropic Messages API-compatible endpoint)"
    echo "    LLM_API_KEY"
    echo ""
else
    echo "  .env already exists — skipping configuration"
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
echo "  # Run Dashboard v1 (7-tab layout with AI Chat tab)"
echo "  streamlit run mcp_dashboard.py"
echo ""
echo "  # Run Dashboard v2 (5-tab layout with side chat panel)"
echo "  streamlit run mcp_dashboard_v2.py"
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

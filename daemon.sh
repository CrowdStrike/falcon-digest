#!/usr/bin/env bash
# CrowdStrike Falcon MCP — Cache Daemon Manager
# Usage: bash daemon.sh {start|stop|status|restart} [poll_interval]

set -e

PIDFILE=".falcon_cache_daemon.pid"
LOGFILE="cache_daemon.log"
POLL_INTERVAL="${2:-300}"

# Resolve python inside venv if available
if [ -f "venv/bin/python" ]; then
    PYTHON="venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    PYTHON="python"
fi

is_running() {
    if [ -f "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            # Stale PID file
            rm -f "$PIDFILE"
            return 1
        fi
    fi
    return 1
}

do_start() {
    if is_running; then
        pid=$(cat "$PIDFILE")
        echo "Daemon is already running (PID $pid)"
        return 0
    fi

    echo "Starting cache daemon (poll_interval=${POLL_INTERVAL}s)..."
    nohup "$PYTHON" falcon_cache_daemon.py "$POLL_INTERVAL" >> "$LOGFILE" 2>&1 &
    pid=$!
    echo "$pid" > "$PIDFILE"
    echo "Daemon started (PID $pid, log: $LOGFILE)"
}

do_stop() {
    if ! is_running; then
        echo "Daemon is not running"
        return 0
    fi

    pid=$(cat "$PIDFILE")
    echo "Stopping daemon (PID $pid)..."
    kill "$pid" 2>/dev/null

    # Wait up to 5 seconds for graceful shutdown
    for i in 1 2 3 4 5; do
        if ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$PIDFILE"
            echo "Daemon stopped"
            return 0
        fi
        sleep 1
    done

    # Force kill if still running
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "Daemon killed"
}

do_status() {
    if is_running; then
        pid=$(cat "$PIDFILE")
        echo "Daemon is running (PID $pid)"
        echo ""
        # Show last 5 log lines
        if [ -f "$LOGFILE" ]; then
            echo "Recent log:"
            tail -5 "$LOGFILE"
        fi
    else
        echo "Daemon is not running"
    fi
}

do_restart() {
    do_stop
    sleep 1
    do_start
}

case "${1:-}" in
    start)
        do_start
        ;;
    stop)
        do_stop
        ;;
    status)
        do_status
        ;;
    restart)
        do_restart
        ;;
    *)
        echo "Usage: bash daemon.sh {start|stop|status|restart} [poll_interval]"
        echo ""
        echo "Commands:"
        echo "  start   [interval]   Start the cache daemon (default: 300s poll)"
        echo "  stop                 Stop the running daemon"
        echo "  status               Show daemon status and recent log"
        echo "  restart [interval]   Restart the daemon"
        echo ""
        echo "Examples:"
        echo "  bash daemon.sh start          # Start with 5-minute polling"
        echo "  bash daemon.sh start 60       # Start with 1-minute polling"
        echo "  bash daemon.sh stop            # Stop the daemon"
        echo "  bash daemon.sh status          # Check if running"
        exit 1
        ;;
esac

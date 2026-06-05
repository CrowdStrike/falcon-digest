#!/usr/bin/env python3
"""
Falcon Digest — Cache Daemon
Standalone background process that keeps .falcon_cache.json warm
so dashboards load instantly.

Usage:
    python falcon_cache_daemon.py [poll_interval_seconds]

Default poll interval is 300 seconds (5 minutes).
Stop with Ctrl-C or SIGTERM.
"""

import logging
import signal
import sys
import time
import threading

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("falcon_mcp.daemon")

from falcon_cache import cache as falcon_cache


def main():
    poll_interval = 300
    if len(sys.argv) > 1:
        try:
            poll_interval = int(sys.argv[1])
        except ValueError:
            logger.warning("Invalid poll interval '%s', using default 300s", sys.argv[1])

    running = threading.Event()
    running.set()

    def _shutdown(sig, frame):
        logger.info("Received signal %s, shutting down...", sig)
        running.clear()
        falcon_cache.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info("Starting Falcon cache daemon (poll_interval=%ds)", poll_interval)
    falcon_cache.start(poll_interval=poll_interval, ttl=poll_interval)

    status_interval = 10  # seconds between status prints
    last_status = 0

    while running.is_set():
        # Auto-restart polling thread if it died
        if not falcon_cache.is_running:
            logger.warning("Polling thread died, restarting...")
            falcon_cache.start(poll_interval=poll_interval, ttl=poll_interval)

        now = time.time()
        if now - last_status >= status_interval:
            errs = falcon_cache.recent_errors
            err_str = f", errors: {len(errs)}" if errs else ""
            duration = falcon_cache.last_refresh_duration
            dur_str = f", last_duration: {duration:.1f}s" if duration is not None else ""
            logger.info(
                "entries: %d, refreshes: %d%s%s",
                falcon_cache.entry_count,
                falcon_cache.refresh_count,
                dur_str, err_str
            )
            last_status = now

        time.sleep(1)

    logger.info("Stopped.")


if __name__ == "__main__":
    main()

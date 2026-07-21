#!/usr/bin/env python3
"""Standalone daemon process for keeping the Falcon data cache warm.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    Falcon Digest
`-------'                         `-------'

Falcon Digest — AI-Powered Falcon Security Dashboard

Copyright 2024 CrowdStrike, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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

"""Guarded cleanup helpers for tests.

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

Tests must never delete "everything in a directory". Use ``clear_state``,
which only removes Falcon Digest state files by name, and only inside a
temporary directory that is not a git checkout.
"""

import os
import shutil
import tempfile

import falcon_secrets


class UnsafeCleanupError(RuntimeError):
    """Raised instead of deleting anything outside a safe temp directory."""


def assert_safe_test_dir(path: str) -> str:
    """Return the real path of ``path`` if it is safe for tests to clean, else raise.

    Safe means: inside the system temp dir, not the temp dir itself, not the
    repo / source tree / home dir, and not containing a ``.git`` directory.
    """
    real = os.path.realpath(path)
    tmp = os.path.realpath(tempfile.gettempdir())
    forbidden = {os.path.realpath(p) for p in (falcon_secrets.SOURCE_DIR, os.path.expanduser("~"),
                                               falcon_secrets.DEFAULT_APP_DIR, tmp, os.sep)}
    if not real.startswith(tmp + os.sep) or real in forbidden or os.path.exists(os.path.join(real, ".git")):
        raise UnsafeCleanupError(f"Refusing to clean {real!r}: not an isolated temp directory")
    return real


def clear_state(path: str | None = None) -> None:
    """Remove Falcon Digest state files (by name) from the test data dir."""
    real = assert_safe_test_dir(path or falcon_secrets.APP_DIR)
    for name in falcon_secrets.STATE_FILES:
        try:
            os.remove(os.path.join(real, name))
        except FileNotFoundError:
            pass
    for name in falcon_secrets.STATE_DIRS:
        shutil.rmtree(os.path.join(real, name), ignore_errors=True)
    for name in os.listdir(real):  # stray atomic-write temp files
        if name.startswith(".falcon_") and name.endswith(".tmp"):
            os.remove(os.path.join(real, name))

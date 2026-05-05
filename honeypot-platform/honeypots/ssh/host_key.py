"""RSA/ECDSA SSH host key persistence helper."""

from __future__ import annotations

from pathlib import Path

import asyncssh


def ensure_host_key(path: Path, *, key_type: str = "ssh-rsa") -> str:
    """Create an RSA host key on disk if missing. Returns path string for asyncssh.listen."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file():
        key = asyncssh.generate_private_key(key_type)
        key.write_private_key(str(path))
    return str(path.resolve())

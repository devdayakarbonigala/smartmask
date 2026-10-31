"""Login for the demo app: each account is bound to one role, and passwords are stored as salted PBKDF2 hashes."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from .policy import Policy

ITERATIONS = 200_000
MAX_ATTEMPTS = 5
DEFAULT_USERS_FILE = Path(__file__).resolve().parent.parent / "db" / "demo_users.json"
# Checked when the user name is unknown, so a wrong name and a wrong password take the same time.
_DUMMY = "00" * 16 + "$" + "00" * 32


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt if salt is not None else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(digest_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return hmac.compare_digest(actual, expected)


def load_users(path: str | Path | None = None) -> dict[str, dict[str, str]]:
    """Read {"users": {name: {"role": ..., "password": "<salt>$<hash>"}}} and reject unknown roles."""
    users = json.loads(Path(path or DEFAULT_USERS_FILE).read_text())["users"]
    known = set(Policy().role_names())
    for name, info in users.items():
        if info.get("role") not in known:
            raise ValueError(f"User '{name}' has an unknown role: {info.get('role')}")
    return users


def authenticate(users: dict[str, dict[str, str]], name: str, password: str) -> str | None:
    """Return the role of a valid account, or None. Never says which of the two inputs was wrong."""
    info = users.get((name or "").strip().lower())
    ok = verify_password(password or "", info["password"] if info else _DUMMY)
    return info["role"] if info and ok else None

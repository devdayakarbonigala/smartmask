from __future__ import annotations

import json
from pathlib import Path

DEFAULT_PATH = Path(__file__).with_name("policy.json")


class Policy:
    def __init__(self, path: str | Path = DEFAULT_PATH):
        self.roles = json.loads(Path(path).read_text())["roles"]

    def role_names(self):
        return list(self.roles)

    def mask_for(self, role: str, entity: str) -> str:
        """none | partial | hash | redact. Anything a role has no rule for falls back to the role default,
        so a newly tagged column is protected (redacted) until someone explicitly allows it."""
        if role not in self.roles:
            raise KeyError(f"Unknown role: {role}")
        r = self.roles[role]
        return r["rules"].get(entity, r["default"])

    def matrix(self, entities):
        return {role: {e: self.mask_for(role, e) for e in entities} for role in self.roles}

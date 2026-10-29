"""Free-text scrubbing: remove identifiers that are embedded inside sentences or JSON text.

The same ordered rule list drives both backends so their output is identical:
  * PostgreSQL applies it inside the database as nested REGEXP_REPLACE(..., 'g') calls
  * SQLite applies it through a registered SM_SCRUB() function (SQLite has no regex replace)

Patterns avoid look-behind and word-boundary escapes because PostgreSQL regular
expressions do not support them. Digit and letter boundaries are matched explicitly
with a leading and a trailing group instead.
"""

from __future__ import annotations

import re

# (pattern, replacement). Order matters: more specific rules run before general ones.
RULES: list[tuple[str, str]] = [
    # names stored as JSON values, e.g. "father_name": "Kuldeep Gill"
    (r'("(?:father_name|mother_name|spouse_name|full_name|name)" *: *")[^"]+(")', r"\1[NAME]\2"),
    # e-mail addresses, then UPI handles such as 9999960427@pragatiupi
    (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}", "[EMAIL]"),
    (r"[A-Za-z0-9._-]+@[A-Za-z][A-Za-z0-9]+", "[UPI-ID]"),
    # Aadhaar next to a label (any spacing), then the grouped 4-4-4 form on its own
    (r"(?i)((?:aadhaar|aadhar|adhaar|adhar|uidai|uid)[^0-9]{0,12})[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}", r"\1[AADHAAR]"),
    (r"(^|[^0-9])[2-9][0-9]{3}[ -][0-9]{4}[ -][0-9]{4}($|[^0-9])", r"\1[AADHAAR]\2"),
    # payment card numbers: 13 to 19 digits, optionally grouped
    (r"(^|[^0-9])[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{1,7}($|[^0-9])", r"\1[CARD]\2"),
    # US social security numbers
    (r"(^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}($|[^0-9])", r"\1[SSN]\2"),
    # Indian PAN
    (r"(^|[^A-Za-z0-9])[A-Z]{5}[0-9]{4}[A-Z]($|[^A-Za-z0-9])", r"\1[PAN]\2"),
    # Indian mobile numbers, with or without +91
    (r"(^|[^0-9])(\+?91[ -]?)?[6-9][0-9]{4}[ -]?[0-9]{5}($|[^0-9])", r"\1[PHONE]\3"),
]

_COMPILED = [(re.compile(p), r) for p, r in RULES]


def scrub_text(value):
    """Python implementation, used by the SQLite function and by the scanner."""
    if value is None:
        return None
    out = str(value)
    for pattern, repl in _COMPILED:
        out = pattern.sub(repl, out)
    return out


def has_embedded_pii(value) -> bool:
    return value is not None and scrub_text(value) != str(value)

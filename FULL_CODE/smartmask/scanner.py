"""Automated PII scanner.

For every column it combines two kinds of evidence:
  * the column NAME (token / regex hints), and
  * a ROW SAMPLE (regex plus checksum validators such as Luhn and Verhoeff).

Output is a tag per sensitive column: PII_HIGH, PII_MEDIUM or FINANCIAL_CONFIDENTIAL.
Long text columns that carry identifiers inside sentences or JSON are tagged FREETEXT.
The scanner only ever reads. Tags are kept in a separate metadata store.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Callable

from .checks import luhn_ok, verhoeff_ok
from .scrub import has_embedded_pii

TAGS = {
    "SSN": "PII_HIGH",
    "AADHAAR": "PII_HIGH",
    "PAN": "PII_HIGH",
    "FREETEXT": "PII_HIGH",
    "CARD": "FINANCIAL_CONFIDENTIAL",
    "ACCOUNT_NO": "FINANCIAL_CONFIDENTIAL",
    "BALANCE": "FINANCIAL_CONFIDENTIAL",
    "EMAIL": "PII_MEDIUM",
    "PHONE": "PII_MEDIUM",
    "DOB": "PII_MEDIUM",
    "NAME": "PII_MEDIUM",
    "ADDRESS": "PII_MEDIUM",
}
# Tie-break order when two entities score the same.
PRIORITY = ["CARD", "SSN", "AADHAAR", "PAN", "EMAIL", "ACCOUNT_NO", "PHONE", "DOB", "BALANCE", "NAME", "ADDRESS"]

NAME_HINTS = {
    "CARD": r"(card_?(no|num|number)|^card$|ccn|cc_?num|credit_?card|debit_?card|(^|_)pan_?card)",
    "SSN": r"(^|_)(ssn|social_?sec\w*|sin)($|_)",
    "AADHAAR": r"(aadhaar|aadhar|uidai|(^|_)uid($|_))",
    "PAN": r"((^|_)pan($|_)|pan_?(no|num|number|card)|tax_?id)",
    "EMAIL": r"(e_?mail)",
    "PHONE": r"(phone|mobile|msisdn|contact_?(no|num|number)|cell|(^|_)mob($|_)|(^|_)tel($|_))",
    "DOB": r"(dob|birth)",
    "NAME": (
        r"((^|_)(full|first|last|middle|given|sur|family|holder|customer|cust|nominee|beneficiary|person|"
        r"father|mother|spouse|pita|applicant)_?(name|nm)($|_)|^(name|nm)$|name_on_card)"
    ),
    "BALANCE": r"(balance|(^|_)bal($|_)|salary|income|credit_?limit|net_?worth|outstanding|od_?limit|sanctioned)",
    "ACCOUNT_NO": r"((acct|account)_?(no|num|number)|linked_?acct|iban)",
    "ADDRESS": r"((^|_)(addr|address)_?(line)?_?\d($|_)|(^|_)(us|home|resid\w*|postal|mailing)_?(addr|address)($|_)|^address$)",
}
NUMERIC_ONLY = {"BALANCE"}
HINT_REQUIRED = {"DOB", "NAME", "BALANCE", "ACCOUNT_NO", "ADDRESS"}  # no distinctive value pattern
# Business contact columns (a branch's own phone or e-mail) are not personal data.
BUSINESS_PREFIXES = ("branch_",)

FREETEXT_HINT = r"(note|remark|comment|text|narration|descr|memo|message|extra_?info|meta|counterparty)"
FREETEXT_MIN_AVG_LEN = 30

_email = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
# Area numbers 000 and 666 are never valid. 900-999 are kept on purpose: test data and ITINs use them.
_ssn = re.compile(r"^(?!000|666)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}$")
_ssn_plain = re.compile(r"^(?!000|666)\d{3}(?!00)\d{2}(?!0000)\d{4}$")
_aad = re.compile(r"^[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}$")
_aad_masked = re.compile(r"^[Xx*]{4}[ -]?[Xx*]{4}[ -]?\d{4}$")
_pan = re.compile(r"^[A-Z]{5}\d{4}[A-Z]$")
_card_shape = re.compile(r"^\d[\d \-]{11,22}\d$")
_phone_fmt = re.compile(r"^(\+\d{1,3}[ \-]?)?(\(?\d{2,5}\)?[ \-.]?){2,4}\d{2,4}$")
_in_mobile = re.compile(r"^(91)?[6-9]\d{9}$")
_date = re.compile(r"^\d{4}-\d{2}-\d{2}([ T].*)?$|^\d{2}[/\-]\d{2}[/\-]\d{4}$")
_acct = re.compile(r"^\d{9,18}$|^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$")


def _digits(s: str) -> str:
    return re.sub(r"[ \-]", "", s)


def _v_card(s, hint):
    return bool(_card_shape.match(s)) and luhn_ok(_digits(s))


def _v_pan(s, hint):
    return bool(_pan.match(s))


def _v_email(s, hint):
    return bool(_email.match(s))


def _v_dob(s, hint):
    return bool(_date.match(s))


def _v_acct(s, hint):
    return bool(_acct.match(s))


def _v_name(s, hint):
    return bool(re.match(r"^[A-Za-z][A-Za-z .'\-]{1,60}$", s))


def _v_addr(s, hint):
    return len(s) >= 4 and bool(re.search(r"[A-Za-z]", s))


def _v_ssn(s, hint):
    return bool(_ssn.match(s)) or (hint and bool(_ssn_plain.match(s)))


def _v_aad(s, hint):
    """A column named like Aadhaar needs only the right shape. Without a name hint the Verhoeff
    check digit must also pass, so ordinary 12-digit references are not tagged."""
    if _aad_masked.match(s):
        return hint
    if not _aad.match(s):
        return False
    return hint or verhoeff_ok(_digits(s))


def _v_phone(s, hint):
    s = s.strip()
    compact = re.sub(r"[\s\-+()]", "", s)
    if _in_mobile.match(compact):
        return hint or any(ch in s for ch in "+ -")
    plain = s.isdigit()
    return bool(_phone_fmt.match(s)) and 10 <= len(re.sub(r"\D", "", s)) <= 13 and (hint or not plain)


VALIDATORS: dict[str, Callable[[str, bool], bool]] = {
    "CARD": _v_card,
    "SSN": _v_ssn,
    "AADHAAR": _v_aad,
    "PAN": _v_pan,
    "EMAIL": _v_email,
    "PHONE": _v_phone,
    "DOB": _v_dob,
    "ACCOUNT_NO": _v_acct,
    "NAME": _v_name,
    "ADDRESS": _v_addr,
}


@dataclass
class ColumnTag:
    table: str
    column: str
    data_type: str
    entity: str
    tag: str
    confidence: float
    name_hit: bool
    value_ratio: float
    source: str = "auto"

    def as_dict(self):
        return asdict(self)


def is_numeric_type(data_type: str) -> bool:
    t = (data_type or "").lower()
    return any(k in t for k in ("int", "numeric", "real", "float", "double", "decimal", "money", "number"))


def _name_hits(column: str) -> dict[str, bool]:
    c = column.lower()
    return {e: bool(re.search(p, c)) for e, p in NAME_HINTS.items()}


def classify_column(table: str, column: str, data_type: str, sample: list) -> ColumnTag | None:
    """Return the best tag for a column, or None if it looks non-sensitive."""
    hits = _name_hits(column)
    values = [str(v).strip() for v in sample if v is not None and str(v).strip() != ""]
    numeric = is_numeric_type(data_type)
    business = column.lower().startswith(BUSINESS_PREFIXES)
    best: tuple[float, ColumnTag] | None = None
    for entity in PRIORITY:
        if business and entity in ("EMAIL", "PHONE"):
            continue
        name_hit = hits[entity]
        if entity in NUMERIC_ONLY:
            ratio = 1.0 if (numeric and values) else 0.0
        elif entity in VALIDATORS and values:
            ok = sum(1 for v in values if VALIDATORS[entity](v, name_hit))
            ratio = ok / len(values)
        else:
            ratio = 0.0

        if entity in HINT_REQUIRED:
            accept = name_hit and ratio >= 0.5
        else:
            accept = ratio >= 0.8 or (name_hit and ratio >= 0.4)
        if not accept:
            continue
        conf = round(min(1.0, 0.65 * ratio + 0.35 * (1.0 if name_hit else 0.0)), 2)
        cand = ColumnTag(table, column, data_type, entity, TAGS[entity], conf, name_hit, round(ratio, 2))
        if best is None or conf > best[0]:
            best = (conf, cand)
    return best[1] if best else None


def _mixed_card_content(values: list[str]) -> bool:
    """True when a short column holds some real card numbers next to ordinary references.

    Among the card-shaped values (13 to 19 digits, optionally grouped), almost all must pass the Luhn check.
    Random reference numbers pass it only about one time in ten, so they are not flagged."""
    shaped = [v.strip() for v in values if _card_shape.match(v.strip())]
    if len(shaped) < 3:
        return False
    valid = sum(1 for v in shaped if luhn_ok(_digits(v)))
    return valid / len(shaped) >= 0.8


def classify_freetext(table: str, column: str, data_type: str, sample: list) -> ColumnTag | None:
    """Tag a text column whose values carry identifiers inside sentences or JSON.

    Candidates are long on average or have a free-text style name. A column is tagged when
    the sample contains embedded identifiers (card, PAN, e-mail, phone, Aadhaar, SSN, JSON names).
    """
    if is_numeric_type(data_type) or column.lower().startswith(BUSINESS_PREFIXES):
        return None
    values = [str(v) for v in sample if v is not None and str(v).strip() != ""]
    if not values:
        return None
    name_hit = bool(re.search(FREETEXT_HINT, column.lower()))
    avg_len = sum(len(v) for v in values) / len(values)
    if not name_hit and not _mixed_card_content(values):
        sentences = sum(1 for v in values if " " in v.strip()) / len(values)
        if avg_len < FREETEXT_MIN_AVG_LEN or sentences < 0.5:  # identifiers such as UUIDs have no spaces
            return None
    hit_ratio = sum(1 for v in values if has_embedded_pii(v)) / len(values)
    if hit_ratio == 0 or (not name_hit and hit_ratio < 0.02):
        return None
    conf = round(min(1.0, 0.5 + 0.35 * (1.0 if name_hit else 0.0) + min(0.15, hit_ratio)), 2)
    return ColumnTag(table, column, data_type, "FREETEXT", TAGS["FREETEXT"], conf, name_hit, round(hit_ratio, 2))


def scan(adapter, sample_size: int = 200) -> list[ColumnTag]:
    tags: list[ColumnTag] = []
    for table, cols in adapter.schema().items():
        for column, dtype in cols.items():
            sample = adapter.sample(table, column, sample_size)
            tag = classify_column(table, column, dtype, sample) or classify_freetext(table, column, dtype, sample)
            if tag:
                tags.append(tag)
    return tags

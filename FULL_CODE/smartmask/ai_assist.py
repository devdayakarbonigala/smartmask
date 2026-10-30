"""AI assist: suggestions for columns the rules may have missed. AI never decides alone.

Three signals look at each column:
  1. RULES      the existing scanner (names, regex, checksums)
  2. LOCAL ML   a small scikit-learn classifier that sees only column-name text and value SHAPES
  3. LLM        optional, off unless an API key is set; sees only names and value SHAPES

Nothing here changes a mask. Suggestions go to a review queue and a person approves them; only an
approved suggestion is written as a manual override. Masking itself stays exact, deterministic SQL.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from . import benchmark as bm
from . import config
from .scanner import BUSINESS_PREFIXES, TAGS, ColumnTag

log = logging.getLogger(__name__)

ENTITIES = ["CARD", "SSN", "AADHAAR", "PAN", "EMAIL", "PHONE", "DOB", "ACCOUNT_NO", "BALANCE", "NAME", "ADDRESS"]
LABELS = ENTITIES + ["NONE"]
MIN_PROB = config.AI_MIN_PROB
PROMPT_FILE = Path(__file__).parent / "prompts" / "column_classifier.txt"


# ---- shapes: the only value information any AI signal ever sees ---------------------------------
def shape(value, max_len: int = 24) -> str:
    out = []
    for ch in str(value)[:max_len]:
        out.append("9" if ch.isdigit() else "A" if ch.isupper() else "a" if ch.islower() else ch)
    return "".join(out)


def top_shapes(sample: list, k: int = 5) -> list[tuple[str, int]]:
    values = [v for v in sample if v is not None and str(v).strip() != ""]
    return Counter(shape(v) for v in values).most_common(k)


# ---- local ML signal ---------------------------------------------------------------------------
def _coarse(s: str) -> str:
    """Collapse runs: 'Aaaaa Aaaa' -> 'Aa Aa', '1234.50' shape '9999.99' -> '9.9'. Names, addresses and amounts vary in length."""
    out = []
    for ch in s:
        if not out or out[-1] != ch:
            out.append(ch)
    return "".join(out)


def _stat_tokens(shapes: list[tuple[str, int]]) -> str:
    total = sum(n for _, n in shapes) or 1
    toks = []
    for s, n in shapes:
        toks.append("sh_" + s.replace(" ", "_"))
        toks.append("co_" + _coarse(s).replace(" ", "_"))
        if n / total >= 0.5:
            toks.append("dom_" + s.replace(" ", "_"))
    lens = [len(s) for s, _ in shapes] or [0]
    toks.append(f"len_{min(lens[0], 30) // 2}")
    joined = "".join(s for s, _ in shapes)
    toks.append("digits_high" if joined and sum(c == "9" for c in joined) / len(joined) > 0.6 else "digits_low")
    toks.append("has_at" if "@" in joined else "no_at")
    toks.append("has_space" if " " in joined else "no_space")
    toks.append("has_dot" if "." in joined else "no_dot")
    return " ".join(toks)


NAMED = {
    "CARD": ["card_number", "card_no", "credit_card", "debit_card_no", "ccn", "pan_card_number", "card_num", "cc_no"],
    "SSN": ["ssn", "social_security_number", "tax_id_us", "social_sec_no"],
    "AADHAAR": ["aadhaar", "aadhar_number", "uid_no", "uidai_id"],
    "PAN": ["pan", "pan_no", "pan_number", "tax_pan", "income_tax_pan"],
    "EMAIL": ["email", "email_address", "mail_id", "contact_email", "e_mail"],
    "PHONE": [
        "phone",
        "mobile",
        "mobile_no",
        "msisdn",
        "contact_number",
        "tel_no",
        "cell",
        "whatsapp_no",
        "mob_no",
        "alt_mob",
        "alt_phone",
        "contact_phone",
    ],
    "DOB": ["dob", "date_of_birth", "birth_date", "born_on", "birthday"],
    "ACCOUNT_NO": [
        "account_number",
        "acct_no",
        "savings_account",
        "bank_acct",
        "iban_no",
        "account_no",
        "linked_acct",
        "acc_num",
        "beneficiary_acct",
    ],
    "BALANCE": [
        "balance",
        "account_balance",
        "available_bal",
        "salary",
        "annual_income",
        "credit_limit",
        "curr_bal",
        "bal_amt",
        "outstanding_amt",
        "monthly_income",
        "loan_amt_sanctioned",
        "overdraft_limit",
    ],
    "NAME": [
        "name",
        "full_name",
        "first_name",
        "customer_name",
        "holder_name",
        "beneficiary",
        "person",
        "party_nm",
        "cust_nm",
        "emp_name",
        "nominee_name",
        "name_on_card",
        "father_nm",
        "spouse_name",
    ],
    "ADDRESS": [
        "address",
        "home_address",
        "street_address",
        "mailing_addr",
        "residence",
        "addr_line1",
        "addr_2",
        "res_addr",
        "permanent_address",
    ],
}
NONE_NAMES = [
    "id",
    "customer_id",
    "status",
    "code",
    "type",
    "created_at",
    "updated_on",
    "txn_date",
    "opened_on",
    "branch_code",
    "city",
    "state",
    "pincode",
    "gender",
    "qty",
    "currency",
    "kyc_status",
    "tier",
    "score",
    "rating",
    "reference",
    "txn_id",
    "order_id",
    "ref_id",
    "issued_on",
    "verified_on",
    "applied_dt",
    "open_dt",
    "since",
    "review_date",
    "reported_on",
    "closed_on",
    "expiry_dt",
    "region",
    "channel",
    "mode",
    "product_code",
]
CRYPTIC = ["col_{n}", "f{n}", "x{n}", "val_{n}", "data{n}", "attr_{n}", "fld_{n}", "c{n}", "field{n}"]


def _gen_values(label: str, rng: random.Random, n: int = 25) -> list[str]:
    d = bm._digits
    streets = ["MG Road", "Lane", "Cross", "Nagar", "Colony", "Street", "Park", "Apartments"]
    gens = {
        "CARD": lambda: bm._luhn_card(rng) if rng.random() < 0.6 else d(rng, 16),
        "SSN": lambda: bm._ssn(rng),
        "AADHAAR": lambda: bm._aad(rng) if rng.random() < 0.5 else " ".join(bm._aad(rng)[i : i + 4] for i in range(0, 12, 4)),
        "PAN": lambda: bm._pan(rng),
        "EMAIL": lambda: bm._email(rng),
        "PHONE": lambda: bm._phone(rng) if rng.random() < 0.6 else "9" + d(rng, 9),
        "DOB": lambda: bm._dob(rng),
        "ACCOUNT_NO": lambda: d(rng, rng.choice([9, 12, 14, 16])),
        "BALANCE": lambda: f"{rng.uniform(100, 9e6):.2f}",
        "NAME": lambda: bm._name(rng),
        "ADDRESS": lambda: f"{rng.randint(1, 500)}, {rng.choice(streets)} {rng.randint(1, 20)}",
    }
    if label != "NONE":
        return [gens[label]() for _ in range(n)]
    kind = rng.choice(["id", "word", "date", "date", "pin", "int", "city", "code", "longid"])
    return [
        {
            "id": lambda: "C" + d(rng, 7),
            "word": lambda: rng.choice(["OPEN", "FROZEN", "ACTIVE", "CLOSED"]),
            "date": lambda: bm._date(rng),
            "pin": lambda: d(rng, 6),
            "int": lambda: str(rng.randint(1, 40)),
            "city": lambda: rng.choice(["Guntur", "Mumbai", "Delhi", "Pune"]),
            "code": lambda: "BR" + d(rng, 4),
            "longid": lambda: d(rng, 16),
        }[kind]()
        for _ in range(n)
    ]


def _training_set(seed: int = 7, per_label: int = 60):
    rng = random.Random(seed)
    rows = []
    for label in LABELS:
        for i in range(per_label * (2 if label == "NONE" else 1)):
            pool = NONE_NAMES if label == "NONE" else NAMED[label]
            if rng.random() < 0.5:
                name = rng.choice(CRYPTIC).format(n=rng.randint(1, 99))  # cryptic: only the shapes help
            else:
                name = rng.choice(pool)
            rows.append((name, top_shapes(_gen_values(label, rng)), label))
    return rows


@dataclass
class MlSignal:
    entity: str | None
    prob: float


class ColumnModel:
    """Name text + value shapes -> entity. Trained from synthetic generators at start-up (a few seconds, fixed seeds)."""

    def __init__(self, seed: int = 7):
        rows = _training_set(seed)
        self.name_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), lowercase=True)
        self.shape_vec = CountVectorizer(token_pattern=r"\S+", lowercase=False, binary=True)
        names = [r[0] for r in rows]
        shapes = [_stat_tokens(r[1]) for r in rows]
        X = hstack([self.name_vec.fit_transform(names), self.shape_vec.fit_transform(shapes)]).tocsr()
        self.clf = LogisticRegression(max_iter=2000, C=8.0, random_state=0)
        self.clf.fit(X, [r[2] for r in rows])

    def predict(self, column: str, shapes: list[tuple[str, int]]) -> MlSignal:
        if not shapes:
            return MlSignal(None, 0.0)
        X = hstack([self.name_vec.transform([column]), self.shape_vec.transform([_stat_tokens(shapes)])]).tocsr()
        probs = self.clf.predict_proba(X)[0]
        i = int(np.argmax(probs))
        label, p = str(self.clf.classes_[i]), float(probs[i])
        if label == "NONE" or p < MIN_PROB:
            return MlSignal(None, p)
        return MlSignal(label, p)


_MODEL: ColumnModel | None = None


def get_model() -> ColumnModel:
    global _MODEL
    if _MODEL is None:
        _MODEL = ColumnModel()
    return _MODEL


# ---- optional LLM signal -----------------------------------------------------------------------
@dataclass
class LlmSignal:
    entity: str | None
    confidence: float
    reason: str


def _post_messages(payload: dict, api_key: str) -> dict:
    req = urllib.request.Request(
        config.LLM_URL,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "x-api-key": api_key, "anthropic-version": "2023-06-01"},
    )
    with urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT) as resp:
        return json.loads(resp.read())


def llm_enabled() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def parse_llm_answer(text: str) -> LlmSignal | None:
    """Validate the model's JSON. Anything unexpected is rejected, never guessed at."""
    try:
        obj = json.loads(text.strip().strip("`").removeprefix("json").strip())
        entity = obj["entity"]
        conf = float(obj["confidence"])
        reason = str(obj.get("reason", ""))[:200]
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    if entity not in LABELS or not 0.0 <= conf <= 1.0:
        return None
    return LlmSignal(None if entity == "NONE" else entity, conf, reason)


def llm_suggest(table: str, column: str, dtype: str, shapes: list[tuple[str, int]], transport=None) -> LlmSignal | None:
    """Ask the model about ONE column. It receives names and shapes only. Returns None on any failure."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key and transport is None:
        return None
    user = json.dumps({"table": table, "column": column, "data_type": dtype, "value_shapes": [s for s, _ in shapes]})
    payload = {
        "model": config.LLM_MODEL,
        "max_tokens": config.LLM_MAX_TOKENS,
        "temperature": config.LLM_TEMPERATURE,
        "system": PROMPT_FILE.read_text(),
        "messages": [{"role": "user", "content": user}],
    }
    send = transport or (lambda p: _post_messages(p, key))
    for attempt in range(2):
        try:
            data = send(payload)
            return parse_llm_answer(data["content"][0]["text"])
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 529) and attempt == 0:
                time.sleep(1.5)
                continue
            log.warning("LLM request failed with HTTP %s", e.code)
            return None
        except (urllib.error.URLError, TimeoutError, KeyError, IndexError, ValueError) as e:
            log.warning("LLM request failed: %s", e)
            return None
    return None


# ---- the vote ----------------------------------------------------------------------------------
@dataclass
class Review:
    table: str
    column: str
    rules: str | None
    ml: str | None
    ml_prob: float
    llm: str | None
    verdict: str  # agree | rules only | suggest | conflict | clear
    suggestion: str | None
    note: str

    @property
    def needs_review(self) -> bool:
        return self.verdict in ("suggest", "conflict")


def review_column(
    table, column, dtype, sample, rule_tag: ColumnTag | None, model: ColumnModel, use_llm=False, transport=None
) -> Review:
    rules = rule_tag.entity if rule_tag else None
    shapes = top_shapes(sample)
    if rules == "FREETEXT":
        return Review(table, column, rules, None, 0.0, None, "rules only", None, "free-text column handled by the scrubber")
    ml = model.predict(column, shapes)
    if column.lower().startswith(BUSINESS_PREFIXES) and ml.entity in ("EMAIL", "PHONE"):
        ml = MlSignal(None, ml.prob)  # a branch's own contact details are business data
    llm = None
    if use_llm and ml.entity != rules and (llm_enabled() or transport):
        llm = llm_suggest(table, column, dtype, shapes, transport)
    llm_entity = llm.entity if llm else None
    if rules and ml.entity == rules:
        verdict, sug, note = "agree", None, "rules and local model agree"
    elif rules and ml.entity and ml.entity != rules:
        verdict, sug, note = "conflict", ml.entity, f"rules say {rules}, local model says {ml.entity}"
    elif rules:
        verdict, sug, note = "rules only", None, "local model has no strong opinion"
    elif ml.entity:
        verdict, sug = "suggest", ml.entity
        note = "rules found nothing; local model suggests " + ml.entity
    elif llm_entity:
        verdict, sug, note = "suggest", llm_entity, "only the LLM suggests this"
    else:
        verdict, sug, note = "clear", None, "no signal marks this column sensitive"
    if llm and verdict in ("suggest", "conflict"):
        note += "; LLM agrees" if llm_entity == sug else f"; LLM says {llm_entity or 'NONE'} ({llm.reason})"
    return Review(table, column, rules, ml.entity, round(ml.prob, 2), llm_entity, verdict, sug, note)


def review_all(
    adapter, rule_tags: dict, model: ColumnModel | None = None, use_llm=False, sample_size=200, transport=None
) -> list[Review]:
    model = model or get_model()
    out = []
    for table, cols in adapter.schema().items():
        for column, dtype in cols.items():
            tag = rule_tags.get((table.lower(), column.lower()))
            sample = adapter.sample(table, column, sample_size)
            out.append(review_column(table, column, dtype, sample, tag, model, use_llm, transport))
    return out


def approve(store, db_key: str, review: Review):
    """The only place an AI suggestion changes anything, and only after a person asks for it."""
    if review.suggestion not in TAGS:
        raise ValueError("nothing to approve")
    store.set_override(db_key, review.table, review.column, review.suggestion)


# ---- optional automatic mode -------------------------------------------------------------------
AUTO_MIN_PROB = config.AI_AUTO_MIN_PROB


def decision(review: Review) -> tuple[str, str]:
    """What the combined signals say about one column: ('MASK', entity) or ('DO NOT MASK', '')."""
    entity = review.rules or review.suggestion or review.ml
    return ("MASK", entity) if entity else ("DO NOT MASK", "")


def auto_apply(store, db_key: str, reviews: list[Review], min_prob: float = AUTO_MIN_PROB) -> list[Review]:
    """Let the AI add masks on its own, but only in the safe direction.

    Applied: columns the rules left unmasked where the local model is at least `min_prob` sure (or the LLM
    independently names the same entity). Never applied: conflicts with the rules, and anything that would
    remove a mask. Each change is a normal override and gets an audit row.
    """
    applied = []
    for r in reviews:
        if r.verdict != "suggest" or r.suggestion not in TAGS:
            continue
        confident = (r.ml == r.suggestion and r.ml_prob >= min_prob) or (r.llm == r.suggestion and r.ml in (None, r.suggestion))
        if not confident:
            continue
        store.set_override(db_key, r.table, r.column, r.suggestion)
        store.audit(db_key, "ai-assist", "system", "auto-tag", "", "", f"{r.table}.{r.column}", 0, r.note)
        applied.append(r)
    return applied

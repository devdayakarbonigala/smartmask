"""SmartMask demo. Run: streamlit run app.py"""

import hashlib
import json

import pandas as pd
import streamlit as st

from smartmask import benchmark, config
from smartmask.adapters import PostgresAdapter, SqliteAdapter
from smartmask.engine import MaskingEngine, PolicyViolation
from smartmask.policy import Policy
from smartmask.samples import samples_for
from smartmask.scanner import TAGS
from smartmask.store import MetaStore

st.set_page_config(page_title="SmartMask", layout="wide")


@st.cache_resource
def get_engine(backend: str):
    store = MetaStore(config.META_PATH)
    ad = SqliteAdapter(config.SQLITE_PATH) if backend == "SQLite" else PostgresAdapter(config.PG_DSN)
    eng = MaskingEngine(ad, store, Policy(), config.SALT)
    if not store.load_tags(eng.db_key):
        eng.run_scan()
    return eng


def show(result):
    df = pd.DataFrame(result.rows, columns=result.columns)
    masks = {m["column"]: m["mask"] for m in result.masked}
    for c in df.columns:
        if masks.get(c.lower()) in ("redact", "partial") and df[c].isna().any():
            df[c] = df[c].astype(object).where(df[c].notna(), "[REDACTED]")
    st.dataframe(df, use_container_width=True, hide_index=True)


with st.sidebar:
    st.header("Session")
    backend = st.radio("Database backend", ["SQLite", "PostgreSQL"], key="backend")
    role = st.radio("Querying role", ["admin", "support", "analyst"], index=1, key="role")
    user = st.text_input("User name (for the audit log)", "demo.user")
    st.caption(
        {
            "admin": "Sees raw values.",
            "support": "Sees partially masked values.",
            "analyst": "Sees hashed identifiers and redacted amounts.",
        }[role]
    )
    st.caption("All data is synthetic.")

try:
    eng = get_engine(backend)
except Exception as e:
    st.error(f"Could not connect to {backend}: {e}")
    st.stop()

SAMPLES = samples_for(eng.schema())

st.title("SmartMask")
st.write(
    "Role-based dynamic data masking. Raw tables are never changed: the mask is applied inside the "
    "database as part of each query, according to the role that asked."
)

tab_q, tab_cmp, tab_scan, tab_pol, tab_audit, tab_proof, tab_about = st.tabs(
    ["Query", "Same query, three roles", "Scanner", "Policy", "Audit log", "Proof", "About"]
)

with tab_q:
    pick = st.selectbox("Sample query", list(SAMPLES), key="sample")
    sql = st.text_area("SQL", SAMPLES[pick], height=110, key=f"sql_{pick}")
    if st.button("Run as " + role, type="primary", key="run"):
        with st.spinner("Running"):
            try:
                res = eng.execute(role, sql, user)
                st.caption(f"{len(res.rows)} rows in {res.elapsed_ms:.0f} ms on {backend}")
                show(res)
                if res.masked:
                    st.write("Masked columns: " + ", ".join(f"{m['table']}.{m['column']} ({m['mask']})" for m in res.masked))
                else:
                    st.write("No protected columns were returned masked for this role.")
                with st.expander("SQL that actually ran in the database"):
                    st.code(res.rewritten_sql, language="sql")
            except PolicyViolation as e:
                st.error(f"Denied: {e}")

with tab_cmp:
    pick2 = st.selectbox("Sample query", list(SAMPLES)[:6], key="sample2")
    sql2 = st.text_area("SQL", SAMPLES[pick2], height=90, key=f"cmp_{pick2}")
    if st.button("Run as admin, support and analyst", type="primary", key="runall"):
        for r in ("admin", "support", "analyst"):
            st.subheader(r)
            try:
                show(eng.execute(r, sql2, user))
            except PolicyViolation as e:
                st.error(f"Denied: {e}")

with tab_scan:
    st.write(
        "The scanner reads column names and a row sample (regex plus Luhn and Verhoeff checksums) and tags sensitive fields, including identifiers hidden inside free text."
    )
    if st.button("Re-scan schema", key="rescan"):
        with st.spinner("Scanning"):
            eng.run_scan()
    tags = eng.store.load_tags(eng.db_key)
    st.dataframe(
        pd.DataFrame([t.as_dict() for t in tags.values()]).sort_values(["table", "column"]) if tags else pd.DataFrame(),
        use_container_width=True,
        hide_index=True,
    )
    st.subheader("Manual override")
    schema = eng.schema()
    c1, c2, c3 = st.columns(3)
    t_sel = c1.selectbox("Table", list(schema), key="ot")
    c_sel = c2.selectbox("Column", list(schema[t_sel]), key="oc")
    e_sel = c3.selectbox("Entity", ["NONE"] + list(TAGS), key="oe")
    if st.button("Save override", key="osave"):
        eng.store.set_override(eng.db_key, t_sel, c_sel, e_sel)
        st.success("Saved. It applies to the next query.")
    st.subheader("Scanner accuracy on a labelled test schema")
    if st.button("Run benchmark", key="bench"):
        r = benchmark.run()
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Precision", f"{r['precision']:.0%}")
        m2.metric("Recall", f"{r['recall']:.0%}")
        m3.metric("Entity accuracy on hits", f"{r['entity_accuracy']:.0%}")
        m4.metric("Columns", r["columns"])
        st.write(f"By group (correct / total): {r['by_group']}")
        st.write(f"Missed ({len(r['misses'])}): " + ", ".join(f"{c} ({e})" for c, e, _ in r["misses"]))
        st.write(f"False positives ({len(r['false_positives'])}): " + (", ".join(c for c, _ in r["false_positives"]) or "none"))
        st.caption(
            "Self-built benchmark of synthetic columns. Misses are columns with a cryptic name and no distinctive value pattern; a manual override fixes them."
        )

with tab_pol:
    pol = Policy()
    st.dataframe(pd.DataFrame(pol.matrix(list(TAGS))).T, use_container_width=True)
    st.caption("A column tagged with an entity that a role has no rule for is redacted by default.")
    st.code(json.dumps(pol.roles, indent=2), language="json")

with tab_audit:
    rows = eng.store.audit_rows(200)
    st.dataframe(
        pd.DataFrame(rows, columns=["time", "user", "role", "status", "sql", "masked columns", "rows", "detail"]),
        use_container_width=True,
        hide_index=True,
    )

with tab_proof:
    st.write(
        "Fingerprint of the raw cards table before and after running every role, plus a direct write attempt against the database."
    )
    if st.button("Run proof", key="proof"):

        def fp():
            _, rows, _ = eng.adapter.execute("SELECT * FROM cards ORDER BY 1", 100000)
            return hashlib.sha256(repr(rows).encode()).hexdigest()[:20]

        before = fp()
        for r in ("admin", "support", "analyst"):
            eng.execute(r, "SELECT * FROM cards", "proof")
        after = fp()
        st.write(f"Before: `{before}`")
        st.write(f"After: `{after}`")
        st.write("Unchanged." if before == after else "CHANGED")
        try:
            eng.adapter.raw_execute_for_test("DELETE FROM cards WHERE 1 = 0")
            st.error("Write succeeded (unexpected)")
        except Exception as e:
            st.write(f"Direct write attempt blocked by the database: {str(e).splitlines()[0]}")

with tab_about:
    st.subheader("Terms and privacy")
    st.write(
        "This is a hackathon prototype. Every record shown is synthetic and generated by a script; no real customer data is used. "
        "The audit log and scanner tags are stored locally in a separate metadata file, not in the protected database. "
        "The software is provided as is, without warranty, and is not certified for GDPR or HIPAA compliance."
    )
    st.subheader("AI assistance")
    st.write("Built with assistance from an AI coding tool. See the README for the disclosure.")

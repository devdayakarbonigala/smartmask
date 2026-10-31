"""SmartMask demo. Run: streamlit run app.py"""

import hashlib

import pandas as pd
import streamlit as st

from smartmask import ai_assist, auth, benchmark, compliance, config, ui
from smartmask.adapters import PostgresAdapter, SqliteAdapter
from smartmask.engine import MaskingEngine, PolicyViolation
from smartmask.policy import Policy
from smartmask.samples import samples_for
from smartmask.scanner import TAGS
from smartmask.store import MetaStore

st.set_page_config(page_title="SmartMask", layout="wide")
st.markdown(ui.CSS, unsafe_allow_html=True)


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
    st.dataframe(ui.style_masked(df, masks), use_container_width=True, hide_index=True)


def login_screen():
    left, right = st.columns([3, 2], gap="large")
    with left:
        st.markdown(ui.title_html(), unsafe_allow_html=True)
        st.markdown("**One customer, one query, three people looking.**")
        st.markdown(ui.specimen_html(), unsafe_allow_html=True)
        st.caption("Specimen with invented data. The mask is applied by the database, not by this page.")
    with right:
        st.subheader("Sign in")
        if st.session_state.get("failed", 0) >= auth.MAX_ATTEMPTS:
            st.error("Too many failed attempts. Reload the page to try again.")
            return
        with st.form("login"):
            name = st.text_input("User name")
            password = st.text_input("Password", type="password")
            go = st.form_submit_button("Sign in", type="primary")
        if go:
            role_found = auth.authenticate(USERS, name, password)
            if role_found:
                st.session_state.update(account=name.strip().lower(), account_role=role_found, failed=0)
                st.rerun()
            st.session_state["failed"] = st.session_state.get("failed", 0) + 1
            st.error("Wrong user name or password.")
        st.caption("Demo accounts and passwords are listed in the README. Each account is bound to one role.")


USERS = auth.load_users()
if "account" not in st.session_state:
    login_screen()
    st.stop()
account, account_role = st.session_state["account"], st.session_state["account_role"]
is_admin = account_role == "admin"


with st.sidebar:
    st.markdown(
        f'<div class="sm-who"><small>Signed in as</small><b>{account}</b><small>role: {account_role}</small></div>',
        unsafe_allow_html=True,
    )
    backend = st.radio("Database backend", ["SQLite", "PostgreSQL"], key="backend")
    # Only an admin may look through another role's eyes; every other account is fixed to its own role.
    role = st.radio("Preview as role", ["admin", "support", "analyst"], key="role") if is_admin else account_role
    user = account
    if st.button("Sign out", key="signout"):
        for k in ("account", "account_role", "failed"):
            st.session_state.pop(k, None)
        st.rerun()

try:
    eng = get_engine(backend)
except Exception as e:
    st.error(f"Could not connect to {backend}: {e}")
    st.stop()

SAMPLES = samples_for(eng.schema())

st.markdown(ui.title_html(), unsafe_allow_html=True)
st.markdown("Cell colour shows what the database did to a column: " + ui.legend(), unsafe_allow_html=True)

ADMIN_TABS = ["Query", "Same query, three roles", "Scanner", "AI Assist", "Policy", "Audit log", "Proof", "About"]
tab_names = ADMIN_TABS if is_admin else ["Query", "Policy", "About"]
_tabs = dict(zip(tab_names, st.tabs(tab_names)))
tab_q, tab_pol, tab_about = _tabs["Query"], _tabs["Policy"], _tabs["About"]
if is_admin:
    tab_cmp, tab_scan, tab_ai, tab_audit, tab_proof = (
        _tabs[n] for n in ("Same query, three roles", "Scanner", "AI Assist", "Audit log", "Proof")
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

if is_admin:
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

if is_admin:
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
            st.write(
                f"False positives ({len(r['false_positives'])}): " + (", ".join(c for c, _ in r["false_positives"]) or "none")
            )
            st.caption(
                "Self-built benchmark of synthetic columns. Misses are columns with a cryptic name and no distinctive value pattern; a manual override fixes them."
            )

if is_admin:
    with tab_ai:
        st.write(
            "A second opinion on the scanner. A small local model reads only column names and value shapes "
            "(digits become 9, letters become A or a) and votes next to the rules. It never changes a mask by itself: "
            "a suggestion becomes an override only when you approve it, and masking stays plain SQL."
        )
        use_llm = False
        if ai_assist.llm_enabled():
            use_llm = st.checkbox(
                "Also ask the language model about disagreements (sends names and shapes, never values)", key="ai_llm"
            )
        if st.button("Run AI review", key="ai_run"):
            with st.spinner("Reviewing columns"):
                st.session_state["ai_reviews"] = ai_assist.review_all(
                    eng.adapter, eng.store.load_tags(eng.db_key), use_llm=use_llm
                )
        reviews = st.session_state.get("ai_reviews")
        if reviews:
            st.subheader("What the AI decides for every column")
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "table": r.table,
                            "column": r.column,
                            "decision": ai_assist.decision(r)[0],
                            "entity": ai_assist.decision(r)[1],
                            "rules": r.rules or "-",
                            "local model": f"{r.ml or '-'} ({r.ml_prob:.0%})",
                            "GDPR": compliance.regulation(ai_assist.decision(r)[1])[0],
                            "HIPAA identifier": compliance.regulation(ai_assist.decision(r)[1])[1],
                            "verdict": r.verdict,
                        }
                        for r in reviews
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )
            st.subheader("Automatic mode")
            floor = st.slider(
                "Minimum confidence to add a mask on its own", 0.5, 0.99, ai_assist.AUTO_MIN_PROB, 0.01, key="ai_floor"
            )
            st.caption(
                "Only adds masks. It never removes one and never overrides a rule. Every change is a normal override and is written to the audit log."
            )
            if st.button("Apply confident additions", key="ai_auto"):
                done = ai_assist.auto_apply(eng.store, eng.db_key, reviews, floor)
                st.success(
                    f"Added {len(done)} mask(s): "
                    + (", ".join(f"{r.table}.{r.column} as {r.suggestion}" for r in done) or "none above the confidence floor")
                )
            with st.expander("How each entity maps to GDPR and HIPAA"):
                st.dataframe(
                    pd.DataFrame([{"entity": k, "GDPR": v[0], "HIPAA identifier": v[1]} for k, v in compliance.MAPPING.items()]),
                    use_container_width=True,
                    hide_index=True,
                )
                st.caption(
                    "Alignment table for reviewers, not legal advice or certification. Not implemented because the Saffron data has none: "
                    + compliance.NOT_IMPLEMENTED
                    + "."
                )
            st.subheader("Needs a human decision")
            counts = pd.Series([r.verdict for r in reviews]).value_counts()
            st.write("Verdicts: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
            queue = [r for r in reviews if r.needs_review]
            if not queue:
                st.success("Nothing needs a human decision: no disagreement between the rules and the local model.")
            for i, r in enumerate(queue):
                c1, c2 = st.columns([4, 1])
                c1.write(
                    f"**{r.table}.{r.column}** : rules {r.rules or '-'}, model {r.ml or '-'} ({r.ml_prob:.0%})"
                    + (f", language model {r.llm}" if r.llm else "")
                    + f" : {r.verdict}. {r.note}"
                )
                if r.suggestion and c2.button(f"Tag as {r.suggestion}", key=f"ai_ok_{i}"):
                    ai_assist.approve(eng.store, eng.db_key, r)
                    st.success("Saved as a manual override. It applies to the next query.")

with tab_pol:
    pol = Policy()
    st.markdown("**What each role receives, counted over the columns tagged in this database**")
    st.markdown(ui.legend(), unsafe_allow_html=True)
    st.markdown(ui.ledger_html(ui.exposure(eng.store.load_tags(eng.db_key), pol)), unsafe_allow_html=True)
    st.markdown("**Rule per entity**")
    st.dataframe(pd.DataFrame(pol.matrix(list(TAGS))).T, use_container_width=True)
    st.caption("A column tagged with an entity that a role has no rule for is redacted by default.")

if is_admin:
    with tab_audit:
        rows = eng.store.audit_rows(200)
        st.dataframe(
            pd.DataFrame(rows, columns=["time", "user", "role", "status", "sql", "masked columns", "rows", "detail"]),
            use_container_width=True,
            hide_index=True,
        )

if is_admin:
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

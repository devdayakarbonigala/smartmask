"""Fills the official InnoSmart Round 1 template for Problem 11. Run from the project root."""
import copy, sys, os
sys.path.insert(0, ".")
from pptx import Presentation
from pptx.util import Emu, Pt, Inches
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE, MSO_CONNECTOR
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.oxml.ns import qn
from lxml import etree

from smartmask import config, benchmark
from smartmask.adapters import SqliteAdapter
from smartmask.engine import MaskingEngine
from smartmask.policy import Policy
from smartmask.store import MetaStore

TEMPLATE = "/root/.claude/uploads/bb53c9cb-00c5-5610-8752-d2568883c110/6a3f9d31-Round1_Template_submission_6.pptx"
OUT = sys.argv[1] if len(sys.argv) > 1 else "SmartMask_Round1_Problem11.pptx"
NAVY, SKY, INK, GREY = RGBColor(0x1F, 0x47, 0x88), RGBColor(0x00, 0xA4, 0xEF), RGBColor(0x2D, 0x2D, 0x2D), RGBColor(0xF5, 0xF5, 0xF5)

prs = Presentation(TEMPLATE)
S = list(prs.slides)


def shp(slide, name):
    return next(s for s in slide.shapes if s.name == name)


def _fill_para(p, text, size=None, bold_label=None):
    runs = p.findall(qn("a:r"))
    for r in runs[1:]:
        p.remove(r)
    r0 = runs[0]
    if bold_label:
        r_label = copy.deepcopy(r0)
        r_label.find(qn("a:t")).text = bold_label
        r_label.find(qn("a:rPr")).set("b", "1")
        r0.addprevious(r_label)
    r0.find(qn("a:t")).text = text
    for el in p.iter(qn("a:rPr"), qn("a:endParaRPr")):
        if size:
            el.set("sz", str(int(size * 100)))


def set_paras(shape, items, size=None):
    txBody = shape.text_frame._txBody
    paras = txBody.findall(qn("a:p"))
    proto = copy.deepcopy(paras[0])
    for p in paras:
        txBody.remove(p)
    for it in items:
        p = copy.deepcopy(proto)
        label, text = it if isinstance(it, tuple) else (None, it)
        _fill_para(p, text, size, label)
        txBody.append(p)


def set_text(shape, text, size=None):
    set_paras(shape, [text], size)


# ------------------------------------------------------------------ slide 1: cover
s = S[0]
set_text(shp(s, "Text 3"), "Team METIS")
set_text(shp(s, "Text 5"), "Dev Dayakar Bonigala")
set_text(shp(s, "Text 7"), "BFSI (Problem 11)", 18)
set_text(shp(s, "Text 9"), "15 Oct 2026")

# ------------------------------------------------------------------ slide 2: use case
s = S[1]
set_paras(shp(s, "Text 3"), [
    ("Problem: ", "Banks and insurers store card numbers, SSNs, Aadhaar and PAN numbers and balances in databases that many internal users can query in raw form. That creates exposure under GDPR, HIPAA and India's DPDP Act, 2023."),
    ("Affected: ", "customers whose data can be seen, support and analyst staff who see more than their job needs, and security and compliance teams who must prove access control."),
    ("Impact: ", "insider exposure, audit findings and regulatory risk. Masked copies made by batch jobs add storage and go stale."),
], 11)
set_paras(shp(s, "Text 5"), [
    ("Market size: ", "the data masking market is estimated at USD 1.42 billion in 2026, growing to USD 4.48 billion by 2035 (13.28% CAGR). Source: Market Research Future, single analyst estimate."),
    ("Target audience: ", "banks, NBFCs, insurers, fintechs and health-tech teams that run PostgreSQL or similar databases and have small security teams."),
    ("Competition: ", "Immuta, Privacera and Delphix are enterprise platforms. Oracle Data Redaction, SQL Server Dynamic Data Masking and PostgreSQL Anonymizer each cover one database. SmartMask is one lightweight policy across several backends."),
], 11)

# ------------------------------------------------------------------ slide 3: solution
s = S[2]
set_paras(shp(s, "Text 3"), [
    ("What: ", "SmartMask, a lightweight engine that scans a database, tags PII columns automatically and masks them at query time by the role that is asking. Stored tables are never changed."),
    ("How it solves the problem: ", "admin sees raw values, support sees partial masks such as 4111-XXXX-XXXX-1111, analyst sees salted hashes and redacted amounts. One policy file, PostgreSQL and SQLite supported."),
    ("Key features: ", "PII scanner (column names, regex, Luhn and Verhoeff checks) with PII_HIGH, PII_MEDIUM and FINANCIAL_CONFIDENTIAL tags; query rewriting inside the database; blocked probing queries; audit log; Streamlit, CLI and API."),
    ("Why it is different: ", "masking happens inside the database engine on read-only connections, and any tagged data without an explicit rule is redacted by default."),
], 11)

# real masked output from the prototype, for the mockup table
store = MetaStore("/tmp/deck_meta.db")
eng = MaskingEngine(SqliteAdapter(config.SQLITE_PATH), store, Policy(), config.SALT)
eng.run_scan()
q = ("SELECT c.ssn, k.card_number, a.balance FROM customers c JOIN cards k ON k.customer_id = c.customer_id "
     "JOIN accounts a ON a.customer_id = c.customer_id ORDER BY c.customer_id, k.card_id, a.account_id LIMIT 1")
rows = {}
for role in ("admin", "support", "analyst"):
    r = eng.execute(role, q)
    rows[role] = ["[REDACTED]" if v is None else (f"{v:,.2f}" if isinstance(v, float) else str(v)) for v in r.rows[0]]

ph = shp(s, "Text 4")
left, top, width, height = ph.left, ph.top, ph.width, ph.height
ph._element.getparent().remove(ph._element)
tbl_shape = s.shapes.add_table(4, 4, left, top, width, height)
tbl = tbl_shape.table
tblPr = tbl._tbl.tblPr
tblPr.set("firstRow", "0"); tblPr.set("bandRow", "0")
for st in tblPr.findall(qn("a:tableStyleId")):
    tblPr.remove(st)
hdr = ["Same query, three roles", "ssn", "card_number", "balance"]
data = [hdr] + [[role] + rows[role] for role in ("admin", "support", "analyst")]
widths = [1.9, 1.7, 2.6, 2.8]
for i, w in enumerate(widths):
    tbl.columns[i].width = Inches(w * 9.0 / sum(widths))
for ri, row in enumerate(data):
    tbl.rows[ri].height = Emu(int(height / 4))
    for ci, val in enumerate(row):
        c = tbl.cell(ri, ci)
        c.fill.solid(); c.fill.fore_color.rgb = NAVY if ri == 0 else GREY
        c.margin_top = c.margin_bottom = Emu(18000)
        c.vertical_anchor = MSO_ANCHOR.MIDDLE
        tf = c.text_frame; tf.text = val
        run = tf.paragraphs[0].runs[0]
        run.font.size = Pt(10); run.font.name = "Calibri"
        run.font.bold = (ri == 0 or ci == 0)
        run.font.color.rgb = RGBColor(255, 255, 255) if ri == 0 else INK

# ------------------------------------------------------------------ slide 4: design steps + architecture
s = S[3]
set_paras(shp(s, "Text 3"), [
    "1. Connect: read-only adapters for PostgreSQL and SQLite read the schema and a row sample.",
    "2. Scan and tag: column-name rules plus regex and Luhn or Verhoeff checks on the sample. Tags go to a separate metadata store.",
    "3. Define policy: a JSON file maps role and data type to none, partial, hash or redact. Anything unmapped is redacted.",
    "4. Rewrite and serve: sqlglot rewrites each SELECT so the database returns masked values. Every request is written to the audit log.",
], 11)

ph = shp(s, "Text 5")
X0, Y0, W, H = ph.left, ph.top, ph.width, ph.height
ph.text_frame.text = ""


def box(x, y, w, h, text, fill, fg, size=9, bold=False, line=None):
    b = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, Emu(int(x)), Emu(int(y)), Emu(int(w)), Emu(int(h)))
    b.shadow.inherit = False
    b.fill.solid(); b.fill.fore_color.rgb = fill
    if line: b.line.color.rgb = line; b.line.width = Pt(1)
    else: b.line.fill.background()
    tf = b.text_frame; tf.word_wrap = True
    tf.margin_left = tf.margin_right = Emu(36000); tf.margin_top = tf.margin_bottom = Emu(18000)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = PP_ALIGN.CENTER
        r = p.add_run(); r.text = ln
        r.font.size = Pt(size); r.font.name = "Calibri"; r.font.color.rgb = fg
        r.font.bold = bold if i == 0 else False
    return b


def arrow(x1, y1, x2, y2):
    c = s.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Emu(int(x1)), Emu(int(y1)), Emu(int(x2)), Emu(int(y2)))
    c.line.color.rgb = SKY; c.line.width = Pt(1.5)
    ln = c.line._get_or_add_ln()
    ln.append(etree.SubElement(ln, qn("a:tailEnd"), type="triangle"))


pad = 45720
bw = W - 2 * pad
h1 = H * 0.17; h2 = H * 0.44; h3 = H * 0.17
gap = (H - h1 - h2 - h3) / 2
y1 = Y0; y2 = y1 + h1 + gap; y3 = y2 + h2 + gap
box(X0 + pad, y1, bw, h1, "Clients: Streamlit demo, CLI, FastAPI", NAVY, RGBColor(255, 255, 255), 9, True)
# engine container
eng_w = bw * 0.64
box(X0 + pad, y2, eng_w, h2, "", GREY, INK, 8, line=NAVY)
box(X0 + pad, y2, eng_w, h2 * 0.2, "SmartMask engine", NAVY, RGBColor(255, 255, 255), 9, True)
box(X0 + pad + 36000, y2 + h2 * 0.25, eng_w - 72000, h2 * 0.33, "Query rewriter (sqlglot)\nSELECT only, deny probing, mask in SQL", RGBColor(255, 255, 255), INK, 8, True, NAVY)
box(X0 + pad + 36000, y2 + h2 * 0.63, eng_w - 72000, h2 * 0.33, "Policy\nrole x data type = none, partial, hash, redact", RGBColor(255, 255, 255), INK, 8, True, NAVY)
# right column
rx = X0 + pad + eng_w + 70000
rw = bw - eng_w - 70000
box(rx, y2, rw, h2 * 0.46, "PII scanner\nnames, regex, Luhn, Verhoeff", GREY, INK, 8, True, NAVY)
box(rx, y2 + h2 * 0.54, rw, h2 * 0.46, "Metadata store\ntags, overrides, audit log", GREY, INK, 8, True, NAVY)
# databases
dw = (bw - 70000) / 2
box(X0 + pad, y3, dw, h3, "PostgreSQL (read-only)", NAVY, RGBColor(255, 255, 255), 9, True)
box(X0 + pad + dw + 70000, y3, dw, h3, "SQLite (read-only)", NAVY, RGBColor(255, 255, 255), 9, True)
arrow(X0 + pad + eng_w / 2, y1 + h1, X0 + pad + eng_w / 2, y2)
arrow(X0 + pad + eng_w / 2, y2 + h2, X0 + pad + eng_w / 2, y3)
arrow(rx + rw / 2, y2 + h2 * 0.46, rx + rw / 2, y2 + h2 * 0.54)

# ------------------------------------------------------------------ slide 5: challenges
bm = benchmark.run()
s = S[4]
chal = [
    ("Challenge 1: Scanner false positives and misses",
     "A 16-digit order reference looks like a card number, and a column with a cryptic name can hide PII.",
     f"Tag only when sampled values pass a checksum (Luhn, Verhoeff) above a match ratio. On a labelled 63-column test it reached {bm['precision']:.0%} precision and {bm['recall']:.0%} recall; the misses are cryptic-name columns that a manual override fixes."),
    ("Challenge 2: Same masking on different SQL dialects",
     "SQLite has no built-in SHA-256 and its string functions differ from PostgreSQL.",
     "Masks are written per dialect and generated with sqlglot, and SHA-256 is registered as a SQLite function. A parity test checks that both backends return identical masked output."),
    ("Challenge 3: Leaking values through filters, joins and sorting",
     "WHERE card_number LIKE '4111%' lets a masked user guess raw values.",
     "Masked roles may not filter, join, group or sort on protected columns. Only SELECT is allowed, unknown functions are blocked and connections are read-only. 60 automated tests cover these attacks."),
]
for (title_name, prob_name, mit_name), (title, prob, mit) in zip(
        [("Text 2", "Text 3", None), ("Text 5", "Text 6", None), ("Text 8", "Text 9", None)], chal):
    set_text(shp(s, title_name), title)
    set_paras(shp(s, prob_name), [("Problem: ", prob), ("Mitigation: ", mit)], 10)

# ------------------------------------------------------------------ slide 6: USP
s = S[5]
usp = [
    ("Text 3", "Text 4", "Masks inside the database",
     "The query is rewritten so PostgreSQL or SQLite returns the masked value. There are no masked copies, and a table fingerprint shown in the demo is identical before and after."),
    ("Text 6", "Text 7", "One policy, two backends",
     "The same JSON policy gives the same masked output on PostgreSQL and SQLite. Adding a backend means adding an adapter."),
    ("Text 9", "Text 10", "Measured and auditable",
     "Scanner accuracy is reported with its misses. Every query is logged with user, role, SQL and masked columns, and probing attempts are denied and logged."),
]
for t, b, title, body in usp:
    set_text(shp(s, t), title, 13)
    set_text(shp(s, b), body, 11)
set_paras(shp(s, "Text 12"), [
    ("Why choose it: ", "lightweight Python service, no agents and no data copies, role views in one config file, and a working demo on two databases."),
    ("Edge over alternatives: ", "vendor features lock you to one database, enterprise platforms are heavy to deploy, and static masked copies go stale and double storage."),
], 11)

# ------------------------------------------------------------------ slide 7: demo
s = S[6]
box_shape = shp(s, "Shape 3")
play = shp(s, "Text 4")
play._element.getparent().remove(play._element)
pic_h = int(box_shape.height * 0.93)
pic_w = int(pic_h * 1280 / 630)
pic = s.shapes.add_picture("demo/slide7_poster.png", box_shape.left + (box_shape.width - pic_w) // 2, box_shape.top + 30000, width=pic_w, height=pic_h)
cap = shp(s, "Text 5")
cap.top = box_shape.top + box_shape.height + 30000
cap.left, cap.width = box_shape.left, box_shape.width
cap.height = Emu(420000)
set_paras(cap, [
    "Demo video (about 85 seconds): [PASTE VIDEO LINK HERE]",
    "Shows: scanner tags, three roles on two databases, denied probe and write attempts, table fingerprint, audit log.",
], 10)
for p in cap.text_frame.paragraphs:
    p.alignment = PP_ALIGN.CENTER

prs.save(OUT)
print("saved", OUT, bm["precision"], bm["recall"])

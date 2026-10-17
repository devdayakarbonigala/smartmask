"""Records the demo video with Playwright. Usage: python scripts/record_demo.py [out_dir]"""
import sys, os, time, glob, shutil
from playwright.sync_api import sync_playwright

OUT = sys.argv[1] if len(sys.argv) > 1 else "demo"
os.makedirs(OUT, exist_ok=True)
URL = "http://localhost:8501"

CAPTION_JS = """(t)=>{let d=document.getElementById('cap');if(!d){d=document.createElement('div');d.id='cap';
d.style.cssText='position:fixed;left:0;right:0;bottom:0;z-index:2147483647;background:#1F2420;color:#EFEAE0;font:600 20px Georgia,serif;padding:14px 24px;letter-spacing:.2px';
document.body.appendChild(d);} d.textContent=t;}"""


def cap(page, text, wait=2.5):
    page.evaluate(CAPTION_JS, text)
    time.sleep(wait)


def click_tab(page, name):
    page.get_by_role("tab", name=name, exact=True).click()
    time.sleep(1.2)


def pick_sample(page, label_text, option):
    page.locator("input[aria-label='Sample query']:visible").first.click()
    time.sleep(.4)
    page.get_by_role("option", name=option).click()
    time.sleep(1.0)


def main():
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1280, "height": 800}, record_video_dir=os.path.join(OUT, "raw"),
                            record_video_size={"width": 1280, "height": 800})
        page = ctx.new_page()
        page.goto(URL)
        page.get_by_text("SmartMask").first.wait_for(timeout=30000)
        time.sleep(1.5)
        cap(page, "SmartMask: one query, three roles. The raw tables are never changed.", 3.5)

        click_tab(page, "Scanner")
        cap(page, "Step 1. The scanner reads column names and a row sample, then tags sensitive fields.", 4)
        page.mouse.wheel(0, 250); time.sleep(1.2)
        cap(page, "Credit cards pass a Luhn check, Aadhaar passes Verhoeff, order references do not get tagged.", 4)
        page.mouse.wheel(0, -400)

        click_tab(page, "Policy")
        cap(page, "Step 2. One policy decides what each role sees for each kind of data.", 4)

        click_tab(page, "Same query, three roles")
        pick_sample(page, "Sample query", "Cards joined to customers")
        page.get_by_role("button", name="Run as admin, support and analyst").click()
        time.sleep(3)
        cap(page, "Step 3. The same query on SQLite: admin sees raw values.", 3.5)
        page.mouse.wheel(0, 380); time.sleep(1)
        cap(page, "Support sees partial masks, for example 4111-XXXX-XXXX-1111.", 3.5)
        page.mouse.wheel(0, 380); time.sleep(1)
        cap(page, "Analyst sees salted hashes, and amounts are redacted.", 3.5)
        page.mouse.wheel(0, -900)

        page.locator('[data-testid="stSidebar"]').get_by_text("PostgreSQL", exact=True).click()
        time.sleep(3)
        click_tab(page, "Same query, three roles")
        page.get_by_role("button", name="Run as admin, support and analyst").click()
        time.sleep(3)
        cap(page, "Step 4. Switch the backend to PostgreSQL: same policy, same masked output.", 4)

        click_tab(page, "Query")
        pick_sample(page, "Sample query", "Probe attempt (should be denied)")
        page.locator('[data-testid="stSidebar"]').get_by_text("analyst", exact=True).click(); time.sleep(1)
        page.get_by_role("button", name="Run as analyst").click()
        time.sleep(2.5)
        cap(page, "Step 5. Probing a protected column with WHERE is denied, so values cannot be guessed.", 4)

        pick_sample(page, "Sample query", "Write attempt (should be denied)")
        page.get_by_role("button", name="Run as analyst").click()
        time.sleep(2.5)
        cap(page, "Writes are rejected too. Only SELECT is allowed.", 3.5)

        click_tab(page, "Proof")
        page.get_by_role("button", name="Run proof").click()
        time.sleep(3)
        cap(page, "Step 6. The raw table fingerprint is identical before and after, and the database refuses writes.", 4.5)

        click_tab(page, "Audit log")
        cap(page, "Step 7. Every request is logged: who, which role, what ran, and what was masked.", 4.5)
        ctx.close(); b.close()
    vids = glob.glob(os.path.join(OUT, "raw", "*.webm"))
    shutil.move(vids[0], os.path.join(OUT, "smartmask_demo.webm"))
    shutil.rmtree(os.path.join(OUT, "raw"), ignore_errors=True)


if __name__ == "__main__":
    main()

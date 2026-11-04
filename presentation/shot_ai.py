"""Screenshot the Alerts page with maria.singh's cached AI case summary (for the deck)."""
import sys
from playwright.sync_api import sync_playwright
out = sys.argv[1]
with sync_playwright() as p:
    b = p.chromium.launch(channel="chrome", headless=True)
    pg = b.new_page(viewport={"width": 1300, "height": 2600}, device_scale_factor=2)
    pg.goto("http://localhost:8501/?ws=demo")
    pg.get_by_role("textbox", name="Username").fill("admin")
    pg.get_by_role("textbox", name="Password").fill("UebaTest-2026!")
    pg.get_by_role("button", name="Sign in").click()
    pg.get_by_text("Security overview").first.wait_for(timeout=60000)
    pg.get_by_text("Alerts", exact=True).first.click()
    pg.get_by_text("What happened").first.wait_for(timeout=60000)
    pg.wait_for_timeout(1500)
    box = pg.get_by_text("What happened").first.locator(
        'xpath=ancestor::div[@data-testid="stVerticalBlockBorderWrapper" or @data-testid="stVerticalBlock"][1]')
    box.scroll_into_view_if_needed()
    pg.wait_for_timeout(800)
    box.screenshot(path=out)
    print("ok", box.bounding_box())
    b.close()

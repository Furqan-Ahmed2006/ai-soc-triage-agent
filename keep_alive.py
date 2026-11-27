import os
import re
import sys
from playwright.sync_api import sync_playwright

APP_URL = os.getenv("STREAMLIT_APP_URL", "").strip()


def wake_up_app() -> None:
    if not APP_URL:
        print("Error: STREAMLIT_APP_URL environment variable is not set.")
        sys.exit(1)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/130.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()
        page.set_default_timeout(30_000)

        print(f"Opening {APP_URL} ...")
        page.goto(APP_URL, wait_until="domcontentloaded", timeout=90_000)
        page.wait_for_timeout(8_000)
        print(f"Landed on URL: {page.url} | Title: {page.title()}")

    
        wake_pattern = re.compile(r"get this app back up", re.I)
        clicked_wake = False

        page_wake = page.get_by_role("button", name=wake_pattern)
        if page_wake.count() > 0 and page_wake.first.is_visible():
            print("Wake-up button found on page. Clicking...")
            page_wake.first.click()
            clicked_wake = True
        else:
            for frame in page.frames:
                frame_wake = frame.get_by_role("button", name=wake_pattern)
                if frame_wake.count() > 0 and frame_wake.first.is_visible():
                    print("Wake-up button found inside iframe. Clicking...")
                    frame_wake.first.click()
                    clicked_wake = True
                    break

        if clicked_wake:
            page.wait_for_timeout(20_000)

        
        container_ready = False
        try:
            page.wait_for_selector('[data-testid="stAppViewContainer"]', timeout=30_000)
            container_ready = True
            print("Streamlit app container is visible.")
        except Exception:
            for frame in page.frames:
                try:
                    frame.wait_for_selector('[data-testid="stAppViewContainer"]', timeout=10_000)
                    container_ready = True
                    print("Streamlit app container is visible inside iframe.")
                    break
                except Exception:
                    continue

        if not container_ready:
            print("Note: App container not yet visible (likely cold-starting/waking). Ping recorded.")


        sidebar_btn = page.locator('[data-testid="stSidebarCollapsedControl"] button')
        if sidebar_btn.count() > 0 and sidebar_btn.first.is_visible():
            print("Opening collapsed sidebar...")
            sidebar_btn.first.click()
            page.wait_for_timeout(2_000)


        page.mouse.wheel(0, 250)
        page.wait_for_timeout(2_000)
        page.mouse.wheel(0, -250)
        page.wait_for_timeout(2_000)

        browser.close()
        print("Keep-alive run completed cleanly.")


if __name__ == "__main__":
    wake_up_app()
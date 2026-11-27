import os
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

        print(f"Opening {APP_URL} ...")
        page.goto(APP_URL, wait_until="domcontentloaded", timeout=60_000)
        page.wait_for_timeout(5_000)

        wake_button = page.locator("button:has-text('Yes, get this app back up!')")
        if wake_button.count() > 0:
            print("App is sleeping. Clicking wake-up button...")
            wake_button.first.click()
            page.wait_for_timeout(15_000)

        page.wait_for_selector('[data-testid="stAppViewContainer"]', timeout=45_000)
        print("Main Streamlit UI loaded.")

        expand_sidebar_btn = page.locator('[data-testid="stSidebarCollapsedControl"] button')
        if expand_sidebar_btn.count() > 0 and expand_sidebar_btn.first.is_visible():
            print("Sidebar is collapsed. Opening sidebar...")
            expand_sidebar_btn.first.click()
            page.wait_for_timeout(2_000)
        else:
            print("Sidebar is already open.")

        page.mouse.wheel(0, 300)
        page.wait_for_timeout(3_000)
        page.mouse.wheel(0, -300)
        page.wait_for_timeout(2_000)

        browser.close()
        print("Keep-alive session completed with zero LLM token usage.")


if __name__ == "__main__":
    wake_up_app()
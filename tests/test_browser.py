import os
import re
import socket
import threading
import time

import pytest
import uvicorn

from agentsec.main import app

from .conftest import ADVISORY, SAMPLE

pytestmark = pytest.mark.browser


@pytest.fixture
def site(upstreams):
    if os.getenv("AGENTSEC_BROWSER") != "1":
        pytest.skip("Set AGENTSEC_BROWSER=1 to run Chromium tests.")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.02)
            assert server.started
            yield url
        finally:
            server.should_exit = True
            thread.join(timeout=5)
            assert not thread.is_alive()


@pytest.mark.parametrize("width", [1280, 390])
def test_browser_upload_and_recommendation(site, upstreams, width):
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=os.getenv("AGENTSEC_CHROMIUM"))
        page = browser.new_page(viewport={"width": width, "height": 900})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(site)

        if width == 1280:
            page.get_by_role("button", name="Run sample scan").click()
        else:
            page.locator("#sbom").set_input_files(
                {"name": "invalid.json", "mimeType": "application/json", "buffer": b"{}"},
            )
            page.get_by_role("button", name="Scan SBOM", exact=True).click()
            expect(page.locator("#scan-status")).to_contain_text("Expected a valid CycloneDX")
            page.locator("#sbom").set_input_files(SAMPLE)
            page.get_by_role("button", name="Scan SBOM", exact=True).click()

        expect(page.locator("#scan-status")).to_have_text("Scan complete.")
        expect(page.get_by_role("button", name=re.compile(ADVISORY))).to_have_attribute(
            "aria-pressed", "true"
        )
        page.get_by_role("button", name="Generate recommendation").click()
        expect(page.get_by_role("heading", name="Remediation recommendation")).to_be_visible()
        page.get_by_text("Inspect source excerpts").click()
        expect(page.get_by_text("<img src=x", exact=False).last).to_be_visible()
        assert page.locator("img").count() == 0
        assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
        page.get_by_role("button", name="Draft mock issue").click()
        if width == 1280:
            page.get_by_role("button", name="Approve and create mock issue").click()
            expect(page.get_by_text("Mock issue #1 created.")).to_be_visible()
            page.reload()
            expect(page.get_by_text("Mock issue #1 created.")).to_be_visible()
        else:
            page.get_by_role("button", name="Reject", exact=True).click()
            expect(page.get_by_text("Issue rejected.")).to_be_visible()
        page.get_by_text("Execution trace", exact=True).click()
        expect(page.get_by_text("lookup vulnerability", exact=False)).to_be_visible()
        expect(page.get_by_text("human review", exact=False)).to_be_visible()
        assert len(upstreams.model_requests) == 1
        assert not errors
        browser.close()

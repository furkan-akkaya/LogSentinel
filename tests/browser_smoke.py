"""Real Chromium workflow against an isolated database. Run directly."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]


def run(screenshots=None):
    with tempfile.TemporaryDirectory(prefix="logsentinel-browser-") as temp:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        env = {**os.environ, "LOGSENTINEL_DB": str(Path(temp) / "events.db")}
        with open(Path(temp) / "server.log", "w+") as log:
            server = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "logsentinel.app:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=log,
            )
            try:
                for _ in range(100):
                    try:
                        with urllib.request.urlopen(url + "/api/health", timeout=1):
                            break
                    except OSError:
                        if server.poll() is not None:
                            log.seek(0)
                            raise RuntimeError(log.read())
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Test server failed to start")
                errors, external, dialogs = [], [], []
                with sync_playwright() as p:
                    browser = p.chromium.launch()
                    context = browser.new_context(
                        viewport={"width": 1440, "height": 1100},
                        reduced_motion="reduce",
                    )
                    page = context.new_page()

                    def capture(name):
                        page.locator("#toast").evaluate(
                            "(element) => element.hidden = true"
                        )
                        if page.locator("#detail-dialog[open]").count():
                            page.locator("#detail-dialog").evaluate(
                                "(element)=>element.scrollTop=0"
                            )
                        page.screenshot(path=str(screenshots / name), full_page=True)

                    page.on("pageerror", lambda err: errors.append(str(err)))
                    page.on(
                        "request",
                        lambda req: (
                            external.append(req.url)
                            if not req.url.startswith(url)
                            else None
                        ),
                    )
                    page.on(
                        "dialog",
                        lambda dialog: (
                            dialogs.append(dialog.message),
                            dialog.dismiss(),
                        ),
                    )
                    page.goto(url)
                    expect(
                        page.get_by_role(
                            "heading", name="Your investigation starts here"
                        )
                    ).to_be_visible()
                    page.get_by_role("button", name="Load sample investigation").click()
                    expect(page.locator(".metric-number").first).to_have_text("85")
                    expect(page.locator(".metric-number").nth(1)).to_have_text("5")
                    if screenshots:
                        screenshots.mkdir(parents=True, exist_ok=True)
                        capture("dashboard.png")
                        page.set_viewport_size({"width": 390, "height": 844})
                        capture("mobile.png")
                        page.set_viewport_size({"width": 1440, "height": 1100})
                    page.locator('nav a[data-page="logs"]').click()
                    expect(
                        page.get_by_role("heading", name="Authentication events")
                    ).to_be_visible()
                    if screenshots:
                        capture("log-explorer.png")
                    page.locator('#log-filters input[name="source_ip"]').fill(
                        "203.0.113.42"
                    )
                    page.get_by_role("button", name="Apply filters").click()
                    expect(page.locator("tbody tr")).to_have_count(7)
                    page.locator("[data-event]").first.click()
                    expect(
                        page.get_by_role("heading", name="Raw source record")
                    ).to_be_visible()
                    expect(page.locator("pre").first).to_contain_text("Failed password")
                    page.get_by_role("button", name="Close details").click()
                    page.locator('nav a[data-page="alerts"]').click()
                    expect(page.locator("tbody tr")).to_have_count(5)
                    if screenshots:
                        capture("security-alerts.png")
                    page.locator("[data-alert]").first.click()
                    expect(
                        page.get_by_role("heading", name="Why this alert fired")
                    ).to_be_visible()
                    expect(page.locator(".timeline-item")).to_have_count(4)
                    expect(
                        page.get_by_role("heading", name="What was observed?")
                    ).to_be_visible()
                    expect(page.locator("#alert-parameters")).to_contain_text(
                        "3 failures within 300 seconds"
                    )
                    summary = page.locator("summary").filter(
                        has_text="Interpretation and analyst checks"
                    )
                    summary.focus()
                    page.keyboard.press("Enter")
                    expect(
                        page.get_by_role("heading", name="Could this be normal?")
                    ).to_be_visible()
                    expect(
                        page.get_by_role(
                            "heading", name="Suggested analyst checks · not automated"
                        )
                    ).to_be_visible()
                    if screenshots:
                        capture("alert-evidence.png")
                    with page.expect_popup() as popup_info:
                        page.get_by_role(
                            "link", name="Read the measured scenario and limitations"
                        ).click()
                    guide = popup_info.value
                    expect(
                        guide.get_by_role(
                            "heading",
                            name="Repeated sudo authentication failures",
                            exact=True,
                        )
                    ).to_be_visible()
                    expect(guide.get_by_role("table").first).to_be_visible()
                    guide.close()
                    page.locator("#investigation-status").select_option("investigating")
                    page.get_by_role("button", name="Save status").click()
                    expect(page.locator("#toast")).to_have_text(
                        "Investigation status saved."
                    )
                    page.get_by_role("button", name="Close details").click()
                    with urllib.request.urlopen(url + "/api/alerts") as response:
                        actual_alerts = json.load(response)["items"]
                    for alert in actual_alerts:
                        page.locator(f'.row-button[data-alert="{alert["id"]}"]').click()
                        expect(page.locator("#detail-dialog")).to_be_visible()
                        expect(
                            page.get_by_role("heading", name=alert["title"], exact=True)
                        ).to_be_visible()
                        expect(page.locator("#alert-parameters")).to_contain_text(
                            f"{alert['parameters']['threshold']} failures within {alert['parameters']['window_seconds']} seconds"
                        )
                        if alert["rule"].startswith("windows"):
                            expect(page.locator(".detail-fields")).to_contain_text(
                                "LAB"
                            )
                            expect(page.locator(".identity-grid")).to_contain_text(
                                "domain"
                            )
                            expect(page.locator(".identity-grid")).to_contain_text(
                                "logon type"
                            )
                            expect(page.locator(".identity-grid")).to_contain_text("10")
                        page.set_viewport_size({"width": 390, "height": 844})
                        assert page.locator("#detail-dialog").evaluate(
                            "(el)=>el.scrollWidth<=el.clientWidth"
                        )
                        page.locator("summary").focus()
                        page.keyboard.press("Enter")
                        expect(
                            page.get_by_role("heading", name="What can this rule miss?")
                        ).to_be_visible()
                        page.locator("#detail-dialog").evaluate(
                            "(element)=>element.scrollTop=element.scrollHeight"
                        )
                        expect(
                            page.get_by_role("button", name="Close details")
                        ).to_be_in_viewport()
                        if (
                            screenshots
                            and alert["rule"] == "windows_success_after_failures"
                        ):
                            capture("windows-context.png")
                        page.keyboard.press("Escape")
                        expect(page.locator("#detail-dialog")).not_to_be_visible()
                        page.set_viewport_size({"width": 1440, "height": 1100})
                    page.get_by_role("button", name="Detection settings").click()
                    page.locator('input[name="ssh_threshold"]').fill("6")
                    page.get_by_role("button", name="Save & reanalyze").click()
                    expect(page.locator("#settings-dialog")).not_to_be_visible()
                    # Settings replay must change the displayed parameters too.
                    ssh = next(
                        a for a in actual_alerts if a["rule"] == "ssh_brute_force"
                    )
                    page.locator(f'.row-button[data-alert="{ssh["id"]}"]').click()
                    expect(page.locator("#detail-dialog")).to_be_visible()
                    expect(page.locator("#alert-parameters")).to_contain_text(
                        "6 failures within 300 seconds"
                    )
                    page.keyboard.press("Escape")
                    page.get_by_role("button", name="Import logs", exact=False).click()
                    page.locator('input[name="file"]').set_input_files(
                        ROOT / "samples" / "linux-auth.log"
                    )
                    page.get_by_role("button", name="Import & analyze").click()
                    expect(page.locator("#toast")).to_contain_text("50 duplicates")
                    # Render hostile content as text in the explorer and detail view.
                    page.get_by_role("button", name="Import logs", exact=False).click()
                    payload = b"2026-10-26T14:00:00Z xss-host sshd[9000]: Failed password for <img/src=x/onerror=alert(1)> from 192.0.2.9 port 22000 ssh2\n"
                    page.locator('input[name="file"]').set_input_files(
                        {"name": "xss.log", "mimeType": "text/plain", "buffer": payload}
                    )
                    page.get_by_role("button", name="Import & analyze").click()
                    expect(page.locator("#toast")).to_contain_text("1 events imported")
                    page.locator('nav a[data-page="logs"]').click()
                    page.get_by_role("button", name="Reset", exact=True).click()
                    expect(page.locator("tbody tr").first).to_contain_text(
                        "<img/src=x/onerror=alert(1)>"
                    )
                    page.locator("[data-event]").first.click()
                    expect(page.locator("pre").first).to_contain_text(
                        "<img/src=x/onerror=alert(1)>"
                    )
                    assert page.locator("img").count() == 0 and not dialogs
                    page.get_by_role("button", name="Close details").click()
                    page.locator('nav a[data-page="dashboard"]').click()
                    expect(page.locator(".metric-number").first).to_have_text("86")
                    page.set_viewport_size({"width": 390, "height": 844})
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= innerWidth"
                    )
                    page.locator(".mobile-settings").click()
                    expect(page.locator("#settings-dialog")).to_be_visible()
                    page.get_by_role("button", name="Close settings").click()
                    with page.expect_popup() as popup_info:
                        page.get_by_role("link", name="Project guide").click()
                    guide = popup_info.value
                    guide.set_viewport_size({"width": 390, "height": 844})
                    expect(
                        guide.get_by_role("heading", name="LogSentinel project guide")
                    ).to_be_visible()
                    assert guide.evaluate(
                        "document.documentElement.scrollWidth<=innerWidth"
                    )
                    guide.get_by_role("link", name="How it works", exact=True).click()
                    expect(
                        guide.get_by_role("heading", name="How LogSentinel works")
                    ).to_be_visible()
                    assert guide.evaluate(
                        "document.documentElement.scrollWidth<=innerWidth"
                    )
                    if screenshots:
                        guide.set_viewport_size({"width": 1440, "height": 1000})
                        guide.screenshot(
                            path=str(screenshots / "how-it-works.png"), full_page=False
                        )
                    guide.close()
                    page.route(
                        "**/api/stats",
                        lambda route: route.fulfill(
                            status=503,
                            content_type="application/json",
                            body='{"detail":"Test outage"}',
                        ),
                    )
                    page.reload()
                    expect(page.locator("#engine-status")).to_have_text(
                        "Connection unavailable"
                    )
                    expect(page.locator(".error-panel")).to_contain_text("Test outage")
                    page.unroute("**/api/stats")
                    page.get_by_role("button", name="Retry", exact=True).click()
                    expect(page.locator("#engine-status")).to_have_text(
                        "Engine operational"
                    )
                    page.goto(url + "/docs")
                    expect(
                        page.get_by_role("heading", name="Local API reference")
                    ).to_be_visible()
                    assert errors == [], errors
                    assert external == [], external
                    browser.close()
                print(
                    "PASS: demo, three screens, five alert explanations, dynamic parameters, Windows identity, raw evidence, keyboard disclosure/Escape, offline guides, filters, status, settings, import, stored XSS, mobile, outage/retry; no JS errors or external requests"
                )
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshots", type=Path)
    run(parser.parse_args().screenshots)

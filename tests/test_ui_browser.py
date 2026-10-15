"""The web UI in a headless browser: dialogs keep the keyboard inside and close when the page changes (review F33,
F34), the command palette gives the focus back (F33), and the sign-in screen shows no text from the URL (F32).

Skipped when Playwright or its Chromium is not installed (``pip install playwright && playwright install chromium``)."""

from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from conftest import ADMIN_PASSWORD

from hub.app import create_app
from hub.config import Settings

sync_api = pytest.importorskip("playwright.sync_api")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def hub_url(tmp_path: Path):
    """A real hub on a free port (never 8710) with its own data directory; stopped after the test."""
    port = free_port()
    settings = Settings(data_dir=tmp_path / "data", host="127.0.0.1", port=port, allowed_hosts=["127.0.0.1"],
                        start_background_tasks=False, admin_username="admin", admin_password=ADMIN_PASSWORD)
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise AssertionError("the hub did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(15)


def launch(p):
    """Playwright's own Chromium, else any Chromium it downloaded earlier (a newer Playwright keeps looking for its own
    build number)."""
    try:
        return p.chromium.launch()
    except Exception as exc:
        found = sorted(Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or Path.home() / ".cache" / "ms-playwright")
                       .glob("chromium-*/chrome-linux*/chrome"))
        if not found:
            pytest.skip(f"Chromium is not available: {str(exc).splitlines()[0]}")
        return p.chromium.launch(executable_path=str(found[-1]))


@pytest.fixture
def page(hub_url):
    with sync_api.sync_playwright() as p:
        browser = launch(p)
        try:
            page = browser.new_page()
            page.set_default_timeout(10_000)
            page.goto(hub_url)
            yield page
        finally:
            browser.close()


def sign_in(page) -> None:
    page.fill("[data-login] input[name=username]", "admin")
    page.fill("[data-login] input[name=password]", ADMIN_PASSWORD)
    page.click("[data-login] button[type=submit]")
    page.wait_for_selector("body.signed-in")
    page.wait_for_selector("#main:not(:has(.empty.faint))")  # the first page finished loading


IN_TOP_DIALOG = "() => { const d = [...document.querySelectorAll('body > .backdrop')].at(-1); return !!d && d.contains(document.activeElement); }"
INERT = "() => ['header.topbar', '.layout', '#auth'].map((s) => document.querySelector(s).inert)"


def test_a_dialog_keeps_tab_inside_and_the_page_behind_is_inert(page):
    sign_in(page)
    page.focus("#start-btn")
    page.keyboard.press("Enter")  # Get Started opens a dialog
    page.wait_for_selector(".backdrop form[role=dialog]")
    page.wait_for_function(IN_TOP_DIALOG)
    assert page.evaluate(INERT) == [True, True, True]
    for key in ["Tab"] * 15 + ["Shift+Tab"] * 15:
        page.keyboard.press(key)
        assert page.evaluate(IN_TOP_DIALOG), f"{key} left the dialog for {page.evaluate('document.activeElement.outerHTML.slice(0, 120)')}"
    page.keyboard.press("Escape")
    page.wait_for_selector(".backdrop", state="detached")
    assert page.evaluate(INERT) == [False, False, False]
    assert page.evaluate("document.activeElement.id") == "start-btn"  # focus went back to the opener


def test_a_dialog_on_a_dialog_keeps_the_lower_one_inert(page):
    sign_in(page)
    page.evaluate("""async () => {
      const ui = await import('/js/ui.js');
      ui.modal({ title: 'Outer', body: ui.html`<button type="button" id="inner-open">Open another</button>` });
      document.getElementById('inner-open').addEventListener('click', () => ui.modal({ title: 'Inner', body: ui.html`<input id="inner-field">` }));
    }""")
    page.wait_for_function(IN_TOP_DIALOG)
    page.click("#inner-open")
    page.wait_for_function("() => document.activeElement?.id === 'inner-field'")
    assert page.evaluate("() => document.querySelectorAll('body > .backdrop')[0].inert") is True
    for _ in range(6):
        page.keyboard.press("Tab")
        assert page.evaluate(IN_TOP_DIALOG)
    page.keyboard.press("Escape")
    page.wait_for_function("() => document.querySelectorAll('body > .backdrop').length === 1")
    assert page.evaluate("() => document.querySelector('body > .backdrop').inert") is False
    assert page.evaluate("document.activeElement.id") == "inner-open"


def test_the_command_palette_gives_the_focus_back(page):
    sign_in(page)
    page.focus("#search-btn")
    page.keyboard.press("Enter")
    page.wait_for_selector(".palette input")
    page.wait_for_function("() => document.activeElement?.matches('.palette input')")
    assert page.evaluate(INERT) == [True, True, True]
    page.keyboard.press("Tab")
    assert page.evaluate(IN_TOP_DIALOG)
    page.keyboard.press("Escape")
    page.wait_for_selector(".palette", state="detached")
    assert page.evaluate("document.activeElement.id") == "search-btn"
    assert page.evaluate(INERT) == [False, False, False]


def test_a_link_inside_a_dialog_closes_the_dialog(page):
    """The agent form's "Settings > AI models" link used to change the page under a dialog that stayed open."""
    sign_in(page)
    page.goto(page.url.split("#")[0] + "#/agents")
    page.click("button[data-act=new]")
    page.wait_for_selector(".backdrop form[role=dialog]")
    page.click(".backdrop a[href='#/settings/ai']")
    page.wait_for_function("() => location.hash === '#/settings/ai'")
    page.wait_for_selector(".backdrop", state="detached")
    assert page.evaluate(INERT) == [False, False, False]


def test_a_token_dialog_survives_navigation_but_not_sign_out(page):
    sign_in(page)
    page.evaluate("""async () => {
      const ui = await import('/js/ui.js');
      ui.modal({ title: 'Copy your new token', submit: null, cancel: 'Done', sticky: true, body: ui.html`<p>secret</p>` });
    }""")
    page.wait_for_selector(".backdrop")
    page.evaluate("location.hash = '#/approvals'")
    page.wait_for_function("() => document.title.startsWith('Approvals')")
    assert page.locator(".backdrop").count() == 1  # only its own buttons close it
    # the session ends elsewhere (another tab signed out): the app notices and shows the sign-in screen
    page.evaluate("""async () => {
      await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-Hub-Request': '1' } });
      window.dispatchEvent(new CustomEvent('atrium:signed-out'));
    }""")
    page.wait_for_selector("[data-login]")
    assert page.locator(".backdrop").count() == 0
    assert page.evaluate(INERT) == [False, False, False]  # the sign-in screen is usable


def test_the_sign_in_screen_shows_no_text_from_the_url(page, hub_url):
    page.goto("about:blank")  # a phishing link opens the hub afresh
    page.goto(f"{hub_url}/#/login?error=Your%20password%20expired.%20Reset%20it%20at%20https%3A%2F%2Fevil.example")
    page.wait_for_selector("[data-login]")
    page.wait_for_function("() => !location.hash.includes('?')")
    assert "evil.example" not in page.inner_text("#auth")
    assert page.evaluate("location.hash") == "#/login"


def test_the_approvals_page_states_the_operator_rule_for_the_hub_machine(page):
    """The Approvals page used to say that every command a person types in the Operator runs directly. Only an
    administrator's do on the hub machine: an operator's (other than read-only ones) and tool starts wait for an
    administrator (``OperatorAgent.on_run`` / ``on_launch``; tests/test_security_core.py plays that rule)."""
    sign_in(page)
    page.evaluate("location.hash = '#/approvals'")
    page.wait_for_function("() => document.title.startsWith('Approvals')")
    intro = page.inner_text(".page-head p")
    assert "Commands typed by a person in the Operator run directly" not in intro
    assert "Commands an administrator types in the Operator run directly" in intro
    assert "an operator's commands on the hub machine (other than read-only ones) and tool starts wait here for an administrator" in intro


def test_wide_content_stays_inside_its_card_and_the_window(page):
    """Found by scripts/screenshots.py's check: a long agent name in the chat's agent picker pushed "New conversation"
    out of the Agents page's chat card, and the screen-reader text of the level badges in the self-assessments table
    (absolutely positioned, outside the table's scroll box) widened the Frameworks page at phone width."""
    sign_in(page)
    page.evaluate("""async () => {
      const send = (path, body) => fetch(path, { method: 'POST', body: JSON.stringify(body),
        headers: { 'Content-Type': 'application/json', 'X-Hub-Request': '1' } }).then((r) => { if (!r.ok) throw new Error(path); });
      await send('/api/agents', { name: 'Inventory reconciliation specialist for every asset register', provider: 'rules' });
      await send('/api/frameworks/cyfun2025/assessments', { name: 'CyFun 2025 self-assessment', target_level: 'B' });
    }""")
    page.evaluate("location.hash = '#/agents'")
    page.wait_for_selector("#chat-agent")
    assert page.evaluate("() => document.querySelector('#chat-agent option:last-child').textContent").startswith("Inventory")
    header = page.evaluate("() => { const h = document.querySelector('#chat-agent').closest('header'); "
                           "return [h.scrollWidth, h.clientWidth]; }")
    assert header[0] <= header[1] + 1, header
    page.set_viewport_size({"width": 390, "height": 844})
    page.evaluate("location.hash = '#/compliance/frameworks'")
    page.wait_for_selector(".fw-verdicts .sr-only")
    assert page.evaluate("() => document.documentElement.scrollWidth") <= 390


SEND = """(calls) => { const send = ([path, body]) => fetch(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined,
  headers: { 'Content-Type': 'application/json', 'X-Hub-Request': '1' } }).then((r) => r.status);
  return calls.reduce((done, call) => done.then((out) => send(call).then((s) => [...out, s])), Promise.resolve([])); }"""


def test_the_agent_bus_keeps_an_older_page_while_live_updates_come_in(page):
    """Review: a live refresh that started while "Show older conversations" loaded dropped the older page."""
    sign_in(page)
    page.evaluate(SEND, [["/api/chat", {"text": "status"}]] * 55)
    page.evaluate("location.hash = '#/bus'")
    page.wait_for_selector("[data-act=more]")
    first = page.locator(".bus-thread").count()
    held = []
    page.route(lambda url: "/api/bus/threads" in url and "before=" in url, lambda route: held.append(route))
    page.click("[data-act=more]")
    for _ in range(100):
        if held:
            break
        page.wait_for_timeout(50)
    assert held, "the older page was not asked for"
    page.evaluate(SEND, [["/api/chat", {"text": "status"}]])  # a live event while the older page loads
    page.wait_for_timeout(2000)  # a refresh is due after 800 ms
    held[0].continue_()
    page.wait_for_function(f"() => document.querySelectorAll('.bus-thread').length > {first}")
    page.wait_for_timeout(1500)  # the refresh held back meanwhile lands too
    assert page.locator(".bus-thread").count() > first == 50


def test_an_errors_drawer_reloads_when_another_agents_error_follows_its_own(page):
    """Review: the drawer gathered every agent's events and then looked only at the last one."""
    sign_in(page)
    ids = page.evaluate("""async () => { const ids = [];
      for (const name of ['Quiet One', 'Quiet Two']) {
        const r = await fetch('/api/agents', { method: 'POST', body: JSON.stringify({ name, provider: 'rules' }),
          headers: { 'Content-Type': 'application/json', 'X-Hub-Request': '1' } });
        ids.push((await r.json()).id);
      }
      return ids; }""")
    assert page.evaluate(SEND, [[f"/api/agents/{ids[0]}/run", None]]) == [400]  # no standing task: an error
    page.evaluate("location.hash = '#/agents'")
    page.click(f"button[data-act=errors][data-id='{ids[0]}']")
    page.wait_for_selector(".errs-item")
    assert page.locator(".errs-item").count() == 1
    page.evaluate(SEND, [[f"/api/agents/{ids[0]}/run", None], [f"/api/agents/{ids[1]}/run", None]])  # its, then another's
    page.wait_for_function("() => document.querySelectorAll('.errs-item').length === 2", timeout=5_000)

"""Retake the screenshots in docs/screenshots from the UI in this checkout, with the demo data of scripts/demo_hub.py.

    .venv/bin/python scripts/screenshots.py [--out docs/screenshots] [--port 8790] [--check-only] [--chromium PATH]

Needs Playwright and a Chromium (``pip install playwright && playwright install chromium``, or --chromium). The script
starts the demo hub (fake tool APIs and model servers, the fake firewall, a temporary data directory, a port other than
8710), seeds it through the hub's API (dashboards, AI providers and agent settings, a subsidiary with its scripted
sidecar included), and then:

1. replaces the PNG files in docs/screenshots (1440 x 900, light theme; home-dark in the dark theme and home-phone at
   390 px; dashboard-edit holds a widget halfway through a drag) - every PNG there is removed first, so screens that no
   longer exist leave no picture behind. With Pillow (in this Python or in ``python3`` on the PATH) the pictures are
   stored as 256-colour PNGs;
2. checks the UI in a real browser: every page and tab - dashboards, agent settings, subsidiaries and the Agent bus
   included - as an administrator, an operator and a viewer, and the administrator's pages at phone width; also the
   Agents page's errors drawer, and that only ava reads her own chat on the Agent bus. It reports console errors, page
   errors, failed API calls (other than 403 for the lower roles), content wider than its card, the drawer or the
   window, and another person's chat text shown, and exits with status 1 when it found any.

The fake tools and the sidecar are stopped, then the hub by its PID, and the data directory is removed afterwards.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
import demo_hub  # noqa: E402 - the sibling module

ROOT = demo_hub.ROOT
DESKTOP = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}
LOADED = "#main:not(:has(.empty.faint))"  # the page's "Loading..." placeholder is gone
SHOT_NAMES = ("home", "apps", "integration-overview", "integration-map", "segmentation-map", "network", "network-device",
              "approvals", "compliance-frameworks", "compliance-controls", "people", "person", "vulnerabilities",
              "agents", "settings-guardrails", "users", "home-dark", "home-phone", "home-dashboard", "dashboard-edit",
              "ai-models", "agent-settings", "subsidiaries", "subsidiary-approval", "agent-bus", "agent-errors")
AGENT_TABS = ("overview", "model", "behaviour", "tools", "limits", "escalation", "playground", "history")
SUBSIDIARY_TABS = ("charter", "activity", "reports", "setup")

# content sticking out of a card (outside its own scroll box) or the window; `boxes`: other containers to check
OVERFLOW = """(boxes = '#main .card') => {
  const out = [];
  if (document.documentElement.scrollWidth > innerWidth + 1)
    out.push(`the page scrolls sideways: ${document.documentElement.scrollWidth} px in a ${innerWidth} px window`);
  const scrollBox = (el, card) => {
    for (let p = el.parentElement; p && p !== card; p = p.parentElement)
      if (/(auto|scroll|hidden)/.test(getComputedStyle(p).overflowX)) return p;
    return null;
  };
  for (const card of document.querySelectorAll(boxes)) {
    const right = card.getBoundingClientRect().right;
    for (const el of card.querySelectorAll('*')) {
      const r = el.getBoundingClientRect();
      if (!r.width || r.right <= right + 1 || scrollBox(el, card)) continue;
      out.push(`<${el.tagName.toLowerCase()} class="${el.getAttribute('class') || ''}"> "${(el.textContent || '').trim().slice(0, 40)}" sticks out of its card by ${Math.round(r.right - right)} px`);
      break;
    }
  }
  return out.slice(0, 5);
}"""


def launch(p, chromium: str | None):
    """The given Chromium, else Playwright's own, else any Chromium it downloaded earlier."""
    if chromium:
        return p.chromium.launch(executable_path=chromium)
    try:
        return p.chromium.launch()
    except Exception:
        found = sorted(Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or Path.home() / ".cache" / "ms-playwright")
                       .glob("chromium-*/chrome-linux*/chrome"))
        if not found:
            raise
        return p.chromium.launch(executable_path=str(found[-1]))


class Browser:
    def __init__(self, browser, base: str, password: str):
        self.browser, self.base, self.password = browser, base, password

    def session(self, user: str, viewport: dict, theme: str = "light", events: list | None = None):
        context = self.browser.new_context(viewport=viewport, color_scheme=theme, reduced_motion="reduce")
        context.add_init_script(f"try {{ localStorage.setItem('hub.theme', '{theme}'); }} catch {{}}")
        page = context.new_page()
        page.set_default_timeout(20_000)
        if events is not None:
            watch(page, self.base, events)
        page.goto(self.base)
        page.fill("[data-login] input[name=username]", user)
        page.fill("[data-login] input[name=password]", self.password)
        page.click("[data-login] button[type=submit]")
        page.wait_for_selector("body.signed-in")
        page.wait_for_selector(LOADED)
        return context, page

    @staticmethod
    def go(page, route: str) -> None:
        page.evaluate("(h) => { location.hash = h; }", route)
        page.wait_for_function("(h) => location.hash === h || location.hash.startsWith(h + '/')", arg=route)
        page.wait_for_selector(LOADED)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(700)


def watch(page, base: str, events: list) -> None:
    """Collect console errors, page errors and failed API calls; events[0] names the page being visited."""
    where = lambda: events[0]  # noqa: E731 - the current route lives in events[0]
    page.on("console", lambda m: m.type == "error" and events.append((where(), "console error", m.text[:300])))
    page.on("pageerror", lambda e: events.append((where(), "page error", str(e)[:300])))
    page.on("response", lambda r: "/api/" in r.url and r.status >= 400 and events.append(
        (where(), f"HTTP {r.status}", f"{r.request.method} {r.url.replace(base, '')}")))
    page.on("requestfailed", lambda r: "/api/events" not in r.url and events.append(
        (where(), "request failed", f"{r.method} {r.url.replace(base, '')} ({r.failure})")))


# -- 1. the check ------------------------------------------------------------------------------------------------------


def routes(info: dict[str, Any], user: str = "ava") -> list[str]:
    """Every page and tab; `user`'s own dashboard too (another person's is not found, by design)."""
    tools, fw, fid = info["tools"], info["firewall"], info["framework"]
    out = ["#/", f"#/d/{info['dashboard']}", "#/tools"]
    if user == "ava":
        out.append(f"#/d/{info['my_dashboard']}")
    for tab, tool in (("", "Snipe-IT"), ("/connection", "Snipe-IT"), ("/manifest", "OpenVAS"), ("/patches", "Keycloak"),
                      ("/process", "Grafana"), ("/supervisor", "Wazuh"), ("/connection", "Edge firewall")):
        out.append(f"#/tools/{tools[tool]}{tab}")
    out += ["#/integration", "#/integration/map", "#/integration/segmentation", "#/agents"]
    for agent, tabs in (("supervisor", AGENT_TABS), ("patcher", ("model",)), (info.get("triage"), AGENT_TABS)):
        if agent:  # agent ids hold ":" - links encode it
            out += [f"#/agents/{quote(agent, safe='')}/settings" + (f"/{tab}" if tab != "overview" else "")
                    for tab in tabs]
    sub = info["subsidiary_tool"]
    out += ["#/subsidiaries", f"#/subsidiaries/{sub}", *(f"#/subsidiaries/{sub}/{tab}" for tab in SUBSIDIARY_TABS),
            f"#/tools/{sub}"]
    out += ["#/bus", "#/bus?errors=1", "#/bus?mine=1", *([f"#/bus/{info['conversation']}"] if info.get("conversation")
                                                        else [])]
    out += ["#/approvals", "#/operator", "#/network", "#/network/drift", "#/network/changes", f"#/network/{fw}"]
    out += [f"#/network/{fw}/{tab}" for tab in ("interfaces", "history", "drift", "backups", "changes")]
    out += ["#/assets", "#/people", "#/people/leavers", "#/people/accounts", f"#/people/{info['person_id']}",
            f"#/people/{info['leaver_id']}", "#/vulnerabilities", "#/vulnerabilities/scope", "#/compliance",
            "#/compliance/frameworks", f"#/compliance/frameworks/{fid}", f"#/compliance/frameworks/{fid}/{info['assessment_id']}",
            "#/compliance/controls", "#/compliance/risks", "#/compliance/policies", "#/extensions", "#/extensions/gaps",
            "#/extensions/self-patches", "#/x/alerts", "#/settings", "#/settings/ai", "#/settings/network",
            "#/settings/sso", "#/users"]
    return out


def check(b: Browser, info: dict[str, Any]) -> list[tuple[str, ...]]:
    problems: list[tuple[str, ...]] = []
    for user, role, viewport in (("ava", "admin", DESKTOP), ("jonas", "operator", DESKTOP), ("lena", "viewer", DESKTOP),
                                 ("ava", "admin", PHONE)):
        label = f"{role} {viewport['width']}px"
        events: list = ["sign-in"]
        context, page = b.session(user, viewport, events=events)
        pages = routes(info, user)
        for route in pages:
            events[0] = route
            try:
                b.go(page, route)
            except Exception as exc:  # a page that never finishes loading is a finding too
                events.append((route, "did not load", str(exc).splitlines()[0][:200]))
                continue
            events += [(route, "layout", issue) for issue in page.evaluate(OVERFLOW)]
        events[0] = "#/agents (the Operator Agent's errors drawer)"
        try:
            events += [(events[0], "layout", issue) for issue in errors_drawer(page)]
        except Exception as exc:
            events.append((events[0], "did not open", str(exc).splitlines()[0][:200]))
        if info.get("conversation"):
            events[0] = f"#/bus/{info['conversation']} (privacy)"
            events += [(events[0], "privacy", issue) for issue in own_chat(page, info["conversation"], user)]
        context.close()
        found = [e for e in events[1:] if not (role != "admin" and e[1] == "HTTP 403")]  # expected for lower roles
        print(f"  {label}: {len(pages)} pages, {len(found)} problem(s)")
        problems += [(label, *e) for e in found]
    return problems


def errors_drawer(page, agent: str = "operator") -> list[str]:
    """The Agents page's error count of `agent` opens its errors in a drawer (the seeded failure listed, nothing
    sticking out of it) and Escape closes it again: what is wrong, else []."""
    Browser.go(page, "#/agents")
    page.click(f'.err-chip[data-id="{agent}"]')
    page.wait_for_selector(".modal.drawer .errs-list, .modal.drawer .errs .empty")
    page.wait_for_load_state("networkidle")
    issues = page.evaluate(OVERFLOW, ".modal.drawer")
    if not page.locator(".modal.drawer .errs-item").count():
        issues.append(f"the errors drawer of {agent} lists no error")
    page.keyboard.press("Escape")
    page.wait_for_selector(".modal.drawer", state="detached")
    return issues


def own_chat(page, conversation: str, user: str) -> list[str]:
    """ava's audit chat on the Agent bus: she reads her own words, nobody else does (review D7)."""
    Browser.go(page, f"#/bus/{conversation}")
    page.wait_for_selector("#bus-thread-title")
    shown = demo_hub.AUDIT_QUESTION[:60] in " ".join(page.inner_text("#main").split())
    if shown == (user == "ava"):
        return []
    return [f"ava's chat text is {'shown to' if shown else 'hidden from'} {user}"]


# -- 2. the screenshots ------------------------------------------------------------------------------------------------


def shot(page, out: Path, name: str) -> Path:
    page.evaluate("() => document.querySelectorAll('.toasts').forEach((t) => t.remove())")
    page.evaluate("() => document.activeElement?.blur?.()")  # no focus ring left on a button
    page.mouse.move(0, page.viewport_size["height"] - 1)  # no hover highlight
    page.wait_for_timeout(200)
    path = out / f"{name}.png"
    page.screenshot(path=str(path))
    print(f"  {path.name}")
    return path


def scroll_to(page, selector: str, offset: int = 76) -> None:
    """Scroll until `selector` is at the top, below the sticky top bar."""
    page.wait_for_selector(selector)
    page.evaluate("([s, o]) => { const el = document.querySelector(s); "
                  "window.scrollBy({ top: el.getBoundingClientRect().top - o, behavior: 'instant' }); }", [selector, offset])
    page.wait_for_timeout(400)


def take(b: Browser, info: dict[str, Any], out: Path) -> list[Path]:
    fw, fid = info["firewall"], info["framework"]
    taken: list[Path] = []
    context, page = b.session("ava", DESKTOP)
    for name, route in (("home", "#/"), ("apps", "#/tools"), ("integration-overview", "#/integration"),
                        ("integration-map", "#/integration/map")):
        b.go(page, route)
        taken.append(shot(page, out, name))

    b.go(page, "#/integration/segmentation")  # zoomed in on the users, servers and management zones
    box = page.locator(".canvas-stage svg.canvas").bounding_box()
    page.mouse.move(box["x"] + box["width"] * 0.5, box["y"] + box["height"] * 0.5)
    page.keyboard.down("Control")
    page.mouse.wheel(0, -300)
    page.keyboard.up("Control")
    page.wait_for_timeout(300)
    page.mouse.wheel(0, 110)
    page.wait_for_timeout(500)
    taken.append(shot(page, out, "segmentation-map"))

    for name, route in (("network", "#/network"), ("network-device", f"#/network/{fw}")):
        b.go(page, route)
        taken.append(shot(page, out, name))
    b.go(page, "#/approvals")  # the firewall change card, with its buttons
    scroll_to(page, "#main .tabs", 66)
    taken.append(shot(page, out, "approvals"))
    for name, route in (("compliance-frameworks", f"#/compliance/frameworks/{fid}/{info['assessment_id']}"),
                        ("compliance-controls", "#/compliance/controls"), ("people", "#/people"),
                        ("person", f"#/people/{info['leaver_id']}"), ("vulnerabilities", "#/vulnerabilities"),
                        ("agents", "#/agents")):
        b.go(page, route)
        taken.append(shot(page, out, name))
    b.go(page, "#/settings")
    scroll_to(page, "#guardrails-card")
    taken.append(shot(page, out, "settings-guardrails"))
    b.go(page, "#/users")
    taken.append(shot(page, out, "users"))
    taken += take_round4(b, page, info, out)
    taken += take_bus(b, page, info, out)
    context.close()

    context, page = b.session("ava", DESKTOP, theme="dark")
    b.go(page, "#/")
    taken.append(shot(page, out, "home-dark"))
    context.close()
    context, page = b.session("ava", PHONE)
    b.go(page, "#/")
    taken.append(shot(page, out, "home-phone"))
    context.close()
    return taken


def drag_shot(page, out: Path, dash: str) -> Path:
    """The shared dashboard in edit mode with a widget held halfway through a drag (the drop target shows where it
    lands), then the drag cancelled with Escape and edit mode left: nothing changes."""
    Browser.go(page, f"#/d/{dash}")
    page.click('[data-act="d-customize"]')
    page.wait_for_selector(".dash-grid.editing .dash-handle")
    page.wait_for_timeout(500)
    handle = page.locator('.widget[data-wid="w_demo0007"] .dash-handle').bounding_box()
    target = page.locator('.widget[data-wid="w_demo0005"]').bounding_box()
    x, y = handle["x"] + handle["width"] / 2, handle["y"] + handle["height"] / 2
    page.mouse.move(x, y)
    page.mouse.down()
    for n in range(1, 11):  # in steps, as a hand would: the board follows pointer moves
        page.mouse.move(x + (target["x"] + 40 - x) * n / 10, y + (target["y"] + 30 - y) * n / 10)
        page.wait_for_timeout(40)
    page.wait_for_timeout(500)
    page.evaluate("() => document.querySelectorAll('.toasts').forEach((t) => t.remove())")
    path = out / "dashboard-edit.png"
    page.screenshot(path=str(path))
    print(f"  {path.name}")
    page.keyboard.press("Escape")
    page.mouse.up()
    page.click('[data-act="e-done"]')
    page.wait_for_selector(".dash-grid:not(.editing)")
    return path


def take_round4(b: Browser, page, info: dict[str, Any], out: Path) -> list[Path]:
    """Dashboards, AI models, agent settings and subsidiaries (round 4)."""
    taken: list[Path] = []
    b.go(page, f"#/d/{info['dashboard']}")
    taken.append(shot(page, out, "home-dashboard"))
    taken.append(drag_shot(page, out, info["dashboard"]))
    b.go(page, "#/settings/ai")  # the providers next to the model choice
    scroll_to(page, "#main .ai-panels", 72)
    taken.append(shot(page, out, "ai-models"))
    b.go(page, "#/agents/supervisor/settings/model")
    taken.append(shot(page, out, "agent-settings"))
    b.go(page, f"#/subsidiaries/{info['subsidiary_tool']}")
    taken.append(shot(page, out, "subsidiaries"))
    b.go(page, "#/approvals")  # the in-tool change the subsidiary's clerk asked for, with its buttons
    scroll_to(page, f'#main section.card:has([data-act="approve"][data-id="{info["subsidiary_approval"]}"])', 70)
    taken.append(shot(page, out, "subsidiary-approval"))
    return taken


def take_bus(b: Browser, page, info: dict[str, Any], out: Path) -> list[Path]:
    """ava's audit chat on the Agent bus - the transcript scrolled to the agents' requests and the Operator Agent's
    failure, the launch request's body open - and the Operator Agent's errors drawer on the Agents page."""
    b.go(page, f"#/bus/{info['conversation']}")
    page.wait_for_selector('#bus-scroll .bus-msg[data-n="6"]')
    page.click('.bus-msg[data-n="6"] details.bus-body > summary')
    page.evaluate("""() => { const s = document.querySelector('#bus-scroll');
      const m = s.querySelector('.bus-msg[data-n="5"]');
      s.scrollTop += m.getBoundingClientRect().top - s.getBoundingClientRect().top - 10; }""")
    page.wait_for_timeout(300)
    taken = [shot(page, out, "agent-bus")]
    b.go(page, "#/agents")
    page.click('.err-chip[data-id="operator"]')
    page.wait_for_selector(".modal.drawer .errs-list")
    page.wait_for_timeout(400)
    taken.append(shot(page, out, "agent-errors"))
    page.keyboard.press("Escape")
    page.wait_for_selector(".modal.drawer", state="detached")
    return taken


QUANTIZE = """
import sys
from PIL import Image
for path in sys.argv[1:]:
    with Image.open(path) as image:
        small = image.convert("RGB").quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    small.save(path, optimize=True)
"""


def compress(paths: list[Path]) -> None:
    """256-colour PNGs (a third of the size; the UI has few colours) with Pillow, here or in python3 on the PATH."""
    python = sys.executable if importlib.util.find_spec("PIL") else shutil.which("python3")
    if not python or subprocess.run([python, "-c", "import PIL"], capture_output=True).returncode != 0:
        print("Pillow is not installed: the PNG files stay as the browser wrote them")
        return
    subprocess.run([python, "-c", QUANTIZE, *map(str, paths)], check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(ROOT / "docs" / "screenshots"), help="where to write the PNG files")
    parser.add_argument("--port", type=int, default=8790, help="the hub's port (never 8710); the fakes use the next 10")
    parser.add_argument("--check-only", action="store_true", help="only check the UI; take no screenshots")
    parser.add_argument("--chromium", help="the Chromium executable to use")
    args = parser.parse_args()
    if args.port == 8710:
        parser.error("use a port other than 8710")
    from playwright.sync_api import sync_playwright

    out = Path(args.out).resolve()
    password = secrets.token_urlsafe(18)
    data_dir = Path(tempfile.mkdtemp(prefix="atrium-shots-"))
    problems: list[tuple[str, ...]] = []
    tools = demo_hub.DemoTools(args.port + 1).start()
    hub = demo_hub.start_hub(data_dir, args.port, password)
    print(f"hub pid {hub.pid} on port {args.port}, data {data_dir}")
    try:
        base = f"http://127.0.0.1:{args.port}"
        info = demo_hub.seed(base, password, tools, log=lambda line: print(f"  {line}"))
        with sync_playwright() as p:
            browser = launch(p, args.chromium)
            try:
                b = Browser(browser, base, password)
                if not args.check_only:  # first, so the activity on Home is the seeding's, not the check's sign-ins
                    out.mkdir(parents=True, exist_ok=True)
                    for old in out.glob("*.png"):
                        old.unlink()
                    print(f"screenshots in {out}:")
                    taken = take(b, info, out)
                    if sorted(p.stem for p in taken) != sorted(SHOT_NAMES):
                        raise SystemExit("the screenshots taken differ from SHOT_NAMES")
                    compress(taken)
                print("checking every page per role:")
                problems = check(b, info)
                for problem in problems:
                    print("  PROBLEM", " | ".join(problem))
            finally:
                browser.close()
    finally:
        tools.stop()  # the fake tools and the subsidiary's sidecar, then the hub
        demo_hub.stop_hub(hub)
        shutil.rmtree(data_dir, ignore_errors=True)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())

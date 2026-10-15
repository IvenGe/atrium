"""Home dashboards in a headless browser (round4-dashboard-spec.md 10.6-10.8, 10.14; stage D6): a widget's options
button says whether its menu is open, tabs and the gallery's category chips expose their state, a keyboard move is
announced and saved, a widget added under the gallery drawer leaves the focus in the drawer (WCAG 2.4.11), and a phone
shows one column without sideways scrolling.

Skipped when Playwright or its Chromium is not installed (tests/test_ui_browser.py has the fixtures)."""

from __future__ import annotations

from test_ui_browser import hub_url, launch, page, sign_in  # noqa: F401  (fixtures)

LIVE = '[data-part="live"]'


def said(page, text: str, *, prefix: bool = False) -> str:
    """What the live region announced, once it says `text` (or starts with it)."""
    page.wait_for_function("""([sel, text, prefix]) => {
      const said = document.querySelector(sel)?.textContent.trim() || '';
      return prefix ? said.startsWith(text) : said === text;
    }""", arg=[LIVE, text, prefix])
    return page.text_content(LIVE).strip()


def personal(page, title: str, origin: str | None = None) -> str:
    """A personal dashboard of the signed-in administrator, opened in its own tab of Home."""
    body = f'{{"title": "{title}"' + (f', "from": "{origin}"' if origin else "") + "}"
    dash_id = page.evaluate("""async (body) => {
      const r = await fetch('/api/dashboards/mine', { method: 'POST', body, headers: { 'Content-Type': 'application/json',
        'X-Hub-Request': '1' } });
      if (!r.ok) throw new Error(await r.text());
      return (await r.json()).id;
    }""", body)
    page.goto(page.url.split("#")[0] + f"#/d/{dash_id}")
    page.wait_for_selector(f'.dash-tab[aria-selected="true"][data-id="{dash_id}"], .dash-tabs [aria-selected="true"]')
    page.wait_for_function("() => !document.querySelector('.widget .skeleton')")
    return dash_id


def edit(page) -> None:
    page.click('[data-act="d-customize"]')
    page.wait_for_selector(".dash-toolbar")


def test_menus_tabs_and_chips_expose_their_state(page):
    sign_in(page)
    personal(page, "Mine", "template:overview")
    tabs = page.locator('.dash-tabs [role="tab"]')
    assert sorted(t.get_attribute("aria-selected") for t in tabs.all()) == ["false", "true"]  # never an empty value
    button = page.locator(".widget .widget-menu-btn").first
    button.click()
    page.wait_for_selector(".dash-pop")
    assert button.get_attribute("aria-expanded") == "true"  # a click elsewhere in the app used to reset it at once
    assert page.evaluate("() => !!document.activeElement.closest('.dash-pop')")
    page.keyboard.press("Escape")
    page.wait_for_selector(".dash-pop", state="detached")
    assert button.get_attribute("aria-expanded") == "false"
    assert page.evaluate("() => document.activeElement.classList.contains('widget-menu-btn')")
    edit(page)
    page.click('[data-act="e-add"]')
    page.wait_for_selector(".dash-gallery")
    pressed = page.locator(".dash-chip").evaluate_all("cs => cs.map((c) => [c.dataset.cat, c.getAttribute('aria-pressed')])")
    assert pressed[0] == ["all", "true"] and {p for _, p in pressed[1:]} == {"false"}


def test_a_keyboard_move_is_announced_and_saved(page):
    sign_in(page)
    dash_id = personal(page, "Mine", "template:overview")
    edit(page)
    handle = page.locator(".widget .dash-handle").first
    wid = handle.get_attribute("data-id")
    handle.focus()
    assert page.evaluate("() => document.getElementById(document.activeElement.getAttribute('aria-describedby')).textContent") \
        .startswith("Press Space to pick up")
    page.keyboard.press("Space")
    said(page, "Picked up", prefix=True)
    page.keyboard.press("ArrowRight")
    page.keyboard.press("Space")
    said(page, "Dropped at row 1, column 2.")
    assert page.evaluate("() => document.activeElement.classList.contains('dash-handle')")  # focus stays on the handle
    page.wait_for_function("() => document.querySelector('.dash-toolbar .dash-save')?.textContent.trim() === 'Saved'")
    saved = page.evaluate("async (id) => (await (await fetch('/api/dashboards/' + id)).json()).widgets", dash_id)
    assert next(w for w in saved if w["id"] == wid)["x"] == 1


def test_a_widget_added_under_the_gallery_drawer_leaves_the_focus_in_the_drawer(page):
    page.set_viewport_size({"width": 1440, "height": 900})
    sign_in(page)
    personal(page, "Blank")
    if not page.locator(".dash-toolbar").count():  # a blank dashboard opens in edit mode
        edit(page)
    page.click('[data-act="e-add"]')
    page.wait_for_selector("aside.dash-drawer")
    page.fill("aside .dash-search", "Assets")
    add = page.locator("aside .dash-card", has=page.locator("b", has_text="Assets")).first.locator('[data-act="g-add"]')
    where = []
    for _ in range(4):  # 3-column tiles: columns 1, 4, 7, then 10, which the drawer covers
        add.click()
        page.wait_for_function("(n) => document.querySelectorAll('.widget').length === n", arg=len(where) + 1)
        where.append((said(page, "Added", prefix=True), page.evaluate("() => !!document.activeElement.closest('aside.dash-drawer')")))
    assert [w[0].rsplit(" at ", 1)[1] for w in where] == ["row 1, column 1", "row 1, column 4", "row 1, column 7",
                                                         "row 1, column 10"]
    assert [w[1] for w in where] == [False, False, False, True]


def test_a_phone_shows_one_column_without_sideways_scrolling(page):
    sign_in(page)
    page.set_viewport_size({"width": 390, "height": 844})
    personal(page, "Mine", "template:overview")
    assert "stack-mode" in page.get_attribute(".dash-grid", "class")
    assert page.evaluate("() => document.documentElement.scrollWidth") <= 390
    edit(page)
    assert not [h for h in page.locator(".dash-resize").all() if h.is_visible()]  # "Resize on a wider screen"
    page.locator(".widget .dash-handle").nth(1).focus()
    page.keyboard.press("Space")
    page.keyboard.press("ArrowUp")
    page.keyboard.press("Space")
    said(page, "Dropped at position 1 of 9.")
    assert page.evaluate("() => document.documentElement.scrollWidth") <= 390

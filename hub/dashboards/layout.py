"""Layout math shared with the browser (round4-dashboard-spec.md 5.6, 10.5): a Python port of ``collides``,
``sortReading``, ``compact``, ``firstFit`` and ``validate`` from ``hub/web/js/dashboard/grid.js``. Both are tested
against the same fixtures (``tests/data/dashboard_layouts.json``), so the server places template widgets and checks
saved layouts exactly as the client arranges them.

Items are dicts ``{id, x, y, w, h}`` (extra keys are kept); every function returns new dicts and never changes its
arguments.
"""

from __future__ import annotations

from typing import Any, Iterable

from .models import COLS, MAX_ROWS

Item = dict[str, Any]


def collides(a: Item, b: Item) -> bool:
    return a["x"] < b["x"] + b["w"] and b["x"] < a["x"] + a["w"] and a["y"] < b["y"] + b["h"] and b["y"] < a["y"] + a["h"]


def sort_reading(items: Iterable[Item]) -> list[Item]:
    """Reading order: row, then column, then id."""
    return sorted(items, key=lambda i: (i["y"], i["x"], str(i["id"])))


def compact(items: Iterable[Item]) -> list[Item]:
    """Vertical gravity: each item, in reading order, moves up while y > 0 and it does not collide with the items
    already placed. Returns the items in reading order."""
    placed: list[Item] = []
    for item in sort_reading(items):
        moved = dict(item)
        while moved["y"] > 0 and not any(collides({**moved, "y": moved["y"] - 1}, p) for p in placed):
            moved["y"] -= 1
        placed.append(moved)
    return sort_reading(placed)


def first_fit(items: Iterable[Item], w: int, h: int, cols: int = COLS, max_rows: int = MAX_ROWS) -> tuple[int, int] | None:
    """The first free (x, y) for a w x h item, scanning rows top-down and columns left to right; None when full."""
    taken = list(items)
    w = max(1, min(w, cols))
    for y in range(0, max_rows - h + 1):
        for x in range(0, cols - w + 1):
            candidate = {"x": x, "y": y, "w": w, "h": h}
            if not any(collides(candidate, t) for t in taken):
                return x, y
    return None


def place(sizes: Iterable[tuple[int, int]], cols: int = COLS, max_rows: int = MAX_ROWS) -> list[tuple[int, int] | None]:
    """Positions for items added one after another with ``first_fit`` (templates; "Add" in the gallery)."""
    taken: list[Item] = []
    out: list[tuple[int, int] | None] = []
    for w, h in sizes:
        spot = first_fit(taken, w, h, cols, max_rows)
        out.append(spot)
        if spot is not None:
            taken.append({"x": spot[0], "y": spot[1], "w": w, "h": h})
    return out


def validate(items: Iterable[Item], cols: int = COLS, max_rows: int = MAX_ROWS) -> list[dict[str, str]]:
    """The server's layout rules as a list of problems ``{code, id}`` (empty: valid): ``duplicate_id``,
    ``out_of_bounds`` (x, y < 0, w, h < 1, x + w > cols, y + h > max_rows) and ``overlap`` (named once, by the later
    item in input order)."""
    problems: list[dict[str, str]] = []
    seen: set[str] = set()
    checked: list[Item] = []
    for item in items:
        wid = str(item["id"])
        if wid in seen:
            problems.append({"code": "duplicate_id", "id": wid})
            continue
        seen.add(wid)
        if (item["x"] < 0 or item["y"] < 0 or item["w"] < 1 or item["h"] < 1 or item["x"] + item["w"] > cols
                or item["y"] + item["h"] > max_rows):
            problems.append({"code": "out_of_bounds", "id": wid})
            continue
        if any(collides(item, other) for other in checked):
            problems.append({"code": "overlap", "id": wid})
        checked.append(item)
    return problems

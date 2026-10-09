# Atrium management panel: Integration map and Segmentation map

## Critique of the submitted design, and the corrected design for implementation

- **Status:** final design for implementation. It replaces the submitted design "Atrium visual management panel: Integration map and Segmentation map (UI design)".
- **Research:** read-only, done 2026-10-09 against the working tree of branch `feature/login-sso-integrations-agent-teams`. Other agents were editing the repository during the review, so the line numbers cited below may drift. Example: `Approval.kind` gained `"agent_team"` while I was reading it.

### Fact labels
| Label | Meaning |
|---|---|
| **[repo]** | I read it in the working tree. |
| **[V]** | I checked it today in official documentation. The URL and doc date are in section 16. |
| **[V-d]** | The original designer verified it against the cited official page. I did not re-fetch it. |
| **[U]** | Unverified: memory, a secondary source, or my own inference or computation. |

---

# Part 1. Critique

## 1.1 Verdict

The submitted design has three strengths:
- clear accessibility intent;
- correct reading of the approval-routing trap for flows (approvals must be requested by `"supervisor"`);
- a sensible split between the integration and segmentation views.

It is not implementable as written, for four reasons:
1. **The engine is overbuilt for a codebase with no libraries and no build step.** It combines free-form positioning, snapping, alignment guides, overlap nudging, zone resizing, obstacle-avoiding orthogonal A* routing with lane nudging and label collision, a spatial index, culling pools and an undo store. Most of this exists only to support free-form layout, which the request ("drag and drop arrows to connect") does not need.
2. **The firewall safety model has gaps.** One operator can push a firewall change through alone. An approved change can be applied to a ruleset that has changed since. The generic connector action path bypasses approvals.
3. **The rule-aggregation semantics are wrong for interface-bound rules.** The compliance evidence built on them can be wrong in both directions: false violations and false passes.
4. **Several "what exists today" statements are stale** against the working tree.

## 1.2 Findings, most severe first

| # | Severity | Area | Finding | Evidence | Fixed in |
|---|---|---|---|---|---|
| F1 | Critical | Safety | **The same operator can propose and approve a firewall change.** The design (section 9) lets operators approve. | `POST /api/approvals/{id}` falls under the default non-GET rule, so it needs only operator (`auth/policy.py` `required_role`). `Approvals.decide` never compares the decider with the requester (`approvals.py:39-56`). [repo] | 6.6 S4, S5 |
| F2 | Critical | Safety | **An approval is not bound to what gets applied.** `FirewallChange.revision` exists in the design, but apply never checks it, and proposals never expire. A change approved hours later lands on a ruleset that has changed. | design 5.5, 7 | 6.6 S6, S7 |
| F3 | Critical | Safety | **The generic `connector.action` path bypasses approvals.** `ToolSupervisor.on_connector_action` runs any action the connector lists, for any bus sender. The design's connector contract ("writes: apply a change") would naturally be an action, so any agent could apply firewall changes. | `tool_supervisor.py:183-191`, `connectors/base.py:415` [repo] | 6.1, 6.6 S8 |
| F4 | High | Safety | **One operator can "Roll back" an applied change without approval** (design 5.5 and 13.2). That can re-enable a rule an approver disabled, which re-opens exposure. | design | 6.6 S9, S10 |
| F5 | High | Correctness | **Edge aggregation ignores which interface a rule is bound to.** "`any` expands to all zones including `z:internet`" turns a LAN-interface rule with source `any` into edges from every zone, Internet included. Floating rules are left out, so some allowed paths are missed (false "compliant"). | design 5.3. pf-style semantics are [U] | 6.4 |
| F6 | High | Compliance | **`HB-NW-*` controls would be scored automatically from approximate rules and heuristic zone roles.** That produces false pass or fail evidence in the Compliance hub. | design 5.4, 7 | 6.5 |
| F7 | High | Correctness | **The Connect panel can create a pull and a push of the same domain for the same tool.** The planner deliberately never does this, "so nothing loops back". | `strategies.py:9-10, 66-71` [repo] | 5.6, 8 |
| F8 | High | Usability | **Moving a tool and releasing it over an identity provider opens the SSO picker and snaps the node back.** A layout gesture is overloaded with a proposal flow, so mis-drops are likely. | design 4.3(3) | 5.5 |
| F9 | High | Usability, safety | **Asset chips inside zones look movable, but dragging one between zones has no defined meaning.** People will read it as "move the server into the DMZ". | design 5.2 and 3.9 | 6.3 |
| F10 | High | Feasibility | **Engine scope (finding F10 below the table) is the main delivery risk.** | design 3 | 4 |
| F11 | High | Accessibility | **Handles, resize grips and the focus ring sit inside the zoomed camera group (`l-ui`).** At zoom k = 0.25-0.5, a 24-unit handle is only 6-12 CSS px, which fails WCAG 2.5.8 (24 px). | design 3.5. 2.5.8 [V] | 4.5 |
| F12 | Medium | Accessibility, usability | **Some edges cannot be clicked.** Lanes are 6 px apart but the invisible hit strokes are 14 px wide, so the topmost edge always wins. | design 3.6, 3.11 | 4.6 |
| F13 | Medium | Accessibility | **`role="toolbar"` is used without arrow-key navigation.** The APG toolbar pattern is one tab stop with arrows moving between controls. | APG toolbar [V] | 9 |
| F14 | Medium | Accessibility | **`modal()` never returns focus when it closes.** Keyboard users who open the Connect panel from the canvas lose their place. | `ui.js:264` [repo] | 3.2 |
| F15 | Medium | Accessibility | **The keyboard map misses macOS:** the Delete key reports `Backspace`, and Undo is Cmd+Z. | [U] (memory) | 9.3 |
| F16 | Medium | Contrast | **Several proposed colours fail 3:1 against the canvas (WCAG 1.4.11).** | computed [U] | 11 |
| F17 | Medium | Clutter | **One SSO edge per tool, plus event routes, overloads the map.** Each IdP edge crosses the whole map. | design 4.2 | 5.3 |
| F18 | Medium | Data, permissions | **A shared `hidden` list lets one operator hide a tool (for example a failing one) from everyone.** Separately, a zone-role override needs only operator, yet it changes compliance verdicts. | design 6.3, 7 | 4.9, 10 |
| F19 | Medium | Live updates | **Snapshot/event race.** The design fetches first and subscribes second, then applies `flow` patches without checking their age. Events arriving during the fetch are lost, and stale events can overwrite fresh data. | design 3.12 | 4.8 |
| F20 | Medium | Feasibility | **Pointer capture on a handle element is lost if that element is re-rendered or removed** (for example, the hover layer disappears). | design 3.7 [U] | 4.6 |
| F21 | Medium | Rendering | **Arrowhead markers are not covered by `non-scaling-stroke`.** MDN says nothing about markers; my expectation is that they scale with the camera, which would mean a 10× size range. | MDN vector-effect [V] (silent); behaviour [U] | 4.5 |
| F22 | Medium | Repository drift | **Several "what exists today" claims are stale** (finding F22 below the table). | [repo] | 2 |
| F23 | Medium | Reuse | **The design re-implements things `flows.js` already does:** flow actions, the options form and the schedule select. `wireFlows` (`flows.js:215-269`), `optionsForm`/`readOptions` (`:111-148`) and `SCHEDULES` (`:16-18`) cover them. That makes `options_schema` and `GET /api/flows/{id}` unnecessary. | [repo] | 3.2, 5.6, 5.7 |
| F24 | Low | Data exposure | **Viewer payloads would carry raw webhook URLs** (they can hold tokens in the query string). Toolbus log entries carry event payloads. | `toolbus.py:24-38, 41-59` [repo] | 7.1 |
| F25 | Low | Copy | **The "No firewall" empty state promises a connector that does not exist.** The registry has only `snipeit`, `openvas`, `ciso_assistant` and `generic_rest`. | `connectors/__init__.py:19` [repo] | 12 |
| F26 | Low | Performance claims | **The budgets are targets presented as facts.** Details below the table. | RAIL [V-d] | 4.10 |
| F27 | Low | Safety | **Writes are allowed with `rollback.mode = "none"`.** | design 5.1 | 6.6 S2 |
| F28 | Low | Safety | **There is no anti-lockout check.** Disabling the rule that lets the hub reach the firewall API leaves the hub unable to confirm or repair. | design | 6.6 S12 |
| F29 | Low | Model | **The two pseudo-zones `z:internet` and `z:external` overlap in meaning.** | design 5.2 | 6.2 |

**F10 in detail (engine scope).** The design needs all of the following, with no libraries:
- free positioning, a snap grid, alignment guides and overlap nudging;
- zone resizing;
- A* routing on a visibility grid, plus lane nudging and label collision;
- a spatial index, culling with element pools, and an undo store.

Most of this exists only to support free-form layout, which the request does not ask for.

**F16 in detail (contrast).** Values computed with the WCAG relative-luminance formula [U]:

| Colour | Used for | Against | Ratio |
|---|---|---|---|
| light `--faint` `#8a94ab` | disabled edges; guest and IoT zones | light canvas background | 2.91:1 |
| `--border-strong` | unknown-zone border | canvas background, both themes | 1.40-1.59:1 |
| light `--warn` | DMZ zone border | its own 5% tint | 2.89:1 |
| today's flow colour `#0ea5e9` | flow edges | white | 2.77:1 |

**F22 in detail (repository drift).**
- A Vulnerabilities view exists: `app.js:12, 27` and `views/vulnerabilities.js`. Its app icon and colour are `bug` and `#dc2626`, not `alert` and `#ea580c`.
- `KIND_ICON` already covers `flow`, `scan` and `repair` (`approvals.js:7`).
- Tabs switch with `history.replaceState` plus an in-view re-render, not by changing the hash (`vulnerabilities.js:340`, `compliance.js:161`, `tools.js:230`).
- `--sev-*` tokens exist (`app.css:25-29, 54-58`).
- `integration.js:135` already listens to `flow`, `flow_removed` and `connection`.
- Line references have moved:

  | Item | Now at |
  |---|---|
  | router | `app.js:275-306` |
  | `startEvents` | `app.js:309-314` |
  | `[data-min-role]` rule | `app.css:323-324` |
  | `.portal-frame` | `app.css:422` |

- The baseline's NIS2 references use Directive Art. 21 points such as `21(2)(i)` (`grc/baseline.py:12-16, 31-50`), not CIR strings.

**F26 in detail (performance claims).**
- The 3600-element estimate leaves out badges and label backgrounds.
- In current engines, a transform change on one `<g>` repaints the whole SVG [U].
- A 4000-step A* cap per edge × 800 edges cannot meet 50 ms.
- Culling with pools adds complexity before anything has been measured.

## 1.3 What the corrected design keeps from the original

- Hash deep links.
- The `ctx.onLeave` hook and the `atrium:events-reconnected` event.
- Routing flow creation through `supervisor`.
- Option rules that mirror `strategies.py`.
- The reconnect, visibility and 120 s re-fetch triggers.
- Layout persistence shared per hub, with the camera kept per browser.
- A non-drag alternative for every drag, a List view, roving focus and a polite live region.
- Reduced motion.
- The `device_changes` guardrail, off by default.
- Approval kind `firewall`, always required.
- The zone-pair matrix.
- `HB-NW-*` controls evaluated by the same function the canvas uses.

---

# Part 2. Corrected design

## 1. Scope and non-goals

**In scope:**
- **A. Integration map.** Tools and the hub apps, linked by data flows. Single sign-on, event routes and capabilities are shown on demand. Operators drag an arrow from one item to another to propose a data flow or SSO.
- **B. Segmentation map.** Shown when a network-capable firewall connection exists. Firewall zones, the assets placed in them, traffic allowed between zones, and compliance and vulnerability overlays. With guardrails on, operators drag an arrow from zone to zone to propose a firewall change; another person approves it.

**Non-goals for v1:**
- free-form node positioning, zone resizing, obstacle-avoiding routing, marquee multi-select, a custom context menu;
- first-match rule evaluation and NAT evaluation;
- editing or removing existing firewall rules, or restricting their services;
- a "People" app (none exists [repo]).

## 2. Repository facts this design depends on [repo]

### Shell
- **Apps and router.** `APPS` is at `app.js:19-31`. The Vulnerabilities app has route `vulnerabilities`, icon `bug`, colour `#dc2626`. The Integration hub has route `integration`.
- **Fresh `<main>` per page.** `route()` (`app.js:275-306`) replaces `<main>` with `old.cloneNode(false)`. That copies attributes, so classes added to `<main>` leak into the next page.
- **View context.** `ctx = {params, state, live(types, fn, wait=350), crumb}`. `live` debounces. Disposers run on the next route.
- **Event stream status.** `startEvents` is at `app.js:309-314`. `connectEvents` calls `onStatus(true)` on every `EventSource` `open`, and `onStatus(false, closed)` on error (`api.js:49-65`).
- **Tab convention.** Views keep the tab in `ctx.params[0]`. Tab clicks call `history.replaceState` and re-render inside the view. No `hashchange` fires.
- **`ui.js`.**
  - `html`, `raw`, `setHTML`.
  - `icon(name)`: `ICONS` (`ui.js:32-81`) is not exported. It already has `cloud`, `server`, `lock`, `users`, `shield`, `key`, `wrench`, `alert`, `bug`, `radar`, `flow`, `link`, `box`.
  - `can`, `appIcon` (`:155-161`), `badge`, `diffView` (`:225-232`).
  - `modal` (`:253-286`): no close callback, no focus restore. `confirmDialog`, `emptyState`, `actions`, `toast`, `timeAgo`, `timeIn`, `dateTime`, `debounce`.
- **`api.js`.** Error objects carry `status` and `code`; `code` is read from `data.code ?? detail.code`, so `HTTPException(detail={"code": ...})` works (`api.js:15`).

### Reusable flow and SSO UI
- **`flows.js`.**
  - Exports `DOMAINS` (labels, icons and hrefs for `assets`, `vulnerabilities`, `risks`, `controls`), `scheduleLabel`, `countsText`, `endName`, `flowsTable`, `wireFlows`, `planFlows`.
  - `wireFlows(root, {find, refresh, names})` handles `data-act` values `flow-toggle`, `flow-enable`, `flow-dismiss`, `flow-run`, `flow-repair`, `flow-edit`, `flow-info` and `flow-delete` inside any root.
  - `SCHEDULES`, `optionsForm` and `readOptions` are module-private.
- **`sso.js`.** `openProviderPicker({toolId, toolName, data, current, done})` (`:26-51`) takes `data` from `GET /api/identity-providers`. It posts `/tools/{id}/sso`, which leads to a Patch Agent proposal.

### CSS (`app.css`)
- **Tokens.** Dark on `:root`, light on `:root[data-theme="light"]`. Lines 2-58, including `--sev-critical|high|medium|low|info`.
- **`.sr-only`** at `:80`.
- **z-index stack.**

  | Element | z-index | Line |
  |---|---|---|
  | topbar (60 px tall) | 40 | `:84` |
  | mobile sidebar | 50 | `:520` |
  | popovers | 60 | `:151` |
  | backdrop / modal | 80 | `:353` |
  | toasts | 90 | `:367` |

- **`main`:** `max-width: 1440px; padding: 24px` (`:219`), 16 px at 860 px and below.
- **Breakpoints:** 1100, 860, 560 and 460 px.
- **No `prefers-reduced-motion` rules exist yet.**

### Backend
- **`GET /api/integration`** (`api.py:417-425`) returns `suite_matrix` plus `routes`, `deliveries`, `flows` (`flows.public`) and `flow_links`.
- **`flows.public`** (`flows.py:124-126`) = `model_dump` + `tool_id`, `direction`, `owner`, `next_run`, `title`. It includes `options`, `reason` and a sanitized, size-bounded `last_result.sample` (`flows.py:230-242`).
- **Flow events.** The `flow` event carries the raw `Flow.model_dump`, without `direction`, `owner` or `next_run` (`core.py:156-160`, `flows.py:45-47`). `Flow.updated_at` is set on every save.
- **Flow mutations.**
  - `PATCH /api/flows/{id}` (`api.py:460-486`) settles a pending approval when the status changes.
  - `POST /flows/{id}/run` returns 400 while the flow is `proposed` without a job.
  - **No endpoint creates a single flow.**
- **Planner** (`strategies.py:33-103`).
  - Rules: scanner → `scan`; else reads vulnerabilities → pull; writes vulnerabilities → push; assets pull if `(sor or not write)`; assets push if `write and not sor`; writes controls → push; reads risks → pull.
  - Existing flows in any state are skipped.
  - `propose` enables flows directly only when `autonomy == "autonomous"`. Otherwise it creates an approval of kind `flow` requested by `"supervisor"`.
- **Approval routing.** `supervisor.on_approval_decided` (`supervisor.py:191-202`) acts only on kind `flow` approvals sent to it. `Approvals.decide` notifies `requested_by` (`approvals.py:54-55`).
- **Bus handlers.** Handler name = `on_` + the subject with `.` and `-` replaced by `_` (`agents/base.py:123`).
- **Capabilities and connectors.**
  - `connections.capabilities(conn)` is at `connections.py:260-269`.
  - The connector class declares `capabilities`, `actions` and `system_of_record` (`connectors/base.py:407-416`).
  - Domains are a closed set `assets | vulnerabilities | risks | controls` (`base.py:56`, `models.py:248`).
- **Identity.** `identity.overview(hub)` (`identity.py:631-681`) returns providers, `default`, `needs_choice`, and per-tool `status`, `connected_to`, `selected`, `choice`, `pending`, `applied.can_register`.
- **Duplicate edge sources.** `suite_matrix` produces `capability`, `identity` and `event` links (`compatibility.py:171-210`). `toolbus.routes()` produces the same event pairs with the emitted event name (`toolbus.py:24-38`).
- **Tools.**
  - `Tool.health = {ok, detail, checked_at}` (`tool_supervisor.py:90-102`).
  - Tool ids are slugs (`importer.py:85-90`).
- **Assets.**
  - `assets.addresses(asset)` (`agents/assets.py:26-35`) returns IPs and hostnames, lower-cased.
  - `Vulnerability` has `asset_id`, `host`, `port`, `severity` and computed `overdue`.
- **Events and bus.**
  - The SSE stream sends `retry: 3000` and no `id:` field (`api.py:833-856`).
  - `Bus.publish` drops events for a full subscriber queue (maxsize 500, `bus.py:119-130`).
- **Roles.** GET needs viewer; everything else needs operator. Admin-only exceptions are in `ADMIN_ROUTES` (`auth/policy.py`), including `PATCH /api/settings`. `POST /api/approvals/{id}` is operator.
- **Guardrails.** `DEFAULT_GUARDRAILS = {"scans_need_approval": True}` (`core.py:30`). `SettingsPatch.guardrails` accepts only that key (`api.py:59`). `autonomy ∈ manual | assisted | autonomous` (`config.py:9`).
- **GRC baseline.** Control ids look like `HB-AC-3`. `refs` use `ISO27001` (e.g. `A.8.5 / A.8.20`) and `NIS2` (Art. 21 points like `21(2)(i)`) (`grc/baseline.py`).
- **Tests.** pytest fixtures `client`, `browser`, `sign_in(role)` and `wait_for` (`tests/conftest.py`); a `remote` fixture in `tests/test_fabric.py:113`. There is no JavaScript test runner.

---

## 3. Placement and shell changes

### 3.1 Placement
- The Integration hub (`#/integration`) becomes a tab container, following the existing tab convention.
  - **Tabs:** `Overview | Map | Segmentation`.
  - **Initial tab:** from `ctx.params[0]` (`map`, `segmentation`, otherwise overview).
  - **Tab click:** `history.replaceState(null, "", "#/integration/<tab>")`, then `mountTab(name)`.
- **Deep links.** The route decodes them (`app.js:278`); build them with `encodeURIComponent`.

  | Link | Opens |
  |---|---|
  | `#/integration/map/node/<node id>` | a tool or app node on the Integration map |
  | `#/integration/map/flow/<flow id>` | a data flow on the Integration map |
  | `#/integration/segmentation/zone/<zone id>` | a zone on the Segmentation map |
  | `#/integration/segmentation/edge/<edge id>` | an allowed-traffic edge |
  | `#/integration/segmentation/change/<change id>` | a firewall change |

  Changing the selection updates the hash with `replaceState`, so no history entries pile up.
- **Overview tab** = today's page with two changes:
  - The "Suite map" card (`integration.js:76-79`) and `graph()`/`LINK_COLORS` (`:8-41`) are removed.
  - A summary card takes their place: "Map: N tools, M data flows (k failing, p proposed)", with an "Open map" button.
  - The existing `ctx.live` redraw (`integration.js:135`) returns early when the overview is not the active tab.
- **Tab module interface.** Each tab module exports `mount(container, ctx, {params}) -> {dispose(), select(kind, id)}`. The host calls `dispose()` on tab switch and through `ctx.onLeave`.
- **Command palette** (`app.js:167-171`): add the pages "Integration map" (`#/integration/map`) and "Network segmentation" (`#/integration/segmentation`).
- **Approvals cards:**
  - kind `flow`: "Open on map" link to `#/integration/map/flow/<payload.flow_id>`;
  - kind `firewall`: link to `#/integration/segmentation/change/<payload.change_id>`.

### 3.2 Small shell and toolkit changes
1. **`ctx.onLeave(fn)`** in `route()` (`app.js:292-297`): `onLeave(fn) { disposers.push(fn); }`.
2. **Reconnect signal** in `startEvents` (`app.js:309-314`). Keep a module-level `let streamDown = false`. In the callback:

   ```js
   if (ok && streamDown) window.dispatchEvent(new CustomEvent("atrium:events-reconnected"));
   streamDown = !ok;
   ```

   This also covers the new `EventSource` that `checkSession` opens after a close.
3. **`modal({..., onClose})`.** `close()` (`ui.js:264`) calls `onClose?.()` exactly once. The canvas uses it to return focus to the item that opened the dialog.
4. **Export `ICONS`** from `ui.js` (read-only use). The canvas builds `<symbol id="i-<name>" viewBox="0 0 24 24">` definitions once from it.
5. **Export `SCHEDULES`, `optionsForm` and `readOptions`** from `flows.js`. The Connect panel renders the same schedule and option fields with a pseudo-flow `{domain, direction, options: {}}`.

### 3.3 Full height and focus mode
- **Canvas height.** `.canvas-shell` gets its height from JavaScript at mount and on `window` `resize`:

  ```js
  const top = shell.getBoundingClientRect().top;
  shell.style.height = `${Math.max(420, innerHeight - top - (innerWidth <= 860 ? 16 : 24))}px`;
  ```

  Measuring from the shell's real top handles the wrapping subbar and the tabs, which the fixed `calc()` of `.portal-frame` does not.
- **Never add classes to `<main>`** (they leak through `cloneNode(false)`).
- **Focus mode** (toolbar button or `F`): `.canvas-shell.full { position: fixed; inset: 60px 0 0 0; z-index: 35; height: auto; }`.
  - It sits below the topbar (40), the mobile sidebar (50), popovers (60), modals (80) and toasts (90).
  - Esc leaves it last in the Esc cascade (9.3).
  - The setting is not persisted.
- **Narrow screens.** Below 560 px, the tab opens in List view with a "Show map" button.

---

## 4. Shared canvas engine (`hub/web/js/canvas/`)

### 4.1 Files

| File | Pure | Responsibility |
|---|---|---|
| `camera.js` | yes | `{k, tx, ty}`: `toWorld`, `toScreen`, `zoomAt(sx, sy, f)`, `fit(bounds, viewport, pad)`, `clampK` (k in [0.3, 2]), `ensureVisible(rect, viewport, insets)` |
| `lanes.js` | yes | Lane (swimlane) geometry: item rectangles from `lanes[] = {id, x, width, items: [{id, h}]}`; insertion index for a drop point; fractional order keys (`between(a, b)`); collision normalization (sort by `(order, id)`) |
| `route.js` | yes | Gutter routes (H-V-H) with track assignment per gutter; cubic Bézier routes for secondary edges; label anchor points |
| `text.js` | no | `measure(text, font)` via an offscreen `CanvasRenderingContext2D.measureText`, cached per string; `ellipsize(text, maxPx)` |
| `engine.js` | no | `createCanvas()`: SVG layers, keyed render, pointer state machine, keyboard, tooltip, focus ring, live region, grips |
| `fixture.js` | yes | Synthetic models: integration (200 tools / 400 flows), segmentation (50 zones / 1000 assets / 300 rules) |

What is deliberately left out of v1:
- **spatial index.** Hit testing uses DOM targets and `document.elementsFromPoint`.
- **culling and pools.** They come back only if the measurement gate in 4.10 fails.
- **snapping, guides, resizing, A\*.**

The client never parses CIDRs; the server places assets.

### 4.2 Engine API
```js
import { createCanvas } from "../canvas/engine.js";
const canvas = createCanvas(containerEl, {
  view: "integration" | "segmentation",
  label: "Integration map",                    // root aria-label prefix; counts are appended
  roledescription: "integration map",
  lanes,                                       // [{id, title, x, width}]
  model: { items, edges },                     // Map<id, Item>, Map<id, Edge>; adapter-built
  layout,                                      // {version, items: {id: {order, lane?}}}
  permissions: { move: bool, connect: bool },  // from can() and server writable flags
  adapter: {
    size(item) -> {w, h},
    lane(item, layout) -> laneId,
    draw(item, g, ctx),                        // fills a <g> with createElementNS + textContent only
    edgeStyle(edge) -> {cls, dash, marker, chip | null, primary: bool},
    name(id) -> string,                        // accessible name (state included)
    grips(item) -> ["left" | "right"],         // sides that show a connect grip
    canConnect(srcId, tgtId) -> {ok, reason},  // synchronous hint for highlighting only
    canMove(item) -> {lanes: [laneId]},        // lanes this item may be dropped in
    onConnect(srcId, tgtId), onMove(id, {lane, order}), onSelect(id | null), onOpen(id), onDelete(id),
  },
});
canvas.update(model, layout);          // full snapshot after a fetch; keyed diff, keeps camera and selection
canvas.patchEdge(id, edge);            // SSE patch of one edge
canvas.applyLayout(items);             // remote layout change (ignored for the id being dragged)
canvas.select(id, { reveal: true });
canvas.fit(); canvas.zoomBy(f); canvas.setFilter(fn); canvas.setList(bool); canvas.setFocusMode(bool);
canvas.announce(text);                 // live region
canvas.destroy();                      // removes listeners, ResizeObserver, rAF
```

### 4.3 State
```js
{
  model, layout,
  camera: { k, tx, ty },
  viewport: { w, h, insets: { top, right, bottom, left } },
  ui: {
    selection: id | null, hover: id | null, focus: id | null,
    mode: "idle" | "press" | "move" | "connect" | "pickTarget" | "pan" | "pinch" | "kbMove" | "kbConnect",
    ghost: { from, x, y, target, ok, reason } | null,
    insert: { lane, index } | null,
    filter, pending: [],
  },
  dirty: Set<"lanes" | "edges" | "items" | "screen" | "camera">,
}
```
- Every change marks layers dirty.
- One `requestAnimationFrame` flush renders the dirty layers only.
- A camera change rewrites one `transform` attribute, plus the screen-space layer.
- Selection is single. Multi-select is out of v1.

### 4.4 Coordinates
- World units are CSS px at k = 1. `screen = world * k + t`.
- Convert pointer positions with `(clientX - rect.left - tx) / k`. `rect` is cached on `ResizeObserver` callbacks [V-d] and on `scroll`.
- **Fit:** world bounds of visible items, padded 48 px, with `k ≤ 1.25`.
- **`ensureVisible`:** after a keyboard focus or selection change, pan so the item is not covered by the toolbar or inspector (WCAG 2.4.11 [V-d]).

### 4.5 Rendering
```html
<div class="canvas-shell" data-view="integration">
  <div class="canvas-bar" role="group" aria-label="Map controls">…buttons…</div>
  <div class="notice" data-part="canvas-notice" hidden></div>
  <a class="skip-link" href="#" data-act="list-view">Skip to list view</a>
  <div class="canvas-stage">
    <svg class="canvas" tabindex="0" role="graphics-document" aria-roledescription="integration map"
         aria-label="Integration map: 14 tools, 3 hub apps, 22 data flows" aria-describedby="cv-help-integration">
      <defs><!-- markers, icon symbols, dot-grid and hatch patterns --></defs>
      <rect class="canvas-bg" width="100%" height="100%"/>
      <g class="cam" transform="translate(tx ty) scale(k)">
        <g class="l-lanes"/><g class="l-edges"/><g class="l-items"/><g class="l-chips"/>
      </g>
      <g class="l-screen"/>  <!-- NOT transformed: grips, ghost arrow, insertion bar, focus ring -->
    </svg>
    <div class="canvas-tip" hidden aria-hidden="true"></div>
  </div>
  <aside class="canvas-inspector" aria-label="Details" hidden></aside>
  <div class="canvas-list" hidden></div>
  <p class="sr-only" id="cv-help-integration">…keyboard help…</p>
  <div class="sr-only" aria-live="polite" data-live></div>
</div>
```
- **Keyed reuse.** `<g data-id>` elements are reused across renders. All text is set with `textContent`. Firewall rule descriptions, alias names and interface names are untrusted and only ever rendered this way.
- **Screen-space layer (`l-screen`).** It holds the connect grips (24×24 CSS px; 32×32 with `pointer: coarse` [V-d]), the ghost arrow, the insertion bar and the focus ring. Positions come from `camera.toScreen`, so these stay a constant size at any zoom (fixes F11). It holds at most a handful of elements and is redrawn on camera change.
- **Strokes.** `vector-effect: non-scaling-stroke` on edges and borders [V].
- **Arrowheads.** `<marker markerUnits="userSpaceOnUse">`. After the zoom settles (150 ms debounce), set `markerWidth`/`markerHeight` to `base / k` on the 6-10 marker definitions. Verify in Chrome, Firefox and Safari in step A5 [U].
- **Icons.** `<use href="#i-<name>">`. No `foreignObject`.
- **Text.** Item labels are ellipsized with `text.js`. The full name goes in the accessible name and the tooltip.
- **Level of detail** (integration): below k = 0.5, hide subtitles and edge chips; below k = 0.35, hide badges.
- **Edge chips** are drawn only for states that need attention (proposed, failing, running, repair pending) and for the selected or focused edge. Enabled, healthy flows have no chip.
- **Motion.** Dash animation for running flows and 180 ms camera transitions. Both are off under `prefers-reduced-motion: reduce` [V-d].

### 4.6 Hit testing and pointer state machine

**Hit testing.**
- Interactive `<g>` elements carry `data-id` and `data-hit="item|edge|grip|lane"`. Clicks resolve with `e.target.closest("[data-hit]")`.
- Each edge has an invisible companion path: `class="hit"`, `stroke: transparent; stroke-width: 14px; pointer-events: stroke; vector-effect: non-scaling-stroke`.
- **Overlapping edges** (fixes F12). On click, `document.elementsFromPoint(x, y)` is filtered to `[data-hit=edge]`.
  - One edge: select it.
  - More than one: a small popover lists them as buttons ("Snipe-IT assets → Hub Assets", …).
  - The List view is the equivalent control under WCAG 2.5.8 [V].
- **During a drag:**
  - The pointer is captured on the root `svg.canvas`, never on a child that may be re-rendered (fixes F20) [U].
  - The dragged item gets `pointer-events: none`.
  - Drop targets come from `document.elementsFromPoint(clientX, clientY)`: the first `[data-hit=item]` [U: elementsFromPoint honours `pointer-events`; verify in step A5].

**Gestures.** `touch-action: none` on `svg.canvas` only [V-d]. This also blocks browser pinch-zoom inside the canvas, so zoom buttons are always present.

| From | Input | To / effect |
|---|---|---|
| idle | `pointerdown` on a grip (`permissions.connect`) | `press(grip)`; capture on svg |
| idle | `pointerdown` on an item body (`permissions.move` and `canMove`) | `press(item)` |
| idle | `pointerdown` on empty space or a lane, or middle button | `pan` |
| any | second touch pointer down | `pinch` (cancel the current gesture and revert it) |
| press | move > 4 px (mouse or pen) or > 10 px (touch) [U] | `move` or `connect` |
| press | `pointerup` without move | click: select. Double-click opens the inspector. Clicking a grip enters `pickTarget` (the click-click alternative) |
| move | move, coalesced per rAF | ghost item follows the pointer; insertion bar in the lane under the pointer if allowed |
| connect | move | ghost arrow from the grip to the pointer; `canConnect` against the item under the pointer; valid targets get an outline, invalid ones dim to 40% and show the reason in the tooltip |
| pickTarget | click on an item | `onConnect`. Status pill: "Choose a target · Esc to cancel" |
| move / connect | pointer within 32 px of the viewport edge | auto-pan, up to 12 px per frame |
| move | `pointerup` over an allowed slot | `onMove(id, {lane, order})`, where order = `between(prev, next)` |
| connect | `pointerup` on a valid item | `onConnect(src, tgt)` |
| connect | `pointerup` on an invalid item | toast with the reason; no side effects |
| move / connect | `pointerup` on empty space, `pointercancel`, `lostpointercapture`, Esc | revert; no side effects [V-d] |
| pinch | two-pointer change | `zoomAt(midpoint, d/d0)` and pan by the midpoint delta |

**Wheel** (listener with `{passive: false}` [V-d]):
- `ctrlKey || metaKey`: zoom at the cursor, `factor = exp(-deltaY * 0.0015)`. Trackpad pinch arrives as `wheel` with `ctrlKey` set [V: MDN]. On macOS Safari this mapping exists too, per WebKit's bug tracker [U, secondary].
- Otherwise: pan by `(deltaX, deltaY)`, normalizing `deltaMode` 1 (×16) and 2 (× viewport height) [U].

### 4.7 Keyboard
See 9.3. All single-key shortcuts are active only while the SVG has focus, which is the "active only on focus" option of WCAG 2.1.4 [V].

### 4.8 Live updates (fixes F19)
1. **Order of operations on mount.** Subscribe with `onEvent` first, buffering events. Then fetch the snapshot. Then:
   - apply buffered `flow` events whose `data.updated_at` is not older than the snapshot copy;
   - if any other relevant event arrived during the fetch, re-fetch once.
2. **Steady state.** Events are queued and flushed once per rAF.
3. **`flow` events.** Patch only if `data.updated_at >= current.updated_at`. The client computes:
   - `direction`: `action == "scan"` → scan, `target == "hub"` → pull, otherwise push;
   - `next_run`: if status is enabled and `schedule_minutes > 0`, `(last_run || 0) + schedule_minutes * 60`, else null (mirrors `flows.next_run`).
4. **Debounced re-fetches:**

   | Events | Delay |
   |---|---|
   | `tool`, `tool_removed`, `connection`, `patch`, `toolbus` | 500 ms |
   | `asset`, `asset_removed`, `vulnerability`, `segmentation`, `firewall_change`, `approval` (kind `firewall`) | 1000 ms |

   `flow_removed` removes the edge directly.
5. **`canvas_layout`** events go to `applyLayout`, except for the id being dragged.
6. **Re-fetch triggers:** `atrium:events-reconnected`, `visibilitychange` to visible, and every 120 s while visible. These cover events dropped by a full SSE queue [repo] and the stream's lack of event ids [V-d].
7. **While dragging,** incoming changes are queued and applied on drop. If the dragged item disappears, the drag is cancelled and announced ("Snipe-IT was removed; move cancelled").
8. **When the stream is down,** a "Live updates paused" chip is shown in the canvas bar.

### 4.9 Layout persistence (fixes F18)
- **Shared (server), per view:** only lane order, plus a left/right lane override for integration tools. Document in section 7.3.
- **Saving.** After a drop, debounced 500 ms, `PATCH /api/layouts/{view}` with the changed ids. The server merges per id (last write wins) and publishes `canvas_layout`.
- **Per viewer (`localStorage`, every access in `try/catch`, the same pattern as `hub.theme`):**
  - `hub.canvas.<view>.camera`
  - `hub.canvas.<view>.hidden` (ids hidden from this viewer's map only)
  - `hub.canvas.<view>.collapsed` (zones)
  - `hub.canvas.<view>.filters`
- **First open with no layout document:** default order is computed on the client and nothing is written until someone moves an item.
- **"Reset arrangement"** (operator): `confirmDialog`, then `DELETE /api/layouts/{view}`.
- **Undo/redo** (Ctrl/Cmd+Z, Ctrl/Cmd+Shift+Z): the last 20 moves of this session, each saved as a new PATCH. Proposals are never undoable; they are withdrawn by rejecting or deleting them.

### 4.10 Performance targets and the measurement gate
All of these are targets, not facts [U]. The RAIL figures are context [V-d].

| Target | Value |
|---|---|
| First render after data arrives | ≤ 300 ms for the integration fixture (200 tools, 400 flows, secondary edges off) and the segmentation fixture (50 zones, 1000 assets clustered, 300 aggregated edges, default filter) |
| Pan and zoom frame | ≤ 16 ms, aim 10 ms |
| `pointermove` handler | ≤ 4 ms |
| Layout and routing for the integration fixture | ≤ 50 ms synchronous |

- **Element estimate.** Integration: about 10 elements per tool × 200 + about 3 per flow × 400 ≈ 3,200. Segmentation: about 40 per zone × 50 ≈ 2,000 plus the visible edges.
- **Instrumentation.** `performance.mark/measure` around layout, route and render when `localStorage["hub.canvas.debug"] === "1"`, with an overlay showing ms and element counts. The fixture is loaded only when the debug flag is on and `localStorage["hub.canvas.fixture"]` is set.
- **Gate (step A5).** If panning the integration fixture exceeds 16 ms per frame in Chrome, Firefox or Safari on a mid-range laptop, add composited panning: during the gesture, set a CSS `transform` on `.canvas-stage > svg` and commit the camera to `g.cam` on gesture end [U]. If that is still too slow, add viewport culling.

---

## 5. View A: Integration map

### 5.1 Lanes (fixes F10)

| Lane | x (world) | Title | Content | Who decides |
|---|---|---|---|---|
| `idp` | -720 | Identity providers | identity providers without a data connection | derived |
| `left` | -360 | Sources | connected tools whose flows mostly bring data into the hub | default derived; operator may swap a tool to `right` |
| `spine` | 0 | Hub apps | Assets, Vulnerabilities, Compliance (and Network in part B) | fixed |
| `right` | +360 | Destinations | connected tools that mostly receive or scan | default derived; operator may swap a tool to `left` |
| `shelf` | +720 | Not connected | tools without a connection (identity providers included) | derived |

- **Sizes.** Items are 184×56. Apps are 208 × (40 + 22 per port). Vertical gap 24. The gutter between lanes is 176, which is room for about 20 routing tracks of 8 px.
- **Default lane** (server field `lane_default`):
  - identity provider without a connection → `idp`;
  - no connection → `shelf`;
  - otherwise count enabled and proposed flows. Pulls > (pushes + scans) → `left`, otherwise `right`.
  - with no flows yet: reads only → `left`, else `right`.
  - An identity provider that does have a data connection goes in `left` or `right` with an IdP badge.
- **Default order within a lane:** primary spine domain (Assets, Vulnerabilities, Compliance), then name. The stored order overrides it.
- **Why this works for routing.** Tools with flows always sit in a lane next to the spine, so every flow edge crosses exactly one gutter.

### 5.2 Nodes
- **Tool node** (`tool:<id>`):
  - Icon: same rule as `appIcon` (`ui.js:155-161`): `manifest.ui.color/icon`, otherwise `colorFor(id)` and the first letter.
  - Name, and subtitle `Source code | Closed source | SaaS · <connector kind or "no connection">`.
  - Status dot: running and `health.ok`.
  - At most 2 badges, text plus glyph, chosen by priority: `failed N×` > `N proposed` > `SSO pending` > `no connection` > role (`IdP`, `scanner`, `system of record`).
  - The score ring moves to the inspector.
- **Hub app nodes:**

  | Node id | Label | Icon and colour | Ports (left and right) | Opens |
  |---|---|---|---|---|
  | `app:assets` | Assets | `box`, `#0d9488` | `assets` | `#/assets` |
  | `app:vulnerabilities` | Vulnerabilities | `bug`, `#dc2626` | `vulnerabilities` | `#/vulnerabilities` |
  | `app:compliance` | Compliance hub | `shield`, `#16a34a` | `controls`, `risks` | `#/compliance` |

  - Labels, icons and hrefs come from `flows.js` `DOMAINS` and `APPS` (`app.js:19-31`). The colours are copied into the adapter with a comment pointing at `app.js`.
  - Each port's y = top + 40 + 22 × index.
- **SSO on the node.** A key glyph with the provider's initial (for example `K`). Its tooltip and accessible name read "signs in through Keycloak" or "single sign-on awaiting approval".

### 5.3 Edges (fixes F17)

| Type | id | Shown by default | Geometry | Editable |
|---|---|---|---|---|
| Data flow | `flow:<flow id>` | yes | H-V-H gutter route from the tool's side facing the spine to the app port of the flow's domain | yes |
| Single sign-on | `sso:<tool id>` | only for the selected tool or IdP, or with the "Single sign-on" filter on | Bézier from the IdP's right side to the tool's left side, 1.5 px | via the SSO picker |
| Event route | `event:<from>:<to>:<event>` | no (filter) | Bézier, 1.5 px, event name chip on hover | no (manifest) |
| Capability | `cap:<from>:<to>:<capability>` | no (filter) | Bézier, 1 px | no |

- **Scan flows** (`action == "scan"`) are one edge, scanner ↔ `app:vulnerabilities`, with a radar glyph and the chip `scan + import`. The tooltip says "Scans in-scope assets from Hub Assets; findings land in Hub Vulnerabilities". No compound edges.
- **Event edges** come from `toolbus.routes()`. The `event` and `identity` links of `suite_matrix` are dropped as duplicates.

**Flow states** (colour + dash pattern + text chip, so state never relies on colour alone; WCAG 1.4.1 and 1.4.11 [V-d]):

| State | Rule (first match wins) | Stroke | Chip |
|---|---|---|---|
| running | `running != null` or `job.status == "running"` | `--edge-flow`, animated dash (static under reduced motion) | `running` / `scan 40%` |
| repair pending | `repair` set | `--edge-bad` + wrench glyph | `repair proposed` / `diagnosing` |
| failing | `status == "enabled"` and (`failures > 0` or `last_result.ok === false`) | `--edge-bad` + alert glyph | `failed N×` |
| proposed | `status == "proposed"` | `--edge-proposed`, dashed `6 4` | `awaiting approval` |
| scan awaiting approval | `job.status == "awaiting_approval"` | `--edge-proposed`, dashed | `scan awaiting approval` |
| enabled | `status == "enabled"` | `--edge-flow`, solid 2 px, arrow toward the data's destination | none (shown on select: `every 60 min` / `by hand`) |
| disabled | `status == "disabled"` | `--edge-muted`, dotted `1 4` | `disabled` (on select) |

**Gutter routing** (`route.js`):
- Each flow is H-V-H: horizontal from the tool's port to a track x in the gutter, vertical to the app port's y, horizontal into the port.
- Tracks are assigned per gutter, ordered by the target port's y, to reduce crossings. Track spacing is 8 px, compressing to 4 px when the gutter is full.
- Corners have radius 8.
- The label anchor is the midpoint of the last horizontal segment.
- Unit tests check that output is deterministic and that two edges in the same gutter never share a track.

### 5.4 Selection, inspection, filters
- **Clicking** an item or edge selects it and opens the inspector (5.7). Hovering or focusing shows a tooltip.
- **Filters popover:**
  - edge types: Data flows (on), Single sign-on, Events, Capabilities;
  - "Failing only", "Proposed only";
  - "Find": dims non-matching items; Enter focuses the first match;
  - "Focus on selection": dims everything outside the selection's 1-hop neighbourhood;
  - "Hidden items": lists this viewer's hidden ids, each with "Show".

### 5.5 Drag interactions (operator and above)
1. **Reorder** (drag a node body):
   - An insertion bar shows inside the node's own lane.
   - Tools in `left`/`right` may also be dropped into the other of those two lanes.
   - Apps, `idp` and `shelf` items reorder only within their lane.
   - On drop: `onMove`, then `PATCH /api/layouts/integration`.
   - **No gesture other than reordering is attached to node bodies.** Dropping a tool over an IdP does nothing special; this removes the overloaded gesture of F8.
2. **Connect** (drag from a grip):
   - **Where grips sit:** on the side facing the spine (left-lane tools: right; right-lane tools: left). Apps have grips on both sides. `idp` items: right. `shelf` items: left.
   - **Grip visibility:** on hover with a fine pointer; only on the selected item with a coarse pointer.
   - **Drop on a hub app or another tool:** `GET /api/integration/map/options?a=<src>&b=<tgt>` loads the options, then the Connect panel (5.6) opens. All options between the pair are listed, whichever way the arrow was drawn; the drawn direction only pre-selects the matching row.
   - **Drop where exactly one end is an identity provider** and the other is a non-IdP tool:
     - already connected to that IdP: toast "Snipe-IT already signs in through Keycloak";
     - otherwise: `openProviderPicker({toolId, toolName, data: identity, current: <IdP id>, done: refetch})`. The picker is the confirmation.
   - **Invalid drops:** IdP ↔ IdP, app ↔ app, an item onto itself, or a tool without a connection onto an app. These show the reason as a toast and do nothing else.
   - **Click-click** (single-pointer alternative, WCAG 2.5.7 [V]): click a grip, then click the target.
3. **Non-drag equivalents** (inspector):
   - "Connect to…": a select of items where `canConnect` is ok, then the same panel or picker;
   - "Single sign-on…";
   - "Move up", "Move down", "Move to Sources" / "Move to Destinations".

**`canConnect(a, b)`** (client-side hint only; the server's options answer is authoritative):

| Pair | Result |
|---|---|
| a == b | not ok |
| app ↔ app | not ok: "Hub apps share data internally" |
| exactly one non-IdP tool and one IdP tool | ok (single sign-on) |
| IdP ↔ IdP | not ok: "Identity providers do not sign in through each other" |
| tool ↔ app, tool has no connection | not ok: "<name> has no connection yet" |
| tool ↔ app, connected tool | ok if some domain d of the app has `read ∈ caps[d]`, or `write ∈ caps[d]` and d ∉ sor, or (d == vulnerabilities and `"scan" ∈ actions`). Otherwise "<name> cannot exchange <domains>" |
| tool ↔ tool | both need connections; ok if some d has (A reads d, B writes d, d ∉ sor(B)) or the reverse. Otherwise "No data these two can exchange through the hub" |

### 5.6 Connect panel
- **Container:** `modal({title: "Connect <A> and <B>", wide: true, minRole: "operator", onClose: restoreFocus})`. Same modal at every width.
- **Option rules** (server function `strategies.connect_options(hub, a, b)`). `proposals()` is refactored to use the same per-tool rule helpers, so the panel and the planner cannot disagree. Notation: `caps = connections.capabilities(conn)`; `cls` = the connector class; app domains are Assets → `assets`, Vulnerabilities → `vulnerabilities`, Compliance → `controls`, `risks`.
  - **Pull** `tool → hub`, domain d: offered when `read ∈ caps[d]`.
    - Recommended exactly when the planner would propose it: (d == vulnerabilities and `"scan" ∉ cls.actions`), or (d == assets and (d ∈ sor or `write ∉ caps[d]`)), or d == risks.
  - **Push** `hub → tool`, domain d: offered when `write ∈ caps[d]`.
    - Blocked if d ∈ `cls.system_of_record`: "<T> is the system of record for <d>; the hub never pushes <d> to it."
    - Recommended when (d == vulnerabilities), (d == assets and not sor), or (d == controls).
  - **Scan:** domain vulnerabilities, `source = "hub"`, `target = "tool:<id>"`, `action = "scan"`, when `"scan" ∈ cls.actions`. Recommended. A vulnerabilities pull is still listed, not recommended: "Findings already arrive through the scan flow."
  - **Loop rule (fixes F7).** A pull of d from T is blocked while a push of d to T is enabled or proposed, and the reverse also holds: "Hub <app> already sends <d> to <T>; pulling them back would loop records." The same rule is enforced by `POST /api/flows` and by `PATCH /api/flows/{id}` when enabling (409 `flow_conflict`).
  - **Tool A ↔ tool B:** for each d where (A reads d, B writes d, d ∉ sor(B)), one chain option "A → Hub <app> → B" with two parts, pull(A, d) and push(B, d). The reverse direction is offered too. Parts that already exist are shown and not re-created. Loop and system-of-record rules apply to each part.
  - **Not connected:** no options. The note reads "Set up the connection first". An "Open connection settings" link to `#/tools/<id>/connection` is shown to admins only (`data-min-role="admin"`), because `PUT /tools/{id}/connection` is admin [repo].
  - **Event routes** matching the pair are listed as information only.
- **Row content:**
  - radio button (one option at a time; a chain is one row);
  - title, direction badge in the same wording as `flows.js:88` ("into the hub", "from the hub", "scan");
  - `recommended` badge, the reason sentence (the planner's wording), and `blocked` text (row disabled).
  - existing parts show their state with "Show" (select the edge), "Enable" (`PATCH status=enabled`) or "Open approval".
- **Fields for the chosen row:**
  - Schedule: `flows.js` `SCHEDULES`, defaulting to the option's `default_schedule` (pull 60, push 60, scan 10080; `flows.py:29`).
  - Options: `flows.js` `optionsForm({domain, direction, options: {}})`, read back with `readOptions`.
  - Scan rows add: "Each scan waits for approval" (when `guardrails.scans_need_approval`) or "Scans start without approval".
- **Submit label:** "Propose" when `autonomy !== "autonomous"`, otherwise "Enable".
  - One `POST /api/flows` per missing part, in order. Each part reports its result inline: proposed (with a link to the approval), enabled, or the error message.
  - The panel stays open (`onSubmit` returns `true`) if any part fails.
  - New edges are drawn at once from the responses.
  - The live region announces, e.g., "Proposed data flow Snipe-IT assets to Hub Assets, awaiting approval".

### 5.7 Inspector
- **Layout.** Side panel 360 px wide. At 860 px and below, a bottom sheet with `max-height: 60vh`.
  - Enter or double-click moves focus into it. Esc returns focus to the item.
  - Flow buttons reuse `wireFlows(inspectorEl, {find, refresh, names})` and the same `data-act` names, so no flow-action code is duplicated.
- **Tool node:**
  - header: icon, name, badges;
  - `.kv`: kind, connector, last test (`timeAgo`, ok or failed), capabilities as a domain × read/write table, actions, system of record, SSO status and provider (`sso.js` `STATUS`), integration score ring, health;
  - incident edges as a list of buttons that select the edge;
  - buttons:
    - Open tool page (`#/tools/<id>`);
    - Connection (`#/tools/<id>/connection`);
    - Connect to…;
    - Single sign-on… (`openProviderPicker`);
    - Run provider registration (when `applied.can_register`; `runRegistration`);
    - Test connection (operator; `POST /tools/{id}/connection/test`);
    - Move up / Move down / Move to other side (operator);
    - Hide from my map.
- **Flow edge:**
  - title, state chips;
  - `.kv`: domain, direction, owner, schedule, next run (`timeIn`), last run (counts via `countsText`, duration, trigger);
  - error block from `last_result.error` (`message`, `status`, `excerpt`), already redacted server-side.
  - buttons (operator, as applicable):
    - `flow-enable` / `flow-dismiss` while proposed (these settle the approval, `api.py:476-482`);
    - `flow-toggle`;
    - `flow-run` (hidden while proposed and no job);
    - `flow-repair` (only after a failure);
    - `flow-edit`, `flow-info`, `flow-delete`.
  - **Delete/Backspace on a selected flow** opens a modal with "Disable" (default, focused), "Remove" and "Cancel".
- **SSO edge:** provider, protocol, strategy (`strategyBadge`), pending patch title with an Approvals link, "Change provider" (picker), "Run provider registration" (when applicable). Delete shows "Single sign-on can be changed here, not removed."
- **Event route:** event, pattern, "webhook set" or "no webhook", recent deliveries for that pair (ok or failed, time). Delete shows "Event routes come from the tools' manifests."

### 5.8 List view (the main screen-reader path)
- The Map/List switch (`L`) and the "Skip to list view" link show the same model as tables:
  - **Tools:** name, lane, connection, flow counts, SSO, buttons (Select on map, Connect to…, Single sign-on…).
  - **Data flows:** the existing `flowsTable(flows, {names})` with `wireFlows`.
  - **Single sign-on:** the existing `identityCard` and `wireIdentity`.
  - **Event routes.**
- All actions work there without the map.

---

## 6. View B: Segmentation map

### 6.1 Dependency: a network read model (proposal for the connector team)
There is no firewall connector, and connector domains are a closed set [repo]. The canvas needs the following. Names are proposals; the connector team owns the final contract.

- **New domain `network`** (read). Extend `Domain` (`models.py:248`) and `DOMAINS` (`connectors/base.py:56`). Add `OWNERS["network"] = "module:network"` and `APPS["network"] = "Hub network segmentation"` (`flows.py:26-28`). Add the planner rule "reads network → pull".
  - A new `module:network` (a `FlowOwner`) runs the pull and stores one snapshot per firewall in collection `network_snapshots` (doc id = tool id).
  - Phase B adds an `app:network` node to the Integration map spine. Its href is `#/integration/segmentation`.
- **`pull("network")` returns one record per firewall:**
  ```json
  {"external_id": "opnsense", "revision": "opaque-ruleset-hash", "read_at": 1760000000.0,
   "interfaces": [{"id": "lan", "name": "LAN", "description": "", "vlan": null, "subnets": ["10.0.10.0/24"], "role": "lan|wan|other"}],
   "zones": [{"id": "trusted", "name": "Trusted", "interfaces": ["lan", "opt1"]}],
   "aliases": [{"name": "MGMT_NET", "cidrs": ["10.0.99.0/24"], "resolved": true}],
   "self_addresses": ["10.0.10.1", "203.0.113.4"],
   "rules": [{"id": "7c1d", "order": 12, "enabled": true, "action": "pass|block|reject", "interfaces": ["wan"],
              "floating": false, "direction": "in|out|any", "quick": true,
              "source": {"any": true}, "destination": {"cidrs": ["10.0.99.0/24"], "alias": "MGMT_NET"},
              "services": [{"proto": "tcp", "ports": "443"}], "log": false, "description": "vCenter from outside",
              "hits": 1532}],
   "nat_evaluated": false}
  ```
  - `zones` may be empty: interfaces then act as zones.
  - `services: null` means any service.
  - An unresolved alias has `resolved: false`.
- **Writes (phase B4) are not `actions`.** A connector that can change rules declares class attributes:
  - `network_write = {"ops": ["allow", "disable_rules"], "rollback": "savepoint" | "none", "window_s": 60}`;
  - methods `preview_change(ops)`, `apply_change(ops, base_revision)`, `confirm_change(token)`.

  They must never appear in `Connector.actions`, so `connector.action` (`tool_supervisor.py:183-191`) cannot reach them (F3). Generated connectors are never write-capable.
- **OPNsense** (example only):
  - The current core firewall API page lists filter commands such as `add_rule`, `set_rule`, `del_rule`, `toggle_rule`, `search_rule`, `get_interface_list`, plus `apply` from the base controller [V, page has no version].
  - The savepoint and timed-rollback flow cited by the original design does **not** appear on that page, and the plugins API page now returns 404 [V, 2026-10-09].
  - Whether rollback is supported must come from the connector's runtime capability, not from this document.

### 6.2 Zones
- **Ids:** `z:<firewall tool id>:<native id>`, plus one pseudo-zone `z:internet` for every address outside known subnets. Assets placed there carry the badge "external" (fixes F29).
- **Containers:** vendor zones or groups when present, otherwise interfaces and VLANs. One level only.
- **Firewall scope:** one firewall at a time, through a selector in the bar when more than one exists. The same subnet seen by two firewalls stays two zones, each with a "same subnet as …" badge.
- **Role.** It drives the lane, the colour and the policy.
  - **Heuristic from names:**

    | Name pattern | Role |
    |---|---|
    | `wan`, `internet`, `outside` | internet |
    | `dmz` | dmz |
    | `mgmt`, `management`, `admin`, `oob`, `ipmi`, `bmc` | management |
    | `srv`, `server`, `prod` | servers |
    | `lan`, `office`, `corp`, `staff`, `users` | users |
    | `guest` | guest |
    | `iot`, `cam`, `printer` | iot |
    | `ot`, `scada`, `ics` | ot |
    | `dev`, `test`, `staging`, `lab` | dev |
    | `backup` | backup |
    | `vpn` | remote |
    | anything else | unknown |

  - `role_source ∈ builtin | heuristic | manual`.
  - Admins override the role (`PATCH /api/segmentation/zones/{id}`, admin, F18).
  - A heuristic or unknown role shows the badge "role not confirmed" and the inspector action "Confirm role…".
- **Lanes** (left to right, trust increasing):

  | Lane | Roles |
  |---|---|
  | Internet | internet |
  | Edge | dmz, remote, guest, iot |
  | Users | users |
  | Servers | servers, dev |
  | Core | management, backup, ot |
  | Unclassified | unknown |

  - Lane x = 0, 380, 760, 1140, 1520, 1900. Zone width is 300.
  - Zone height = 40 (header) + clusters (6.3) + 12.
  - Zones reorder within their lane (layout only). They never change lane by drag, because the lane is the role.

### 6.3 Asset placement (server: `hub/integration/segmentation.py`, standard-library `ipaddress`)
- **Which assets:** all non-retired assets. Addresses come from `agents.assets.addresses(asset)`.
- **Matching:**
  - Each IP literal or CIDR is matched against the subnets of the selected firewall's zones by longest prefix. A CIDR matches only if it is `subnet_of` a zone subnet.
  - The first address that matches decides `zone`. Other matches go to `zones[]` and add the "multi-homed" badge.
  - A non-private address with no match goes to `z:internet` ("external").
  - A private address with no match, or a hostname-only asset, is `unplaced`. The server never does DNS lookups.
- **Manual placement** (operator, `PUT /api/segmentation/placements/{asset_id}`) wins. It is flagged "manual". If an address contradicts it, the asset gets a warning badge.
  - The inspector states: "This only changes where Atrium draws the asset. It does not change the network."
- **Asset chips are not draggable** (F9).
- **Inside a zone:**
  - 12 assets or fewer: individual chips (name, type glyph, worst-severity dot);
  - more than 12: up to 8 type clusters (`server ×42`) with a count and the worst-severity dot;
  - an "Unplaced" tray below the lanes lists unplaced assets.
  - This bounds the element count at any zoom, so segmentation needs no zoom-based level of detail.

### 6.4 Allowed traffic between zones (corrected semantics, F5)
Phase 1 is an **over-approximation** labelled "may allow". For every enabled `pass` rule r:
1. **Ingress zones I(r):**
   - zones whose interfaces are in `r.interfaces` (direction `in` or `any`);
   - for WAN-role interfaces, `z:internet`;
   - for floating rules with no interface, all zones plus `z:internet`.
   - For direction `out` rules, the constraint applies to the destination instead: D ⊆ zones of `r.interfaces`.
2. **Source zones** S = {z ∈ I(r) | r.source intersects z}.
   - `source.any` → all of I(r).
   - `net:<interface>` → that interface's zone.
   - An alias resolves to its CIDRs. An unresolved alias is treated as any, and the edge carries `notes: ["unresolved alias MGMT_NET"]`.
3. **Destination zones** D = {z ∈ zones ∪ {z:internet} | r.destination intersects z} \ S. Traffic inside one zone does not cross the firewall.
4. **Edges.** Add an ordered pair (s, d) for every s ∈ S, d ∈ D. Accumulate services (deduplicated), `any_service`, rule ids and hit counts.
5. **Deliberately not evaluated in phase 1:** block and reject rules, rule order and `quick`, NAT and port forwards, VPN, implicit vendor rules. The canvas shows the banner: "Approximate: block rules, rule order and NAT are not evaluated, so some edges may not be reachable."

Vendor rule semantics differ [U]. Phase 2 does first-match evaluation per (source zone, destination zone, service) behind the same API.

**Drawing:**
- Bézier from the facing sides of the two zones, with an arrowhead.
- Width 1.5 px (1-2 services), 3 px (3-10), 5 px (more than 10).
- `any_service`: hatch pattern plus an `any` chip.
- `bidirectional` (both directions can start connections): one edge with two arrowheads.
- **Default filter:** edges touching the selected zone, plus every possible violation. A toggle shows all allowed traffic; above 60 edges it suggests the matrix (9.4).

### 6.5 Overlays and compliance (F6)
- **Policy** (`GET` viewer, `PUT` admin; JSON in 7.6) is evaluated per edge by `segmentation.evaluate_policy()`. The canvas, the matrix and the GRC checks all use it.
- **Compliance overlay** (toggle, `aria-pressed`):
  - possible violations are drawn in `--edge-bad` with a dashed halo and the chip `may violate HB-NW-1`;
  - compliant edges dim to 35%;
  - the inspector shows the policy rule, the control, its references and a link to `#/compliance/controls`.
- **Vulnerability overlay:**
  - zone headers get a severity bar in `--sev-*` colours and text like `critical 2 · high 5 · overdue 1`;
  - chips and clusters get a worst-severity dot plus a text count in their accessible name.
  - An edge from `z:internet`, `guest` or `iot` into a zone with open critical or high findings gets the chip `exposes 2 critical`. It counts only findings whose `port` (`443`, `443/tcp`) is inside the edge's services, or all findings when `any_service`. Other findings are listed as "not on allowed ports".
- **GRC controls** (new in `grc/baseline.py`; family "Network security"):

  | Id | Title |
  |---|---|
  | `HB-NW-1` | Untrusted zones cannot reach management |
  | `HB-NW-2` | Internet traffic terminates in a DMZ |
  | `HB-NW-3` | Guest and IoT isolated from internal zones |
  | `HB-NW-4` | Production separated from development and test |
  | `HB-NW-5` | No any-to-any pass rules |

  - **References:** `{"ISO27001": "A.8.22", "NIS2": "21(2)(e)"}`, following the baseline's convention. The description mentions "CIR (EU) 2024/2690 Annex 6.8 network segmentation". All three are [U] and must be confirmed against the official texts.
  - **Status rules:**

    | Condition | Status |
    |---|---|
    | no network snapshot | `manual`, detail "No firewall connected; segmentation is not verified" |
    | any possible violation | `partial`, detail "Possible violation: LAN → MGMT (approximate evaluation)". Never `fail` while evaluation is approximate |
    | no violation, all zone roles `manual` or `builtin`, no unresolved alias | `pass` |
    | otherwise | `partial` ("roles not confirmed" / "unresolved aliases") |

### 6.6 Proposing firewall changes: safety model
v1 operations are `allow` (add a pass rule between two zone networks) and `disable_rules`. Editing, removing and restricting rules come later.

| # | Rule | Enforced by |
|---|---|---|
| S1 | Off by default: guardrail `device_changes = false`. Only admins change it (`PATCH /api/settings` is admin). | server |
| S2 | **Writable only when all hold:** role operator or higher; `device_changes` on; the connector declares `network_write` with `rollback != "none"` (F27); the last connection test is ok; the snapshot is 15 minutes old or less ("Refresh first" otherwise); no other change for this firewall is `approved`, `applying` or `verifying`. When any condition fails, the canvas shows no grips and a `.notice` names the reason. | server (`writable`, `reason` in payload and on preview) |
| S3 | Every change is a proposal: approval kind `firewall`, even in autonomous mode. | server |
| S4 | **Four eyes:** only an admin can approve a `firewall` approval, and not the person who proposed it. Guardrail `device_changes_need_second_person`, default `true`; an admin may turn it off for single-admin installations, and that is logged. | `POST /api/approvals/{id}`: 403 `admin_required` / `same_person` |
| S5 | Firewall approvals are decided only on the Approvals page, which shows the diff (`diffView`), violations, impact and justification. The canvas inspector links there and has no Approve button. | client |
| S6 | **Binding.** At proposal time, the preview runs against a fresh read of the live ruleset. The change stores `base_revision` and `ops_hash` (SHA-256 of the canonical ops JSON); the approval payload carries both. Before applying, the executor re-reads the revision. A mismatch sets status `stale` and applies nothing. | `module:network` |
| S7 | Proposals expire 24 h after creation: approval withdrawn, status `expired`. | `module:network` sweep + check before apply |
| S8 | **Execution path.** Only `module:network`, through the tool supervisor subjects `network.apply` and `network.confirm`. Each re-loads the `FirewallChange` and its approval from the store and checks kind `firewall`, status `approved`, not expired, matching `ops_hash`, the four-eyes rule, and the guardrail still on. Never through `connector.action`. | tool supervisor |
| S9 | **Verify, then confirm.** After applying with a savepoint, `module:network` checks within `window_s`: (1) `connector.test` ok, so the hub still reaches the firewall API; (2) a re-read snapshot shows the expected rule added or disabled. Only then does it call `confirm_change`. Otherwise it does not confirm, the firewall reverts, a re-read confirms the revert, and the status becomes `rolled_back`. | `module:network` |
| S10 | After `applied`, a revert is a **new proposal** (`op: "revert"`, pre-filled with the inverse ops, `revert_of`) with its own approval. | server |
| S11 | **Policy.** A `forbidden` violation blocks submit for operators. Admins may submit with a justification of at least 20 characters, and the approval card shows a red "Violates HB-NW-1" banner. A `restricted` violation needs a justification from anyone. | server (422 `policy_forbidden`) and client |
| S12 | **Anti-lockout** (F28). `disable_rules` is refused for any rule whose destination includes a `self_addresses` entry or "this firewall"; S9 check 1 catches the rest. | server |
| S13 | `allow` from the canvas never uses `any`: source and destination are the two zones' networks, and services are explicit, 16 entries at most. | server |
| S14 | **Kill switch.** Turning `device_changes` off makes `approved` changes `blocked` (never applied). A change in `verifying` completes or rolls back as usual. | `module:network` |
| S15 | **Audit.** Activity entries for propose, approve, reject, apply, confirm, roll back, expire and stale. | server |
| S16 | Rule text from the firewall is untrusted. It is rendered only through `html` / `textContent` and is never added to agent or LLM chat tools. | client, server |

**Starting a change** (operator, only when writable):
- drag from a zone's grip (right side of its header) to another zone;
- click-click;
- zone inspector "Allow traffic to…" with From and To selects.

All three open the **Change panel** (`modal`, wide, `minRole: "operator"`):
- From → To, with role glyphs and names, and a "Swap" button;
- services multi-select: presets HTTPS 443/tcp, SSH 22/tcp, RDP 3389/tcp, DNS 53/udp+tcp, ICMP echo; custom rows `{proto ∈ tcp|udp|icmp, ports: "443" | "8000-8080" | "80,443"}`. No "any".
- Log matched traffic (on by default);
- Description (120 characters at most);
- Justification (shown when the preview requires it).
- **Live preview** (`POST /api/segmentation/changes/preview`, debounced 400 ms) shows:
  - the operations, with their placement in words ("top of LAN rules");
  - `diff` through `diffView`;
  - violations with control and references;
  - impact: number of assets in the two zones;
  - rollback mode and window;
  - `writable` / `reason`.
- **Submit "Propose change"** sends `POST /api/segmentation/changes`. The response shows "Waiting for approval by an administrator other than you", with a link to the approval.

**Disabling rules:** select an edge and press Delete/Backspace, or use the inspector's "Disable rules…". The Change panel opens with op `disable_rules`, the edge's rules listed as checkboxes, and no rule checked by default.

**Lifecycle** (chips on the edge and in the bar's "Changes" popover):
```
proposed ──approve──> approved ──> applying ──> verifying (countdown window_s) ──confirm──> applied ──"Revert…"──> new proposal
   │ reject/withdraw     │ expire / revision changed / guardrail off      │ checks fail or no confirm
   v                     v                                                v
rejected / withdrawn   expired / stale / blocked                        rolled_back (automatic)        failed (apply error, nothing changed)
```
- **Pending additions** are drawn as ghost edges: dashed `--accent-2` with a clock glyph and the text "proposed". Pending disables are drawn as a dashed `--edge-bad` strike with the text "disable proposed".
- **During `verifying`,** a banner reads: "Applying change on OPNsense, confirming connectivity (42 s left)", followed by the check list.

---

## 7. Data contracts

### 7.1 `GET /api/integration/map` (new, viewer)
```json
{
  "generated_at": 1760000000.0,
  "autonomy": "assisted",
  "guardrails": {"scans_need_approval": true},
  "apps": [
    {"id": "app:assets", "domains": ["assets"]},
    {"id": "app:vulnerabilities", "domains": ["vulnerabilities"]},
    {"id": "app:compliance", "domains": ["controls", "risks"]}
  ],
  "nodes": [
    {"id": "tool:snipe-it", "ref": "snipe-it", "label": "Snipe-IT", "kind": "oss", "ui": {"icon": null, "color": null},
     "status": "ready", "running": true, "health": {"ok": true, "checked_at": 1759999000.0},
     "score": 82, "level": "good", "is_idp": false, "lane_default": "left",
     "connection": {"kind": "snipeit", "generated": false, "tested": {"ok": true, "at": 1759990000.0}},
     "capabilities": {"assets": ["read", "write"]}, "actions": [], "system_of_record": ["assets"]},
    {"id": "tool:keycloak", "ref": "keycloak", "label": "Keycloak", "kind": "oss", "ui": {"icon": null, "color": null},
     "status": "ready", "running": true, "health": null, "score": 90, "level": "good", "is_idp": true, "lane_default": "idp",
     "connection": null, "capabilities": {}, "actions": [], "system_of_record": []}
  ],
  "flows": ["<flows.public(f) for every flow, unchanged (same as GET /api/flows)>"],
  "sso": [{"id": "sso:snipe-it", "source": "tool:keycloak", "target": "tool:snipe-it", "state": "connected|pending"}],
  "events": [{"id": "event:gitea:ci:push", "source": "tool:gitea", "target": "tool:ci", "event": "push", "pattern": "push*",
              "has_webhook": true, "last_delivery": {"ok": true, "ts": 1759998000.0}}],
  "capability_links": [{"id": "cap:keycloak:gitea:auth.oidc", "source": "tool:keycloak", "target": "tool:gitea", "capability": "auth.oidc"}],
  "identity": "<identity.overview(hub), unchanged: the data openProviderPicker needs>",
  "layout": {"id": "integration", "version": 7, "items": {}}
}
```
- Never include connection `config` or `secrets`, webhook URLs, or toolbus payloads (F24). `last_delivery` is derived from `toolbus.recent(50)`.
- `kind` is `oss | closed | saas`. The subtitle maps it to Source code / Closed source / SaaS.
- `sso` edges come from `identity.overview().tools`:
  - status `connected` → state `connected` from `connected_to`;
  - `pending` → state `pending` from `pending.provider`.
  - Tools whose status is `not_connected` get no edge.
- `flows` uses `flows.public` as-is: options, reason and the bounded sample are already viewer-visible through `GET /api/flows`. So `wireFlows` `flow-info` and `flow-edit` work unchanged, and no `GET /api/flows/{id}` is needed.
- Build it from one call each to `hub.tools()`, `flows.all_flows(hub)`, `connections.all_connections(hub)`, `identity.overview(hub)` and `hub.toolbus.routes()/recent()`. Measure it with 200 tools: `identity.overview` calls `hub.patches(tool.id)` per tool (`identity.py:646`), which reloads every patch each time [repo].

### 7.2 `GET /api/integration/map/options?a=<id>&b=<id>` (new, viewer)
```json
{
  "a": "tool:snipe-it", "b": "app:assets",
  "options": [
    {"id": "pull:assets", "recommended": true,
     "reason": "Snipe-IT keeps an asset inventory and is its system of record: its assets are merged into Hub Assets (matched by address, hostname or serial).",
     "parts": [{"domain": "assets", "source": "tool:snipe-it", "target": "hub", "action": null, "direction": "pull",
                "title": "Snipe-IT assets -> Hub Assets", "default_schedule": 60, "exists": null, "blocked": null}]},
    {"id": "push:assets", "recommended": false, "reason": "",
     "parts": [{"domain": "assets", "source": "hub", "target": "tool:snipe-it", "action": null, "direction": "push",
                "title": "Hub Assets -> Snipe-IT", "default_schedule": 60, "exists": null,
                "blocked": "Snipe-IT is the system of record for assets; the hub never pushes assets to it."}]}
  ],
  "sso": null,
  "events": [],
  "notes": []
}
```
- `exists`: `{"flow_id": "fl_x", "status": "disabled", "approval_id": null}`.
- `sso`, for an IdP pair: `{"tool_id": "snipe-it", "provider": "keycloak", "status": "not_connected"}`.
- In parts, `source`/`target` use flow notation (`"hub"` / `"tool:<id>"`); the client posts them unchanged.
- 404 for unknown ids.

### 7.3 Layout document (collection `canvas_layouts`, doc id = view)
```json
{"id": "integration", "version": 8, "updated_at": 1760000100.0, "updated_by": "alice",
 "items": {"tool:snipe-it": {"order": 1.5, "lane": "left"}, "z:opnsense:lan": {"order": 3}}}
```
- **`GET /api/layouts/{view}`** (viewer) returns the document, or `{"id": view, "version": 0, "items": {}}`.
- **`PATCH /api/layouts/{view}`** (operator): body `{"items": {"<id>": {"order": 2.25, "lane": "right"}}, "remove": ["tool:gone"]}`. Response: the full document.
- **`DELETE /api/layouts/{view}`** (operator) resets it.
- **Validation** (pydantic, `extra="forbid"`):
  - `view` matches `^(integration|segmentation)$`;
  - ids match `^(tool|app|z):[A-Za-z0-9._:\-]{1,200}$`;
  - `order` is finite with absolute value ≤ 1e9;
  - `lane ∈ {"left", "right"}`, allowed only on `tool:` ids in `integration`;
  - at most 5000 items after merging.
- Each write publishes `canvas_layout {view, version, ids, updated_by}`.

### 7.4 `POST /api/flows` (new, operator)
- **Body:** `{"domain", "source", "target", "action": null | "scan", "schedule_minutes"?: 0..525600, "options"?: {}}`.
- **Routing.** Implemented as `ask(p, "supervisor", "flows.create", {..., "actor": p.actor})`, so `supervisor.on_flows_create` creates the flow and, when not autonomous, the approval with `requested_by = "supervisor"`. That is required for `on_approval_decided` to act (`supervisor.py:191-202`).
- **Recording:** `created_by = p.actor`; approval `payload.proposed_by = p.actor`; activity "alice proposed data flow …". The Approvals card shows "proposed by alice".
- **Response 201:** `{"flow": <flows.public>, "approval_id": "ap_x" | null}`.
- **Errors** (`detail = {"code", "message"}`):
  - 400: `no_connection`, `no_capability`, `system_of_record`, `invalid` (from `validate_options` or a bad shape);
  - 409: `flow_exists` (with `flow_id`), `flow_conflict` (loop rule, with `flow_id`).
- **`PATCH /api/flows/{id}`** gains the loop check when `status` becomes `enabled` (409 `flow_conflict`).

### 7.5 `GET /api/segmentation[?firewall=<tool id>]` (new, viewer)
```json
{
  "generated_at": 1760000000.0,
  "firewalls": [{"tool_id": "opnsense", "name": "OPNsense", "snapshot": {"revision": "r-5521", "read_at": 1759999900.0, "age_s": 100, "stale": false},
                 "write": {"capable": true, "ops": ["allow", "disable_rules"], "rollback": {"mode": "savepoint", "window_s": 60}},
                 "writable": false, "reason": "guardrail"}],
  "selected": "opnsense",
  "evaluation": {"mode": "approximate", "notes": ["Block rules, rule order and NAT are not evaluated."]},
  "zones": [
    {"id": "z:internet", "kind": "pseudo", "name": "Internet", "role": "internet", "role_source": "builtin", "lane": "internet",
     "subnets": [], "asset_count": 2, "vuln": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "overdue": 0}},
    {"id": "z:opnsense:opt2", "kind": "vlan", "name": "MGMT", "vlan": 99, "interfaces": ["opt2"], "subnets": ["10.0.99.0/24"],
     "parent": null, "role": "management", "role_source": "heuristic", "lane": "core", "asset_count": 6,
     "vuln": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0, "overdue": 1}}
  ],
  "assets": [{"id": "a_1f2e", "name": "esxi-01", "type": "server", "criticality": "critical", "zone": "z:opnsense:opt2",
              "zones": ["z:opnsense:opt2"], "addresses": ["10.0.99.10"], "placement": "subnet|manual|external",
              "warning": null, "vuln": {"critical": 0, "high": 1, "overdue": 1}}],
  "unplaced": [{"id": "a_77aa", "name": "printer-3", "reason": "hostname only"}],
  "edges": [
    {"id": "zp:z:internet>z:opnsense:opt2", "source": "z:internet", "target": "z:opnsense:opt2",
     "services": [{"proto": "tcp", "ports": "443", "label": "HTTPS", "rule_ids": ["opnsense:7c1d"]}],
     "any_service": false, "rule_count": 1, "bidirectional": false, "approximate": true, "notes": [],
     "rules": [{"id": "opnsense:7c1d", "order": 12, "action": "pass", "enabled": true, "interfaces": ["wan"], "floating": false,
                "source": "any", "destination": "MGMT_NET", "service": "tcp/443", "log": false,
                "description": "vCenter from outside", "hits": 1532}],
     "violations": [{"policy": "untrusted-to-management", "verdict": "forbidden", "control": "HB-NW-1", "possible": true}],
     "exposure": {"critical": 0, "high": 1, "not_on_allowed_ports": {"critical": 0, "high": 0}},
     "pending_changes": ["chg_31"]}
  ],
  "changes": [{"id": "chg_31", "status": "verifying", "op": "disable_rules", "edge": "zp:z:internet>z:opnsense:opt2",
               "approval_id": "ap_44", "rollback_until": 1760000060.0, "proposed_by": "alice"}],
  "guardrails": {"device_changes": false, "device_changes_need_second_person": true},
  "policy_version": 3,
  "layout": {"id": "segmentation", "version": 2, "items": {}}
}
```
- With no network-capable connection, `firewalls` is `[]` and everything else is empty.
- Edge ids are URL-encoded in deep links.

### 7.6 Segmentation policy (`GET` viewer, `PUT` admin, `/api/segmentation/policy`; collection `settings`, id `segmentation_policy`)
```json
{"version": 3, "rules": [
  {"id": "untrusted-to-management", "from": ["internet", "guest", "iot", "users"], "to": ["management"], "verdict": "forbidden", "control": "HB-NW-1"},
  {"id": "internet-must-hit-dmz", "from": ["internet"], "to": ["servers", "users", "dev", "backup", "ot", "management"], "verdict": "forbidden", "control": "HB-NW-2"},
  {"id": "guest-iot-isolated", "from": ["guest", "iot"], "to": ["users", "servers", "backup", "ot", "dev", "management"], "verdict": "forbidden", "control": "HB-NW-3"},
  {"id": "prod-dev-separated", "from": ["dev"], "to": ["servers"], "verdict": "restricted", "control": "HB-NW-4", "except_services": []},
  {"id": "no-any-any", "match": "any_source_any_destination_any_service", "verdict": "forbidden", "control": "HB-NW-5"}]}
```
- `forbidden` is drawn in `--edge-bad`; `restricted` in `--edge-proposed` and passes only for the listed `except_services`.
- Edges touching an `unknown` zone are reported as "cannot evaluate: unclassified zone".

### 7.7 Firewall changes
**Preview request** (`POST /api/segmentation/changes/preview`, operator, no side effects):
```json
{"firewall": "opnsense", "op": "allow", "source_zone": "z:opnsense:lan", "target_zone": "z:opnsense:opt1",
 "services": [{"proto": "tcp", "ports": "443"}], "log": true, "description": "Users to intranet web", "justification": null}
```
For `disable_rules`, the body has `"rule_ids": ["opnsense:7c1d"]` instead of zones and services.

**Preview response:**
```json
{"writable": false, "reason": "guardrail", "base_revision": "r-5521", "ops_hash": "sha256:9f…",
 "ops": [{"kind": "add_rule", "interface": "lan", "position": "top of LAN rules", "rule": {"action": "pass", "source": "LAN net", "destination": "OPT1 net", "service": "tcp/443", "log": true}}],
 "diff": "+ pass in on lan from LAN net to OPT1 net port 443/tcp log  # Users to intranet web",
 "violations": [], "requires_justification": false, "submit_roles": ["operator", "admin"],
 "impact": {"assets": 42, "zones": ["z:opnsense:lan", "z:opnsense:opt1"]},
 "rollback": {"mode": "savepoint", "window_s": 60}}
```

**Create** (`POST /api/segmentation/changes`, operator):
- Implemented as `ask(p, "module:network", "change.propose", {..., "actor": p.actor})`, so the approval's `requested_by` is `module:network`, which also handles the decision.
- **201:** `{"change": {...}, "approval_id": "ap_45"}`.
- **Errors:** 403 `device_changes_disabled` | `not_writable`; 409 `change_in_flight` | `stale_snapshot`; 422 `policy_forbidden` | `justification_required` | `invalid`.

**`FirewallChange` model** (collection `firewall_changes`, SSE event `firewall_change`):
- `id`, `firewall`, `op` (`allow | disable_rules | revert`), `request`, `preview`, `base_revision`, `ops_hash`;
- `status` (`proposed | approved | applying | verifying | applied | rejected | withdrawn | expired | stale | blocked | failed | rolled_back`);
- `approval_id`, `proposed_by`, `justification`, `created_at`, `decided_at`, `applied_at`, `rollback_until`, `result`, `revert_of`.

**Approval payload:** `{change_id, firewall, op, diff, violations, base_revision, ops_hash, proposed_by, justification}`.

---

## 8. Endpoints, models and configuration

| Method | Path | Role | Status | Notes |
|---|---|---|---|---|
| GET | `/api/integration/map` | viewer | new | 7.1 |
| GET | `/api/integration/map/options` | viewer | new | 7.2; `strategies.connect_options` shared with `proposals()` |
| POST | `/api/flows` | operator | new | 7.4; supervisor `flows.create` |
| PATCH | `/api/flows/{id}` | operator | exists | add the loop check on enable (409 `flow_conflict`) |
| POST / DELETE | `/api/flows/{id}/run`, `/repair`, `/api/flows/{id}` | operator | exist | reused through `wireFlows` |
| POST | `/api/tools/{id}/sso` | operator | exists | reused through `openProviderPicker` |
| POST | `/api/tools/{id}/connection/test` | operator | exists | |
| GET / PATCH / DELETE | `/api/layouts/{view}` | viewer / operator / operator | new | 7.3; SSE `canvas_layout` |
| GET | `/api/segmentation` | viewer | new | 7.5 |
| POST | `/api/segmentation/refresh` | operator | new | runs the firewall's `network` flow now (same as `POST /flows/{id}/run`); returns `{started: [...]}` |
| PATCH | `/api/segmentation/zones/{zone_id}` | **admin** | new | `{role?, label?}`; collection `segmentation_zones`. Add `("PATCH", r"/api/segmentation/zones/[^/]+")` to `ADMIN_ROUTES` |
| PUT | `/api/segmentation/placements/{asset_id}` | operator | new | `{zone_id: str or null}` |
| GET / PUT | `/api/segmentation/policy` | viewer / **admin** | new | add `("PUT", r"/api/segmentation/policy")` to `ADMIN_ROUTES` |
| POST | `/api/segmentation/changes/preview` | operator | new | no side effects |
| POST | `/api/segmentation/changes` | operator | new | `module:network` `change.propose` |
| GET | `/api/segmentation/changes[?status=]`, `/changes/{id}` | viewer | new | |
| DELETE | `/api/segmentation/changes/{id}` | operator | new | withdraws a `proposed` change: the proposer, or an admin |
| POST | `/api/segmentation/changes/{id}/revert` | operator | new | creates a new proposal (S10) |
| POST | `/api/approvals/{id}` | operator | exists | for kind `firewall`: 403 `admin_required` unless admin; 403 `same_person` when `p.actor == payload.proposed_by` and the four-eyes guardrail is on |

**Model and configuration changes:**
- `Approval.kind` adds `"firewall"` (`models.py:138`; that list now also contains `"agent_team"` [repo]).
- `approvals.js`: `KIND_ICON.firewall = "shield"`, `APPROVE_LABEL.firewall = "Approve change"`, and `firewallDetails(p)` using `diffView(p.diff)`, a violations banner, "Proposed by", and the justification. Hide the approve button when `p.proposed_by === session.user.username` or the role is not admin; the server enforces both anyway.
- Guardrails:
  - `DEFAULT_GUARDRAILS = {"scans_need_approval": True, "device_changes": False, "device_changes_need_second_person": True}` (`core.py:30`);
  - `SettingsPatch.guardrails: dict[Literal["scans_need_approval", "device_changes", "device_changes_need_second_person"], bool]` (`api.py:59`);
  - two admin toggles in `settings.js` next to the existing scans guardrail.
- Agents: new `module:network` (`FlowOwner`) handling `flow.run` (network pull), `change.propose`, `approval.decided`, the expiry sweep and verification. New tool-supervisor subjects `network.preview`, `network.apply`, `network.confirm`.
- New SSE event types: `canvas_layout`, `segmentation` (`{firewall_ids, generated_at}`, after a snapshot or zone/placement change), `firewall_change`.
- GRC: `HB-NW-1..5` with check keys that call `segmentation.evaluate_policy()` (6.5).

---

## 9. Accessibility

### 9.1 Every drag has a single-pointer, non-drag path (WCAG 2.5.7 [V]; a keyboard path alone does not meet it [V])

| Drag | Single-pointer alternative |
|---|---|
| Reorder node or zone | Inspector "Move up", "Move down", "Move to other side" |
| Connect (integration) | Click the grip, then the target; inspector "Connect to…" (select), then the panel or picker |
| Single sign-on | Inspector "Single sign-on…" (`openProviderPicker`) |
| Allow traffic (segmentation) | Click-click; zone inspector "Allow traffic to…" with From and To selects |
| Disable rules | Inspector "Disable rules…" |
| Pan, zoom, pinch | Bar buttons (zoom out, zoom %, zoom in, fit); keyboard |

### 9.2 Semantics and focus
- **Root.** `svg.canvas` has `role="graphics-document"` (maps to Document [V]), `aria-roledescription`, an `aria-label` with counts, and `aria-describedby` pointing at the help text. The SVG is one tab stop.
- **Items.** `role="graphics-object"` (maps to group [V]) with `aria-roledescription` of "tool", "hub app", "zone" or "asset group", and `aria-label`, for example: "Snipe-IT, tool, Sources, connected, 1 data flow, none failing, signs in through Keycloak".
- **Edges.** `role="graphics-symbol"` (maps to image [V]) with `aria-roledescription` "data flow" or "allowed traffic", and an `aria-label` such as "Data flow, Snipe-IT to Hub Assets, assets into the hub, enabled, last run 5 minutes ago, succeeded".
- **Selection** is stated in the accessible name (", selected") and announced, because `aria-selected` is not supported on these roles [U]. React Flow uses `role="group"` on nodes and edges [V]; either is acceptable.
- **Roving `tabindex`:** one item has `tabindex="0"`, the rest `-1` [V-d APG]. Focusing an item calls `ensureVisible`.
- **Focus ring:** a screen-space rectangle, 2 px `--accent-2` with a 2 px `--surface` halo.
- **Dialogs** opened from the canvas pass `onClose` to restore focus to the originating item (F14).
- **Skip link** "Skip to list view" sits before the SVG. `.skip-link` is visually hidden until `:focus-visible`.
- **Live region:** one `aria-live="polite"` element present from the start [V-d]. It announces mode changes, results, and live state changes **of the selected item only**. Never `assertive`.
- **Tooltips** are HTML, appear on hover and on focus, can be hovered, persist while hovered or focused, and close with Esc (WCAG 1.4.13 [V]). They are `aria-hidden="true"` because the accessible name already carries their text.
- **Map controls bar:** `role="group"` with plain buttons, each a tab stop. It does not claim `role="toolbar"` unless it implements the APG toolbar keyboard model (F13) [V]. Toggles use `aria-pressed`.
- **Targets:**
  - grips, chips that act as buttons, and bar buttons are 24×24 CSS px or larger (32 with `pointer: coarse`), drawn in screen space (WCAG 2.5.8 [V]);
  - items and edges that become small at low zoom rely on the "Equivalent" exception of 2.5.8 (List view, inspector) [V], plus the edge disambiguation popover.
- **Colour** is never the only signal: dash patterns, glyphs and text chips carry state (1.4.1 [V-d]). Graphic contrast is at least 3:1 (section 11).
- **Reduced motion** (`prefers-reduced-motion: reduce` [V-d]): no dash animation, instant camera moves, no `pop`/`fade` animations inside the canvas.

### 9.3 Keyboard map (SVG focused; single-key shortcuts only while it has focus, WCAG 2.1.4 [V]; ignored while focus is in an input)

| Key | Action |
|---|---|
| Up / Down | previous or next item in the same lane |
| Left / Right | the nearest item by y in the adjacent non-empty lane |
| Home / End | first or last item in the current lane |
| Enter | open the inspector; focus moves into it, Esc returns |
| Space | select or deselect (`preventDefault` stops page scrolling) |
| E / Shift+E | next or previous edge of the focused item (focus moves to the edge) |
| M | move mode (operator): Up/Down reorder; Left/Right switch Sources/Destinations where allowed; Enter commits; Esc cancels |
| C | connect mode (operator): arrows cycle through **valid** targets only, in reading order, each announced with its name. Enter opens the panel or picker; Esc cancels. "No valid targets: <reason>" if none |
| S | Single sign-on… for the focused tool (operator) |
| Delete or Backspace | on a selected edge: flow → Disable/Remove dialog; segmentation → Change panel (`disable_rules`); otherwise an announcement of why nothing happens |
| + / − / 0 | zoom in, zoom out, fit |
| Shift + arrows | pan 64 px |
| / | find |
| L | Map/List |
| F | focus mode |
| ? | shortcut help (`modal`) |
| Ctrl+Z / Cmd+Z, Ctrl+Shift+Z / Cmd+Shift+Z | undo or redo a move |
| Esc | cancel the mode, then close the popover or tooltip, then close the inspector, then clear the selection, then leave focus mode |

`Ctrl+K` stays the global palette (`app.js:76`).

### 9.4 List views
- **Integration:** section 5.8.
- **Segmentation:**
  - Zones table: name, role (with "not confirmed"), subnets, assets, findings, actions.
  - Allowed traffic table, one row per edge: from, to, services, rules, "may violate", exposure, actions.
  - Zone-pair matrix `<table>` (`<th scope="col">` and `<th scope="row">`) when the firewall has 20 zones or fewer. Each cell shows the service count and "may violate HB-NW-1" as text, and holds a button that opens the edge inspector.
- **Manual checks in step A8:** keyboard-only run-through; NVDA + Firefox and VoiceOver + Safari smoke tests of the List view and the SVG names.

---

## 10. Roles

| Capability | viewer | operator | admin | Enforced by |
|---|---|---|---|---|
| Pan, zoom, select, inspect, List view, filters, overlays, per-viewer hide | yes | yes | yes | GETs need viewer |
| Reorder items, reset arrangement (shared) | no (hint: "Operators can arrange the map") | yes | yes | `PATCH/DELETE /api/layouts` need operator |
| Create flows, propose SSO, enable/disable/run/repair/delete flows | no | yes | yes | default non-GET rule |
| Approve or reject flows and SSO patches | no | yes | yes | `POST /api/approvals/{id}` |
| Test a connection | no | yes | yes | |
| Set up or change a tool connection | no | no | yes (link to the tool page) | `ADMIN_ROUTES` |
| Place assets manually | no | yes | yes | new route |
| Confirm or override a zone role | no | no | yes | `ADMIN_ROUTES` addition (F18) |
| Edit the segmentation policy; toggle `device_changes` and the four-eyes guardrail | no | no | yes | `ADMIN_ROUTES`; `PATCH /api/settings` is admin |
| Propose, withdraw (own) or revert firewall changes | no | yes, when writable (S2) | yes, when writable | server |
| Approve a firewall change | no | no | yes, not their own (S4) | `POST /api/approvals/{id}` kind check |

- HTML controls use `data-min-role` (`app.css:323-324`) and `modal({minRole})`.
- SVG grips follow the engine `permissions`: `can()` combined with the server's `writable`.
- The server enforces everything regardless of what the client shows.

---

## 11. Theming

New tokens go in `app.css` under a `/* ---------- canvas ---------- */` section. They are defined once on `:root` (dark) and overridden under `:root[data-theme="light"]`. The SVG uses classes and variables only, so a theme switch needs no re-render. `LINK_COLORS` (`integration.js:8`) is deleted.

```css
:root {
  --canvas-bg: color-mix(in srgb, var(--bg) 60%, var(--surface));   /* dark ≈ #0d1627 */
  --edge-flow: var(--link);        /* #8b8ff8: 6.4:1 on canvas */
  --edge-ok: var(--ok);            /* #22c55e: 7.9:1 */
  --edge-proposed: var(--warn);    /* #f59e0b: 8.4:1 */
  --edge-bad: var(--bad);          /* #ef4444: 4.8:1 */
  --edge-event: var(--info);       /* #38bdf8: 8.4:1 */
  --edge-capability: #8b5cf6;      /* 4.3:1 */
  --edge-muted: var(--muted);      /* #8d98b3: 6.3:1; replaces --faint for meaningful strokes */
  --node-bg: var(--surface); --node-border: var(--muted); --node-selected: var(--accent-2);
  --zone-fill-pct: 5%;
  --zone-internet: var(--bad); --zone-edge: var(--warn); --zone-users: var(--ok); --zone-servers: var(--info);
  --zone-core: var(--accent-2); --zone-ot: #db2777; --zone-dev: #0d9488; --zone-unknown: var(--muted);
}
:root[data-theme="light"] {
  --canvas-bg: color-mix(in srgb, var(--bg) 60%, var(--surface));   /* ≈ #f9fafc */
  --edge-proposed: #b45309;        /* 4.8:1; plain --warn is 3.05:1 and 2.89:1 on a 5% warn tint */
  --edge-ok: #15803d;              /* 4.8:1 */
  --zone-edge: #b45309; --zone-users: #15803d;
}
.zone { fill: color-mix(in srgb, var(--zone-c) var(--zone-fill-pct), transparent); stroke: var(--zone-c); }
.zone.unknown { stroke-dasharray: 4 3; }
```

- **Contrast figures** (computed with the WCAG relative-luminance formula [U]; re-check with a contrast tool in step A8). On the light canvas: `--link` 5.5:1, `--bad` 4.6:1, `--info` 3.9:1, `#8b5cf6` 4.1:1, `#db2777` 4.4:1, `#0d9488` 3.6:1, `--muted` 5.1:1, `--accent-2` 4.3:1. The dark-theme figures are in the comments of the `:root` block above.
- **What these values fix:** `--faint` was 2.91:1 on the light canvas, `--border-strong` 1.40-1.59:1, and `#0ea5e9` on white 2.77:1 (F16).
- **Severity** uses the existing `--sev-*` tokens (`app.css:25-29, 54-58`) and the `.sev` classes.
- **Zone role glyphs**, so role is never colour alone:

  | Role | Glyph |
  |---|---|
  | internet | `cloud` |
  | dmz | `shield` |
  | users | `users` |
  | servers | `server` |
  | management | `lock` |
  | unknown | `alert` |
  | other roles | `grid` (the `icon()` fallback) |

- **Hatch pattern** for `any` services: stroke `var(--edge-bad)` at 40% opacity.
- **Proposed and ghost elements** use `--accent-2`. Selection uses `--node-selected` with a 2 px `--surface` halo.

---

## 12. Empty, loading, error and stale states

| Situation | Integration map | Segmentation map |
|---|---|---|
| Loading | Bar visible; centred `.empty.faint` "Loading map…" | same |
| Error | `emptyState("alert", "Could not load the map", err.message, <Retry>)` | same |
| No tools | Apps still drawn; `emptyState("plug", "Nothing to connect yet", "Import a tool and it appears here next to the hub apps.", <Import tool, data-min-role=operator>)` | n/a |
| Tools but no connections | Map drawn; notice: "Tools exchange data through the hub apps. An administrator sets up a tool's connection (Tool > Connection); then drag from the tool to an app." Viewer variant: "Operators can connect tools." | n/a |
| No network-capable connector kind in `GET /api/connectors` | n/a | `emptyState("shield", "No firewall connector yet", "Atrium has no connector that reads firewall zones and rules yet. Once one is available, connect your firewall and its zones appear here.")` (F25) |
| Firewall connector available, none connected | n/a | `emptyState("shield", "No firewall connected", "Import your firewall and set up its connection; its zones and rules appear here.", <Import tool>)` |
| Connected, never read | n/a | `.notice.warn` "Test the firewall connection and run its network flow to read interfaces and rules", with Test and Refresh buttons (operator) |
| Zones but no assets placed | n/a | Zones drawn; notice "Assets appear in a zone when one of their addresses is in its subnet", with a link to `#/assets`; Unplaced tray expanded |
| Snapshot older than 15 min | n/a | `.notice.warn` "Firewall data is from 3h ago" + Refresh (operator); proposing disabled |
| Not writable | n/a | `.notice` with a lock icon and the reason from the server, e.g. "Read-only: device changes are off. An administrator can turn them on in Settings > Guardrails" (the link is visible to admins only) |
| Approximate evaluation | n/a | persistent `.notice` (6.4 step 5) |
| Event stream down | brand mark dims (existing) and a "Live updates paused" chip; re-fetch on reconnect | same |
| Filter hides everything | "No items match the filter" + Clear filter | same |

---

## 13. Implementation plan

Each step can be built and tested on its own. Part A ships without any firewall connector.

**A1. Shell.**
- `ctx.onLeave`, `atrium:events-reconnected`, `modal({onClose})`, export `ICONS`, export `SCHEDULES`/`optionsForm`/`readOptions`.
- Integration tabs (`Overview | Map | Segmentation`) using `replaceState`, with placeholder `emptyState`s; Overview summary card.
- Tests: `pytest` stays green; manual tab and deep-link navigation.

**A2. Server read model and layouts.** `hub/integration/canvas.py`, `GET /api/integration/map`, `/api/layouts/{view}`, `tests/test_canvas.py`:
- app list present; one `sso` edge per connected or pending tool;
- event edges come from routes, not `suite_matrix`;
- no `config`, `secrets`, `webhook` URL or toolbus `payload` key anywhere (walk the JSON);
- viewer can read;
- layout: per-id merge, version increments, viewer gets 403 on PATCH and DELETE, bad ids/order/lane get 422, the 5000-item cap holds, `canvas_layout` is published.

**A3. Options and flow creation.**
- Refactor the planner rules into helpers shared by `proposals()` and `connect_options()`; `supervisor.on_flows_create`; `POST /api/flows`; loop check in `PATCH`.
- Tests (style of `tests/test_fabric.py`):
  - assisted mode: approval kind `flow` with `requested_by == "supervisor"`, and approving it enables the flow;
  - autonomous mode: enabled directly;
  - `manual` behaves like assisted;
  - 409 `flow_exists`; 409 `flow_conflict` (create and enable);
  - 400 `no_capability`, `system_of_record`, `no_connection`;
  - viewer gets 403;
  - `proposals()` output unchanged for the existing connector fixtures (regression).

**A4. Pure JavaScript.** `camera.js`, `lanes.js`, `route.js`, `fixture.js`.
- Tests in `tests/js/*.test.mjs` with Node's built-in runner (`node --test`, stable since Node 20 [V-d]).
- `tests/test_js.py` runs `node --test tests/js` when `node` is on PATH and skips otherwise, so there is no new dependency.
- Cases: zoomAt keeps the point under the cursor fixed; fit clamps; `between()` ordering; insertion index; deterministic routes; no shared track in a gutter; the integration fixture lays out and routes in 50 ms or less under Node.

**A5. Engine DOM and CSS.** `engine.js`, `text.js`, the canvas CSS section, the debug overlay, the fixture harness.
- Manual checklist: pan, zoom, wheel, trackpad pinch (Chrome, Firefox, Safari), touch pinch; reorder; connect; click-click; `pointercancel` (rotate the device mid-drag); Esc; reduced motion; both themes; marker sizing across zoom; `elementsFromPoint` with `pointer-events`.
- Measurement gate from 4.10.

**A6. Integration map, read-only.** Adapter `views/integration-map.js`: lanes, nodes, edges, chips, inspector (reusing `wireFlows`), filters, List view, live updates (4.8), deep links, Approvals "Open on map".
- Test: walk through as a viewer; enable a flow in one tab and watch another tab update; kill the stream and confirm the reconnect re-fetch.

**A7. Integration map, editing.** Reorder with persistence, grips, click-click, the Connect panel, the SSO picker on IdP drops, inspector actions, undo of moves.
- Test: an operator creates a pull flow; it appears dashed; approving it in Approvals turns it solid. A viewer sees no grips, and direct calls return 403.

**A8. Accessibility pass.** Roving focus, modes, live region, help dialog, focus return, contrast re-check, screen-reader smoke tests (9.4).

**B1. Network read model** (with the connector team). Domain `network`, `module:network`, `network_snapshots`, a fake connector registered in `connectors.REGISTRY` and driven with `httpx.MockTransport`.
- Tests: pull stores the snapshot; `segmentation` event published; stale detection.

**B2. Segmentation read model.** `hub/integration/segmentation.py`, `GET /api/segmentation`, zones PATCH (admin), placements PUT, policy GET/PUT, `HB-NW-*` checks.
- Tests:
  - longest-prefix placement, multi-homed, external, unplaced, retired assets excluded, manual override and its warning;
  - interface-bound aggregation: a LAN rule with source `any` creates no Internet edge; a WAN rule does; a floating rule is included;
  - unresolved alias note;
  - policy verdicts; control status rules (manual / partial / pass);
  - viewer read; admin-only role override and policy PUT.

**B3. Segmentation map, read-only.** Lanes, zones, chips and clusters, edges with the default filter, overlays, the zones / allowed-traffic / matrix List views, empty and stale states.
- Test: the segmentation fixture stays within the element and frame budget.

**B4. Firewall change proposals.** Guardrails and Settings toggles; preview, create, withdraw and revert endpoints; `module:network` lifecycle; approval kind `firewall` with the four-eyes check; Change panel; Approvals card. Tests with the fake connector:
- 403 when the guardrail is off;
- an approval is required even in autonomous mode;
- the proposer cannot approve (`same_person`); an operator cannot approve (`admin_required`);
- preview has no side effects (snapshot and connector call log unchanged);
- revision changed before apply → `stale`, nothing applied;
- expired → withdrawn;
- guardrail turned off after approval → `blocked`;
- verification failure → `rolled_back`, with no `confirm_change` call;
- `connector.action` with a write op name is refused;
- anti-lockout refusal;
- `forbidden` violation: operator gets 422, admin passes with a justification;
- revert creates a new proposal.

**B5. Documentation.** `docs/ARCHITECTURE.md`: the canvas, the endpoints, the new SSE events, the network domain, the segmentation policy and controls, and the firewall safety rules S1-S16.

---

## 14. Open decisions

1. **Four-eyes guardrail.** Its default is `true`. Should the switch exist at all? Single-admin installations would otherwise be unable to make firewall changes. Recommendation: keep the switch, default on, log every change to it.
2. **Firewall changes and autonomy.** Should firewall changes ever skip approval in autonomous mode? Recommendation: never (S3).
3. **First-match evaluation.** When to replace the phase-1 approximation, and how the connector contract represents floating rules, NAT and interface groups per vendor.
4. **Network domain contract.** The exact contract and owner of the `network` domain and `module:network` (6.1). Both are proposals here.
5. **Compliance references.** Confirm the `HB-NW-*` reference strings against the licensed ISO/IEC 27001:2022 text and the EUR-Lex text of CIR (EU) 2024/2690. All of them are [U].
6. **Free placement.** Whether operators later need free placement on the integration map. If so, add it as a separate mode with Bézier edges rather than reintroducing obstacle routing.

---

## 15. Line references used in this document

All [repo], 2026-10-09; lines may drift because of concurrent edits.

| Area | References |
|---|---|
| `app.js` | 19-31 APPS; 76 Ctrl+K; 167-171 palette; 275-306 route; 292-298 ctx and disposers; 309-314 startEvents; 317-325 checkSession; 391 global refresh subscription |
| `ui.js` | 32-81 ICONS; 155-161 appIcon; 225-232 diffView; 253-286 modal (close at 264); 288-296 confirmDialog; 314-321 actions |
| `api.js` | 6-29 api and error code; 42-46 onEvent; 49-65 connectEvents |
| `app.css` | 2-58 tokens; 80 .sr-only; 84 topbar z 40; 151 popover z 60; 219 main; 279 .tabs; 292-297 .notice; 323-324 data-min-role; 353 backdrop z 80; 367 toasts z 90; 422 .portal-frame; 513-542 breakpoints |
| `integration.js` | 8 LINK_COLORS; 11-41 graph; 76-79 Suite map card; 135 live |
| `flows.js` | 8-13 DOMAINS; 16-18 SCHEDULES; 105-109 flowsTable; 111-148 optionsForm and readOptions; 215-269 wireFlows |
| `sso.js` | 6-12 STATUS; 26-51 openProviderPicker |
| `approvals.js` | 7-8 KIND_ICON and APPROVE_LABEL |
| Other views | `vulnerabilities.js:340`, `compliance.js:161`, `tools.js:230` (replaceState tabs) |
| `api.py` | 55-59 SettingsPatch; 293-305 connection test; 335-346 SSO; 417-425 integration; 460-486 update_flow; 577-585 decide; 813-830 settings; 833-856 SSE |
| Backend modules | `approvals.py:39-56` decide; `bus.py:119-130` publish and subscribe; `core.py:30` guardrails; `models.py:136-149` Approval; `models.py:248-286` Domain and Flow; `flows.py:26-29, 67, 71-77, 80-108, 124-126, 159-168, 230-242`; `strategies.py:33-81, 84-103`; `supervisor.py:183-202`; `connections.py:59, 66, 260-269`; `connectors/base.py:56, 407-416`; `tool_supervisor.py:90-102, 183-191`; `identity.py:631-681`; `compatibility.py:171-210`; `toolbus.py:24-38, 41-62`; `agents/assets.py:26-35`; `grc/baseline.py:12-16, 30-50` |

---

## 16. Sources

**Verified by me on 2026-10-09 [V]:**
- W3C, Understanding WCAG 2.2 SC 2.5.7 Dragging Movements (updated 10 Aug 2026): https://www.w3.org/WAI/WCAG22/Understanding/dragging-movements.html
- W3C, Understanding SC 1.4.13 Content on Hover or Focus (updated 12 Jul 2026): https://www.w3.org/WAI/WCAG22/Understanding/content-on-hover-or-focus.html
- W3C, Understanding SC 2.5.8 Target Size (Minimum), with the Spacing and Equivalent exceptions (updated 11 May 2026): https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html
- W3C, Understanding SC 2.1.4 Character Key Shortcuts (updated 23 Feb 2026): https://www.w3.org/WAI/WCAG22/Understanding/character-key-shortcuts.html
- W3C WAI-ARIA APG, Toolbar pattern (one tab stop, arrow keys; no date shown): https://www.w3.org/WAI/ARIA/apg/patterns/toolbar/
- W3C, Graphics Accessibility API Mappings 1.0, Recommendation 2 Oct 2018 (graphics-document → Document, graphics-object → Group, graphics-symbol → Image): https://www.w3.org/TR/graphics-aam-1.0/
- MDN, MouseEvent.ctrlKey (trackpad pinch sends wheel with ctrlKey; modified 13 Feb 2026): https://developer.mozilla.org/en-US/docs/Web/API/MouseEvent/ctrlKey
- MDN, vector-effect (Baseline widely available since July 2020; says nothing about markers; modified 3 Apr 2025): https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Attribute/vector-effect
- React Flow, Accessibility (nodes and edges `role="group"`, tabIndex 0, assertive live region; updated 31 Aug 2026), used as a precedent only: https://reactflow.dev/learn/advanced-use/accessibility
- OPNsense, core firewall API reference (no version shown; savepoint and cancel-rollback not present on the page): https://docs.opnsense.org/development/api/core/firewall.html
- OPNsense plugins firewall API page: HTTP 404 on 2026-10-09: https://docs.opnsense.org/development/api/plugins/firewall.html
- ENISA, NIS2 Technical Implementation Guidance (26 Jun 2025, v1.0). The page exists; I could not extract the PDF text: https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance

**Verified by the original designer, not re-fetched by me [V-d]:**
- WCAG 2.2 Understanding 1.4.1, 1.4.11 and 2.4.11; WAI-ARIA APG "Developing a Keyboard Interface"; WAI-ARIA Graphics Module 1.0.
- MDN: aria-live, Element.setPointerCapture, pointercancel, CSS touch-action, wheel event (`passive: false`), ResizeObserver, prefers-reduced-motion, the `pointer` media feature.
- WHATWG HTML Server-sent events; web.dev RAIL; Node.js test runner (stable since v20.0.0).
- The URLs are listed in the submitted design, section 14.

**Unverified or secondary [U]:**
- WebKit Bugzilla 230545, citing 225788 (Safari macOS maps pinch to ctrl+wheel; seen through a search summary only): https://bugs.webkit.org/show_bug.cgi?id=230545
- W3C public-webapps-github post, Oct 2024 (pinch → ctrl wheel in Safari 18): https://lists.w3.org/Archives/Public/public-webapps-github/2024Oct/0088.html
- CIR (EU) 2024/2690 Annex 6.8: the official text was not retrievable (the EUR-Lex fetch returned empty pages): https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/eng
- Secondary summaries of 6.8: https://www.cyberday.ai/requirement/nis2-guide-6-8-network-segmentation and https://nisd2.eu/en/wiki/implementation/nis2-network-security (maps 6.8 to Art. 21(2)(e) and to ISO/IEC 27001:2022 A.8.20-A.8.22)
- ISO/IEC 27001:2022 A.8.22 title: secondary sources only.
- All contrast ratios in sections 1.2 and 11 were computed by me with the WCAG relative-luminance formula, not checked with a tool.


## Confidence notes
- The repository was being edited by other agents during the review. Observed live: Approval.kind gained 'agent_team', and new files hub/llm_providers.py and hub/agents/toolkit.py appeared. Line numbers in the document are from 2026-10-09 and may drift.
- Firewall rule semantics (pf-style interface binding, floating rules, quick, direction) come from memory and are unverified. The corrected aggregation (ingress-zone constraint, labelled as an over-approximation) is a conservative design choice, not a vendor-verified model.
- OPNsense savepoint and timed-rollback endpoints could not be confirmed. They do not appear on the current core firewall API page, and the plugins API page returns 404. The design therefore treats rollback support purely as a runtime capability the connector declares, and refuses writes when the rollback mode is 'none'.
- The NIS2 CIR 2024/2690 Annex 6.8 text and its Art. 21(2)(e) mapping, and the ISO/IEC 27001:2022 A.8.22 title, come only from secondary sources. EUR-Lex returned empty content, and the ENISA PDF was fetched but could not be text-extracted without poppler or pypdf.
- Several engine claims are unverified and must be checked in step A5: SVG markers not following vector-effect non-scaling-stroke, panning a transformed <g> repainting the whole SVG, document.elementsFromPoint honouring pointer-events on SVG hit paths, focusability of SVG elements with tabindex across browsers, and Safari's mapping of pinch to ctrl+wheel (seen only through a WebKit Bugzilla search summary).
- All contrast ratios were computed locally with the WCAG relative-luminance formula, not with a contrast tool. Key results: light --faint on the canvas 2.91:1; light --warn on a 5% warn tint 2.89:1; #b45309 and #15803d about 4.8:1 on the light canvas.
- The aria-selected restriction (not supported on the graphics-* roles) is from memory of ARIA 1.2.
- The performance budgets (first render 300 ms or less, frame 16 ms or less, pointermove 4 ms or less) and the element-count estimates are targets and inferences, not measurements. The design gates further optimisation on fixture measurements.
- The network read-model contract (domain 'network', module:network, network_snapshots, the network_write class attributes, the network.apply/confirm subjects) is my proposal. No firewall connector exists in the registry, and the connector team owns the final contract.
- The submitted design's source facts that I did not re-fetch are marked [V-d] (WCAG 1.4.1/1.4.11/2.4.11, the MDN pointer and touch pages, WHATWG SSE, RAIL, the Node test runner). I re-verified 2.5.7, 2.5.8, 1.4.13, 2.1.4, the APG toolbar pattern, the Graphics AAM mappings, MDN ctrlKey and MDN vector-effect.

## Sources
- https://www.w3.org/WAI/WCAG22/Understanding/dragging-movements.html (updated 10 Aug 2026) [V]
- https://www.w3.org/WAI/WCAG22/Understanding/content-on-hover-or-focus.html (updated 12 Jul 2026) [V]
- https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html (updated 11 May 2026) [V]
- https://www.w3.org/WAI/WCAG22/Understanding/character-key-shortcuts.html (updated 23 Feb 2026) [V]
- https://www.w3.org/WAI/ARIA/apg/patterns/toolbar/ (no date) [V]
- https://www.w3.org/TR/graphics-aam-1.0/ (W3C Recommendation 2 Oct 2018) [V]
- https://developer.mozilla.org/en-US/docs/Web/API/MouseEvent/ctrlKey (modified 13 Feb 2026) [V]
- https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Attribute/vector-effect (modified 3 Apr 2025) [V]
- https://reactflow.dev/learn/advanced-use/accessibility (updated 31 Aug 2026) [V, precedent only]
- https://docs.opnsense.org/development/api/core/firewall.html (no version shown) [V]
- https://docs.opnsense.org/development/api/plugins/firewall.html (HTTP 404 on 2026-10-09) [V]
- https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance (26 Jun 2025, v1.0; PDF text not extracted) [V page only]
- https://bugs.webkit.org/show_bug.cgi?id=230545 [U, seen through search summary]
- https://lists.w3.org/Archives/Public/public-webapps-github/2024Oct/0088.html [U, seen through search summary]
- https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/eng (not retrievable) [U]
- https://www.cyberday.ai/requirement/nis2-guide-6-8-network-segmentation [U, secondary]
- https://nisd2.eu/en/wiki/implementation/nis2-network-security [U, secondary]
- Original design's verified sources, not re-fetched [V-d]: WCAG 2.2 Understanding 1.4.1, 1.4.11, 2.4.11; APG keyboard interface; Graphics ARIA 1.0; MDN aria-live, setPointerCapture, pointercancel, touch-action, wheel, ResizeObserver, prefers-reduced-motion, pointer media feature; WHATWG SSE; web.dev RAIL; Node.js test runner
- Repository files read (working tree 2026-10-09): hub/web/js/app.js, ui.js, api.js, flows.js, sso.js, views/integration.js, views/vulnerabilities.js, views/approvals.js, views/settings.js; hub/web/css/app.css; hub/web/index.html; hub/api.py; hub/auth/policy.py; hub/approvals.py; hub/bus.py; hub/core.py; hub/store.py; hub/config.py; hub/models.py; hub/integration/flows.py, strategies.py, connections.py, identity.py, compatibility.py, toolbus.py, importer.py; hub/agents/supervisor.py, tool_supervisor.py, assets.py, fabric.py, base.py; hub/connectors/base.py, __init__.py, snipeit.py, openvas.py, ciso_assistant.py; hub/grc/baseline.py; tests/conftest.py; tests/test_fabric.py
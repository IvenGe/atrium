// The Change panel (canvas-design 6.6): propose a guarded firewall change - allow traffic between two zones (named
// services, never "any") or disable rules of an allowed-traffic edge - with a live preview (POST
// /api/segmentation/changes/preview, debounced 400 ms; the device is not contacted) and "Propose change" (POST
// /api/segmentation/changes). A proposal waits for an administrator's approval (another person while the second-person
// rule is on): nothing reaches the device from here. Zone names, rule text and the diff come from the device and are
// rendered through html`` (escaped) and diffView only.
import { post } from "./api.js";
import { ROLLBACK, proposedDialog, reasonText, rollbackLabel, stepsView, violationsBanner } from "./netchanges.js";
import { can, dateTime, debounce, diffView, field, html, icon, modal, options, setHTML, timeAgo, timeIn } from "./ui.js";
import { MAX_SERVICES, PRESETS, ROLE_LABEL, canAllow, changeRequest, servicesFrom, zoneLabel } from "./canvas/segmentation-model.js";

const PROTOS = [["tcp", "TCP"], ["udp", "UDP"], ["icmp", "ICMP"]];
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

function ruleText(r) {
  return `#${r.order ?? "?"} ${r.action} ${r.source} -> ${r.destination} ${r.service}${r.log ? " log" : ""}`;
}

function maintenanceText(m) {
  if (!m?.required) return "at once after approval (no maintenance window is required)";
  if (m.open) return html`now: the maintenance window "${m.open.name}" is open`;
  if (m.next && m.expires_before_window) {
    return html`in the next maintenance window, ${dateTime(m.next.start)} (${timeIn(m.next.start)}) - <span class="warn-text">but the approval would expire
      before that window opens, so the change could only be applied as an emergency. Propose it closer to the window.</span>`;
  }
  if (m.next) return html`in the next maintenance window, ${dateTime(m.next.start)} (${timeIn(m.next.start)})`;
  return html`<span class="warn-text">when a maintenance window covers this device - none does yet (Settings > Network changes)</span>`;
}

function previewView(p, changed = false) {
  const fresh = p.snapshot && !p.snapshot.stale;
  return html`
    ${changed ? html`<div class="notice warn" role="status">${icon("refresh")}<div style="min-width:0"><b>The device's rules changed since the previous preview</b>
      <div class="muted" style="font-size:12.5px">Nothing was proposed. This is the preview against the device's new revision: check it, then propose again.</div></div></div>` : ""}
    ${p.writable ? "" : html`<div class="notice warn">${icon("lock")}<div style="min-width:0"><b>Cannot be proposed now: ${reasonText(p.reason)}</b>
      ${(p.reasons || []).filter((r) => r !== p.reason).length ? html`<ul class="cp-list">${p.reasons.filter((r) => r !== p.reason).map((r) => html`<li>${reasonText(r)}</li>`)}</ul>` : ""}</div></div>`}
    ${violationsBanner(p.violations)}
    ${p.requires_justification ? html`<p class="cp-need ${p.submit_roles?.includes("operator") ? "" : "bad-text"}">${icon("alert")}
      ${p.submit_roles?.includes("operator") ? `A justification of at least ${p.min_justification} characters is required.`
        : `Only an administrator can propose this change, with a justification of at least ${p.min_justification} characters.`}</p>` : ""}
    ${p.problems?.length ? html`<div class="notice bad">${icon("alert")}<div style="min-width:0"><b>Refused by the anti-lockout check</b>
      <ul class="cp-list">${p.problems.map((x) => html`<li>${x}</li>`)}</ul></div></div>` : ""}
    <h3 class="nc-h">Operations</h3>${stepsView(p.steps)}
    <h3 class="nc-h">Diff <span class="faint" style="font-weight:400;font-size:12px">(rule text comes from the device)</span></h3>${diffView(p.diff)}
    <dl class="kv cp-facts">
      <dt>Impact</dt><dd>${plural(p.impact?.assets || 0, "asset")} in ${plural((p.impact?.zones || []).length, "zone")}</dd>
      <dt>Rollback</dt><dd>${rollbackLabel(p.rollback)}${p.rollback?.mode ? html` <span class="faint">- ${ROLLBACK[p.rollback.mode]?.[1] || ""}</span>` : ""}</dd>
      <dt>Applied</dt><dd>${maintenanceText(p.maintenance)}</dd>
      <dt>Approval</dt><dd>by an administrator${p.expires_in_hours ? `; it expires ${p.expires_in_hours} h after the proposal` : ""}</dd>
      <dt>Based on</dt><dd>${p.snapshot ? html`revision <span class="mono">${p.base_revision || "-"}</span>, read ${timeAgo(p.snapshot.read_at)}${fresh ? "" : html` <span class="warn-text">(stale: refresh the device first)</span>`}` : "-"}</dd>
    </dl>
    ${p.notes?.length ? html`<div class="nc-notes"><b>Notes</b><ul>${p.notes.map((n) => html`<li>${n}</li>`)}</ul></div>` : ""}`;
}

/**
 * Opens the panel. `zones`: the firewall's zones (GET /api/segmentation); for "allow", `source` / `target` preselect the
 * two ends; for "disable_rules", `rules` are the edge's rules ([{id, order, action, source, destination, service, ...}])
 * and `edge` its id. `onDone(result)` runs after a proposal ({change, approval_id}); `onClose` whenever the panel closes.
 */
export function openChangePanel({ firewall, deviceName, op = "allow", zones = [], source = null, target = null, edge = null, edgeTitle = "", rules = [], onDone, onClose }) {
  const ends = zones.filter(canAllow);
  const zoneOptions = (selected) => [["", "Choose a zone..."], ...ends.map((z) => [z.id, `${zoneLabel(z)} (${ROLE_LABEL[z.role] || z.role})`])].map(([v, t]) =>
    html`<option value="${v}" ${v === (selected || "") ? "selected" : ""}>${t}</option>`);
  const custom = [];
  let last = null; // the preview shown, for the request `lastKey` (the proposal is bound to its base_revision - S6)
  let lastKey = null;
  let changed = false; // the last proposal was refused because the device changed after the preview
  let result = null;
  let seq = 0;
  const unique = [...new Map(rules.map((r) => [r.id, r])).values()].sort((a, b) => (a.order ?? 0) - (b.order ?? 0));

  const allowBody = html`
    <div class="cp-ends">
      <div class="field"><label for="cp-from">From</label><select id="cp-from" name="source">${zoneOptions(source)}</select></div>
      <button type="button" class="icon-btn" data-act="cp-swap" title="Swap From and To" aria-label="Swap From and To">${icon("refresh")}</button>
      <div class="field"><label for="cp-to">To</label><select id="cp-to" name="target">${zoneOptions(target)}</select></div>
    </div>
    <fieldset class="plain cp-services"><legend>Services</legend>
      <div class="cp-presets">${PRESETS.map((p) => html`<label class="check"><input type="checkbox" name="preset" value="${p.id}">${p.label}</label>`)}</div>
      <div data-part="cp-custom"></div>
      <button type="button" class="btn sm" data-act="cp-add">${icon("plus")}Add a service</button>
      <p class="hint">Every service is named: a change never opens "any". Ports like 443, 8000-8080 or 80,443; at most ${MAX_SERVICES} services.</p>
    </fieldset>
    <label class="check" style="margin:10px 0"><input type="checkbox" name="log" checked> Log matched traffic</label>
    ${field("Description", html`<input name="description" maxlength="120" placeholder="e.g. Users to the intranet web servers">`, "At most 120 characters. Atrium adds its marker atrium:<change id> to the rule.")}`;

  const disableBody = html`
    <p class="muted" style="margin-bottom:8px">Rules that allow <b>${edgeTitle}</b>. Choose the rules to disable - none is chosen yet. Only pass rules are listed:
      disabling a block rule would open traffic. Disabling stops <em>all</em> the traffic a rule allows, not only this zone pair.</p>
    ${unique.length ? html`<div class="cp-rules">${unique.map((r) => html`<label class="check cp-rule"><input type="checkbox" name="rule" value="${r.id}">
      <div style="min-width:0"><div class="mono nc-line">${ruleText(r)}</div><div class="faint" style="font-size:12px;overflow-wrap:anywhere">${r.description || "no description"}
        ${(r.interfaces || []).length ? html` · on ${r.interfaces.join(", ")}` : r.floating ? " · floating" : ""}${r.hits != null ? ` · ${r.hits} hits` : ""}</div></div></label>`)}</div>`
      : html`<p class="muted">This edge has no rules to disable.</p>`}`;

  const m = modal({
    title: op === "allow" ? `Allow traffic on ${deviceName}` : `Disable rules on ${deviceName}`, wide: true, minRole: "operator",
    body: html`${op === "allow" ? allowBody : disableBody}
      ${field("Justification", html`<textarea name="justification" rows="3" maxlength="2000" placeholder="Why this change is needed"></textarea>`, "Shown to the administrator who decides; required when the change may violate the segmentation policy.")}
      <section class="cp-preview" data-part="cp-preview" aria-live="polite"></section>`,
    footer: html`<span class="cp-why faint" data-part="cp-why"></span><button type="button" class="btn" data-close>Cancel</button>
      <button type="submit" class="btn primary" data-min-role="operator" disabled>${icon("send")}Propose change</button>`,
    async onSubmit() {
      const req = gather().req;
      if (!req || !ready()) return true; // ready(): the preview shown is of exactly this request
      try {
        // bound to the revision the preview showed: the server refuses (409 stale_snapshot) when the device changed since
        result = await post("/segmentation/changes", { ...req, base_revision: last.base_revision });
      } catch (err) {
        if (err.status === 401) return true;
        if (err.code === "stale_snapshot" && last) { // the proposal re-read the device: preview against its new revision
          changed = true;
          last = null;
          lastKey = null;
          preview();
          return true;
        }
        showError(err, "Not proposed");
        setTimeout(update, 0); // after modal() re-enables its submit button
        return true;
      }
      return undefined;
    },
    onClose: () => {
      if (result) setTimeout(() => { proposedDialog(result); onDone?.(result); }, 0);
      onClose?.();
    },
  });
  const form = m.el;
  const $ = (sel) => form.querySelector(sel);
  const submit = $('button[type="submit"]');

  function drawCustom() {
    setHTML($('[data-part="cp-custom"]'), html`${custom.map((row, i) => html`<div class="cp-row">
      <select name="cproto" data-i="${i}" aria-label="Protocol of service ${i + 1}">${options(PROTOS, row.proto)}</select>
      <input name="cports" data-i="${i}" value="${row.ports || ""}" placeholder="${row.proto === "icmp" ? "no ports" : "443"}" aria-label="Ports of service ${i + 1}" ${row.proto === "icmp" ? "disabled" : ""}>
      <button type="button" class="icon-btn sm" data-act="cp-del" data-i="${i}" aria-label="Remove service ${i + 1}" title="Remove">${icon("x")}</button></div>`)}`);
  }

  function readCustom() {
    form.querySelectorAll("[name=cproto]").forEach((s) => { custom[Number(s.dataset.i)].proto = s.value; });
    form.querySelectorAll("[name=cports]").forEach((s) => { custom[Number(s.dataset.i)].ports = s.value; });
  }

  function gather() {
    const justification = String($("[name=justification]")?.value || "").trim();
    if (op === "disable_rules") {
      const picked = [...form.querySelectorAll("[name=rule]:checked")].map((x) => x.value);
      return { req: changeRequest({ firewall, op, rules: picked, edge, justification }), problems: [], missing: picked.length ? null : "Choose at least one rule" };
    }
    readCustom();
    const presets = [...form.querySelectorAll("[name=preset]:checked")].map((x) => x.value);
    const { services, problems } = servicesFrom(presets, custom);
    const state = { firewall, op, source: $("[name=source]").value, target: $("[name=target]").value, services, log: $("[name=log]").checked,
      description: $("[name=description]").value.trim(), justification };
    if (state.source && state.source === state.target) problems.push("From and To are the same zone: traffic inside a zone does not cross the firewall");
    const missing = !state.source || !state.target ? "Choose both zones" : !services.length ? "Choose at least one service" : null;
    return { req: problems.length ? null : changeRequest(state), problems, missing };
  }

  const out = () => $('[data-part="cp-preview"]');
  function showIdle(text) {
    last = null;
    setHTML(out(), html`<p class="faint cp-idle">${text}</p>`);
    update();
  }
  function showError(err, prefix = "No preview") {
    setHTML(out(), html`<div class="notice bad">${icon("alert")}<div style="min-width:0;overflow-wrap:anywhere"><b>${prefix}:</b> ${err.message}
      ${err.code === "stale_snapshot" ? html`<div class="faint" style="font-size:12.5px">Read the device again (Refresh on the map or "Read now" in the Network app), then try again.</div>` : ""}</div></div>`);
    if (prefix === "No preview") last = null;
    update();
  }

  const keyOf = (req) => JSON.stringify({ ...req, justification: undefined });

  function ready() {
    const just = String($("[name=justification]")?.value || "").trim();
    return !!last && lastKey === keyOf(gather().req || {}) && last.writable && !last.problems?.length && (!last.requires_justification || just.length >= (last.min_justification || 0))
      && (last.submit_roles || []).includes(can("admin") ? "admin" : "operator");
  }
  function update() {
    const ok = ready();
    submit.disabled = !ok;
    let why = "";
    if (!ok) {
      const g = gather();
      const just = String($("[name=justification]")?.value || "").trim();
      why = g.problems[0] || g.missing || (!last || lastKey !== keyOf(g.req || {}) ? "Waiting for the preview" : !last.writable ? "Not possible now (see the preview)"
        : last.problems?.length ? "Refused by the anti-lockout check" : last.requires_justification && just.length < (last.min_justification || 0)
          ? `Write a justification of at least ${last.min_justification} characters` : "");
    }
    $('[data-part="cp-why"]').textContent = why;
  }

  const preview = debounce(async () => {
    const g = gather();
    if (g.problems.length) {
      last = null;
      setHTML(out(), html`<div class="notice warn">${icon("alert")}<ul class="cp-list">${g.problems.map((p) => html`<li>${p}</li>`)}</ul></div>`);
      return update();
    }
    if (!g.req) return showIdle(`${g.missing || "Complete the change"} to see what it would do.`);
    const mine = ++seq;
    out().setAttribute("aria-busy", "true");
    if (!last) setHTML(out(), html`<p class="faint cp-idle">Checking the change against the device's last snapshot...</p>`);
    try {
      const key = keyOf(g.req);
      const p = await post("/segmentation/changes/preview", { ...g.req, justification: undefined });
      if (mine !== seq || !form.isConnected) return;
      last = p;
      lastKey = key;
      setHTML(out(), previewView(p, changed));
      changed = false;
    } catch (err) {
      if (mine !== seq || !form.isConnected) return;
      showError(err);
    } finally {
      if (mine === seq) out().removeAttribute("aria-busy");
    }
    update();
  }, 400);

  form.addEventListener("input", (e) => {
    if (e.target.name === "justification") return update();
    preview();
  });
  form.addEventListener("change", (e) => {
    if (e.target.name === "cproto") { readCustom(); drawCustom(); }
    if (e.target.name !== "justification") preview();
  });
  form.addEventListener("click", (e) => {
    const act = e.target.closest("[data-act]")?.dataset;
    if (!act) return;
    if (act.act === "cp-swap") {
      const a = $("[name=source]"), b = $("[name=target]");
      [a.value, b.value] = [b.value, a.value];
      preview();
    } else if (act.act === "cp-add") {
      readCustom();
      if (custom.length >= MAX_SERVICES) return;
      custom.push({ proto: "tcp", ports: "" });
      drawCustom();
      form.querySelectorAll("[name=cports]")[custom.length - 1]?.focus();
    } else if (act.act === "cp-del") {
      readCustom();
      custom.splice(Number(act.i), 1);
      drawCustom();
      preview();
    }
  });
  if (op === "allow") drawCustom();
  if (op === "allow" && !source) setTimeout(() => $("[name=source]")?.focus(), 40);
  showIdle(op === "allow" ? "Choose both zones and at least one service to see what the change would do." : "Choose the rules to disable to see what the change would do.");
  preview();
  return m;
}

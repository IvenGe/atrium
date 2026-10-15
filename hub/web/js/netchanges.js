// Guarded network device changes in the UI, shared by the Network app, the Approvals page and the segmentation map:
// lifecycle chips, countdowns, the reasons a device cannot be changed now, the change dialog (withdraw, revert,
// emergency apply) and backup restore proposals. Changes are always proposals an administrator approves; nothing
// here writes to a device. Device text (rule lines, diffs, zone and rule names) is untrusted: it is only ever
// rendered through html`` (escaped) or diffView, never as markup.
import { del, get, onEvent, post } from "./api.js";
import { session } from "./auth.js";
import { actions, badge, can, dateTime, diffView, field, html, icon, modal, setHTML, timeAgo, timeIn, toast } from "./ui.js";

const enc = encodeURIComponent;

export const STATUS_TONE = {
  proposed: "warn", approved: "info", scheduled: "info", applying: "info", verifying: "info", applied: "ok",
  rejected: "bad", withdrawn: "", expired: "", stale: "warn", blocked: "warn", failed: "bad", rolled_back: "warn",
};
const STATUS_HELP = {
  proposed: "Waiting for an administrator's approval",
  approved: "Approved; applied next by the Network Supervisor",
  scheduled: "Approved; waits for the next maintenance window that covers the device",
  applying: "A backup is taken and the change is being written to the device",
  verifying: "Written; Atrium checks the device still answers and shows the change before it confirms",
  applied: "Applied, verified and confirmed",
  rejected: "Rejected by an administrator",
  withdrawn: "Withdrawn before it was applied",
  expired: "Not approved and applied in time; propose it again",
  stale: "The device's rules changed since the proposal: nothing was applied; propose it again",
  blocked: "Device changes were switched off before it was applied: nothing was applied",
  failed: "Not applied, or the device's state could not be proven - see the result",
  rolled_back: "Verification failed, the change was rolled back and a re-read proved it",
};
export const WAITING = ["proposed", "approved", "scheduled"];
export const ACTIVE = ["applying", "verifying"];
const PATH = ["proposed", "approved", "scheduled", "applying", "verifying", "applied"];
export const OP_LABEL = { allow: "Allow traffic", disable_rules: "Disable rules", revert: "Revert", restore: "Restore backup" };

export const ROLLBACK = {
  savepoint: ["savepoint", "The device reverts by itself unless Atrium confirms the change within the window."],
  commit_confirm: ["confirmed commit", "The device reverts by itself unless Atrium confirms the commit within the window."],
  deadman: ["dead-man timer", "A timer on the device reverts the change unless Atrium cancels it within the window."],
  backup_restore: ["backup restore", "No device timer: when verification fails, Atrium puts the device's own backup back."],
  none: ["no rollback", "The connector has no safe rollback, so Atrium never changes this device."],
};

/** Why a device cannot be changed now (write_status / preview reasons). */
export const REASONS = {
  not_capable: "This device's connector cannot change it safely (read-only, or no rollback)",
  guardrail: "Device changes are switched off (Settings > Network changes)",
  connection_test: "The last connection test did not pass - test the connection first",
  no_snapshot: "The device has not been read yet - refresh it first",
  stale_snapshot: "The snapshot is older than the freshness limit - refresh first",
  change_in_flight: "Another change of this device is approved, scheduled or being applied",
  op_not_supported: "This device's connection does not offer this kind of change",
  policy_forbidden: "Only an administrator can propose this change (segmentation policy)",
};
export const reasonText = (r) => REASONS[r] || String(r || "").replace(/_/g, " ");

export const statusLabel = (s) => String(s || "").replace(/_/g, " ");
export const statusBadge = (s) => html`<span class="badge ${STATUS_TONE[s] ?? ""}" title="${STATUS_HELP[s] || ""}">${statusLabel(s)}</span>`;
export const rollbackLabel = (rb) => (rb ? `${ROLLBACK[rb.mode]?.[0] || rb.mode}${rb.window_s && rb.mode !== "none" ? `, ${rb.window_s} s` : ""}` : "none");
export const changeHref = (firewall, id) => `#/network/${enc(firewall)}/changes/${enc(id)}`;

/** One line naming what a change does, from its canonical ops (zone ids are the device's, shown as text). */
export function changeSummary(c) {
  const op = c.ops?.[0];
  if (c.op === "allow" && op) {
    const services = (op.services || []).map((s) => (s.ports ? `${s.proto}/${s.ports}` : s.proto)).join(", ");
    return `${op.source?.zone} -> ${op.destination?.zone} (${services})`;
  }
  const rules = (c.ops || []).reduce((n, o) => n + (o.rules?.length || 0), 0);
  if (c.op === "disable_rules") return `disable ${rules} rule${rules === 1 ? "" : "s"}`;
  if (c.op === "revert") return `undo ${c.revert_of || "a change"}${rules ? ` (${rules} rule${rules === 1 ? "" : "s"})` : ""}`;
  if (c.op === "restore") return `put back backup ${c.request?.backup_id || ""}`;
  return c.op;
}

/** The lifecycle as chips: the stages reached, the current one highlighted, and how it ended when off the happy path. */
export function lifecycle(c, compact = false) {
  const seen = new Set((c.history || []).map((h) => h.status));
  seen.add(c.status);
  const off = !PATH.includes(c.status);
  const stages = PATH.filter((s) => (s === "scheduled" ? seen.has(s) : !off || seen.has(s)));
  return html`<ol class="nc-life ${compact ? "compact" : ""}" aria-label="Lifecycle, now ${statusLabel(c.status)}">${stages.map((s) => {
    const state = s === c.status ? "current" : seen.has(s) ? "done" : "todo";
    return html`<li class="${state} ${state === "current" ? STATUS_TONE[s] : ""}" title="${STATUS_HELP[s]}">${statusLabel(s)}</li>`;
  })}${off ? html`<li class="current end ${STATUS_TONE[c.status]}" title="${STATUS_HELP[c.status] || ""}">${statusLabel(c.status)}</li>` : ""}</ol>`;
}

// ---------- countdowns ----------

function left(until) {
  const s = Math.round(until - Date.now() / 1000);
  if (s <= 0) return "due now";
  if (s < 120) return `${s} s left`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s left`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min left`;
}

/** A live "42 s left" text (kept current by startTicker). */
export const countdown = (until) => html`<span class="nc-count" data-until="${until}">${left(until)}</span>`;

/** Updates every countdown inside `root` once a second until `root` leaves the page. */
export function startTicker(root) {
  const timer = setInterval(() => {
    if (!root.isConnected) return clearInterval(timer);
    root.querySelectorAll("[data-until]").forEach((el) => { el.textContent = left(Number(el.dataset.until)); });
  }, 1000);
  return () => clearInterval(timer);
}

// ---------- pieces of a change ----------

export function violationsBanner(violations) {
  if (!violations?.length) return "";
  const forbidden = violations.some((v) => v.verdict === "forbidden");
  const controls = [...new Set(violations.map((v) => v.control || v.policy))].join(", ");
  return html`<div class="notice ${forbidden ? "bad" : "warn"} nc-violations">${icon("alert")}<div style="min-width:0">
    <b>${forbidden ? `Violates ${controls}` : `Touches a restricted zone pair (${controls})`}</b>
    <ul>${violations.map((v) => html`<li><span class="mono">${v.from} -> ${v.to}</span>: ${v.verdict} by policy rule <span class="mono">${v.policy}</span>${v.possible ? " (may apply: the analysis is an approximation)" : ""}</li>`)}</ul></div></div>`;
}

function stepLine(step) {
  const r = step.rule;
  const text = r && typeof r === "object"
    ? `${r.action} ${r.source} -> ${r.destination} ${r.service}${r.log ? " log" : ""}${r.marker ? `  # ${r.marker}` : ""}`
    : String(r ?? "");
  return html`<li><span class="badge">${String(step.kind || "").replace(/_/g, " ")}</span> <span class="faint">${step.position}</span>
    <div class="mono nc-line">${text}</div></li>`;
}

export const stepsView = (steps) => (steps?.length ? html`<ol class="nc-steps">${steps.map(stepLine)}</ol>` : "");

const notesView = (title, list, tone = "") => (list?.length ? html`<div class="nc-notes ${tone}"><b>${title}</b><ul>${list.map((n) => html`<li>${n}</li>`)}</ul></div>` : "");

function checksView(list) {
  if (!list?.length) return "";
  return html`<div class="nc-checks">${list.map((c) => html`<div class="check-row"><div class="ico ${c.ok === true ? "pass" : c.ok === false ? "fail" : "manual"}">${icon(c.ok === true ? "check" : c.ok === false ? "x" : "clock")}</div>
    <div style="min-width:0"><b>${String(c.name || "").replace(/_/g, " ")}</b>${c.detail ? html`<div class="faint" style="font-size:12px;overflow-wrap:anywhere">${c.detail}</div>` : ""}</div></div>`)}</div>`;
}

/** When the change waits for a maintenance window (or none exists), or is being applied: a banner saying so. */
export function stateBanner(c, deviceName) {
  const name = deviceName || c.firewall;
  if (c.status === "verifying" && c.result && !c.result.ok) {
    return html`<div class="notice bad nc-banner" role="status">${icon("alert")}<div style="min-width:0"><b>Verification failed on ${name}: waiting for the device's own rollback
      ${c.rollback_until ? html`(${countdown(c.rollback_until)})` : ""}</b><div class="muted" style="font-size:12.5px">The change was not confirmed. Atrium reads the device again when its
      rollback window has passed; if the device cannot be reached by then, the change is marked failed and an alert is raised.</div>${checksView(c.verification)}</div></div>`;
  }
  if (c.status === "verifying") {
    return html`<div class="notice nc-banner" role="status">${icon("activity")}<div style="min-width:0"><b>Applied on ${name}, confirming connectivity
      ${c.rollback_until ? html`(${countdown(c.rollback_until)})` : ""}</b><div class="muted" style="font-size:12.5px">Atrium checks that the device still answers and shows the change;
      without that it does not confirm and the change is rolled back${c.rollback?.mode ? ` (${rollbackLabel(c.rollback)})` : ""}.</div>${checksView(c.verification)}</div></div>`;
  }
  if (c.status === "applying") {
    return html`<div class="notice nc-banner" role="status">${icon("refresh")}<div><b>Applying the change on ${name}</b>
      <div class="muted" style="font-size:12.5px">Re-reading the device, taking a backup, then writing the change.</div></div></div>`;
  }
  if (c.status === "scheduled") {
    const w = c.window;
    return html`<div class="notice nc-banner">${icon("calendar")}<div><b>${w ? html`Scheduled for the maintenance window "${w.name}"` : "Waiting for a maintenance window"}</b>
      <div class="muted" style="font-size:12.5px">${c.scheduled_for ? html`Applied at ${dateTime(c.scheduled_for)} (${timeIn(c.scheduled_for)}). `
        : "No maintenance window covers this device yet: an administrator adds one in Settings > Network changes, or applies the change now as an emergency. "}
      The approval expires ${dateTime(c.expires_at)}.</div>
      ${c.expires_before_window ? html`<div class="warn-text" style="font-size:12.5px;margin-top:4px">The approval expires before that window opens: the change will expire
        while it waits, unless an administrator applies it now as an emergency. Propose it again closer to the window, or add an earlier window.</div>` : ""}</div></div>`;
  }
  return "";
}

// ---------- dialogs ----------

/** "Waiting for approval" after a proposal (create, revert, restore). */
export function proposedDialog(result) {
  const c = result.change;
  modal({
    title: "Change proposed", submit: null, cancel: "Close", wide: true,
    body: html`<div class="notice ok" style="margin-bottom:12px">${icon("checkCircle")}<div><b>Waiting for approval by an administrator.</b>
        <div class="muted" style="font-size:12.5px">While the second-person rule is on (the default), that is an administrator other than the proposer.
          Nothing changes on the device before then. The approval expires ${dateTime(c.expires_at)}.</div></div></div>
      <dl class="kv"><dt>Change</dt><dd><a href="${changeHref(c.firewall, c.id)}" data-close>${c.id}</a> - ${OP_LABEL[c.op] || c.op}: ${changeSummary(c)}</dd>
        <dt>Approval</dt><dd><a href="#/approvals" data-close>Open Approvals</a></dd></dl>
      ${violationsBanner(c.preview?.violations)}
      ${notesView("Notes", c.preview?.notes)}
      <div style="margin-top:10px">${diffView(c.preview?.diff)}</div>`,
  });
}

async function askJustification({ title, text, submit, min = 0, required = false, send }) {
  modal({
    title, submit, wide: true, minRole: "operator",
    body: html`<p class="muted" style="margin-bottom:12px">${text}</p>
      ${field(`Justification${min ? ` (at least ${min} characters)` : required ? "" : " (optional)"}`, html`<textarea name="justification" maxlength="2000" rows="4" ${required || min ? "required" : ""}></textarea>`,
        "Shown to the administrator who decides and kept with the change.")}`,
    async onSubmit(data) {
      const value = String(data.get("justification") || "").trim();
      if (value.length < min) {
        toast(`Write at least ${min} characters`, "bad");
        return true;
      }
      await send(value || null);
    },
  });
}

export function proposeRevert(c) {
  return askJustification({
    title: `Revert ${c.id}?`, submit: "Propose revert",
    text: c.op === "restore" ? "A revert of a restore puts back the backup Atrium took just before it. Like every change it is a new proposal: an administrator (not you) approves it, and it follows the backup and maintenance-window rules."
      : "A revert is a new proposal with the inverse operations (the rule Atrium added is disabled, disabled rules are enabled again). An administrator (not you) approves it, and it follows the backup and maintenance-window rules.",
    send: async (justification) => proposedDialog(await post(`/segmentation/changes/${enc(c.id)}/revert`, { justification })),
  });
}

export function applyEmergency(c) {
  return askJustification({
    title: "Apply now as an emergency?", submit: "Apply now", min: 20,
    text: "The change is applied at once, outside the maintenance windows. Everything else still holds: the device is re-read (a different revision stops it), a backup is taken, and the change is verified and rolled back when the checks fail. Emergencies are logged and counted as exceptions in control HB-CM-3.",
    send: async (justification) => {
      await post(`/segmentation/changes/${enc(c.id)}/emergency`, { justification });
      toast("Applying now - follow it in the change", "warn");
    },
  });
}

/** Restoring an Atrium backup is a proposal like any other change (never a direct restore). */
export function proposeRestore(backup, deviceName) {
  return askJustification({
    title: `Restore the backup of ${deviceName}?`, submit: "Propose restore",
    text: html`The device's whole configuration is replaced by the backup taken ${dateTime(backup.taken_at)} (${backup.reason}, revision ${backup.revision || "unknown"},
      SHA-256 <span class="mono">${String(backup.sha256 || "").slice(0, 16)}</span>...). This is a proposal: an administrator who did not propose it approves it,
      a fresh backup is taken first, and it is applied in a maintenance window. When no stored snapshot has the backup's revision, Atrium cannot check it against
      the segmentation policy: then only an administrator can propose it, with a justification of at least 20 characters.`,
    send: async (justification) => proposedDialog(await post(`/network/backups/${enc(backup.id)}/restore`, { justification })),
  });
}

function resultView(r) {
  const back = !r.ok && r.state === "rolled_back";
  const text = r.detail || (r.ok ? "Applied, verified and confirmed" : back ? "Verification failed: the change was rolled back and a re-read proved it" : "Failed");
  return html`<h3 class="nc-h">Result</h3><div class="notice ${r.ok ? "ok" : back ? "warn" : "bad"}">${icon(r.ok ? "checkCircle" : "alert")}<div style="min-width:0;overflow-wrap:anywhere">
    ${text}${r.state ? html` <span class="faint">(device state: ${String(r.state).replace(/_/g, " ")}${r.method ? `, ${String(r.method).replace(/_/g, " ")}` : ""})</span>` : ""}</div></div>`;
}

function changeBody(c, deviceName) {
  const p = c.preview || {};
  const mine = session.user && c.proposed_by === session.user.username;
  const decided = c.approval && c.approval.status !== "pending";
  return html`
    <div class="row" style="gap:8px;margin-bottom:10px">${badge(OP_LABEL[c.op] || c.op, "accent")}${statusBadge(c.status)}
      ${c.emergency ? badge("emergency", "bad") : ""}<span class="faint" style="font-size:12.5px">${changeSummary(c)}</span></div>
    <div style="margin-bottom:12px">${lifecycle(c)}</div>
    ${stateBanner(c, deviceName)}
    ${WAITING.includes(c.status) && c.expires_at ? html`<p class="faint" style="font-size:12.5px;margin:8px 0">Expires ${dateTime(c.expires_at)} (${countdown(c.expires_at)}).</p>` : ""}
    <dl class="kv" style="margin:12px 0">
      <dt>Device</dt><dd><a href="#/network/${enc(c.firewall)}" data-close>${deviceName || c.firewall}</a></dd>
      <dt>Proposed by</dt><dd>${c.proposed_by}${mine ? " (you)" : ""} - ${dateTime(c.created_at)}</dd>
      <dt>Approval</dt><dd>${c.approval ? html`${badge(c.approval.status)}
        ${decided && c.approval.decided_by ? html` by ${c.approval.decided_by} ${timeAgo(c.approval.decided_at)}` : ""}
        ${c.approval.note ? html`<div class="faint">Note: ${c.approval.note}</div>` : ""}
        ${c.approval.status === "pending" ? html` <a href="#/approvals" data-close>Open Approvals</a>` : ""}` : "-"}</dd>
      ${c.emergency ? html`<dt>Emergency</dt><dd>by ${c.emergency.by} ${timeAgo(c.emergency.at)}<div class="nc-just">${c.emergency.justification}</div></dd>` : ""}
      <dt>Rollback</dt><dd>${rollbackLabel(c.rollback)}${c.rollback?.mode ? html` <span class="faint">- ${ROLLBACK[c.rollback.mode]?.[1] || ""}</span>` : ""}</dd>
      ${c.backup_id ? html`<dt>Backup before</dt><dd><a href="#/network/${enc(c.firewall)}/backups" data-close class="mono">${c.backup_id}</a></dd>` : ""}
      <dt>Bound to</dt><dd><span class="mono" title="The device revision and the hash of the operations the approval covers">revision ${c.base_revision || "-"} - ${String(c.ops_hash || "").slice(0, 19)}</span></dd>
      ${c.revert_of ? html`<dt>Reverts</dt><dd><a href="${changeHref(c.firewall, c.revert_of)}" data-close>${c.revert_of}</a></dd>` : ""}
      ${c.reverted_by ? html`<dt>Reverted by</dt><dd><a href="${changeHref(c.firewall, c.reverted_by)}" data-close>${c.reverted_by}</a></dd>` : ""}
    </dl>
    ${c.justification ? html`<h3 class="nc-h">Justification</h3><div class="nc-just">${c.justification}</div>` : ""}
    ${violationsBanner(p.violations)}
    ${p.steps?.length ? html`<h3 class="nc-h">Operations</h3>${stepsView(p.steps)}` : ""}
    <h3 class="nc-h">Diff <span class="faint" style="font-weight:400;font-size:12px">(rule text comes from the device)</span></h3>
    ${diffView(p.diff)}
    ${notesView("Anti-lockout", p.problems, "bad")}
    ${notesView("Notes", [...(p.notes || []), ...(p.device_notes || [])])}
    ${c.status !== "verifying" && c.verification?.length ? html`<h3 class="nc-h">Verification</h3>${checksView(c.verification)}` : ""}
    ${c.result ? resultView(c.result) : ""}
    <h3 class="nc-h">History</h3>
    <ol class="nc-history">${(c.history || []).map((h) => html`<li>${statusBadge(h.status)} <span class="faint">${dateTime(h.at)} - ${h.actor}</span>${h.note ? html`<div class="muted nc-note">${h.note}</div>` : ""}</li>`)}</ol>`;
}

function changeFooter(c) {
  const me = session.user?.username;
  const canWithdraw = WAITING.includes(c.status) && can("operator") && (c.proposed_by === me || can("admin"));
  return html`<button type="button" class="btn" data-close>Close</button>
    ${canWithdraw ? html`<button type="button" class="btn danger" data-act="withdraw">${icon("x")}Withdraw</button>` : ""}
    ${c.status === "applied" && !c.reverted_by ? html`<button type="button" class="btn" data-act="revert" data-min-role="operator">${icon("undo")}Revert...</button>` : ""}
    ${["approved", "scheduled"].includes(c.status) ? html`<button type="button" class="btn danger" data-act="emergency" data-min-role="admin">${icon("alert")}Apply now (emergency)...</button>` : ""}`;
}

/** The change dialog: everything about one change, kept live, with withdraw / revert / emergency apply. */
export async function openChange(id, { deviceName, onClose } = {}) {
  let c = await get(`/segmentation/changes/${enc(id)}`);
  const m = modal({
    title: `Device change ${c.id}`, wide: true, footer: changeFooter(c), body: html`<div data-change>${changeBody(c, deviceName)}</div>`,
    onClose: () => { off(); onClose?.(); },
  });
  const draw = () => {
    setHTML(m.el.querySelector("[data-change]"), changeBody(c, deviceName));
    setHTML(m.el.querySelector("footer"), changeFooter(c));
  };
  const off = onEvent(["firewall_change", "approval"], async (e) => {
    if (e.type === "firewall_change" && e.data?.id !== c.id) return;
    try { c = await get(`/segmentation/changes/${enc(id)}`); } catch { return; }
    if (m.el.isConnected) draw();
  });
  startTicker(m.el);
  m.el.addEventListener("click", (e) => { if (e.target.closest("[data-close]")) m.close(); }); // also after a redraw
  actions(m.el, {
    async withdraw(_, btn) {
      btn.disabled = true;
      try {
        c = await del(`/segmentation/changes/${enc(c.id)}`);
        toast("Change withdrawn", "ok");
        c = await get(`/segmentation/changes/${enc(id)}`);
        draw();
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
        btn.disabled = false;
      }
    },
    revert: () => proposeRevert(c),
    emergency: () => applyEmergency(c),
  });
  return m;
}

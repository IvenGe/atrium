import { get, post } from "../api.js";
import { actions, badge, diffView, emptyState, html, icon, setHTML, timeAgo, toast } from "../ui.js";

const KIND_ICON = { command: "terminal", patch: "wrench", process: "play" };

const diffLines = (patch) => (patch.diff ? patch.diff.split("\n").length : 0);

function pendingCard(a) {
  const p = a.patch;
  return html`<section class="card">
    <div class="row" style="justify-content:space-between;flex-wrap:nowrap;align-items:flex-start">
      <div class="row" style="flex-wrap:nowrap;align-items:flex-start;gap:12px;min-width:0">
        <div class="stat-icon">${icon(KIND_ICON[a.kind])}</div>
        <div style="min-width:0"><h3 style="overflow-wrap:anywhere">${a.title}</h3>
          <div class="faint" style="font-size:12px">requested by <b>${a.requested_by}</b> - ${timeAgo(a.created_at)}</div></div></div>
      ${badge(a.kind, "accent")}</div>
    ${a.detail ? html`<p class="muted" style="margin:10px 0;white-space:pre-line">${a.detail}</p>` : ""}
    ${a.kind === "command" ? html`<dl class="kv" style="margin:10px 0"><dt>Target</dt><dd>${a.payload.target}</dd>
        <dt>Command</dt><dd><code>${a.payload.command}</code></dd>${a.payload.cwd ? html`<dt>Directory</dt><dd><code>${a.payload.cwd}</code></dd>` : ""}</dl>` : ""}
    ${p ? html`<div class="row" style="margin:6px 0 10px;gap:6px"><span class="badge">${p.target}</span><span class="badge">${p.strategy.replace(/_/g, " ")}</span>
        ${p.target === "repo" ? html`<span class="faint" style="font-size:12px">applied on a new git branch in a separate worktree - your checkout is not touched</span>` : ""}</div>
      ${diffLines(p) > 30
        ? html`<details><summary class="muted" style="cursor:pointer">Show diff (${diffLines(p)} lines)</summary><div style="margin-top:8px">${diffView(p.diff)}</div></details>`
        : diffView(p.diff)}` : ""}
    <div class="row" style="margin-top:12px" data-min-role="operator">
      <input placeholder="Note (optional)" data-note="${a.id}" style="flex:1;min-width:180px" aria-label="Note">
      <button class="btn" data-act="reject" data-id="${a.id}">${icon("x")}Reject</button>
      <button class="btn ok" data-act="approve" data-id="${a.id}">${icon("check")}Approve</button>
    </div></section>`;
}

export async function render(el, ctx) {
  let tab = "pending";
  const draw = async () => {
    const all = await get("/approvals");
    const pending = all.filter((a) => a.status === "pending");
    const history = all.filter((a) => a.status !== "pending");
    setHTML(el, html`
      <div class="page-head"><div><h1>Approvals</h1><p class="muted">Agents ask before they change anything. Commands typed by a person in the Operator run directly.</p></div></div>
      <div class="tabs"><button class="${tab === "pending" ? "active" : ""}" data-act="tab" data-tab="pending">Waiting (${pending.length})</button>
        <button class="${tab === "history" ? "active" : ""}" data-act="tab" data-tab="history">History (${history.length})</button></div>
      ${tab === "pending" ? (pending.length ? html`<div class="stack">${pending.map(pendingCard)}</div>`
        : html`<section class="card">${emptyState("checkCircle", "Nothing waiting", "When an agent wants to run a state-changing command or apply a patch, it shows up here.")}</section>`)
      : html`<section class="card flush">${history.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Action</th><th>Kind</th><th>By</th><th>Decision</th><th>Result</th><th>When</th></tr></thead><tbody>
          ${history.map((a) => html`<tr><td style="max-width:420px;overflow-wrap:anywhere">${a.title}${a.note ? html`<div class="faint">Note: ${a.note}</div>` : ""}</td>
            <td>${badge(a.kind)}</td><td>${a.requested_by}</td><td>${badge(a.status)}${a.decided_by ? html`<div class="faint" style="font-size:12px">by ${a.decided_by}</div>` : ""}</td>
            <td class="faint" style="font-size:12px;max-width:260px;overflow-wrap:anywhere">${a.result ? (a.result.error || a.result.branch || (a.result.exit_code !== undefined ? `exit ${a.result.exit_code}` : a.result.location || "")) : ""}</td>
            <td class="faint">${timeAgo(a.decided_at || a.created_at)}</td></tr>`)}</tbody></table></div>`
        : emptyState("checkCircle", "No decisions yet", "Approved and rejected actions are kept here as an audit trail.")}</section>`}`);
  };
  const decide = async (id, approve) => {
    const note = el.querySelector(`[data-note="${CSS.escape(id)}"]`)?.value || null;
    try {
      await post(`/approvals/${id}`, { approve, note });
      toast(approve ? "Approved - the agent is carrying it out" : "Rejected", approve ? "ok" : "warn");
    } catch (err) {
      toast(err.message, "bad");
    }
    draw();
  };
  actions(el, {
    tab: (d) => { tab = d.tab; draw(); },
    approve: (d) => decide(d.id, true),
    reject: (d) => decide(d.id, false),
  });
  await draw();
  ctx.live(["approval"], draw, 400);
}

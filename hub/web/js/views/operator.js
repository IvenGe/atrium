import { del, get, post } from "../api.js";
import { actions, badge, can, confirmDialog, emptyState, field, html, icon, modal, options, setHTML, timeAgo, toast } from "../ui.js";

export function openAddHost() {
  modal({
    title: "Add an SSH host",
    submit: "Add host",
    minRole: "operator",
    body: html`<div class="form-grid">
        ${field("Name", html`<input name="name" placeholder="web-1" required>`)}
        ${field("Address", html`<input name="address" placeholder="10.0.0.12 or web-1.example.com" required>`)}
        ${field("User", html`<input name="username" placeholder="ops" required>`)}
        ${field("Port", html`<input name="port" type="number" value="22" min="1" max="65535">`)}</div>
      ${field("Private key file", html`<input name="key_path" placeholder="~/.ssh/id_ed25519">`,
        "Key-based auth only - the hub never stores passwords. Leave empty to use your SSH agent / default keys.")}
      ${field("Tags", html`<input name="tags" placeholder="production, eu-west">`)}
      <label class="check"><input type="checkbox" name="strict_host_keys" checked> Verify the host key against ~/.ssh/known_hosts (recommended)</label>`,
    async onSubmit(data) {
      const body = {
        name: data.get("name"), address: data.get("address"), username: data.get("username"),
        port: Number(data.get("port") || 22), key_path: data.get("key_path") || null,
        strict_host_keys: data.get("strict_host_keys") === "on",
        tags: String(data.get("tags") || "").split(",").map((t) => t.trim()).filter(Boolean),
      };
      if (!body.name || !body.address || !body.username) throw new Error("Name, address and user are required");
      await post("/hosts", body);
      toast(`Host ${body.name} added - the Asset Supervisor registered it`, "ok");
    },
  });
}

export async function render(el, ctx) {
  let output = null;
  const draw = async () => {
    const [hosts, history, settings] = await Promise.all([get("/hosts"), get("/commands?limit=30"), get("/settings")]);
    const targets = [["local", "This machine (hub server)"], ...hosts.map((h) => [h.id, `${h.name} - ${h.username}@${h.address}`])];
    const target = el.querySelector("[name=target]")?.value || "local";
    const command = el.querySelector("[name=command]")?.value || "";
    setHTML(el, html`
      <div class="page-head"><div><h1>Operator</h1><p class="muted">Run commands on this machine or on your servers over SSH. The Operator Agent runs the same commands for the other agents.</p></div>
        <button class="btn" data-act="add-host" data-min-role="operator">${icon("plus")}Add host</button></div>
      <div class="grid split">
        <div class="stack">
          <section class="card"><header><h2>Console</h2></header>
            ${can("operator") ? "" : html`<p class="muted">Running commands needs the operator role. Pick a recent command below to see its output.</p>`}
            <form id="run-form" data-min-role="operator">
              <div class="form-grid">${field("Target", html`<select name="target">${options(targets, target)}</select>`)}
                ${field("Working directory (optional)", html`<input name="cwd" placeholder="defaults to the hub's directory">`)}</div>
              <div class="row" style="flex-wrap:nowrap"><input name="command" class="mono" placeholder="e.g. df -h" value="${command}" autocomplete="off" aria-label="Command">
                <button class="btn primary">${icon("play")}Run</button></div>
            </form>
            <p class="faint" style="font-size:12px;margin-top:8px">Commands you type here run directly; catastrophic ones (wiping disks, shutting down, piping downloads into a shell) are always refused.
              Agent commands follow the <a href="#/settings">autonomy setting</a>: currently <b>${settings.autonomy}</b>.</p>
            ${output ? html`<div style="margin-top:12px"><div class="row" style="margin-bottom:6px">${badge(output.status === "done" ? (output.exit_code === 0 ? "exit 0" : `exit ${output.exit_code}`) : output.status,
              output.status === "done" && output.exit_code === 0 ? "ok" : "bad")}<span class="faint">${output.duration ? `${output.duration.toFixed(2)}s` : ""}</span></div>
              <pre class="code wrap">${output.output || output.reason || "(no output)"}</pre></div>` : ""}
          </section>
          <section class="card flush"><header><h2>Recent commands</h2></header>
            ${history.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Command</th><th>Target</th><th>By</th><th>Exit</th><th>When</th></tr></thead><tbody>
              ${history.slice().reverse().map((c, i) => html`<tr class="clickable" data-act="show" data-i="${history.length - 1 - i}">
                <td class="mono" style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${c.command}</td><td>${c.target}</td>
                <td>${c.origin}</td><td>${badge(String(c.exit_code), c.exit_code === 0 ? "ok" : "bad")}</td><td class="faint">${timeAgo(c.ts)}</td></tr>`)}</tbody></table></div>`
            : html`<div style="padding:0 16px 16px" class="muted">No commands yet.</div>`}</section>
        </div>
        <section class="card"><header><h2>Hosts</h2></header>
          ${hosts.length ? hosts.map((h) => html`<div class="check-row"><div class="stat-icon">${icon("server")}</div>
            <div style="flex:1;min-width:0"><b>${h.name}</b><div class="faint mono" style="font-size:12px">${h.username}@${h.address}:${h.port}</div>
              <div class="row" style="gap:6px;margin-top:6px">${h.key_path ? badge("key auth", "ok") : badge("agent/default keys")}
                ${h.strict_host_keys ? badge("host key verified", "ok") : badge("host key NOT verified", "bad")}${h.tags.map((t) => badge(t, ""))}</div></div>
            <div class="row" style="gap:6px;align-items:flex-start" data-min-role="operator"><button class="btn sm" data-act="discover" data-id="${h.id}" title="Collect OS, CPU, memory and disk facts">${icon("search")}Discover</button>
              <button class="btn sm danger" data-act="remove-host" data-id="${h.id}" aria-label="Remove host">${icon("trash")}</button></div></div>`)
          : emptyState("server", "No hosts", "Add a server to run commands over SSH and inventory it in Assets.",
            html`<button class="btn primary" data-act="add-host" data-min-role="operator">${icon("plus")}Add host</button>`)}
        </section>
      </div>`);
    el.querySelector("#run-form").addEventListener("submit", run);
    el._history = history;
  };

  async function run(e) {
    e.preventDefault();
    const data = new FormData(e.target);
    const command = String(data.get("command") || "").trim();
    if (!command) return;
    const btn = e.target.querySelector("button");
    btn.disabled = true;
    try {
      output = await post("/commands", { command, target: data.get("target"), cwd: data.get("cwd") || null });
      if (output.status === "denied") toast(output.reason, "bad");
    } catch (err) {
      output = { status: "error", output: err.message };
    }
    await draw();
  }

  actions(el, {
    "add-host": () => openAddHost(),
    show: (d) => { const c = el._history[+d.i]; output = { status: "done", ...c }; draw(); },
    async discover(d) {
      toast("Discovering - the Asset Supervisor asked the Operator to run a read-only scan", "info");
      try {
        const r = await post(`/hosts/${d.id}/discover`);
        toast(r.status === "done" ? `Discovered: ${r.facts.os || "facts updated"}` : `Discovery ${r.status.replace(/_/g, " ")}`, r.status === "done" ? "ok" : "warn");
      } catch (err) { toast(err.message, "bad"); }
    },
    async "remove-host"(d) {
      if (!(await confirmDialog("Remove host", "Remove this host? Its asset is retired.", "Remove"))) return;
      await del(`/hosts/${d.id}`);
      draw();
    },
  });
  await draw();
  ctx.live(["host", "host_removed", "command"], draw, 500);
}

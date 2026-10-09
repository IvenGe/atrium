import { get, patch, post } from "../api.js";
import { actions, badge, builtinIcon, colorFor, field, html, icon, md, modal, setHTML, timeAgo, toast } from "../ui.js";

// Chat history survives navigation inside the app.
const chat = { log: [], busy: false };

const GROUPS = [
  ["Orchestration", (a) => a.role === "supervisor"],
  ["Specialists", (a) => a.role === "patcher" || a.role === "operator"],
  ["App supervisors - built-in apps", (a) => a.role === "module-supervisor"],
  ["App supervisors - your tools", (a) => a.role === "tool-supervisor"],
];
const ROLE_ICON = { supervisor: "bot", patcher: "wrench", operator: "terminal", "module-supervisor": "shield", "tool-supervisor": "grid" };

function agentCard(a) {
  const tone = a.status === "working" ? "working" : a.status === "paused" ? "warn" : "ok";
  return html`<div class="card agent-card">
    <div class="head">${builtinIcon(a.id === "module:assets" ? "box" : ROLE_ICON[a.role] || "bot", a.role === "tool-supervisor" ? colorFor(a.scope) : "#7c3aed", "sm")}
      <div style="flex:1;min-width:0"><b>${a.name}</b><div class="faint" style="font-size:12px">${a.title}</div></div>
      <span class="row" style="gap:6px;font-size:12px"><span class="dot ${tone}"></span>${a.status}</span></div>
    <div class="desc">${a.description}</div>
    <div class="meta"><span>${a.handled} handled</span>${a.errors ? html`<span style="color:var(--bad)">${a.errors} errors</span>` : ""}
      ${a.queued ? html`<span>${a.queued} queued</span>` : ""}<span>${a.last_active ? `active ${timeAgo(a.last_active)}` : "not active yet"}</span></div>
    <div class="row" style="justify-content:space-between">
      <span class="row" style="gap:6px">${a.uses_llm ? (a.llm_active ? badge(a.model, "accent") : badge("rules mode")) : badge("deterministic")}
        ${a.custom_instructions ? badge("custom instructions", "info") : ""}</span>
      <span class="row" style="gap:6px">
        <button class="btn sm" data-act="toggle" data-id="${a.id}" data-paused="${a.paused}">${icon(a.paused ? "play" : "pause")}${a.paused ? "Resume" : "Pause"}</button>
        <button class="btn sm" data-act="configure" data-id="${a.id}">${icon("sliders")}Configure</button></span></div>
  </div>`;
}

function chatLog() {
  if (!chat.log.length) {
    return html`<div class="bubble bot">${md("Hi! I'm the **Hub Supervisor**. I coordinate the other agents. Try `status`, `import owner/repo`, `run df -h`, `compliance`, or just describe what you want.")}</div>`;
  }
  return html`${chat.log.map((m) => html`<div class="bubble ${m.me ? "me" : "bot"}">${m.me ? m.text : md(m.text)}</div>`)}
    ${chat.busy ? html`<div class="bubble bot faint">Thinking and asking the other agents...</div>` : ""}`;
}

export async function render(el, ctx) {
  let agents = await get("/agents");
  let messages = await get("/messages?limit=80");
  const draw = () => {
    setHTML(el, html`
      <div class="page-head"><div><h1>Agents</h1><p class="muted">The Hub Supervisor talks to every agent. Each app has its own supervisor; the Patch Agent and Operator do the hands-on work.</p></div></div>
      <div class="grid split">
        <div class="stack" id="agent-groups">${GROUPS.map(([title, test]) => {
          const list = agents.filter(test);
          return list.length ? html`<div><h3 class="muted" style="margin:0 0 10px">${title}</h3><div class="grid cols-3">${list.map(agentCard)}</div></div>` : "";
        })}</div>
        <div class="stack">
          <section class="card chat"><header><h2>Hub Supervisor</h2><button class="btn sm ghost" data-act="reset">${icon("refresh")}New conversation</button></header>
            <div class="msgs" id="chat-msgs">${chatLog()}</div>
            <form id="chat-form"><input name="text" placeholder="Ask the supervisor..." autocomplete="off" aria-label="Message" ${chat.busy ? "disabled" : ""}>
              <button class="btn primary" ${chat.busy ? "disabled" : ""} aria-label="Send">${icon("send")}</button></form></section>
          <section class="card"><header><h2>Agent conversations</h2><span class="faint" style="font-size:12px">live</span></header>
            <div class="scroll" style="max-height:360px" id="msg-stream">${messages.slice().reverse().map((m) => html`<div class="msg-line">
              <span class="route">${m.sender} &rarr; ${m.recipient}</span><span><span class="subj">${m.subject}</span> <span class="faint">${m.kind}</span></span>
              <span class="faint">${timeAgo(m.ts)}</span></div>`)}</div></section>
        </div>
      </div>`);
    const box = el.querySelector("#chat-msgs");
    box.scrollTop = box.scrollHeight;
    el.querySelector("#chat-form").addEventListener("submit", send);
    if (!chat.busy) el.querySelector("#chat-form input").focus({ preventScroll: true });
  };

  async function send(e) {
    e.preventDefault();
    const text = new FormData(e.target).get("text").trim();
    if (!text || chat.busy) return;
    chat.log.push({ me: true, text });
    chat.busy = true;
    draw();
    try {
      const reply = await post("/chat", { text });
      chat.log.push({ me: false, text: reply.reply });
    } catch (err) {
      chat.log.push({ me: false, text: `Error: ${err.message}` });
    } finally {
      chat.busy = false;
      if (el.querySelector("#chat-msgs")) draw(); // only if the person is still on this page
    }
  }

  actions(el, {
    async toggle(d) {
      await patch(`/agents/${encodeURIComponent(d.id)}`, { paused: d.paused !== "true" });
    },
    configure(d) {
      const a = agents.find((x) => x.id === d.id);
      modal({
        title: `Configure ${a.name}`,
        wide: true,
        body: html`<p class="muted" style="margin-bottom:12px">${a.description}</p>
          ${a.uses_llm ? html`${field("Model", html`<input name="model" list="models" value="${a.model_override || ""}" placeholder="Default: ${a.model}">
            <datalist id="models"><option value="claude-opus-5-5"><option value="claude-sonnet-5-5"><option value="claude-haiku-5-5"><option value="claude-fable-5-1"></datalist>`,
            "Leave empty to use the hub default from Settings.")}
            ${field("Instructions (system prompt)", html`<textarea name="instructions" rows="12" class="mono" style="font-size:12.5px">${a.instructions}</textarea>`,
              "Clear the box to restore the built-in instructions.")}`
          : html`<p>This agent is deterministic - it follows the hub's policies and has no model to configure.</p>`}`,
        async onSubmit(data) {
          if (!a.uses_llm) return;
          const instructions = String(data.get("instructions") ?? "");
          await patch(`/agents/${encodeURIComponent(a.id)}`, {
            model: String(data.get("model") ?? ""),
            instructions: instructions.trim() === a.instructions.trim() && !a.custom_instructions ? "" : instructions,
          });
          toast(`${a.name} updated`, "ok");
        },
      });
    },
    async reset() {
      await post("/chat/reset");
      chat.log = [];
      draw();
    },
  });

  draw();
  ctx.live(["agent", "agent_removed"], async () => {
    agents = await get("/agents");
    const groups = el.querySelector("#agent-groups");
    if (!groups) return;
    const tmp = document.createElement("div");
    setHTML(tmp, html`${GROUPS.map(([title, test]) => {
      const list = agents.filter(test);
      return list.length ? html`<div><h3 class="muted" style="margin:0 0 10px">${title}</h3><div class="grid cols-3">${list.map(agentCard)}</div></div>` : "";
    })}`);
    groups.replaceChildren(...tmp.childNodes);
  }, 400);
  ctx.live(["message"], async () => {
    messages = await get("/messages?limit=80");
    const stream = el.querySelector("#msg-stream");
    if (!stream) return;
    setHTML(stream, html`${messages.slice().reverse().map((m) => html`<div class="msg-line">
      <span class="route">${m.sender} &rarr; ${m.recipient}</span><span><span class="subj">${m.subject}</span> <span class="faint">${m.kind}</span></span>
      <span class="faint">${timeAgo(m.ts)}</span></div>`)}`);
  }, 400);
}

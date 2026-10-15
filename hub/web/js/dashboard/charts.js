// Charts of the dashboard widgets (round4-dashboard-spec.md 10.10): pure functions (data) -> html``, no DOM, so they
// are tested in Node. One series per chart, coloured --series-1; severity and status use their reserved tokens and always
// keep the text label beside the bar (colour never carries the category alone). Every bar, column and matrix cell is a
// link with a full accessible name, and each chart has a table view (<th scope>). No pie charts, no dual axes.
import { html } from "../ui.js";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const TONES = new Set(["ok", "warn", "bad", "info", ...SEVERITIES.map((s) => `sev-${s}`)]);

const pct = (n, total) => (total > 0 ? Math.round((n / total) * 100) : 0);
const num = (n) => (typeof n === "number" && Number.isFinite(n) ? n.toLocaleString("en-US") : "-");
const toneClass = (tone) => (TONES.has(tone) ? `tone-${tone}` : "");

/** True when the groups are severities (they keep their order instead of being sorted by count). */
export const isOrdinal = (groups) => groups.length > 0 && groups.every((g) => SEVERITIES.includes(String(g.key)) || String(g.tone || "").startsWith("sev-"));

/** The rows a breakdown shows: sorted by count unless ordinal, "Other" last; each with its share of the total. */
export function barRows(groups, { other = 0, total = null, ordinal = null } = {}) {
  const keep = ordinal ?? isOrdinal(groups);
  const rows = (keep ? [...groups] : [...groups].sort((a, b) => (b.count ?? 0) - (a.count ?? 0)))
    .map((g) => ({ key: g.key, label: String(g.label ?? g.key ?? ""), count: g.count ?? 0, tone: g.tone || null, href: g.href || null }));
  if (other > 0) rows.push({ key: "__other", label: "Other", count: other, tone: null, href: null });
  const sum = total ?? rows.reduce((s, r) => s + r.count, 0);
  return rows.map((r) => ({ ...r, share: pct(r.count, sum) }));
}

/** Horizontal bars of one series. `noun` names what is counted ("records", "open findings"); `href` is where a row
 *  without its own link goes (the app). */
export function bars(groups, { other = 0, total = null, ordinal = null, noun = "records", href = null, label = "" } = {}) {
  const rows = barRows(groups, { other, total, ordinal });
  if (!rows.length) return html`<p class="muted dash-none">Nothing to count yet.</p>`;
  const max = Math.max(1, ...rows.map((r) => r.count));
  return html`<ul class="dash-bars" ${label ? html`aria-label="${label}"` : ""}>${rows.map((r) => {
    const name = `${r.label}: ${num(r.count)} ${noun}, ${r.share}%`;
    const width = r.count > 0 ? Math.max(1.5, (r.count / max) * 100) : 0;
    const inner = html`<span class="bar-label">${r.label}</span>
      <span class="bar-track" aria-hidden="true"><span class="bar-fill ${toneClass(r.tone)}" style="width:${width.toFixed(1)}%"></span></span>
      <span class="bar-value" aria-hidden="true">${num(r.count)}</span>
      <span class="dash-tip" aria-hidden="true">${num(r.count)} ${noun} - ${r.share}%</span>`;
    const target = r.href || href;
    return html`<li>${target ? html`<a class="bar-row" href="${target}" aria-label="${name}">${inner}</a>`
      : html`<span class="bar-row" role="img" aria-label="${name}">${inner}</span>`}</li>`;
  })}</ul>`;
}

/** A plain table: columns [{label, numeric?}], rows of cells; the first cell of a row is its header (scope="row"). */
export function table(columns, rows, { caption = "" } = {}) {
  return html`<div class="table-wrap dash-table-wrap"><table class="table compact dash-table">
    ${caption ? html`<caption class="sr-only">${caption}</caption>` : ""}
    <thead><tr>${columns.map((c) => html`<th scope="col" class="${c.numeric ? "num" : ""}">${c.label}</th>`)}</tr></thead>
    <tbody>${rows.map((cells) => html`<tr>${cells.map((cell, i) => (i === 0
      ? html`<th scope="row">${cell}</th>` : html`<td class="${columns[i]?.numeric ? "num" : ""}">${cell}</td>`))}</tr>`)}</tbody>
  </table></div>`;
}

/** The table view of a breakdown. */
export function barsTable(groups, { other = 0, total = null, ordinal = null, noun = "records", label = "Group" } = {}) {
  const rows = barRows(groups, { other, total, ordinal });
  return table([{ label }, { label: noun[0].toUpperCase() + noun.slice(1), numeric: true }, { label: "Share", numeric: true }],
    rows.map((r) => [r.href ? html`<a href="${r.href}">${r.label}</a>` : r.label, num(r.count), `${r.share}%`]), { caption: label });
}

/** Columns over time: buckets [{day: "YYYY-MM-DD", count}] (one series). */
export function columns(buckets, { noun = "records", href = null } = {}) {
  if (!buckets.length) return html`<p class="muted dash-none">Nothing in this period.</p>`;
  const max = Math.max(1, ...buckets.map((b) => b.count ?? 0));
  const total = buckets.reduce((s, b) => s + (b.count ?? 0), 0);
  return html`<div class="dash-cols-wrap"><ol class="dash-cols">${buckets.map((b) => {
    const name = `${b.day}: ${num(b.count ?? 0)} ${noun}, ${pct(b.count ?? 0, total)}%`;
    const inner = html`<span class="col-fill" style="height:${(((b.count ?? 0) / max) * 100).toFixed(1)}%"></span>
      <span class="dash-tip" aria-hidden="true">${b.day}: ${num(b.count ?? 0)} ${noun}</span>`;
    return html`<li>${href ? html`<a class="col" href="${href}" aria-label="${name}">${inner}</a>` : html`<span class="col" role="img" aria-label="${name}">${inner}</span>`}</li>`;
  })}</ol>
  <div class="dash-cols-axis" aria-hidden="true"><span>${buckets[0].day}</span><span>${buckets.at(-1).day}</span></div></div>`;
}

/** The risk band of a likelihood x impact score (1..25). */
export const riskBand = (score) => (score >= 15 ? "critical" : score >= 10 ? "high" : score >= 5 ? "medium" : "low");

/** A 5 x 5 risk matrix: cells[likelihood - 1][impact - 1] = count; likelihood 5 is the top row. */
export function matrix(cells, { href = null, noun = "risks" } = {}) {
  const rows = [5, 4, 3, 2, 1];
  return html`<div class="dash-matrix" role="group" aria-label="Risks by likelihood and impact">
    <span class="mx-axis mx-y" aria-hidden="true">Likelihood</span>
    <div class="mx-grid">${rows.map((l) => html`<span class="mx-tick" aria-hidden="true">${l}</span>${[1, 2, 3, 4, 5].map((i) => {
      const n = cells?.[l - 1]?.[i - 1] ?? 0;
      const band = riskBand(l * i);
      const name = `Likelihood ${l}, impact ${i}: ${num(n)} ${noun} (${band})`;
      return href ? html`<a class="mx-cell band-${band} ${n ? "" : "zero"}" href="${href}" aria-label="${name}">${n || ""}</a>`
        : html`<span class="mx-cell band-${band} ${n ? "" : "zero"}" role="img" aria-label="${name}">${n || ""}</span>`;
    })}`)}
      <span></span>${[1, 2, 3, 4, 5].map((i) => html`<span class="mx-tick" aria-hidden="true">${i}</span>`)}</div>
    <span class="mx-axis mx-x" aria-hidden="true">Impact</span></div>`;
}

/** The table view of a matrix. */
export function matrixTable(cells, { noun = "risks" } = {}) {
  const rows = [];
  for (const l of [5, 4, 3, 2, 1]) for (const i of [1, 2, 3, 4, 5]) {
    const n = cells?.[l - 1]?.[i - 1] ?? 0;
    if (n) rows.push([`Likelihood ${l}, impact ${i}`, num(n), riskBand(l * i)]);
  }
  return rows.length ? table([{ label: "Cell" }, { label: noun[0].toUpperCase() + noun.slice(1), numeric: true }, { label: "Band" }], rows)
    : html`<p class="muted dash-none">No ${noun}.</p>`;
}

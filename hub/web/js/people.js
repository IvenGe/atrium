// People helpers shared by the People app, Assets, Compliance and Users & access: avatars, name chips and pickers.
import { get } from "./api.js";
import { badge, colorFor, html, options } from "./ui.js";

export function initialsOf(name) {
  const words = String(name || "").split(/[\s._@-]+/).filter(Boolean);
  return (words.slice(0, 2).map((w) => w[0]).join("") || "?").toUpperCase();
}

export function personAvatar(p, size = "") {
  return html`<span class="avatar ${size}" style="background:${colorFor(p.id || p.display_name || "")}" aria-hidden="true">${p.initials || initialsOf(p.display_name)}</span>`;
}

/** A person's name with a small avatar, linked to their page; leavers get their status badge. */
export function personChip(p, { link = true } = {}) {
  if (!p) return "";
  const inner = html`${personAvatar(p, "sm")}<span class="name">${p.display_name}</span>${p.status && p.status !== "active" ? badge(p.status) : ""}`;
  return link ? html`<a class="person-chip" href="#/people/${p.id}" title="${p.email || ""}">${inner}</a>` : html`<span class="person-chip">${inner}</span>`;
}

/** Everyone, for pickers (sorted by name; id, name, email, title, status, initials). Viewers may read people; a failure gives an empty list. */
export async function loadPeople() {
  try {
    return (await get("/people?brief=1")).people;
  } catch {
    return [];
  }
}

const label = (p) => `${p.display_name}${p.email ? ` - ${p.email}` : ""}${p.status !== "active" ? ` (${p.status})` : ""}`;

/** <option>s for a person picker: `none` first, then `extra` [value, label] pairs, then everyone except `exclude`. */
export function personOptions(people, selected, { none = "Nobody", exclude = null, extra = [] } = {}) {
  return options([["", none], ...extra, ...people.filter((p) => p.id !== exclude).map((p) => [p.id, label(p)])], selected || "");
}

/**
 * Keep a free-text owner input in step with a person picker: picking someone fills the text when it is empty or
 * still shows the previously picked person's name.
 */
export function followPicker(select, input, people) {
  const name = (id) => people.find((p) => p.id === id)?.display_name || "";
  let previous = name(select.value);
  select.addEventListener("change", () => {
    const next = name(select.value);
    const text = input.value.trim();
    if (next ? !text || text === previous : previous && text === previous) input.value = next;
    previous = next;
  });
}

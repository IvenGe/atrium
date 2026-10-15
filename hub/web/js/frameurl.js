// Which addresses Atrium may show inside a frame (round4-dashboard-spec.md 9.2, 9.6): pure checks, no DOM. The Portal
// uses them today; tools' own pages in dashboard widgets would reuse them.
//
// A frame with allow-scripts + allow-same-origin that shows a page of Atrium's own origin can remove its own sandbox, so
// such an address is refused. Addresses come from tools' manifests, which the tools themselves control.

// Query parameter names that carry credentials (the same words as hub/extensions/pack.py CREDENTIAL).
const CREDENTIAL = /(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|credential)/i;

/** True when `url` has the same origin (scheme, host and port) as `here` (e.g. location.href). */
export function sameOrigin(url, here) {
  try {
    return new URL(url).origin === new URL(here).origin;
  } catch {
    return false;
  }
}

/** {ok, reason, url}: an http(s) address without user name or password, without a query parameter named like a
 *  credential and (unless `fragment` is allowed) without a fragment; `url` is the normalised address. */
export function validFrameUrl(url, { fragment = false } = {}) {
  let u;
  try {
    u = new URL(String(url ?? ""));
  } catch {
    return { ok: false, reason: "This address is not a valid URL.", url: null };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, reason: "Only http:// and https:// addresses can be shown.", url: null };
  if (u.username || u.password) return { ok: false, reason: "This address contains a user name or password and cannot be shown here.", url: null };
  if ([...u.searchParams.keys()].some((k) => CREDENTIAL.test(k))) {
    return { ok: false, reason: "This address carries a credential in its query and cannot be shown here.", url: null };
  }
  if (u.hash && !fragment) return { ok: false, reason: "This address has a fragment (#...) and cannot be shown here.", url: null };
  return { ok: true, reason: null, url: u.href };
}

/** The check of a frame's address for a page at `here`: validFrameUrl plus the same-origin refusal. */
export function frameCheck(url, here, opts = {}) {
  const v = validFrameUrl(url, opts);
  if (!v.ok) return v;
  if (sameOrigin(v.url, here)) return { ok: false, reason: "This tool's address is Atrium itself and cannot be shown here.", url: null };
  return v;
}

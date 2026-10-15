// Text measurement for SVG labels: an offscreen 2D context measures each (font, text) once; labels longer than
// their room are ellipsized (the full text stays in the accessible name and the tooltip).

const cache = new Map();
let ctx = null;

function context() {
  if (ctx === null) {
    try {
      ctx = (typeof OffscreenCanvas !== "undefined" ? new OffscreenCanvas(1, 1) : document.createElement("canvas")).getContext("2d") || false;
    } catch {
      ctx = false;
    }
  }
  return ctx;
}

/** Width in CSS px of `text` in `font` (a CSS font shorthand); a rough estimate where no 2D context exists. */
export function measure(text, font) {
  const key = `${font}\u0000${text}`;
  let w = cache.get(key);
  if (w === undefined) {
    const c = context();
    if (c) {
      c.font = font;
      w = c.measureText(text).width;
    } else {
      w = String(text).length * (parseFloat(/(\d+(?:\.\d+)?)px/.exec(font)?.[1]) || 13) * 0.56;
    }
    if (cache.size > 20000) cache.clear();
    cache.set(key, w);
  }
  return w;
}

/** `text` cut with "…" to fit `maxPx` (binary search on the length). */
export function ellipsize(text, maxPx, font) {
  const s = String(text ?? "");
  if (measure(s, font) <= maxPx) return s;
  let lo = 0, hi = s.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (measure(`${s.slice(0, mid).trimEnd()}…`, font) <= maxPx) lo = mid; else hi = mid - 1;
  }
  return lo ? `${s.slice(0, lo).trimEnd()}…` : "…";
}

/** The page's UI font at a size and weight, for measuring (matches body in app.css). */
export const font = (size = 13, weight = 600) => `${weight} ${size}px Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`;

// The canvas camera {k, tx, ty}: screen = world * k + t (world units are CSS px at k = 1). Pure functions: no DOM,
// unit-tested under Node (tests/js/camera.test.mjs). A viewport is {w, h, insets?: {top, right, bottom, left}} in
// CSS px; insets are the parts covered by the bar or the inspector.

export const MIN_K = 0.3;
export const MAX_K = 2;
export const FIT_MAX_K = 1.25;
const NO_INSETS = { top: 0, right: 0, bottom: 0, left: 0 };

export const clampK = (k) => Math.min(MAX_K, Math.max(MIN_K, Number.isFinite(k) ? k : 1));

export const toWorld = (cam, sx, sy) => ({ x: (sx - cam.tx) / cam.k, y: (sy - cam.ty) / cam.k });
export const toScreen = (cam, wx, wy) => ({ x: wx * cam.k + cam.tx, y: wy * cam.k + cam.ty });
export const pan = (cam, dx, dy) => ({ k: cam.k, tx: cam.tx + dx, ty: cam.ty + dy });

/** Zoom by `factor` around the screen point (sx, sy): the world point under it stays put (k is clamped). */
export function zoomAt(cam, sx, sy, factor) {
  const k = clampK(cam.k * factor);
  const w = toWorld(cam, sx, sy);
  return { k, tx: sx - w.x * k, ty: sy - w.y * k };
}

/** Zoom to an absolute k around the viewport centre (the zoom buttons and +/-). */
export function zoomTo(cam, viewport, k) {
  const ins = viewport.insets || NO_INSETS;
  const cx = ins.left + (viewport.w - ins.left - ins.right) / 2;
  const cy = ins.top + (viewport.h - ins.top - ins.bottom) / 2;
  return zoomAt(cam, cx, cy, clampK(k) / cam.k);
}

/** The bounding box {x, y, w, h} of rects ({x, y, w, h}); null for none. */
export function boundsOf(rects) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const r of rects) {
    if (!r) continue;
    x0 = Math.min(x0, r.x); y0 = Math.min(y0, r.y);
    x1 = Math.max(x1, r.x + r.w); y1 = Math.max(y1, r.y + r.h);
  }
  return x0 === Infinity ? null : { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
}

/** A camera that shows `bounds` (world) centred in the free part of the viewport with `pad` px around it, never
 *  zoomed in beyond `maxK` (and within MIN_K..MAX_K). No bounds: k = 1 with the world origin at the top left. */
export function fit(bounds, viewport, pad = 48, maxK = FIT_MAX_K) {
  const ins = viewport.insets || NO_INSETS;
  const aw = Math.max(1, viewport.w - ins.left - ins.right - 2 * pad);
  const ah = Math.max(1, viewport.h - ins.top - ins.bottom - 2 * pad);
  if (!bounds) return { k: 1, tx: ins.left + pad, ty: ins.top + pad };
  const k = clampK(Math.min(maxK, aw / Math.max(1, bounds.w), ah / Math.max(1, bounds.h)));
  return {
    k,
    tx: ins.left + pad + (aw - bounds.w * k) / 2 - bounds.x * k,
    ty: ins.top + pad + (ah - bounds.h * k) / 2 - bounds.y * k,
  };
}

/** Pan the least needed so the world rect is inside the free part of the viewport (not under the bar or the
 *  inspector; WCAG 2.4.11). A rect larger than the free area is aligned to its top left. */
export function ensureVisible(cam, rect, viewport, margin = 16) {
  const ins = viewport.insets || NO_INSETS;
  const s = toScreen(cam, rect.x, rect.y);
  const w = rect.w * cam.k, h = rect.h * cam.k;
  const left = ins.left + margin, right = viewport.w - ins.right - margin;
  const top = ins.top + margin, bottom = viewport.h - ins.bottom - margin;
  const shift = (start, size, lo, hi) => (size > hi - lo || start < lo ? lo - start : start + size > hi ? hi - (start + size) : 0);
  const dx = shift(s.x, w, left, right), dy = shift(s.y, h, top, bottom);
  return dx || dy ? pan(cam, dx, dy) : cam;
}

/** Wheel deltas in px: deltaMode 1 (lines) x16, 2 (pages) x the viewport height [U]. */
export function wheelPixels(deltaX, deltaY, deltaMode, pageHeight = 800) {
  const unit = deltaMode === 1 ? 16 : deltaMode === 2 ? pageHeight : 1;
  return { dx: deltaX * unit, dy: deltaY * unit };
}

/** Zoom factor of a ctrl/cmd + wheel step (trackpad pinch arrives as wheel with ctrlKey). */
export const wheelZoomFactor = (deltaY) => Math.exp(-deltaY * 0.0015);

/** Linear interpolation between two cameras (the 180 ms camera transition); t in 0..1. */
export function lerp(a, b, t) {
  const e = t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2; // ease in-out
  return { k: a.k + (b.k - a.k) * e, tx: a.tx + (b.tx - a.tx) * e, ty: a.ty + (b.ty - a.ty) * e };
}

/** A camera read back from storage, or null when it is not a usable one. */
export function parseCamera(value) {
  try {
    const c = typeof value === "string" ? JSON.parse(value) : value;
    if (c && [c.k, c.tx, c.ty].every(Number.isFinite) && Math.abs(c.tx) < 1e7 && Math.abs(c.ty) < 1e7) return { k: clampK(c.k), tx: c.tx, ty: c.ty };
  } catch { /* not JSON */ }
  return null;
}

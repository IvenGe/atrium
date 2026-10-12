/** Camera math for the canvas. World units are CSS pixels at k = 1. screen = world * k + t. */

export const K_MIN = 0.3;
export const K_MAX = 2;

export function clampK(k) {
  if (!Number.isFinite(k)) return 1;
  return Math.min(K_MAX, Math.max(K_MIN, k));
}

export function toScreen(camera, x, y) {
  return { x: x * camera.k + camera.tx, y: y * camera.k + camera.ty };
}

export function toWorld(camera, sx, sy) {
  const k = camera.k || 1;
  return { x: (sx - camera.tx) / k, y: (sy - camera.ty) / k };
}

/** Zoom toward a screen point. factor > 1 zooms in. */
export function zoomAt(camera, sx, sy, factor) {
  const k = clampK(camera.k * factor);
  const world = toWorld(camera, sx, sy);
  return { k, tx: sx - world.x * k, ty: sy - world.y * k };
}

/**
 * Fit world bounds into a viewport. k is at most maxK (default 1.25) and never above K_MAX.
 * bounds: {minX, minY, maxX, maxY}. viewport: {w, h}.
 */
export function fit(bounds, viewport, pad = 48, maxK = 1.25) {
  const w = Math.max(1, bounds.maxX - bounds.minX);
  const h = Math.max(1, bounds.maxY - bounds.minY);
  const vw = Math.max(1, (viewport.w || 1) - pad * 2);
  const vh = Math.max(1, (viewport.h || 1) - pad * 2);
  const k = clampK(Math.min(maxK, vw / w, vh / h));
  return {
    k,
    tx: ((viewport.w || 1) - w * k) / 2 - bounds.minX * k,
    ty: ((viewport.h || 1) - h * k) / 2 - bounds.minY * k,
  };
}

/** Pan so a world rect stays inside the viewport, clear of toolbar/inspector insets. */
export function ensureVisible(camera, rect, viewport, insets = {}) {
  const top = insets.top || 0;
  const right = insets.right || 0;
  const bottom = insets.bottom || 0;
  const left = insets.left || 0;
  const s = toScreen(camera, rect.x, rect.y);
  const s2 = toScreen(camera, rect.x + rect.w, rect.y + rect.h);
  let { tx, ty } = camera;
  const margin = 16;
  if (s.x < left + margin) tx += left + margin - s.x;
  if (s2.x > viewport.w - right - margin) tx -= s2.x - (viewport.w - right - margin);
  if (s.y < top + margin) ty += top + margin - s.y;
  if (s2.y > viewport.h - bottom - margin) ty -= s2.y - (viewport.h - bottom - margin);
  return { k: camera.k, tx, ty };
}

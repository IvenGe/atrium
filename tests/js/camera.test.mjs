// Camera math of the canvas engine (hub/web/js/canvas/camera.js).
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MAX_K, MIN_K, boundsOf, clampK, ensureVisible, fit, lerp, pan, parseCamera, toScreen, toWorld, wheelPixels, wheelZoomFactor, zoomAt, zoomTo,
} from "../../hub/web/js/canvas/camera.js";

const close = (a, b, eps = 1e-9) => assert.ok(Math.abs(a - b) < eps, `${a} != ${b}`);

test("toWorld and toScreen are inverse", () => {
  const cam = { k: 1.7, tx: -120, ty: 33 };
  const w = toWorld(cam, 400, 250);
  const s = toScreen(cam, w.x, w.y);
  close(s.x, 400);
  close(s.y, 250);
});

test("zoomAt keeps the point under the cursor fixed", () => {
  for (const [cam, f] of [[{ k: 1, tx: 0, ty: 0 }, 1.5], [{ k: 0.8, tx: 300, ty: -40 }, 0.6], [{ k: 1.9, tx: -50, ty: 10 }, 1.3]]) {
    const before = toWorld(cam, 321, 123);
    const after = toWorld(zoomAt(cam, 321, 123, f), 321, 123);
    close(after.x, before.x, 1e-6);
    close(after.y, before.y, 1e-6);
  }
});

test("zoom is clamped to 0.3..2", () => {
  assert.equal(zoomAt({ k: 1, tx: 0, ty: 0 }, 0, 0, 100).k, MAX_K);
  assert.equal(zoomAt({ k: 1, tx: 0, ty: 0 }, 0, 0, 0.001).k, MIN_K);
  assert.equal(clampK(NaN), 1);
  assert.equal(zoomTo({ k: 1, tx: 0, ty: 0 }, { w: 800, h: 600 }, 5).k, MAX_K);
});

test("fit centres the bounds and never zooms in beyond 1.25", () => {
  const vp = { w: 1000, h: 600 };
  const small = fit({ x: 0, y: 0, w: 100, h: 50 }, vp);
  assert.equal(small.k, 1.25);
  const centre = toScreen(small, 50, 25);
  close(centre.x, 500);
  close(centre.y, 300);
  const big = fit({ x: -2000, y: 0, w: 4000, h: 3000 }, vp);
  assert.ok(big.k >= MIN_K && big.k < 1);
  assert.equal(fit({ x: 0, y: 0, w: 1e6, h: 1e6 }, vp).k, MIN_K);
  // insets shift the free area: the centre moves right by half the inspector width
  const withInspector = fit({ x: 0, y: 0, w: 100, h: 50 }, { ...vp, insets: { top: 0, right: 360, bottom: 0, left: 0 } });
  close(toScreen(withInspector, 50, 25).x, 320);
  assert.deepEqual(fit(null, vp), { k: 1, tx: 48, ty: 48 });
});

test("ensureVisible pans the least needed and keeps visible rects as they are", () => {
  const vp = { w: 800, h: 600, insets: { top: 50, right: 360, bottom: 0, left: 0 } };
  const cam = { k: 1, tx: 0, ty: 0 };
  assert.equal(ensureVisible(cam, { x: 100, y: 100, w: 50, h: 50 }, vp), cam);
  const right = ensureVisible(cam, { x: 500, y: 100, w: 50, h: 50 }, vp); // under the inspector (440..800)
  assert.equal(toScreen(right, 550, 0).x, 800 - 360 - 16);
  const top = ensureVisible(cam, { x: 100, y: 10, w: 50, h: 20 }, vp); // under the bar
  assert.equal(toScreen(top, 0, 10).y, 66);
});

test("boundsOf, pan, lerp, wheel helpers and stored cameras", () => {
  assert.deepEqual(boundsOf([{ x: 0, y: 0, w: 10, h: 10 }, { x: -5, y: 20, w: 5, h: 5 }]), { x: -5, y: 0, w: 15, h: 25 });
  assert.equal(boundsOf([]), null);
  assert.deepEqual(pan({ k: 2, tx: 1, ty: 2 }, 3, 4), { k: 2, tx: 4, ty: 6 });
  assert.deepEqual(lerp({ k: 1, tx: 0, ty: 0 }, { k: 2, tx: 10, ty: 10 }, 1), { k: 2, tx: 10, ty: 10 });
  assert.deepEqual(wheelPixels(1, 2, 1), { dx: 16, dy: 32 });
  assert.deepEqual(wheelPixels(0, 1, 2, 700), { dx: 0, dy: 700 });
  assert.ok(wheelZoomFactor(-100) > 1 && wheelZoomFactor(100) < 1);
  assert.deepEqual(parseCamera('{"k":9,"tx":1,"ty":2}'), { k: MAX_K, tx: 1, ty: 2 });
  assert.equal(parseCamera("nonsense"), null);
  assert.equal(parseCamera('{"k":1,"tx":"x","ty":0}'), null);
});

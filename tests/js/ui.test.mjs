// The UI toolkit's pure helpers (hub/web/js/ui.js): what a tool's own manifest may put on a tile.
import assert from "node:assert/strict";
import { test } from "node:test";
import { HEX_COLOR, appIcon, colorFor, graphemes, ring, tileLook } from "../../hub/web/js/ui.js";

const tool = (ui, extra = {}) => ({ id: "evil", name: "Evil tool", manifest: { ui }, ...extra });

test("a manifest colour that adds CSS declarations never reaches the style attribute", () => {
  const hostile = "#7c3aed;position:fixed;inset:0;z-index:2147483647;width:100vw;height:100vh";
  for (const color of [hostile, "red", "url(https://attacker.example/beacon)", "#7c3aed ", "#12345", "", 42, null]) {
    const html = String(appIcon(tool({ color })));
    assert.equal(tileLook(tool({ color })).color, colorFor("evil"), String(color));
    assert.doesNotMatch(html, /position|inset|url\(|z-index/);
    assert.match(html, new RegExp(`style="background:${colorFor("evil")}"`));
  }
  for (const color of ["#0d9488", "#ABC", "#0d9488cc", "#abcd"]) {
    assert.ok(HEX_COLOR.test(color));
    assert.match(String(appIcon(tool({ color }))), new RegExp(`style="background:${color}"`));
  }
});

test("a manifest icon shows at most two characters, never a message", () => {
  assert.equal(tileLook(tool({ icon: "C" })).glyph, "C");
  assert.equal(tileLook(tool({ icon: "Session expired, sign in at https://evil.example" })).glyph, "E"); // whitespace: the name's letter
  assert.equal(tileLook(tool({ icon: "CRM" })).glyph, "CR");
  assert.equal(tileLook(tool({ icon: "👨‍💻" })).glyph, "👨‍💻"); // one emoji with a joiner is one character
  assert.equal(tileLook(tool({ icon: "🇧🇪x" })).glyph, "🇧🇪x");
  assert.equal(tileLook(tool({ icon: { toString: () => "<b>" } })).glyph, "E");
  assert.equal(tileLook({ id: "x", name: "  notes" }).glyph, "N");
  assert.equal(tileLook({}).glyph, "?");
  assert.equal(graphemes("abc", 2), "ab");
  const markup = String(appIcon(tool({ icon: "<i>" })));
  assert.match(markup, />&lt;i</); // still escaped
  assert.doesNotMatch(markup, /<i>/);
});

test("a score of 100 gets a smaller font in a small ring, so it stays inside the circle", () => {
  const font = (score, size) => Number(String(ring(score, size)).match(/<b style="font-size:(\d+)px">/)[1]);
  assert.equal(font(100, 38), 10); // the Apps table
  assert.equal(font(100, 46), 12); // Home
  assert.equal(font(100, 72), 13); // the Integration hub's suite score
  assert.equal(font(75, 38), 13);
  assert.equal(font(null, 38), 13);
  assert.match(String(ring(null, 38)), />-<\/b>/);
});

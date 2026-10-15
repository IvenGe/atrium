// Which addresses Atrium shows in a frame (hub/web/js/frameurl.js; the Portal, finding R4-F1 of the dashboard spec).
import assert from "node:assert/strict";
import { test } from "node:test";
import { frameCheck, sameOrigin, validFrameUrl } from "../../hub/web/js/frameurl.js";

const HERE = "https://atrium.corp.example/#/portal/grafana";

test("a tool whose address is Atrium's own origin is refused", () => {
  assert.equal(sameOrigin("https://atrium.corp.example/some/page", HERE), true);
  assert.equal(sameOrigin("https://atrium.corp.example:443/", HERE), true, "the default port is the same origin");
  assert.equal(sameOrigin("https://atrium.corp.example:8443/", HERE), false);
  assert.equal(sameOrigin("http://atrium.corp.example/", HERE), false, "another scheme is another origin");
  assert.equal(sameOrigin("not a url", HERE), false);
  const own = frameCheck("https://atrium.corp.example/api/tools", HERE, { fragment: true });
  assert.equal(own.ok, false);
  assert.match(own.reason, /Atrium itself/);
  assert.equal(frameCheck("http://127.0.0.1:8710/", "http://127.0.0.1:8710/#/portal/x").ok, false);
  assert.equal(frameCheck("http://127.0.0.1:3000/", "http://127.0.0.1:8710/#/portal/x").ok, true, "another port is another origin");
});

test("addresses with a user name or password, a credential query or another scheme are refused", () => {
  for (const [url, why] of [
    ["https://user:pass@grafana.corp.example/", /user name or password/],
    ["https://admin@grafana.corp.example/", /user name or password/],
    ["https://grafana.corp.example/?api_key=abc", /credential/],
    ["https://grafana.corp.example/d/x?orgId=1&auth_token=abc", /credential/],
    ["https://grafana.corp.example/?Session=1", /credential/],
    ["javascript:alert(1)", /http/],
    ["data:text/html,<script>alert(1)</script>", /http/],
    ["file:///etc/passwd", /http/],
    ["//grafana.corp.example/", /valid URL/],
    ["", /valid URL/],
    [null, /valid URL/],
  ]) {
    const v = validFrameUrl(url, { fragment: true });
    assert.equal(v.ok, false, String(url));
    assert.match(v.reason, why, String(url));
    assert.equal(v.url, null);
  }
});

test("a plain http(s) address passes, normalised; a fragment only where it is allowed", () => {
  assert.deepEqual(validFrameUrl("https://grafana.corp.example/d/abc?orgId=1"),
    { ok: true, reason: null, url: "https://grafana.corp.example/d/abc?orgId=1" });
  assert.equal(validFrameUrl("HTTP://Snipe.corp.example:8080").url, "http://snipe.corp.example:8080/");
  assert.equal(validFrameUrl("https://app.example/#/dashboard").ok, false, "no fragment by default");
  assert.equal(validFrameUrl("https://app.example/#/dashboard", { fragment: true }).ok, true, "the Portal allows app routes");
});

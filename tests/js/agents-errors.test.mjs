// The error count on an agent card (hub/web/js/views/agents.js): the label, and which activity lines it opens.
import assert from "node:assert/strict";
import { test } from "node:test";
import { agentErrorLines, errorCountLabel } from "../../hub/web/js/views/agents.js";

test("the count says error once and errors after that", () => {
  assert.equal(errorCountLabel(1), "1 error");
  assert.equal(errorCountLabel(2), "2 errors");
});

test("only that agent's error lines are shown, in log order", () => {
  const log = [
    { actor: "operator", level: "error", text: "launch failed" },
    { actor: "patcher", level: "error", text: "pom.xml" },
    { actor: "operator", level: "warn", text: "a warning is not an error" },
    { actor: "operator", level: "info", text: "started" },
    { actor: "operator", level: "error", text: "launch failed again" },
    null,
  ];
  assert.deepEqual(agentErrorLines(log, "operator").map((e) => e.text), ["launch failed", "launch failed again"]);
  assert.deepEqual(agentErrorLines(log, "patcher").map((e) => e.text), ["pom.xml"]);
  assert.deepEqual(agentErrorLines(undefined, "operator"), []);
});

import assert from "node:assert/strict";
import test from "node:test";
import { ToolPolicy } from "../src/tool-policy.js";

test("dangerous tools are denied by default", () => {
  const policy = new ToolPolicy({});

  assert.equal(policy.evaluate("run_shell_command").allowed, false);
  assert.equal(policy.evaluate("read_status").allowed, true);
});

test("deny rules win over allow rules", () => {
  const policy = new ToolPolicy({
    defaultDenyDangerousTools: false,
    allow: ["service_*"],
    deny: ["service_stop"],
  });

  assert.equal(policy.evaluate("service_read").allowed, true);
  assert.equal(policy.evaluate("service_stop").allowed, false);
  assert.equal(policy.evaluate("unlisted").allowed, false);
});

test("blocked tools/call requests are identified", () => {
  const policy = new ToolPolicy({});

  assert.deepEqual(
    policy.findBlockedCall({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "restart_server" },
    }),
    {
      id: 7,
      name: "restart_server",
      reason: "tool name matched the denylist",
    },
  );
});

test("tools/list payloads omit denied tools", () => {
  const policy = new ToolPolicy({});

  assert.deepEqual(
    policy.filterToolsListPayload({
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "read_status" }, { name: "run_exec" }] },
    }),
    {
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "read_status" }] },
    },
  );
});

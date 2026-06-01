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

test("allowlist blocks tools not on the list", () => {
  const policy = new ToolPolicy(
    { defaultDenyDangerousTools: false },
    { allowlist: ["get_status", "list_items"] },
  );

  assert.equal(policy.evaluate("get_status").allowed, true);
  assert.equal(policy.evaluate("list_items").allowed, true);
  assert.equal(policy.evaluate("other_tool").allowed, false);
  assert.deepEqual(policy.evaluate("other_tool"), {
    allowed: false,
    reason: "tool is not on the route allowlist",
  });
});

test("allowlist blocks tools/call for unlisted tools", () => {
  const policy = new ToolPolicy(
    { defaultDenyDangerousTools: false },
    { allowlist: ["get_status"] },
  );

  const blocked = policy.findBlockedCall({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "other_tool" },
  });
  assert.ok(blocked);
  assert.equal(blocked.name, "other_tool");
  assert.equal(blocked.reason, "tool is not on the route allowlist");

  assert.equal(
    policy.findBlockedCall({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "get_status" },
    }),
    undefined,
  );
});

test("allowlist filters tools/list JSON responses", () => {
  const policy = new ToolPolicy(
    { defaultDenyDangerousTools: false },
    { allowlist: ["get_status"] },
  );

  assert.deepEqual(
    policy.filterToolsListPayload({
      jsonrpc: "2.0",
      id: 1,
      result: {
        tools: [
          { name: "get_status" },
          { name: "run_exec" },
          { name: "other" },
        ],
      },
    }),
    {
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "get_status" }] },
    },
  );
});

test("deny rules still apply when allowlist is set", () => {
  const policy = new ToolPolicy(
    { defaultDenyDangerousTools: true },
    { allowlist: ["get_status", "run_exec"] },
  );

  // get_status passes both allowlist and deny check
  assert.equal(policy.evaluate("get_status").allowed, true);
  // run_exec is on allowlist but matches dangerous denylist
  assert.equal(policy.evaluate("run_exec").allowed, false);
  assert.equal(
    policy.evaluate("run_exec").reason,
    "tool name matched the denylist",
  );
});

test("empty allowlist blocks all tool calls", () => {
  const policy = new ToolPolicy(
    { defaultDenyDangerousTools: false },
    { allowlist: [] },
  );

  assert.equal(policy.evaluate("any_tool").allowed, false);
  assert.equal(
    policy.evaluate("any_tool").reason,
    "tool is not on the route allowlist",
  );
});

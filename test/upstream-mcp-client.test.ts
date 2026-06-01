import assert from "node:assert/strict";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import test from "node:test";
import { discoverTools } from "../src/upstream-mcp-client.js";

function makeToolsServer(
  tools: Array<{ name: string; description?: string }>,
  responseFormat: "json" | "sse" = "sse",
): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      if (req.method === "DELETE") {
        res.writeHead(200);
        res.end();
        return;
      }
      let body = "";
      req.on("data", (chunk: Buffer) => (body += chunk.toString()));
      req.on("end", () => {
        const parsed: unknown = JSON.parse(body || "{}");
        const method =
          typeof parsed === "object" && parsed !== null
            ? (parsed as Record<string, unknown>).method
            : undefined;

        if (method === "initialize") {
          const sessionId = "test-session-id";
          if (responseFormat === "json") {
            res.writeHead(200, {
              "Content-Type": "application/json",
              "Mcp-Session-Id": sessionId,
            });
            res.end(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: {
                  protocolVersion: "2024-11-05",
                  capabilities: {},
                  serverInfo: { name: "test", version: "1.0" },
                },
              }),
            );
          } else {
            res.writeHead(200, {
              "Content-Type": "text/event-stream",
              "Mcp-Session-Id": sessionId,
            });
            res.end(
              `event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "test", version: "1.0" } } })}\n\n`,
            );
          }
          return;
        }

        if (method === "tools/list") {
          const payload = { jsonrpc: "2.0", id: 2, result: { tools } };
          if (responseFormat === "json") {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(payload));
          } else {
            res.writeHead(200, { "Content-Type": "text/event-stream" });
            res.end(`event: message\ndata: ${JSON.stringify(payload)}\n\n`);
          }
          return;
        }

        res.writeHead(200);
        res.end("{}");
      });
    });

    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => server.close(),
      });
    });
  });
}

test("discoverTools returns tools from SSE upstream", async () => {
  const tools = [
    { name: "get_status", description: "Get system status" },
    { name: "list_containers", description: "List containers" },
  ];
  const { url, close } = await makeToolsServer(tools, "sse");

  const result = await discoverTools(url);

  assert.equal(result.error, undefined);
  assert.deepEqual(result.tools, tools);
  close();
});

test("discoverTools returns tools from JSON upstream", async () => {
  const tools = [{ name: "get_info" }, { name: "list_items" }];
  const { url, close } = await makeToolsServer(tools, "json");

  const result = await discoverTools(url);

  assert.equal(result.error, undefined);
  assert.deepEqual(result.tools, [
    { name: "get_info", description: undefined },
    { name: "list_items", description: undefined },
  ]);
  close();
});

test("discoverTools returns error and empty tools when upstream is unreachable", async () => {
  const result = await discoverTools("http://127.0.0.1:1");

  assert.ok(result.error);
  assert.deepEqual(result.tools, []);
});

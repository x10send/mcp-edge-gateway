import { randomBytes } from "node:crypto";
import { request } from "undici";
import type { Dispatcher } from "undici";

export interface DiscoveredTool {
  name: string;
  description?: string;
}

export interface DiscoverToolsResult {
  tools: DiscoveredTool[];
  error?: string;
}

const DISCOVER_TIMEOUT_MS = 10_000;

export async function discoverTools(
  upstreamBaseUrl: string,
  dispatcher?: Dispatcher,
): Promise<DiscoverToolsResult> {
  const mcpUrl = upstreamBaseUrl.replace(/\/$/, "") + "/mcp";
  const requestId = randomBytes(4).readUInt32BE(0);

  let sessionId: string | undefined;

  try {
    // Step 1: initialize
    const initRes = await request(mcpUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: requestId,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "mcp-edge-gateway-discovery", version: "1.0" },
        },
      }),
      bodyTimeout: DISCOVER_TIMEOUT_MS,
      headersTimeout: DISCOVER_TIMEOUT_MS,
      dispatcher,
    });

    sessionId =
      (initRes.headers["mcp-session-id"] as string | undefined) ?? undefined;

    // Drain the init response body (SSE or JSON)
    await initRes.body.dump();

    // Step 2: tools/list
    const listRes = await request(mcpUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        ...(sessionId ? { "Mcp-Session-Id": sessionId } : {}),
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: requestId + 1,
        method: "tools/list",
        params: {},
      }),
      bodyTimeout: DISCOVER_TIMEOUT_MS,
      headersTimeout: DISCOVER_TIMEOUT_MS,
      dispatcher,
    });

    const contentType =
      (listRes.headers["content-type"] as string | undefined) ?? "";
    const rawBody = await listRes.body.text();

    // Step 3: close the session if we have one
    if (sessionId) {
      try {
        const closeRes = await request(mcpUrl, {
          method: "DELETE",
          headers: { "Mcp-Session-Id": sessionId },
          bodyTimeout: 3_000,
          headersTimeout: 3_000,
          dispatcher,
        });
        await closeRes.body.dump();
      } catch {
        // best-effort close
      }
    }

    const tools = parseToolsFromResponse(rawBody, contentType);
    return { tools };
  } catch (error) {
    return {
      tools: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function parseToolsFromResponse(
  rawBody: string,
  contentType: string,
): DiscoveredTool[] {
  const jsonLines: string[] = contentType.includes("text/event-stream")
    ? rawBody
        .split("\n")
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.slice(5).trim())
    : [rawBody];

  for (const line of jsonLines) {
    try {
      const parsed: unknown = JSON.parse(line);
      if (!isRecord(parsed)) continue;
      const result = parsed.result;
      if (!isRecord(result)) continue;
      const tools = result.tools;
      if (!Array.isArray(tools)) continue;
      return tools
        .filter((t): t is Record<string, unknown> => isRecord(t))
        .filter((t) => typeof t.name === "string")
        .map((t) => ({
          name: t.name as string,
          description:
            typeof t.description === "string" ? t.description : undefined,
        }));
    } catch {
      // try next line
    }
  }
  return [];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

import type { ToolPolicyConfig } from "./config.js";

const DEFAULT_DANGEROUS_TOOL_PATTERNS = [
  "*shell*",
  "*exec*",
  "*write*",
  "*delete*",
  "*restart*",
  "*stop*",
  "*start*",
  "*reboot*",
  "*shutdown*",
  "*update*",
  "*install*",
];

interface JsonRpcRequest {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
  params?: unknown;
}

export interface BlockedToolCall {
  id: unknown;
  name: string;
  reason: string;
}

export class ToolPolicy {
  private readonly allowPatterns: RegExp[];
  private readonly denyPatterns: RegExp[];
  private readonly allowlist: Set<string> | undefined;

  constructor(
    globalPolicy: ToolPolicyConfig,
    routePolicy: ToolPolicyConfig = {},
  ) {
    const defaultDenyDangerousTools =
      routePolicy.defaultDenyDangerousTools ??
      globalPolicy.defaultDenyDangerousTools ??
      true;

    this.allowPatterns = [
      ...(globalPolicy.allow ?? []),
      ...(routePolicy.allow ?? []),
    ].map(toPattern);

    this.denyPatterns = [
      ...(defaultDenyDangerousTools ? DEFAULT_DANGEROUS_TOOL_PATTERNS : []),
      ...(globalPolicy.deny ?? []),
      ...(routePolicy.deny ?? []),
    ].map(toPattern);

    this.allowlist =
      routePolicy.allowlist !== undefined
        ? new Set(routePolicy.allowlist)
        : undefined;
  }

  evaluate(name: string): { allowed: boolean; reason?: string } {
    // Whitelist is checked first: if set, only listed tools pass
    if (this.allowlist !== undefined && !this.allowlist.has(name)) {
      return { allowed: false, reason: "tool is not on the route allowlist" };
    }
    if (this.denyPatterns.some((pattern) => pattern.test(name))) {
      return { allowed: false, reason: "tool name matched the denylist" };
    }
    if (
      this.allowPatterns.length > 0 &&
      !this.allowPatterns.some((pattern) => pattern.test(name))
    ) {
      return {
        allowed: false,
        reason: "tool name is not present in the allowlist",
      };
    }
    return { allowed: true };
  }

  findBlockedCall(payload: unknown): BlockedToolCall | undefined {
    const requests = Array.isArray(payload) ? payload : [payload];

    for (const request of requests) {
      if (
        !isRecord(request) ||
        request.method !== "tools/call" ||
        !isRecord(request.params)
      ) {
        continue;
      }

      const name = request.params.name;
      if (typeof name !== "string") {
        continue;
      }

      const decision = this.evaluate(name);
      if (!decision.allowed) {
        return {
          id: (request as JsonRpcRequest).id ?? null,
          name,
          reason: decision.reason ?? "tool is not allowed",
        };
      }
    }

    return undefined;
  }

  filterToolsListPayload(payload: unknown): unknown {
    if (Array.isArray(payload)) {
      return payload.map((item) => this.filterToolsListPayload(item));
    }
    if (
      !isRecord(payload) ||
      !isRecord(payload.result) ||
      !Array.isArray(payload.result.tools)
    ) {
      return payload;
    }

    return {
      ...payload,
      result: {
        ...payload.result,
        tools: payload.result.tools.filter(
          (tool) =>
            isRecord(tool) &&
            typeof tool.name === "string" &&
            this.evaluate(tool.name).allowed,
        ),
      },
    };
  }
}

function toPattern(glob: string): RegExp {
  const escaped = glob
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

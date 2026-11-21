import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { GatewayError } from "../util/errors";
import { errorInfo, log } from "../util/log";
import type { Gateway } from "./gateway";

const INSTRUCTIONS = `This gateway fronts several MCP servers. Start with list_servers, then list_tools(server)
for the server you need, then call(server, tool, args). Server ids look like <group>.<name>, e.g. personal.pm_tool.`;

const text = (value: unknown): CallToolResult => ({ content: [{ type: "text", text: JSON.stringify(value, null, 2) }] });
const failure = (message: string): CallToolResult => ({ isError: true, content: [{ type: "text", text: message }] });

/** Run a tool: rate limit first, then map errors to safe messages. Never leaks stacks or secrets. */
async function guarded(gw: Gateway, tool: string, fn: () => Promise<CallToolResult>): Promise<CallToolResult> {
  try {
    await gw.rateLimit();
    return await fn();
  } catch (e) {
    if (e instanceof GatewayError) return failure(e.message);
    log("error", "tool.failed", { tool, error: errorInfo(e) });
    return failure("Internal gateway error. The details are in the gateway logs.");
  }
}

const serverArg = z.string().describe("Namespaced server id: <group>.<name>, e.g. personal.pm_tool");

export function buildMcpServer(gw: Gateway): McpServer {
  const server = new McpServer({ name: "mcp-vault-gateway", version: "0.1.0" }, { instructions: INSTRUCTIONS });

  server.registerTool(
    "list_servers",
    {
      description: "List the MCP servers you can use, with status (ok, invalid, needs_connect, disabled, error) and a short description.",
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    () => guarded(gw, "list_servers", async () => text(await gw.listServers())),
  );

  server.registerTool(
    "list_tools",
    {
      description: "List the tools of one server (name, description, input schema, annotations), filtered by your access policy.",
      inputSchema: { server: serverArg },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    ({ server: id }) => guarded(gw, "list_tools", async () => text(await gw.listTools(id))),
  );

  server.registerTool(
    "call",
    {
      description: "Call a tool on a server. The result is returned exactly as the downstream server sent it.",
      inputSchema: {
        server: serverArg,
        tool: z.string().describe("Tool name from list_tools"),
        args: z.record(z.string(), z.unknown()).optional().describe("Tool arguments, matching the tool's input schema"),
      },
      annotations: { openWorldHint: true },
    },
    ({ server: id, tool, args }) => guarded(gw, "call", () => gw.call(id, tool, args)),
  );

  server.registerTool(
    "refresh_servers",
    {
      description: "Reload servers and policy from 1Password now instead of waiting for the cache. Once per minute.",
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    () => guarded(gw, "refresh_servers", async () => text(await gw.refreshServers())),
  );

  return server;
}

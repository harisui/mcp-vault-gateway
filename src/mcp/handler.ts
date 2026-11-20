import type { Env } from "../env";

/** MCP endpoint (/mcp). Reached only with a valid gateway token; ctx.props holds the caller. */
export const mcpApiHandler = {
  async fetch(_req: Request, _env: Env, _ctx: ExecutionContext): Promise<Response> {
    return new Response("Not implemented yet", { status: 501 });
  },
};

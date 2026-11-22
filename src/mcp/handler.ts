import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { getApp } from "../app";
import type { Env } from "../env";
import type { Caller } from "../policy/caller";
import { oauthCredentials } from "../oauth-downstream/refresh";
import { durableDownstream } from "../proxy/forward";
import { counter } from "../util/counter-do";
import { Gateway } from "./gateway";
import { buildMcpServer } from "./server";

type Props = { email?: string; caller?: Caller };

function callerFrom(props: Props | undefined): Caller | undefined {
  if (props?.caller?.kind === "key") return props.caller;
  if (props?.email) return { kind: "user", id: props.email.toLowerCase(), email: props.email.toLowerCase() };
  return undefined;
}

/**
 * /mcp, reached only with a valid gateway token (OAuth or access key); ctx.props holds the caller.
 * Stateless Streamable HTTP: a fresh MCP server per request, JSON responses, no CORS headers.
 */
export const mcpApiHandler = {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const caller = callerFrom((ctx as ExecutionContext & { props?: Props }).props);
    if (!caller) return new Response("Unauthorized", { status: 401 });
    if (req.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "POST" } });

    const app = await getApp(env);
    const declared = Number(req.headers.get("Content-Length") ?? "0");
    if (declared > app.cfg.maxRequestBytes) return new Response("Request too large", { status: 413 });

    const gateway = new Gateway(
      {
        cfg: app.cfg,
        publicUrl: app.publicUrl,
        registry: app.registry,
        tools: app.tools,
        downstream: durableDownstream(env.SERVER_DO),
        limiter: { hit: async (name, windowMs, limit) => (await counter(env.COUNTER_DO, name).hit(windowMs, limit)).allowed },
        credentials: (server, opts) => oauthCredentials(env.SERVER_DO, app.publicUrl, server, opts),
      },
      caller,
    );
    const server = buildMcpServer(gateway);
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(transport);
    try {
      return await transport.handleRequest(req);
    } finally {
      ctx.waitUntil(server.close());
    }
  },
};

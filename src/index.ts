import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { getApp } from "./app";
import { parseAccessKey, verifyAccessKey } from "./auth/access-keys";
import { handleAuthRoute } from "./auth/authorize";
import type { Env } from "./env";
import { mcpApiHandler } from "./mcp/handler";
import { handleConnectRoute } from "./oauth-downstream/connect";
import { healthKey } from "./registry/registry";
import { messagePage } from "./util/html";
import { errorInfo, log } from "./util/log";

export { ServerDO } from "./proxy/server-do";
export { CounterDO } from "./util/counter-do";

const ACCESS_TOKEN_TTL_S = 3600; // spec: 1 hour max
const REFRESH_TOKEN_TTL_S = 30 * 86_400;

const defaultHandler = {
  async fetch(req: Request, env: Env): Promise<Response> {
    const app = await getApp(env);
    const path = new URL(req.url).pathname;
    const auth = await handleAuthRoute(req, app, path);
    if (auth) return auth;
    const connect = await handleConnectRoute(req, app, path);
    if (connect) return connect;
    return messagePage("Not found", "Nothing here.", 404);
  },
};

let provider: { url: string; instance: OAuthProvider<Env> } | undefined;

function getProvider(publicUrl: string): OAuthProvider<Env> {
  if (provider?.url === publicUrl) return provider.instance;
  const instance = new OAuthProvider<Env>({
    apiRoute: "/mcp",
    apiHandler: mcpApiHandler,
    defaultHandler,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/token",
    clientRegistrationEndpoint: "/register",
    accessTokenTTL: ACCESS_TOKEN_TTL_S,
    refreshTokenTTL: REFRESH_TOKEN_TTL_S,
    scopesSupported: ["mcp"],
    resourceMetadata: { resource: `${publicUrl}/mcp`, resource_name: "MCP Vault Gateway" },
    // Gateway access keys (mcpk_...). These are keys issued by this gateway, not upstream tokens.
    resolveExternalToken: async ({ token, env }) => {
      if (!parseAccessKey(token)) return null;
      const app = await getApp(env as Env);
      const caller = await verifyAccessKey(token, await app.registry.getAll());
      if (!caller) {
        log("warn", "auth.key_rejected", {});
        return null;
      }
      return { props: { caller }, audience: `${publicUrl}/mcp` };
    },
  });
  provider = { url: publicUrl, instance };
  return instance;
}

const plain = (body: string, status: number) =>
  new Response(body, { status, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });

/**
 * GET /health, no auth. Answers only "ok" or "degraded", never details. Degraded means: bad
 * config, no groups configured, a group whose last 1Password load failed, or the hourly
 * 1Password budget is used up.
 */
async function health(env: Env): Promise<Response> {
  try {
    const app = await getApp(env);
    const groups = app.registry.groups;
    if (groups.length === 0) return plain("degraded", 503);
    const states = await Promise.all(groups.map((g) => env.CACHE_KV.get(healthKey(g))));
    if (states.some((s) => s === "degraded")) return plain("degraded", 503);
    if ((await app.budget.used()) >= app.cfg.opMaxCallsPerHour) return plain("degraded", 503);
    return plain("ok", 200);
  } catch {
    return plain("degraded", 503);
  }
}

/** The OAuth library reflects Origin on API routes; the MCP endpoint must not send CORS headers. */
function withoutCors(res: Response): Response {
  const out = new Response(res.body, res);
  for (const name of [...out.headers.keys()]) if (name.toLowerCase().startsWith("access-control-")) out.headers.delete(name);
  return out;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const path = new URL(req.url).pathname;
    if (path === "/health" && req.method === "GET") return health(env);

    let publicUrl: string;
    try {
      publicUrl = (await getApp(env)).publicUrl;
    } catch (e) {
      // Bad or missing ENCRYPTION_KEY_V*, PUBLIC_URL, ...: refuse to run.
      log("error", "config.invalid", { error: errorInfo(e) });
      return messagePage("Gateway misconfigured", "The gateway is not configured correctly. Check the Worker logs.", 503);
    }
    const res = await getProvider(publicUrl).fetch(req, env, ctx);
    return path === "/mcp" || path.startsWith("/mcp/") ? withoutCors(res) : res;
  },
} satisfies ExportedHandler<Env>;

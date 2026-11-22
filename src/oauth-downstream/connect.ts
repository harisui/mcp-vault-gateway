import type { App } from "../app";
import { pkceChallenge, pkceVerifier, randomState } from "../auth/pkce";
import { readSession } from "../auth/session";
import { decrypt, encrypt } from "../crypto/aes";
import { grantFor, serverAllowed } from "../policy/caller";
import { timingSafeEqualString } from "../util/constant-time";
import { sha256Hex } from "../util/encoding";
import { escapeHtml, htmlPage, messagePage, notAuthorizedPage } from "../util/html";
import { errorInfo, log } from "../util/log";
import { OAuthFlowError } from "./http";
import { cachedAuthServer } from "./metadata";
import { exchangeCode, registerClient, tokenFields } from "./tokens";

/**
 * Browser flow that connects an `auth_type: oauth` server:
 *   GET /connect/<group>/<name>  -> discovery, DCR if needed, redirect to the server's login
 *   GET /oauth/callback          -> code exchange, tokens written back to the 1Password item
 * Requires a gateway browser session (GitHub login) and access to that server in _policy.
 */

const STATE_TTL_S = 600;
const stateKey = async (state: string) => `oauthstate:${await sha256Hex(state)}`;

interface PendingConnect {
  serverId: string;
  group: string;
  itemId: string;
  email: string;
  verifier: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret?: string;
  resource: string;
  exp: number;
}

const callbackUrl = (app: App) => `${app.publicUrl}/oauth/callback`;

async function requireSession(req: Request, app: App, path: string): Promise<{ email: string } | Response> {
  const session = await readSession(req, app.ring);
  if (session) return session;
  return new Response(null, { status: 302, headers: { Location: `/login?next=${encodeURIComponent(path)}`, "Cache-Control": "no-store" } });
}

async function startConnect(req: Request, app: App, group: string, name: string, path: string): Promise<Response> {
  const session = await requireSession(req, app, path);
  if (session instanceof Response) return session;

  const found = await app.registry.find(`${group}.${name}`);
  const grant = found && grantFor(found.state.policy.ok ? found.state.policy.policy : undefined, group, { kind: "user", id: session.email, email: session.email });
  if (!found || !serverAllowed(grant, name)) return notAuthorizedPage();
  const server = found.server;
  if (server.authType !== "oauth" || !server.url) return messagePage("Nothing to connect", `${server.id} does not use OAuth.`, 400);
  if (server.status === "invalid" || server.status === "disabled") return messagePage("Cannot connect", `${server.id} is ${server.status}.`, 400);

  const meta = await cachedAuthServer(app.env.CACHE_KV, server.id, server.url, true);
  let clientId = server.oauth?.clientId;
  let clientSecret = server.oauth?.clientSecret;
  if (!clientId) {
    if (!meta.registrationEndpoint) {
      return messagePage("Client registration needed", `${meta.issuer} does not support dynamic registration. Add client_id and client_secret to the 1Password item, then try again.`, 400);
    }
    const reg = await registerClient(meta.registrationEndpoint, callbackUrl(app), server.oauth?.scopes, `MCP Vault Gateway (${new URL(app.publicUrl).host})`);
    clientId = reg.clientId;
    clientSecret = reg.clientSecret;
    const fields: Record<string, { value: string; concealed: boolean }> = { client_id: { value: clientId, concealed: false } };
    if (clientSecret) fields.client_secret = { value: clientSecret, concealed: true };
    await app.registry.writeItemFields(group, server.itemId, fields);
    log("info", "connect.registered_client", { server: server.id });
  }

  const state = randomState();
  const verifier = pkceVerifier();
  const pending: PendingConnect = {
    serverId: server.id,
    group,
    itemId: server.itemId,
    email: session.email,
    verifier,
    tokenEndpoint: meta.tokenEndpoint,
    clientId,
    clientSecret,
    resource: meta.resource,
    exp: Date.now() + STATE_TTL_S * 1000,
  };
  const key = await stateKey(state);
  await app.env.CACHE_KV.put(key, await encrypt(app.ring, "oauth-state-v1", key, JSON.stringify(pending)), { expirationTtl: STATE_TTL_S });

  const u = new URL(meta.authorizationEndpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", callbackUrl(app));
  u.searchParams.set("state", state);
  u.searchParams.set("code_challenge", await pkceChallenge(verifier));
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("resource", meta.resource);
  if (server.oauth?.scopes) u.searchParams.set("scope", server.oauth.scopes);
  return new Response(null, { status: 302, headers: { Location: u.toString(), "Cache-Control": "no-store" } });
}

async function finishConnect(req: Request, app: App): Promise<Response> {
  const url = new URL(req.url);
  const session = await readSession(req, app.ring);
  if (!session) return messagePage("Signed out", "Your gateway session expired. Open the connect link again.", 401);

  const state = url.searchParams.get("state") ?? "";
  if (!state) return messagePage("Invalid request", "Missing state.", 400);
  const key = await stateKey(state);
  const raw = await app.env.CACHE_KV.get(key);
  if (!raw) return messagePage("Link expired", "This connect attempt expired or was already used. Open the connect link again.", 400);
  await app.env.CACHE_KV.delete(key); // single use
  const pending = JSON.parse(await decrypt(app.ring, "oauth-state-v1", key, raw)) as PendingConnect;
  if (pending.exp < Date.now() || !(await timingSafeEqualString(pending.email, session.email))) {
    return messagePage("Link expired", "This connect attempt belongs to another session. Open the connect link again.", 400);
  }
  const err = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  if (err || !code) return messagePage("Not connected", `The server declined the connection${err ? ` (${err})` : ""}.`, 400);

  const tokens = await exchangeCode(pending.tokenEndpoint, { clientId: pending.clientId, clientSecret: pending.clientSecret }, {
    code,
    redirectUri: callbackUrl(app),
    verifier: pending.verifier,
    resource: pending.resource,
  });
  await app.registry.writeItemFields(pending.group, pending.itemId, tokenFields(tokens));
  await app.env.SERVER_DO.get(app.env.SERVER_DO.idFromName(pending.serverId)).resetOAuth();
  log("info", "connect.connected", { server: pending.serverId, caller: session.email });
  return htmlPage("Connected", `<h1>Connected</h1><p><code>${escapeHtml(pending.serverId)}</code> is connected. You can close this tab.</p>`);
}

const CONNECT_PATH = /^\/connect\/([a-z0-9_]+)\/([a-z0-9_]+)$/;

export async function handleConnectRoute(req: Request, app: App, path: string): Promise<Response | undefined> {
  if (req.method !== "GET") return undefined;
  const m = CONNECT_PATH.exec(path);
  if (!m && path !== "/oauth/callback") return undefined;
  try {
    return m ? await startConnect(req, app, m[1]!, m[2]!, path) : await finishConnect(req, app);
  } catch (e) {
    log("error", "connect.failed", { path, error: errorInfo(e) });
    const msg = e instanceof OAuthFlowError ? e.message : "Something went wrong while connecting. Check the gateway logs.";
    return messagePage("Connection failed", msg, 502);
  }
}

import { assertSafeUrl, fetchJson, OAuthFlowError } from "./http";

export interface AuthServerInfo {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
  scopesSupported?: string[];
  /** RFC 8707 resource indicator for the downstream MCP server. */
  resource: string;
}

/** RFC 9728 / RFC 8414 well-known URLs, path-aware (`/.well-known/x` inserted before the path). */
function wellKnown(base: string, name: string): string[] {
  const u = new URL(base);
  const path = u.pathname.replace(/\/+$/, "");
  const urls = [`${u.origin}/.well-known/${name}${path}`];
  if (path) urls.push(`${u.origin}/.well-known/${name}`);
  return urls;
}

/** Read `resource_metadata` from the 401 challenge, if the server sends one. */
async function challengeMetadataUrl(serverUrl: string): Promise<string | undefined> {
  try {
    const res = await fetch(serverUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "ping" }),
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    const header = res.headers.get("WWW-Authenticate") ?? "";
    return /resource_metadata="([^"]+)"/.exec(header)?.[1];
  } catch {
    return undefined;
  }
}

/**
 * Find the authorization server for a downstream MCP server:
 * 1. Protected Resource Metadata (RFC 9728), from the 401 challenge or the well-known URL.
 * 2. Authorization Server Metadata (RFC 8414), falling back to OpenID discovery.
 * Servers without PRM are assumed to be their own authorization server (older MCP servers).
 */
export async function discoverAuthServer(serverUrl: string): Promise<AuthServerInfo> {
  let resource = serverUrl;
  let issuer = new URL(serverUrl).origin;

  const prmCandidates = [await challengeMetadataUrl(serverUrl), ...wellKnown(serverUrl, "oauth-protected-resource")].filter(
    (u): u is string => Boolean(u),
  );
  for (const url of prmCandidates) {
    assertSafeUrl(url, "resource metadata URL");
    const prm = await fetchJson(url).catch(() => undefined);
    if (!prm || prm.status !== 200) continue;
    const servers = prm.body.authorization_servers;
    if (Array.isArray(servers) && typeof servers[0] === "string") issuer = assertSafeUrl(servers[0], "authorization server");
    if (typeof prm.body.resource === "string") resource = prm.body.resource;
    break;
  }

  const asCandidates = [...wellKnown(issuer, "oauth-authorization-server"), ...wellKnown(issuer, "openid-configuration")];
  for (const url of asCandidates) {
    const meta = await fetchJson(url).catch(() => undefined);
    if (!meta || meta.status !== 200) continue;
    const b = meta.body;
    const methods = b.code_challenge_methods_supported;
    if (Array.isArray(methods) && !methods.includes("S256")) throw new OAuthFlowError("authorization server does not support PKCE S256");
    return {
      issuer,
      authorizationEndpoint: assertSafeUrl(b.authorization_endpoint, "authorization_endpoint"),
      tokenEndpoint: assertSafeUrl(b.token_endpoint, "token_endpoint"),
      registrationEndpoint: b.registration_endpoint ? assertSafeUrl(b.registration_endpoint, "registration_endpoint") : undefined,
      scopesSupported: Array.isArray(b.scopes_supported) ? (b.scopes_supported as string[]) : undefined,
      resource,
    };
  }
  throw new OAuthFlowError(`no OAuth metadata found for ${new URL(serverUrl).host}`);
}

const metaKey = (serverId: string) => `asmeta:${serverId}`;

/** Discovery result cached in KV for a day. Not secret: it is public metadata. */
export async function cachedAuthServer(kv: KVNamespace, serverId: string, serverUrl: string, fresh = false): Promise<AuthServerInfo> {
  if (!fresh) {
    const hit = await kv.get<AuthServerInfo & { url: string }>(metaKey(serverId), "json");
    if (hit && hit.url === serverUrl) return hit;
  }
  const info = await discoverAuthServer(serverUrl);
  await kv.put(metaKey(serverId), JSON.stringify({ ...info, url: serverUrl }), { expirationTtl: 86_400 });
  return info;
}

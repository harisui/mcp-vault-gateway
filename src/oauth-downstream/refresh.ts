import { connectUrl } from "../proxy/forward";
import type { ServerDO } from "../proxy/server-do";
import type { Registry } from "../registry/registry";
import type { ServerEntry } from "../registry/types";
import { GatewayError } from "../util/errors";
import { errorInfo, log } from "../util/log";
import { OAuthFlowError } from "./http";
import { cachedAuthServer } from "./metadata";
import { refreshAccessToken, type TokenSet, tokenFields } from "./tokens";

/** Refresh when the access token expires within this window. */
export const REFRESH_SKEW_MS = 2 * 60_000;

export type RefreshResult =
  | { ok: true; accessToken: string; expiresAt?: number }
  | { ok: false; kind: "needs_connect" | "error"; message: string };

export interface RefreshDeps {
  registry: Pick<Registry, "reloadItem" | "writeItemFields">;
  kv: KVNamespace;
  /** Token set kept in Durable Object storage until it is safely written to 1Password. */
  stash: { get(): Promise<TokenSet | undefined>; set(t: TokenSet): Promise<void>; clear(): Promise<void> };
  now?: () => number;
}

const usable = (t: { accessToken?: string; expiresAt?: number }, now: number) =>
  Boolean(t.accessToken) && (t.expiresAt === undefined || t.expiresAt - now > REFRESH_SKEW_MS);

/**
 * Runs inside the server's Durable Object, which serializes it: only one refresh per server
 * at a time, concurrent callers share the result.
 */
export async function refreshServerToken(deps: RefreshDeps, group: string, itemId: string, force: boolean): Promise<RefreshResult> {
  const now = (deps.now ?? Date.now)();

  // A previous refresh succeeded but its 1Password write failed: finish that first.
  const stashed = await deps.stash.get();
  if (stashed) {
    try {
      await deps.registry.writeItemFields(group, itemId, tokenFields(stashed));
      await deps.stash.clear();
    } catch (e) {
      log("warn", "oauth.writeback_retry_failed", { group, error: errorInfo(e).message });
      if (usable(stashed, now)) return { ok: true, accessToken: stashed.accessToken, expiresAt: stashed.expiresAt };
    }
  }

  const server = await deps.registry.reloadItem(group, itemId);
  if (!server || server.authType !== "oauth" || !server.url) return { ok: false, kind: "error", message: "server is not an OAuth server" };
  const o = server.oauth ?? {};
  if (!force && usable(o, now)) return { ok: true, accessToken: o.accessToken!, expiresAt: o.expiresAt };
  if (!o.refreshToken || !o.clientId) return { ok: false, kind: "needs_connect", message: "no refresh token" };

  let tokens: TokenSet;
  try {
    const meta = await cachedAuthServer(deps.kv, server.id, server.url);
    tokens = await refreshAccessToken(meta.tokenEndpoint, { clientId: o.clientId, clientSecret: o.clientSecret }, o.refreshToken, meta.resource);
  } catch (e) {
    if (e instanceof OAuthFlowError && e.code === "invalid_grant") {
      log("warn", "oauth.invalid_grant", { server: server.id });
      await deps.registry
        .writeItemFields(group, itemId, { access_token: { value: "", concealed: true }, refresh_token: { value: "", concealed: true }, expires_at: { value: "", concealed: false } })
        .catch((err) => log("warn", "oauth.clear_failed", { server: server.id, error: errorInfo(err).message }));
      return { ok: false, kind: "needs_connect", message: "refresh token rejected" };
    }
    log("warn", "oauth.refresh_failed", { server: server.id, error: errorInfo(e).message });
    return { ok: false, kind: "error", message: "token refresh failed" };
  }

  if (!tokens.refreshToken) tokens.refreshToken = o.refreshToken; // server did not rotate it
  await deps.stash.set(tokens);
  try {
    await deps.registry.writeItemFields(group, itemId, tokenFields(tokens));
    await deps.stash.clear();
  } catch (e) {
    log("warn", "oauth.writeback_failed", { server: server.id, error: errorInfo(e).message });
  }
  log("info", "oauth.refreshed", { server: server.id });
  return { ok: true, accessToken: tokens.accessToken, expiresAt: tokens.expiresAt };
}

/** Worker side: make sure an OAuth server has a usable access token before calling it. */
export async function oauthCredentials(
  ns: DurableObjectNamespace<ServerDO>,
  publicUrl: string,
  server: ServerEntry,
  opts: { afterAuthFailure?: boolean } = {},
): Promise<ServerEntry> {
  if (server.authType !== "oauth") return server;
  const o = server.oauth ?? {};
  if (!opts.afterAuthFailure && usable(o, Date.now())) return server;
  const r = (await ns.get(ns.idFromName(server.id)).refreshOAuth(server.group, server.itemId, Boolean(opts.afterAuthFailure))) as RefreshResult;
  if (r.ok) return { ...server, oauth: { ...o, accessToken: r.accessToken, expiresAt: r.expiresAt } };
  if (r.kind === "needs_connect") {
    throw new GatewayError(`${server.id} needs to be reconnected. Open ${connectUrl(publicUrl, server)} in a browser.`);
  }
  throw new GatewayError(`Could not refresh the OAuth token for ${server.id}. Try again, or reconnect at ${connectUrl(publicUrl, server)}.`);
}

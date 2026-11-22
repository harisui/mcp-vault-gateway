import { toBase64, utf8 } from "../util/encoding";
import { fetchJson, OAuthFlowError } from "./http";

export interface ClientCreds {
  clientId: string;
  clientSecret?: string;
}

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  /** Epoch ms; undefined if the server did not say. */
  expiresAt?: number;
}

/** RFC 7591 Dynamic Client Registration. */
export async function registerClient(registrationEndpoint: string, redirectUri: string, scopes: string | undefined, name: string): Promise<ClientCreds> {
  const res = await fetchJson(registrationEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: name,
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
      ...(scopes ? { scope: scopes } : {}),
    }),
  });
  const id = res?.body.client_id;
  if (!res || res.status >= 300 || typeof id !== "string") throw new OAuthFlowError(`client registration failed (${res?.status ?? 404})`);
  const secret = res.body.client_secret;
  return { clientId: id, clientSecret: typeof secret === "string" ? secret : undefined };
}

async function tokenRequest(tokenEndpoint: string, client: ClientCreds, params: Record<string, string>): Promise<TokenSet> {
  const body = new URLSearchParams(params);
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
  if (client.clientSecret) {
    const enc = (s: string) => encodeURIComponent(s);
    headers.Authorization = `Basic ${toBase64(utf8(`${enc(client.clientId)}:${enc(client.clientSecret)}`))}`;
  } else {
    body.set("client_id", client.clientId);
  }
  const res = await fetchJson(tokenEndpoint, { method: "POST", headers, body: body.toString() });
  if (!res) throw new OAuthFlowError("token endpoint not found");
  const b = res.body;
  if (res.status >= 400 || typeof b.access_token !== "string") {
    const code = typeof b.error === "string" ? b.error : `http_${res.status}`;
    throw new OAuthFlowError(`token request failed (${code})`, code);
  }
  const expiresIn = Number(b.expires_in);
  return {
    accessToken: b.access_token,
    refreshToken: typeof b.refresh_token === "string" ? b.refresh_token : undefined,
    expiresAt: Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : undefined,
  };
}

export function exchangeCode(
  tokenEndpoint: string,
  client: ClientCreds,
  p: { code: string; redirectUri: string; verifier: string; resource: string },
): Promise<TokenSet> {
  return tokenRequest(tokenEndpoint, client, {
    grant_type: "authorization_code",
    code: p.code,
    redirect_uri: p.redirectUri,
    code_verifier: p.verifier,
    resource: p.resource,
  });
}

export function refreshAccessToken(tokenEndpoint: string, client: ClientCreds, refreshToken: string, resource: string): Promise<TokenSet> {
  return tokenRequest(tokenEndpoint, client, { grant_type: "refresh_token", refresh_token: refreshToken, resource });
}

/** Fields written back to the 1Password item. */
export function tokenFields(t: TokenSet): Record<string, { value: string; concealed: boolean }> {
  const f: Record<string, { value: string; concealed: boolean }> = {
    access_token: { value: t.accessToken, concealed: true },
    expires_at: { value: t.expiresAt ? new Date(t.expiresAt).toISOString() : "", concealed: false },
  };
  if (t.refreshToken) f.refresh_token = { value: t.refreshToken, concealed: true };
  return f;
}

import { type PolicyResult, parsePolicy } from "../policy/policy";
import { splitPatterns } from "../util/glob";
import { type AuthType, MCP_TAG, POLICY_TITLE, type RawItem, type ServerEntry } from "./types";

const NAME = /^[a-z0-9_]+$/;
const AUTH_TYPES: readonly AuthType[] = ["none", "bearer", "header", "oauth"];
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "content-type", "accept", "connection", "transfer-encoding", "cookie", "mcp-session-id", "mcp-protocol-version"]);

/** Field value by label (case-insensitive), falling back to the field id. Empty string = missing. */
export function field(item: RawItem, name: string): string | undefined {
  const lower = name.toLowerCase();
  const f = item.fields.find((x) => x.title.toLowerCase() === lower) ?? item.fields.find((x) => x.id.toLowerCase() === lower);
  const v = f?.value.trim();
  return v ? v : undefined;
}

export const isMcpItem = (item: { tags: string[] }): boolean => item.tags.some((t) => t.toLowerCase() === MCP_TAG);

/**
 * Downstream URLs must be https, with a DNS host name: no IP literals, no localhost,
 * no embedded credentials. Returns an error message or undefined when valid.
 */
export function validateDownstreamUrl(value: string): string | undefined {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return "url is not a valid URL";
  }
  if (u.protocol !== "https:") return "url must use https://";
  if (u.username || u.password) return "url must not contain credentials";
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return "url must not point at localhost";
  if (/^[0-9.]+$/.test(host) || /^[0-9a-f:]+$/.test(host)) return "url must use a host name, not an IP address";
  if (!host.includes(".")) return "url must use a fully qualified host name";
  return undefined;
}

function slug(title: string): string {
  return title.toLowerCase().replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "") || "item";
}

/** Parse one item into a server entry. Never throws: problems become status "invalid". */
export function parseServerItem(group: string, item: RawItem): ServerEntry {
  const rawName = field(item, "name");
  const name = rawName ?? slug(item.title);
  const base: ServerEntry = {
    id: `${group}.${name}`,
    group,
    name,
    itemId: item.id,
    vaultId: item.vaultId,
    status: "ok",
    blockedTools: splitPatterns(field(item, "blocked_tools")),
  };
  const invalid = (reason: string): ServerEntry => ({ ...base, status: "invalid", reason });

  if (!rawName) return invalid("missing required field `name`");
  if (!NAME.test(rawName)) return invalid("`name` must be lowercase [a-z0-9_]");

  const url = field(item, "url");
  if (!url) return invalid("missing required field `url`");
  const urlError = validateDownstreamUrl(url);
  if (urlError) return invalid(urlError);

  const authType = field(item, "auth_type")?.toLowerCase() as AuthType | undefined;
  if (!authType) return invalid("missing required field `auth_type`");
  if (!AUTH_TYPES.includes(authType)) return invalid(`unknown auth_type '${authType}' (use none, bearer, header or oauth)`);

  const entry: ServerEntry = { ...base, url, authType };

  if (authType === "bearer" || authType === "header") {
    const token = field(item, "token");
    if (!token) return invalid(`auth_type ${authType} needs a \`token\` field`);
    entry.token = token;
  }
  if (authType === "header") {
    const headerName = field(item, "header_name");
    if (!headerName) return invalid("auth_type header needs a `header_name` field");
    if (!HEADER_NAME.test(headerName) || FORBIDDEN_HEADERS.has(headerName.toLowerCase())) {
      return invalid(`header_name '${headerName}' is not allowed`);
    }
    entry.headerName = headerName;
  }
  if (authType === "oauth") {
    const expires = field(item, "expires_at");
    const expiresAt = expires ? Date.parse(expires) : undefined;
    entry.oauth = {
      clientId: field(item, "client_id"),
      clientSecret: field(item, "client_secret"),
      scopes: field(item, "scopes"),
      accessToken: field(item, "access_token"),
      refreshToken: field(item, "refresh_token"),
      expiresAt: Number.isFinite(expiresAt) ? expiresAt : undefined,
    };
    if (!entry.oauth.accessToken && !entry.oauth.refreshToken) {
      entry.status = "needs_connect";
      entry.reason = "not connected yet";
    }
  }

  const enabled = field(item, "enabled")?.toLowerCase();
  if (enabled !== undefined && enabled !== "true" && enabled !== "false") return invalid("`enabled` must be true or false");
  if (enabled === "false") {
    entry.status = "disabled";
    entry.reason = "disabled in 1Password";
  }
  return entry;
}

export interface ParsedGroup {
  servers: ServerEntry[];
  policy: PolicyResult;
}

/** Parse all items of one group. Only items tagged `mcp` are considered. */
export function parseGroup(group: string, items: RawItem[]): ParsedGroup {
  const mcpItems = items.filter(isMcpItem);
  const policyItems = mcpItems.filter((i) => i.title === POLICY_TITLE);
  const policy: PolicyResult =
    policyItems.length > 1
      ? { ok: false, error: "more than one _policy item in this vault" }
      : parsePolicy(policyItems[0] ? field(policyItems[0], "policy") : undefined);

  const servers: ServerEntry[] = [];
  const seen = new Set<string>();
  for (const item of mcpItems) {
    if (item.title === POLICY_TITLE) continue;
    const entry = parseServerItem(group, item);
    if (entry.status !== "invalid" && seen.has(entry.name)) {
      servers.push({ ...entry, status: "invalid", reason: `duplicate name '${entry.name}' in group ${group}`, token: undefined, oauth: undefined });
      continue;
    }
    seen.add(entry.name);
    servers.push(entry);
  }
  return { servers, policy };
}

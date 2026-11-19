import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { CounterDO } from "./util/counter-do";

/**
 * Bindings and settings. Secrets (OP_TOKEN_*, ENCRYPTION_KEY_V*, GITHUB_*, COOKIE_SECRET) are set
 * with `wrangler secret put --env <personal|client>`; see SETUP.md. Plain vars live in wrangler.jsonc.
 */
export interface Env {
  OAUTH_KV: KVNamespace;
  CACHE_KV: KVNamespace;
  COUNTER_DO: DurableObjectNamespace<CounterDO>;

  /** Injected by workers-oauth-provider for the default handler. */
  OAUTH_PROVIDER: OAuthHelpers;

  PUBLIC_URL: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  ACTIVE_KEY_VERSION?: string;
  /** Comma-separated emails that see policy and load errors in list_servers. */
  ADMIN_EMAILS?: string;

  CACHE_TTL_SECONDS?: string;
  TOOLS_CACHE_TTL_SECONDS?: string;
  OP_MAX_CALLS_PER_HOUR?: string;
  DOWNSTREAM_TIMEOUT_MS?: string;
  MAX_REQUEST_BYTES?: string;
  MAX_RESPONSE_BYTES?: string;
  RATE_LIMIT_PER_MINUTE?: string;

  /** OP_TOKEN_<GROUP>, ENCRYPTION_KEY_V<n>: enumerated dynamically. */
  [key: string]: unknown;
}

export interface Settings {
  cacheTtlMs: number;
  toolsCacheTtlMs: number;
  opMaxCallsPerHour: number;
  downstreamTimeoutMs: number;
  maxRequestBytes: number;
  maxResponseBytes: number;
  rateLimitPerMinute: number;
  adminEmails: string[];
}

function int(value: string | undefined, fallback: number, min: number, max: number): number {
  const n = value === undefined || value === "" ? fallback : Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return fallback;
  return n;
}

export function settings(env: Env): Settings {
  return {
    cacheTtlMs: int(env.CACHE_TTL_SECONDS, 3600, 60, 86_400) * 1000,
    toolsCacheTtlMs: int(env.TOOLS_CACHE_TTL_SECONDS, 3600, 60, 86_400) * 1000,
    opMaxCallsPerHour: int(env.OP_MAX_CALLS_PER_HOUR, 200, 1, 1000),
    downstreamTimeoutMs: int(env.DOWNSTREAM_TIMEOUT_MS, 30_000, 1000, 300_000),
    maxRequestBytes: int(env.MAX_REQUEST_BYTES, 1_048_576, 1024, 50_000_000),
    maxResponseBytes: int(env.MAX_RESPONSE_BYTES, 5_242_880, 1024, 100_000_000),
    rateLimitPerMinute: int(env.RATE_LIMIT_PER_MINUTE, 120, 1, 100_000),
    adminEmails: (env.ADMIN_EMAILS ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  };
}

const GROUP_TOKEN = /^OP_TOKEN_([A-Z0-9_]+)$/;

/** Every OP_TOKEN_<GROUP> binding -> { group: token }. Group is the lowercased suffix. */
export function discoverGroups(env: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    const m = GROUP_TOKEN.exec(name);
    if (m && typeof value === "string" && value.trim()) out[m[1]!.toLowerCase()] = value.trim();
  }
  return out;
}

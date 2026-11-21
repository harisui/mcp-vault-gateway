import { getKeyRing, type KeyRing } from "./crypto/keys";
import { discoverGroups, type Env, type Settings, settings } from "./env";
import { HourlyBudget } from "./onepassword/budget";
import type { OpClient } from "./onepassword/client";
import { SdkOpClient } from "./onepassword/sdk-client";
import { ToolsCache } from "./proxy/tools-cache";
import type { GroupState } from "./registry/registry";
import { Registry } from "./registry/registry";

/** Per-isolate wiring. Built once per env, reused across requests. */
export interface App {
  env: Env;
  cfg: Settings;
  ring: KeyRing;
  registry: Registry;
  budget: HourlyBudget;
  tools: ToolsCache;
  publicUrl: string;
}

const apps = new WeakMap<Env, Promise<App>>();

export function getApp(env: Env): Promise<App> {
  let app = apps.get(env);
  if (!app) {
    app = buildApp(env);
    app.catch(() => apps.delete(env));
    apps.set(env, app);
  }
  return app;
}

export function publicUrl(env: Env): string {
  const raw = (env.PUBLIC_URL ?? "").trim().replace(/\/+$/, "");
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("PUBLIC_URL is not set to a valid URL");
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !local) throw new Error("PUBLIC_URL must be https://");
  return u.origin;
}

async function buildApp(env: Env): Promise<App> {
  const cfg = settings(env);
  const ring = await getKeyRing(env); // refuses to start with a bad master key
  const budget = new HourlyBudget(env.COUNTER_DO, cfg.opMaxCallsPerHour);
  const clients: Record<string, OpClient> = {};
  for (const [group, token] of Object.entries(discoverGroups(env))) clients[group] = new SdkOpClient(group, token, budget);
  const registry = new Registry({ kv: env.CACHE_KV, ring, clients, ttlMs: cfg.cacheTtlMs });
  const tools = new ToolsCache(env.CACHE_KV, ring, cfg.toolsCacheTtlMs);
  return { env, cfg, ring, registry, budget, tools, publicUrl: publicUrl(env) };
}

/** True when the email is listed in at least one group's valid _policy. */
export function isKnownUser(email: string, groups: GroupState[]): boolean {
  const e = email.toLowerCase();
  return groups.some((g) => g.policy.ok && e in g.policy.policy.users);
}

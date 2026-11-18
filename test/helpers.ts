import { KeyRing } from "../src/crypto/keys";
import { randomBytes, toBase64 } from "../src/util/encoding";

export const newMasterKey = (): string => toBase64(randomBytes(32));

export function keyRing(env: Record<string, string> = { ENCRYPTION_KEY_V1: newMasterKey() }): Promise<KeyRing> {
  return KeyRing.fromEnv(env);
}

import type { RawItem } from "../src/registry/types";

let counter = 0;

/** Build a 1Password-like item. `fields` maps label -> value; labels ending in a known secret are concealed. */
export function rawItem(title: string, fields: Record<string, string>, opts: Partial<RawItem> = {}): RawItem {
  counter++;
  const concealed = new Set(["token", "client_secret", "access_token", "refresh_token", "policy"]);
  return {
    id: opts.id ?? `item${counter}`,
    vaultId: opts.vaultId ?? "vault1",
    title,
    tags: opts.tags ?? ["mcp"],
    version: opts.version ?? 1,
    updatedAt: opts.updatedAt ?? "2026-11-01T00:00:00.000Z",
    fields: Object.entries(fields).map(([k, v]) => ({ id: k, title: k, type: concealed.has(k) ? "concealed" : "text", value: v })),
  };
}

export function policyItem(policy: unknown, opts: Partial<RawItem> = {}): RawItem {
  return rawItem("_policy", { policy: typeof policy === "string" ? policy : JSON.stringify(policy) }, opts);
}

import type * as Sdk from "@1password/sdk";
import type { RawItem } from "../registry/types";
import { log } from "../util/log";
import { type FieldWrite, type ItemOverviewInfo, OpError, type OpClient, type VaultInfo } from "./client";

/**
 * OpClient backed by @1password/sdk. The SDK's WASM core is loaded through the shim built by
 * scripts/build-op-shim.mjs (aliased in wrangler.jsonc), and only on first use, so requests
 * that are served from cache never pay for it.
 */

type SdkModule = typeof Sdk;

let sdkModule: Promise<SdkModule> | undefined;
const loadSdk = (): Promise<SdkModule> => (sdkModule ??= import("@1password/sdk"));

/** One signed-in SDK client per token per isolate. Sign-in takes ~3s, so it is reused. */
const clients = new Map<string, Promise<Sdk.Client>>();

export interface Budget {
  /** Throws OpError("budget_exceeded") when over the hourly cap. */
  take(calls: number): Promise<void>;
}

const MAX_RETRIES = 3;

const isRateLimit = (e: unknown): boolean =>
  e instanceof Error && (e.constructor?.name === "RateLimitExceededError" || /rate limit/i.test(e.message));
const isAuthExpired = (e: unknown): boolean =>
  e instanceof Error && (e.constructor?.name === "AuthExpiredError" || /auth(entication)? expired/i.test(e.message));

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function toRawItem(item: Sdk.Item): RawItem {
  return {
    id: item.id,
    vaultId: item.vaultId,
    title: item.title,
    tags: item.tags ?? [],
    version: item.version,
    updatedAt: new Date(item.updatedAt).toISOString(),
    fields: item.fields.map((f) => ({ id: f.id, title: f.title, type: String(f.fieldType).toLowerCase(), value: f.value ?? "" })),
  };
}

export class SdkOpClient implements OpClient {
  constructor(
    private readonly group: string,
    private readonly token: string,
    private readonly budget: Budget,
  ) {}

  private async client(): Promise<Sdk.Client> {
    let c = clients.get(this.token);
    if (!c) {
      const pending = (async () => {
        await this.budget.take(1);
        const sdk = await loadSdk();
        return sdk.createClient({ auth: this.token, integrationName: "mcp-vault-gateway", integrationVersion: "0.1.0" });
      })();
      pending.catch(() => clients.delete(this.token));
      clients.set(this.token, pending);
      c = pending;
    }
    return c;
  }

  /** Budgeted call with exponential backoff on 1Password rate limits and one re-sign-in on expiry. */
  private async call<T>(op: string, calls: number, fn: (c: Sdk.Client) => Promise<T>): Promise<T> {
    let reauthed = false;
    for (let attempt = 0; ; attempt++) {
      await this.budget.take(calls);
      try {
        return await fn(await this.client());
      } catch (e) {
        if (e instanceof OpError) throw e;
        if (isAuthExpired(e) && !reauthed) {
          reauthed = true;
          clients.delete(this.token);
          continue;
        }
        if (isRateLimit(e)) {
          if (attempt >= MAX_RETRIES) throw new OpError(`1Password rate limit (${op})`, "rate_limited");
          const delay = 500 * 2 ** attempt + Math.random() * 250;
          log("warn", "op.rate_limited", { group: this.group, op, attempt, delay_ms: Math.round(delay) });
          await sleep(delay);
          continue;
        }
        const msg = e instanceof Error ? e.message : String(e);
        throw new OpError(`1Password ${op} failed: ${msg}`, /not found/i.test(msg) ? "not_found" : "other");
      }
    }
  }

  async listVaults(): Promise<VaultInfo[]> {
    const vaults = await this.call("vaults.list", 1, (c) => c.vaults.list());
    return vaults.map((v) => ({ id: v.id, title: v.title, contentVersion: v.contentVersion }));
  }

  async listItems(vaultId: string): Promise<ItemOverviewInfo[]> {
    const items = await this.call("items.list", 1, (c) => c.items.list(vaultId));
    return items.map((i) => ({ id: i.id, title: i.title, tags: i.tags ?? [], updatedAt: new Date(i.updatedAt).toISOString() }));
  }

  async getItems(vaultId: string, itemIds: string[]): Promise<RawItem[]> {
    if (itemIds.length === 0) return [];
    const res = await this.call("items.getAll", 1, (c) => c.items.getAll(vaultId, itemIds));
    const out: RawItem[] = [];
    for (const r of res.individualResponses) {
      if (r.content) out.push(toRawItem(r.content));
      else log("warn", "op.item_unreadable", { group: this.group, vault: vaultId });
    }
    return out;
  }

  async writeFields(vaultId: string, itemId: string, fields: Record<string, FieldWrite>): Promise<RawItem> {
    const sdk = await loadSdk();
    const item = await this.call("items.get", 1, (c) => c.items.get(vaultId, itemId));
    const next = item.fields.map((f) => ({ ...f }));
    for (const [label, w] of Object.entries(fields)) {
      const existing = next.find((f) => f.title.toLowerCase() === label.toLowerCase());
      const fieldType = w.concealed ? sdk.ItemFieldType.Concealed : sdk.ItemFieldType.Text;
      if (existing) {
        existing.value = w.value;
      } else {
        next.push({ id: label, title: label, fieldType, value: w.value });
      }
    }
    const updated = await this.call("items.put", 1, (c) => c.items.put({ ...item, fields: next }));
    return toRawItem(updated);
  }
}

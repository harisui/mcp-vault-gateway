import { decrypt, encrypt } from "../crypto/aes";
import type { KeyRing } from "../crypto/keys";
import type { OpClient, VaultInfo } from "../onepassword/client";
import type { PolicyResult } from "../policy/policy";
import { errorInfo, log } from "../util/log";
import { isMcpItem, parseGroup } from "./item-parser";
import type { RawItem, ServerEntry } from "./types";

/** What is cached per group: the raw items, encrypted. Parsing is cheap and done on read. */
export interface GroupSnapshot {
  group: string;
  /** Last successful load from 1Password (epoch ms). */
  loadedAt: number;
  /** Last attempt, successful or not. Throttles retries while 1Password is failing. */
  attemptAt: number;
  vaults: VaultInfo[];
  items: RawItem[];
  /** Set when the last attempt failed and this snapshot is being served stale. */
  error?: string;
}

export interface GroupState {
  group: string;
  servers: ServerEntry[];
  policy: PolicyResult;
  loadedAt: number;
  stale: boolean;
  error?: string;
}

export interface RegistryDeps {
  kv: KVNamespace;
  ring: KeyRing;
  /** One OpClient per group, from OP_TOKEN_<GROUP>. */
  clients: Record<string, OpClient>;
  ttlMs: number;
  now?: () => number;
  /** How long a decrypted snapshot is reused in memory before re-reading KV. */
  memoMs?: number;
}

const RETRY_AFTER_ERROR_MS = 5 * 60_000;
export const snapshotKey = (group: string) => `reg:${group}`;
export const healthKey = (group: string) => `health:${group}`;

export class Registry {
  private readonly memo = new Map<string, { snap: GroupSnapshot | undefined; at: number }>();
  private readonly inflight = new Map<string, Promise<GroupSnapshot | undefined>>();
  private readonly now: () => number;
  private readonly memoMs: number;

  constructor(private readonly deps: RegistryDeps) {
    this.now = deps.now ?? Date.now;
    this.memoMs = deps.memoMs ?? 30_000;
  }

  get groups(): string[] {
    return Object.keys(this.deps.clients).sort();
  }

  async getAll(opts: { force?: boolean } = {}): Promise<GroupState[]> {
    return Promise.all(this.groups.map((g) => this.getGroup(g, opts)));
  }

  async getGroup(group: string, opts: { force?: boolean } = {}): Promise<GroupState> {
    if (!this.deps.clients[group]) throw new Error(`unknown group ${group}`);
    let snap = await this.readSnapshot(group);
    if (opts.force || this.needsReload(snap)) snap = await this.reload(group, snap);
    return toState(group, snap);
  }

  /** Look up `<group>.<name>`. */
  async find(serverId: string): Promise<{ state: GroupState; server: ServerEntry } | undefined> {
    const dot = serverId.indexOf(".");
    if (dot <= 0) return undefined;
    const group = serverId.slice(0, dot);
    if (!this.deps.clients[group]) return undefined;
    const state = await this.getGroup(group);
    const server = state.servers.find((s) => s.id === serverId);
    return server ? { state, server } : undefined;
  }

  /** Re-read one item from 1Password (e.g. after a downstream 401) and update the cache. */
  async reloadItem(group: string, itemId: string): Promise<ServerEntry | undefined> {
    const snap = await this.readSnapshot(group);
    const old = snap?.items.find((i) => i.id === itemId);
    if (!snap || !old) return undefined;
    const [fresh] = await this.client(group).getItems(old.vaultId, [itemId]);
    await this.replaceItem(snap, itemId, fresh);
    return toState(group, snap).servers.find((s) => s.itemId === itemId);
  }

  /** Write fields back to a 1Password item (OAuth tokens) and update the cache. */
  async writeItemFields(group: string, itemId: string, fields: Record<string, { value: string; concealed: boolean }>): Promise<ServerEntry | undefined> {
    const snap = await this.readSnapshot(group);
    const old = snap?.items.find((i) => i.id === itemId);
    if (!snap || !old) throw new Error("item not in cache");
    const updated = await this.client(group).writeFields(old.vaultId, itemId, fields);
    await this.replaceItem(snap, itemId, updated);
    return toState(group, snap).servers.find((s) => s.itemId === itemId);
  }

  private client(group: string): OpClient {
    const c = this.deps.clients[group];
    if (!c) throw new Error(`unknown group ${group}`);
    return c;
  }

  private needsReload(snap: GroupSnapshot | undefined): boolean {
    if (!snap) return true;
    const now = this.now();
    if (snap.error) return now - snap.attemptAt >= Math.min(this.deps.ttlMs, RETRY_AFTER_ERROR_MS);
    return now - snap.loadedAt >= this.deps.ttlMs;
  }

  private reload(group: string, cached: GroupSnapshot | undefined): Promise<GroupSnapshot | undefined> {
    let p = this.inflight.get(group);
    if (!p) {
      p = this.doReload(group, cached).finally(() => this.inflight.delete(group));
      this.inflight.set(group, p);
    }
    return p;
  }

  private async doReload(group: string, cached: GroupSnapshot | undefined): Promise<GroupSnapshot | undefined> {
    const op = this.client(group);
    const now = this.now();
    try {
      const vaults = await op.listVaults();
      const items: RawItem[] = [];
      let fetched = 0;
      for (const vault of vaults) {
        const prevVault = cached?.vaults.find((v) => v.id === vault.id);
        const prevItems = cached?.items.filter((i) => i.vaultId === vault.id) ?? [];
        if (prevVault && vault.contentVersion !== undefined && prevVault.contentVersion === vault.contentVersion) {
          items.push(...prevItems);
          continue;
        }
        const overviews = (await op.listItems(vault.id)).filter(isMcpItem);
        const changed = overviews.filter((o) => prevItems.find((i) => i.id === o.id)?.updatedAt !== o.updatedAt);
        const fresh = await op.getItems(vault.id, changed.map((o) => o.id));
        fetched += fresh.length;
        for (const o of overviews) {
          const item = fresh.find((i) => i.id === o.id) ?? prevItems.find((i) => i.id === o.id);
          if (item) items.push(item);
        }
      }
      const snap: GroupSnapshot = { group, loadedAt: now, attemptAt: now, vaults, items };
      await this.writeSnapshot(snap);
      await this.setHealth(group, cached, "ok");
      log("info", "registry.reloaded", { group, vaults: vaults.length, items: items.length, fetched });
      return snap;
    } catch (e) {
      const err = errorInfo(e);
      log("warn", "registry.reload_failed", { group, error: err.message, serving_stale: Boolean(cached) });
      await this.setHealth(group, cached, "degraded");
      if (!cached) return undefined;
      const stale: GroupSnapshot = { ...cached, attemptAt: now, error: err.message };
      await this.writeSnapshot(stale).catch(() => undefined);
      return stale;
    }
  }

  private async replaceItem(snap: GroupSnapshot, itemId: string, item: RawItem | undefined): Promise<void> {
    snap.items = item ? snap.items.map((i) => (i.id === itemId ? item : i)) : snap.items.filter((i) => i.id !== itemId);
    await this.writeSnapshot(snap);
  }

  private async readSnapshot(group: string): Promise<GroupSnapshot | undefined> {
    const m = this.memo.get(group);
    if (m && this.now() - m.at < this.memoMs) return m.snap;
    const key = snapshotKey(group);
    const raw = await this.deps.kv.get(key);
    let snap: GroupSnapshot | undefined;
    if (raw) {
      try {
        snap = JSON.parse(await decrypt(this.deps.ring, "kv-cache-v1", key, raw)) as GroupSnapshot;
      } catch (e) {
        log("warn", "registry.cache_unreadable", { group, error: errorInfo(e).message });
      }
    }
    this.memo.set(group, { snap, at: this.now() });
    return snap;
  }

  private async writeSnapshot(snap: GroupSnapshot): Promise<void> {
    const key = snapshotKey(snap.group);
    // No KV expiry: an old snapshot is still worth serving when 1Password is down.
    await this.deps.kv.put(key, await encrypt(this.deps.ring, "kv-cache-v1", key, JSON.stringify(snap)));
    this.memo.set(snap.group, { snap, at: this.now() });
  }

  private async setHealth(group: string, prev: GroupSnapshot | undefined, status: "ok" | "degraded"): Promise<void> {
    const wasDegraded = Boolean(prev?.error) || !prev;
    if ((status === "degraded") === wasDegraded && prev) return;
    await this.deps.kv.put(healthKey(group), status).catch(() => undefined);
  }
}

function toState(group: string, snap: GroupSnapshot | undefined): GroupState {
  if (!snap) {
    return { group, servers: [], policy: { ok: false, error: "1Password not reachable and nothing cached" }, loadedAt: 0, stale: false, error: "not loaded" };
  }
  const parsed = parseGroup(group, snap.items);
  return { group, servers: parsed.servers, policy: parsed.policy, loadedAt: snap.loadedAt, stale: Boolean(snap.error), error: snap.error };
}

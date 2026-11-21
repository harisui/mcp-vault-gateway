import { decrypt, encrypt } from "../crypto/aes";
import type { KeyRing } from "../crypto/keys";
import { errorInfo, log } from "../util/log";
import type { ToolList } from "./server-do";

interface Entry extends ToolList {
  at: number;
}

const key = (serverId: string) => `tools:${serverId}`;

/**
 * Downstream tool lists, cached per server (60 minutes by default). Encrypted because tool
 * names and descriptions of client systems can be confidential too.
 */
export class ToolsCache {
  private readonly memo = new Map<string, Entry>();

  constructor(
    private readonly kv: KVNamespace,
    private readonly ring: KeyRing,
    private readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  async get(serverId: string): Promise<ToolList | undefined> {
    const fresh = (e: Entry | undefined) => (e && this.now() - e.at < this.ttlMs ? e : undefined);
    const m = fresh(this.memo.get(serverId));
    if (m) return m;
    const raw = await this.kv.get(key(serverId));
    if (!raw) return undefined;
    try {
      const e = fresh(JSON.parse(await decrypt(this.ring, "kv-cache-v1", key(serverId), raw)) as Entry);
      if (e) this.memo.set(serverId, e);
      return e;
    } catch (err) {
      log("warn", "tools_cache.unreadable", { server: serverId, error: errorInfo(err).message });
      return undefined;
    }
  }

  async put(serverId: string, list: ToolList): Promise<void> {
    const e: Entry = { ...list, at: this.now() };
    this.memo.set(serverId, e);
    const ttlS = Math.max(60, Math.ceil(this.ttlMs / 1000));
    await this.kv.put(key(serverId), await encrypt(this.ring, "kv-cache-v1", key(serverId), JSON.stringify(e)), { expirationTtl: ttlS });
  }

  /** Description only, for list_servers. Never triggers a downstream call. */
  async description(serverId: string): Promise<string | undefined> {
    return (await this.get(serverId))?.description;
  }
}

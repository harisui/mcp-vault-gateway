import { DurableObject } from "cloudflare:workers";

export interface HitResult {
  allowed: boolean;
  count: number;
  resetAt: number;
}

interface Window {
  start: number;
  count: number;
}

/**
 * Fixed-window counter. One instance per counter name (caller rate limit, refresh_servers
 * cooldown, 1Password call budget). A Durable Object is used instead of KV because KV is not
 * atomic and allows roughly one write per second per key.
 */
export class CounterDO extends DurableObject {
  private window: Window | undefined;

  async hit(windowMs: number, limit: number, cost = 1): Promise<HitResult> {
    const now = Date.now();
    const start = Math.floor(now / windowMs) * windowMs;
    const w = this.window ?? (await this.ctx.storage.get<Window>("w"));
    const current: Window = w && w.start === start ? w : { start, count: 0 };
    const resetAt = start + windowMs;
    if (current.count + cost > limit) {
      this.window = current;
      return { allowed: false, count: current.count, resetAt };
    }
    current.count += cost;
    this.window = current;
    await this.ctx.storage.put("w", current);
    return { allowed: true, count: current.count, resetAt };
  }

  async peek(windowMs: number): Promise<number> {
    const start = Math.floor(Date.now() / windowMs) * windowMs;
    const w = this.window ?? (await this.ctx.storage.get<Window>("w"));
    return w && w.start === start ? w.count : 0;
  }
}

export type CounterNamespace = DurableObjectNamespace<CounterDO>;

export function counter(ns: CounterNamespace, name: string): DurableObjectStub<CounterDO> {
  return ns.get(ns.idFromName(name));
}

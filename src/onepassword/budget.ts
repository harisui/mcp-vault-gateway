import { type CounterNamespace, counter } from "../util/counter-do";
import { log } from "../util/log";
import { OpError } from "./client";
import type { Budget } from "./sdk-client";

const HOUR_MS = 3_600_000;
export const BUDGET_COUNTER = "op-budget";

/**
 * Hard cap on 1Password calls per hour for this Worker (OP_MAX_CALLS_PER_HOUR, default 200).
 * Over the cap the registry serves from cache only.
 */
export class HourlyBudget implements Budget {
  constructor(
    private readonly ns: CounterNamespace,
    private readonly maxPerHour: number,
  ) {}

  async take(calls: number): Promise<void> {
    const r = await counter(this.ns, BUDGET_COUNTER).hit(HOUR_MS, this.maxPerHour, calls);
    if (!r.allowed) {
      log("warn", "op.budget_exceeded", { used: r.count, cap: this.maxPerHour });
      throw new OpError("1Password hourly call budget reached; serving from cache", "budget_exceeded");
    }
  }

  async used(): Promise<number> {
    return counter(this.ns, BUDGET_COUNTER).peek(HOUR_MS);
  }
}

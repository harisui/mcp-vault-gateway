import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { OpError } from "../src/onepassword/client";
import { Registry, snapshotKey } from "../src/registry/registry";
import { FakeOp } from "./fake-op";
import { keyRing, policyItem, rawItem } from "./helpers";

const TTL = 60 * 60_000;
const kv = (env as unknown as { CACHE_KV: KVNamespace }).CACHE_KV;

function setup(op: FakeOp) {
  let now = Date.parse("2026-11-20T10:00:00Z");
  const clock = { advance: (ms: number) => (now += ms) };
  const make = async () => new Registry({ kv, ring: await ring, clients: { personal: op }, ttlMs: TTL, now: () => now, memoMs: 0 });
  return { clock, make };
}

let ring: ReturnType<typeof keyRing>;
let op: FakeOp;

beforeEach(async () => {
  ring = keyRing();
  await kv.delete(snapshotKey("personal"));
  op = new FakeOp([
    rawItem("Jira", { name: "jira", url: "https://jira.example.com/mcp", auth_type: "bearer", token: "secret-token-1" }, { id: "jira" }),
    rawItem("Ledger", { name: "ledger", url: "https://ledger.example.com/mcp", auth_type: "none" }, { id: "ledger" }),
    policyItem({ users: { "me@example.com": { servers: ["*"] } } }, { id: "pol" }),
  ]);
});

describe("registry cache", () => {
  it("loads from 1Password and stores the snapshot encrypted", async () => {
    const { make } = setup(op);
    const state = await (await make()).getGroup("personal");
    expect(state.servers.map((s) => s.id).sort()).toEqual(["personal.jira", "personal.ledger"]);
    expect(state.policy.ok).toBe(true);
    const stored = await kv.get(snapshotKey("personal"));
    expect(stored).toMatch(/^v1\./);
    expect(stored).not.toContain("secret-token-1");
  });

  it("serves from cache within the TTL without calling 1Password", async () => {
    const { make, clock } = setup(op);
    await (await make()).getGroup("personal");
    op.calls = [];
    clock.advance(TTL - 1000);
    await (await make()).getGroup("personal");
    expect(op.calls).toEqual([]);
  });

  it("after the TTL, an unchanged vault costs one call", async () => {
    const { make, clock } = setup(op);
    await (await make()).getGroup("personal");
    op.calls = [];
    clock.advance(TTL);
    await (await make()).getGroup("personal");
    expect(op.calls).toEqual(["listVaults"]);
  });

  it("only re-fetches items that changed", async () => {
    const { make, clock } = setup(op);
    await (await make()).getGroup("personal");
    op.edit("jira", "token", "secret-token-2");
    op.calls = [];
    clock.advance(TTL);
    const state = await (await make()).getGroup("personal");
    expect(op.calls).toEqual(["listVaults", "listItems:vault1", "getItems:jira"]);
    expect(state.servers.find((s) => s.name === "jira")?.token).toBe("secret-token-2");
  });

  it("force reload bypasses the TTL", async () => {
    const { make } = setup(op);
    await (await make()).getGroup("personal");
    op.add(rawItem("HR", { name: "hr", url: "https://hr.example.com/mcp", auth_type: "none" }, { id: "hr" }));
    op.calls = [];
    const state = await (await make()).getGroup("personal", { force: true });
    expect(state.servers.some((s) => s.name === "hr")).toBe(true);
    expect(op.calls).toEqual(["listVaults", "listItems:vault1", "getItems:hr"]);
  });
});

describe("stale-on-error", () => {
  it("keeps serving the last good cache when 1Password fails", async () => {
    const { make, clock } = setup(op);
    await (await make()).getGroup("personal");
    op.failWith = new OpError("1Password rate limit", "rate_limited");
    clock.advance(TTL + 1);
    const state = await (await make()).getGroup("personal");
    expect(state.stale).toBe(true);
    expect(state.servers.map((s) => s.status)).toEqual(["ok", "ok"]);
    expect(state.policy.ok).toBe(true);
  });

  it("does not hammer 1Password while it is failing", async () => {
    const { make, clock } = setup(op);
    await (await make()).getGroup("personal");
    op.failWith = new Error("boom");
    clock.advance(TTL + 1);
    await (await make()).getGroup("personal");
    op.calls = [];
    clock.advance(60_000);
    await (await make()).getGroup("personal");
    expect(op.calls).toEqual([]);
  });

  it("recovers once 1Password is back", async () => {
    const { make, clock } = setup(op);
    await (await make()).getGroup("personal");
    op.failWith = new Error("boom");
    clock.advance(TTL + 1);
    await (await make()).getGroup("personal");
    op.failWith = undefined;
    clock.advance(5 * 60_000);
    const state = await (await make()).getGroup("personal");
    expect(state.stale).toBe(false);
  });

  it("with no cache and 1Password down, the group denies everything", async () => {
    const { make } = setup(op);
    op.failWith = new OpError("1Password hourly call budget reached", "budget_exceeded");
    const state = await (await make()).getGroup("personal");
    expect(state.servers).toEqual([]);
    expect(state.policy.ok).toBe(false);
  });

  it("an unreadable cache entry (wrong key) is ignored, not fatal", async () => {
    const { make } = setup(op);
    await (await make()).getGroup("personal");
    ring = keyRing();
    op.calls = [];
    const state = await (await make()).getGroup("personal");
    expect(state.servers).toHaveLength(2);
    expect(op.calls[0]).toBe("listVaults");
  });
});

describe("single-item updates", () => {
  it("reloadItem re-reads one item", async () => {
    const { make } = setup(op);
    const reg = await make();
    await reg.getGroup("personal");
    op.edit("jira", "token", "rotated");
    op.calls = [];
    const s = await reg.reloadItem("personal", "jira");
    expect(s?.token).toBe("rotated");
    expect(op.calls).toEqual(["getItems:jira"]);
  });

  it("writeItemFields writes to 1Password and updates the cache", async () => {
    const { make } = setup(op);
    const reg = await make();
    await reg.getGroup("personal");
    await reg.writeItemFields("personal", "ledger", { access_token: { value: "at", concealed: true } });
    expect(op.items.find((i) => i.id === "ledger")?.fields.some((f) => f.title === "access_token" && f.value === "at")).toBe(true);
  });
});

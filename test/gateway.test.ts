import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { settings } from "../src/env";
import { Gateway, type Limiter } from "../src/mcp/gateway";
import type { Caller } from "../src/policy/caller";
import type { DResult } from "../src/proxy/downstream";
import type { Downstream } from "../src/proxy/forward";
import type { ToolList } from "../src/proxy/server-do";
import { ToolsCache } from "../src/proxy/tools-cache";
import type { Target } from "../src/proxy/target";
import { Registry, snapshotKey } from "../src/registry/registry";
import { GatewayError } from "../src/util/errors";
import { FakeOp } from "./fake-op";
import { keyRing, policyItem, rawItem } from "./helpers";

const kv = (env as unknown as { CACHE_KV: KVNamespace }).CACHE_KV;
const PUBLIC_URL = "https://gw.example.com";

const TOOLS: Tool[] = [
  { name: "get_issue", inputSchema: { type: "object" } },
  { name: "create_issue", inputSchema: { type: "object" } },
  { name: "delete_issue", inputSchema: { type: "object" }, annotations: { destructiveHint: true } },
  { name: "purge_project", inputSchema: { type: "object" }, annotations: { readOnlyHint: false, destructiveHint: true } },
];

/** Accepts only tokens in `valid`; records every Authorization header it sees. */
class FakeDownstream implements Downstream {
  valid = new Set<string>(["good"]);
  seen: string[] = [];
  calls = 0;

  private authorized(t: Target): boolean {
    const token = (t.headers.Authorization ?? "").replace(/^Bearer /, "");
    this.seen.push(token);
    return this.valid.has(token);
  }

  async listTools(t: Target): Promise<DResult<ToolList>> {
    if (!this.authorized(t)) return { ok: false, kind: "auth", message: "401" };
    return { ok: true, value: { tools: TOOLS, description: "Issue tracker" } };
  }

  async callTool(t: Target, name: string, args: Record<string, unknown>): Promise<DResult<CallToolResult>> {
    this.calls++;
    if (!this.authorized(t)) return { ok: false, kind: "auth", message: "401" };
    return { ok: true, value: { content: [{ type: "text", text: `${name}:${JSON.stringify(args)}` }] } };
  }
}

class MemoryLimiter implements Limiter {
  counts = new Map<string, number>();
  async hit(name: string, _w: number, limit: number) {
    const n = (this.counts.get(name) ?? 0) + 1;
    this.counts.set(name, n);
    return n <= limit;
  }
}

const me: Caller = { kind: "user", id: "me@example.com", email: "me@example.com" };
const ro: Caller = { kind: "user", id: "ro@example.com", email: "ro@example.com" };
const admin: Caller = { kind: "user", id: "admin@example.com", email: "admin@example.com" };
const stranger: Caller = { kind: "user", id: "x@example.com", email: "x@example.com" };

let op: FakeOp;
let down: FakeDownstream;
let limiter: MemoryLimiter;

async function gateway(caller: Caller, extraEnv: Record<string, string> = {}) {
  const ring = await keyRing();
  const registry = new Registry({ kv, ring, clients: { personal: op }, ttlMs: 3_600_000, memoMs: 0 });
  const cfg = settings({ ADMIN_EMAILS: "admin@example.com", ...extraEnv } as never);
  return new Gateway(
    { cfg, publicUrl: PUBLIC_URL, registry, downstream: down, tools: new ToolsCache(kv, ring, cfg.toolsCacheTtlMs), limiter, credentials: async (s) => s },
    caller,
  );
}

beforeEach(async () => {
  await kv.delete(snapshotKey("personal"));
  for (const k of (await kv.list({ prefix: "tools:" })).keys) await kv.delete(k.name);
  down = new FakeDownstream();
  limiter = new MemoryLimiter();
  op = new FakeOp([
    rawItem("Jira", { name: "jira", url: "https://jira.example.com/mcp", auth_type: "bearer", token: "good", blocked_tools: "purge_*" }, { id: "jira" }),
    rawItem("Ledger", { name: "ledger", url: "https://ledger.example.com/mcp", auth_type: "bearer", token: "good" }, { id: "ledger" }),
    rawItem("Broken", { name: "broken", url: "http://insecure.example.com", auth_type: "none" }, { id: "broken" }),
    policyItem(
      {
        users: {
          "me@example.com": { servers: ["jira"], allow_destructive: true },
          "ro@example.com": { servers: ["*"], read_only: true },
          "admin@example.com": { servers: ["ledger"] },
        },
      },
      { id: "pol" },
    ),
  ]);
});

const textOf = (r: CallToolResult) => (r.content[0] as { text: string }).text;

describe("401 auto-retry", () => {
  it("re-reads the item from 1Password and retries once with the new key", async () => {
    const gw = await gateway(me);
    await gw.listTools("personal.jira"); // warm caches with token "good"
    op.edit("jira", "token", "rotated");
    down.valid = new Set(["rotated"]);
    down.seen = [];
    // The cached snapshot still has "good"; the first call gets 401.
    const r = await gw.call("personal.jira", "get_issue", { id: 1 });
    expect(textOf(r)).toBe('get_issue:{"id":1}');
    expect(down.seen).toEqual(["good", "rotated"]);
    expect(op.calls).toContain("getItems:jira");
  });

  it("gives up after one retry with a clear message", async () => {
    const gw = await gateway(me);
    await gw.listTools("personal.jira");
    down.valid = new Set();
    down.calls = 0;
    await expect(gw.call("personal.jira", "get_issue", {})).rejects.toThrow(
      new GatewayError("Auth failed for personal.jira. Update the key in 1Password or reconnect at https://gw.example.com/connect/personal/jira."),
    );
    expect(down.calls).toBe(2);
  });
});

describe("call enforcement", () => {
  it("denies servers the caller is not allowed on, with the same message as unknown servers", async () => {
    const gw = await gateway(me);
    const forbidden = await gw.call("personal.ledger", "get_x", {}).catch((e: Error) => e.message);
    const unknown = await gw.call("personal.nope", "get_x", {}).catch((e: Error) => e.message);
    expect(forbidden).toContain("Unknown server");
    expect(forbidden.replace("ledger", "X")).toBe(unknown.replace("nope", "X"));
  });

  it("denies everything for callers not in the policy", async () => {
    const gw = await gateway(stranger);
    expect((await gw.listServers()).servers).toEqual([]);
    await expect(gw.call("personal.jira", "get_issue", {})).rejects.toThrow("Unknown server");
  });

  it("applies item blocked_tools even with allow_destructive", async () => {
    const gw = await gateway(me);
    await expect(gw.call("personal.jira", "purge_project", {})).rejects.toThrow("blocked for this server");
  });

  it("allows destructive tools only with allow_destructive", async () => {
    expect(textOf(await (await gateway(me)).call("personal.jira", "delete_issue", {}))).toContain("delete_issue");
    await expect((await gateway(admin)).call("personal.ledger", "delete_issue", {})).rejects.toThrow("destructive");
  });

  it("read_only callers get only read-only tools", async () => {
    const gw = await gateway(ro);
    expect(textOf(await gw.call("personal.jira", "get_issue", {}))).toContain("get_issue");
    await expect(gw.call("personal.jira", "create_issue", {})).rejects.toThrow("read-only");
    const listed = await gw.listTools("personal.ledger");
    expect(listed.tools.map((t) => t.name)).toEqual(["get_issue"]);
  });

  it("rejects unknown tools", async () => {
    await expect((await gateway(me)).call("personal.jira", "nope", {})).rejects.toThrow("not found");
  });

  it("rejects oversized arguments", async () => {
    const gw = await gateway(me, { MAX_REQUEST_BYTES: "1024" });
    await expect(gw.call("personal.jira", "get_issue", { blob: "x".repeat(2000) })).rejects.toThrow("larger than");
  });

  it("returns downstream results untouched", async () => {
    const r = await (await gateway(me)).call("personal.jira", "get_issue", { a: [1, 2] });
    expect(r).toEqual({ content: [{ type: "text", text: 'get_issue:{"a":[1,2]}' }] });
  });
});

describe("list_servers", () => {
  it("shows only allowed servers, with descriptions once known", async () => {
    const gw = await gateway(me);
    await gw.listTools("personal.jira");
    expect((await gw.listServers()).servers).toEqual([{ server: "personal.jira", status: "ok", description: "Issue tracker" }]);
  });

  it("reports invalid items with the reason", async () => {
    const s = (await (await gateway(ro)).listServers()).servers.find((x) => x.server === "personal.broken");
    expect(s).toMatchObject({ status: "invalid", reason: expect.stringContaining("https") });
  });

  it("a broken _policy denies everyone and is shown to admins only", async () => {
    op.edit("pol", "policy", "{ not json");
    const users = await gateway(me);
    await users.refreshServers();
    expect((await users.listServers()).servers).toEqual([]);
    const adminView = (await (await gateway(admin)).listServers()).servers;
    expect(adminView[0]).toMatchObject({ server: "personal.*", status: "error", reason: expect.stringContaining("policy") });
  });
});

describe("rate limits", () => {
  it("limits calls per caller per minute", async () => {
    const gw = await gateway(me, { RATE_LIMIT_PER_MINUTE: "2" });
    await gw.rateLimit();
    await gw.rateLimit();
    await expect(gw.rateLimit()).rejects.toThrow("Rate limit");
  });

  it("refresh_servers runs once per minute per caller", async () => {
    const gw = await gateway(me);
    await gw.refreshServers();
    await expect(gw.refreshServers()).rejects.toThrow("once per minute");
  });
});

import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { refreshServerToken } from "../src/oauth-downstream/refresh";
import type { TokenSet } from "../src/oauth-downstream/tokens";
import { Registry, snapshotKey } from "../src/registry/registry";
import { FakeOp } from "./fake-op";
import { keyRing, policyItem, rawItem } from "./helpers";

const kv = (env as unknown as { CACHE_KV: KVNamespace }).CACHE_KV;
const NOW = Date.parse("2026-11-22T12:00:00Z");

let op: FakeOp;
let registry: Registry;
let stashed: TokenSet | undefined;
const stash = {
  get: async () => stashed,
  set: async (t: TokenSet) => void (stashed = t),
  clear: async () => void (stashed = undefined),
};
const tokenCalls: URLSearchParams[] = [];
let tokenResponse: { status: number; body: unknown };

beforeEach(async () => {
  vi.useFakeTimers({ now: NOW, toFake: ["Date"] });
  stashed = undefined;
  tokenCalls.length = 0;
  tokenResponse = { status: 200, body: { access_token: "new-at", refresh_token: "new-rt", expires_in: 3600 } };
  await kv.delete(snapshotKey("personal"));
  await kv.put(
    "asmeta:personal.crm",
    JSON.stringify({ url: "https://crm.example.com/mcp", issuer: "https://auth.example.com", authorizationEndpoint: "https://auth.example.com/authorize", tokenEndpoint: "https://auth.example.com/token", resource: "https://crm.example.com/mcp" }),
  );
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe("https://auth.example.com/token");
    tokenCalls.push(new URLSearchParams(String(init?.body)));
    return new Response(JSON.stringify(tokenResponse.body), { status: tokenResponse.status, headers: { "Content-Type": "application/json" } });
  });
  op = new FakeOp([
    rawItem(
      "CRM",
      {
        name: "crm",
        url: "https://crm.example.com/mcp",
        auth_type: "oauth",
        client_id: "cid",
        access_token: "old-at",
        refresh_token: "old-rt",
        expires_at: new Date(NOW + 60_000).toISOString(), // inside the 2 minute window
      },
      { id: "crm" },
    ),
    policyItem({ users: { "me@example.com": { servers: ["*"] } } }),
  ]);
  registry = new Registry({ kv, ring: await keyRing(), clients: { personal: op }, ttlMs: 3_600_000, memoMs: 0 });
  await registry.getGroup("personal");
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const field = (label: string) => op.items.find((i) => i.id === "crm")!.fields.find((f) => f.title === label)?.value;

describe("downstream OAuth refresh", () => {
  it("refreshes a token that expires within 2 minutes and writes it back to 1Password", async () => {
    const r = await refreshServerToken({ registry, kv, stash }, "personal", "crm", false);
    expect(r).toEqual({ ok: true, accessToken: "new-at", expiresAt: NOW + 3_600_000 });
    expect(tokenCalls[0]?.get("grant_type")).toBe("refresh_token");
    expect(tokenCalls[0]?.get("refresh_token")).toBe("old-rt");
    expect(tokenCalls[0]?.get("resource")).toBe("https://crm.example.com/mcp");
    expect(field("access_token")).toBe("new-at");
    expect(field("refresh_token")).toBe("new-rt");
    expect(stashed).toBeUndefined();
  });

  it("does not refresh a token that is still fresh", async () => {
    op.edit("crm", "expires_at", new Date(NOW + 30 * 60_000).toISOString());
    const r = await refreshServerToken({ registry, kv, stash }, "personal", "crm", false);
    expect(r).toMatchObject({ ok: true, accessToken: "old-at" });
    expect(tokenCalls).toHaveLength(0);
  });

  it("keeps the old refresh token when the server does not rotate it", async () => {
    tokenResponse = { status: 200, body: { access_token: "new-at", expires_in: 60 } };
    await refreshServerToken({ registry, kv, stash }, "personal", "crm", true);
    expect(field("refresh_token")).toBe("old-rt");
  });

  it("invalid_grant marks the server needs_connect", async () => {
    tokenResponse = { status: 400, body: { error: "invalid_grant" } };
    const r = await refreshServerToken({ registry, kv, stash }, "personal", "crm", true);
    expect(r).toMatchObject({ ok: false, kind: "needs_connect" });
    const state = await registry.getGroup("personal");
    expect(state.servers.find((s) => s.name === "crm")?.status).toBe("needs_connect");
  });

  it("a failed 1Password write keeps the new tokens in the stash and retries next time", async () => {
    const write = registry.writeItemFields.bind(registry);
    const spy = vi.spyOn(registry, "writeItemFields").mockRejectedValueOnce(new Error("1Password down"));
    const r = await refreshServerToken({ registry, kv, stash }, "personal", "crm", true);
    expect(r).toMatchObject({ ok: true, accessToken: "new-at" });
    expect(stashed?.refreshToken).toBe("new-rt");
    spy.mockImplementation(write);
    await refreshServerToken({ registry, kv, stash }, "personal", "crm", false);
    expect(field("refresh_token")).toBe("new-rt");
    expect(stashed).toBeUndefined();
  });

  it("without a refresh token the server needs a connect", async () => {
    op.edit("crm", "refresh_token", "");
    const r = await refreshServerToken({ registry, kv, stash }, "personal", "crm", true);
    expect(r).toMatchObject({ ok: false, kind: "needs_connect" });
  });
});

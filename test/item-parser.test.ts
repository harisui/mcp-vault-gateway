import { describe, expect, it } from "vitest";
import { parseGroup, parseServerItem, validateDownstreamUrl } from "../src/registry/item-parser";
import { policyItem, rawItem } from "./helpers";

const ok = { name: "jira", url: "https://mcp.example.com/mcp", auth_type: "bearer", token: "t0k" };

describe("item parsing", () => {
  it("parses a bearer server", () => {
    const s = parseServerItem("sunshine", rawItem("Jira", ok));
    expect(s).toMatchObject({ id: "sunshine.jira", status: "ok", authType: "bearer", token: "t0k" });
  });

  it("parses header auth and blocked_tools", () => {
    const s = parseServerItem("p", rawItem("X", { ...ok, auth_type: "header", header_name: "X-API-Key", blocked_tools: "delete_*, drop_*" }));
    expect(s).toMatchObject({ status: "ok", headerName: "X-API-Key", blockedTools: ["delete_*", "drop_*"] });
  });

  it("accepts none without a token", () => {
    expect(parseServerItem("p", rawItem("X", { name: "a", url: "https://a.example.com", auth_type: "none" })).status).toBe("ok");
  });

  it("oauth without tokens needs a connect", () => {
    const s = parseServerItem("p", rawItem("X", { name: "a", url: "https://a.example.com", auth_type: "oauth" }));
    expect(s.status).toBe("needs_connect");
  });

  it("oauth reads written-back tokens and expiry", () => {
    const s = parseServerItem("p", rawItem("X", { name: "a", url: "https://a.example.com", auth_type: "oauth", access_token: "at", refresh_token: "rt", expires_at: "2026-12-01T00:00:00Z" }));
    expect(s.status).toBe("ok");
    expect(s.oauth).toMatchObject({ accessToken: "at", refreshToken: "rt", expiresAt: Date.parse("2026-12-01T00:00:00Z") });
  });

  it("enabled=false marks the server disabled", () => {
    expect(parseServerItem("p", rawItem("X", { ...ok, enabled: "false" })).status).toBe("disabled");
    expect(parseServerItem("p", rawItem("X", { ...ok, enabled: "true" })).status).toBe("ok");
  });

  it.each([
    ["missing name", { ...ok, name: "" }, "name"],
    ["bad name", { ...ok, name: "My-Jira" }, "lowercase"],
    ["missing url", { ...ok, url: "" }, "url"],
    ["http url", { ...ok, url: "http://mcp.example.com" }, "https"],
    ["unknown auth", { ...ok, auth_type: "basic" }, "unknown auth_type"],
    ["missing token", { ...ok, token: "" }, "token"],
    ["header without name", { ...ok, auth_type: "header" }, "header_name"],
    ["forbidden header", { ...ok, auth_type: "header", header_name: "Host" }, "not allowed"],
    ["bad enabled", { ...ok, enabled: "yes" }, "enabled"],
  ])("invalid: %s", (_n, fields, reason) => {
    const s = parseServerItem("p", rawItem("X", fields));
    expect(s.status).toBe("invalid");
    expect(s.reason).toContain(reason);
  });
});

describe("downstream URL rules", () => {
  it.each([
    "http://example.com",
    "https://localhost/mcp",
    "https://api.localhost/mcp",
    "https://127.0.0.1/mcp",
    "https://10.0.0.8:8443/mcp",
    "https://user:pw@example.com/mcp",
    "https://intranet/mcp",
    "ftp://example.com",
    "not a url",
  ])("rejects %s", (u) => {
    expect(validateDownstreamUrl(u)).toBeDefined();
  });

  it("accepts a normal https host", () => {
    expect(validateDownstreamUrl("https://mcp.atlassian.com/v1/mcp")).toBeUndefined();
  });
});

describe("group parsing", () => {
  it("ignores items without the mcp tag", () => {
    const g = parseGroup("p", [rawItem("Jira", ok, { tags: ["work"] })]);
    expect(g.servers).toHaveLength(0);
  });

  it("marks duplicate names invalid and keeps the first", () => {
    const g = parseGroup("p", [rawItem("A", ok), rawItem("B", ok)]);
    expect(g.servers.map((s) => s.status)).toEqual(["ok", "invalid"]);
    expect(g.servers[1]?.reason).toContain("duplicate");
    expect(g.servers[1]?.token).toBeUndefined();
  });

  it("one bad item does not affect the others", () => {
    const g = parseGroup("p", [rawItem("A", { ...ok, url: "http://x" }), rawItem("B", { ...ok, name: "ledger" })]);
    expect(g.servers.map((s) => s.status)).toEqual(["invalid", "ok"]);
  });

  it("reads the _policy item", () => {
    const g = parseGroup("p", [policyItem({ users: { "me@example.com": { servers: ["*"] } } })]);
    expect(g.policy.ok).toBe(true);
  });

  it("missing _policy is an error", () => {
    expect(parseGroup("p", [rawItem("A", ok)]).policy.ok).toBe(false);
  });

  it("two _policy items is an error", () => {
    const p = { users: {} };
    expect(parseGroup("p", [policyItem(p), policyItem(p)]).policy.ok).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import { type Caller, grantFor, serverAllowed } from "../src/policy/caller";
import { checkTool, isReadOnlyTool } from "../src/policy/enforce";
import { type Grant, parsePolicy } from "../src/policy/policy";

const user = (email: string): Caller => ({ kind: "user", id: email, email });
const HASH = "a".repeat(64);

const good = JSON.stringify({
  users: {
    "Me@Example.com": { servers: ["pm_tool", "ledger"], blocked_tools: ["delete_*"] },
    "ro@example.com": { servers: ["*"], read_only: true },
  },
  access_keys: {
    k1abcdef: { label: "laptop", sha256: HASH, servers: ["pm_tool"], read_only: true, expires_at: "2027-06-01T00:00:00Z" },
  },
});

const grant = (g: Partial<Grant> = {}): Grant => ({ servers: ["*"], blockedTools: [], readOnly: false, allowDestructive: false, ...g });

describe("policy parsing", () => {
  it("parses a valid policy and lowercases emails", () => {
    const r = parsePolicy(good);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(Object.keys(r.policy.users)).toEqual(["me@example.com", "ro@example.com"]);
    expect(r.policy.accessKeys.k1abcdef?.expiresAt).toBe(Date.parse("2027-06-01T00:00:00Z"));
  });

  it.each([
    ["missing", undefined],
    ["empty", "  "],
    ["not JSON", "{users:"],
    ["unknown top-level key", JSON.stringify({ users: {}, admins: [] })],
    ["typo in a grant (readonly)", JSON.stringify({ users: { "a@b.co": { servers: ["*"], readonly: true } } })],
    ["bad server name", JSON.stringify({ users: { "a@b.co": { servers: ["PM Tool"] } } })],
    ["bad hash", JSON.stringify({ access_keys: { k1abcdef: { label: "x", sha256: "nope", servers: ["*"] } } })],
    ["bad expiry", JSON.stringify({ access_keys: { k1abcdef: { label: "x", sha256: HASH, servers: ["*"], expires_at: "soon" } } })],
    ["not an email", JSON.stringify({ users: { someone: { servers: ["*"] } } })],
  ])("broken _policy (%s) is an error, never allow-all", (_name, json) => {
    const r = parsePolicy(json);
    expect(r.ok).toBe(false);
  });
});

describe("deny by default", () => {
  const r = parsePolicy(good);
  const policy = r.ok ? r.policy : undefined;

  it("denies callers not in the policy", () => {
    expect(grantFor(policy, "personal", user("stranger@example.com"))).toBeUndefined();
    expect(serverAllowed(grantFor(policy, "personal", user("stranger@example.com")), "pm_tool")).toBe(false);
  });

  it("denies everyone when the policy is missing or broken", () => {
    expect(grantFor(undefined, "personal", user("me@example.com"))).toBeUndefined();
  });

  it("matches emails case-insensitively", () => {
    expect(serverAllowed(grantFor(policy, "personal", user("ME@example.COM")), "pm_tool")).toBe(true);
  });

  it("only allows listed servers, and * allows all", () => {
    const me = grantFor(policy, "personal", user("me@example.com"));
    expect(serverAllowed(me, "ledger")).toBe(true);
    expect(serverAllowed(me, "hr")).toBe(false);
    expect(serverAllowed(grantFor(policy, "personal", user("ro@example.com")), "hr")).toBe(true);
  });

  it("access keys only count in groups where they were verified", () => {
    const key: Caller = { kind: "key", id: "key:k1abcdef", keyId: "k1abcdef", label: "laptop", groups: ["personal"] };
    expect(serverAllowed(grantFor(policy, "personal", key), "pm_tool")).toBe(true);
    expect(grantFor(policy, "sunshine", key)).toBeUndefined();
  });
});

describe("tool enforcement", () => {
  it("blocks item-level and caller-level blocked_tools globs", () => {
    expect(checkTool(grant(), ["delete_*", "drop_*"], { name: "drop_table" }).allowed).toBe(false);
    expect(checkTool(grant({ blockedTools: ["delete_*"] }), [], { name: "Delete_User" }).allowed).toBe(false);
    expect(checkTool(grant({ blockedTools: ["delete_*"] }), [], { name: "get_user" }).allowed).toBe(true);
  });

  it("read_only uses readOnlyHint when present", () => {
    const ro = grant({ readOnly: true });
    expect(checkTool(ro, [], { name: "create_ticket", annotations: { readOnlyHint: true } }).allowed).toBe(true);
    expect(checkTool(ro, [], { name: "get_ticket", annotations: { readOnlyHint: false } }).allowed).toBe(false);
  });

  it("read_only falls back to name heuristics without annotations", () => {
    const ro = grant({ readOnly: true });
    for (const name of ["get_user", "list_tickets", "search_issues", "read_file", "describe_table", "fetch_page"]) {
      expect(checkTool(ro, [], { name }).allowed, name).toBe(true);
    }
    for (const name of ["create_ticket", "update_user", "run_query", "getuser", "sendmail"]) {
      expect(checkTool(ro, [], { name }).allowed, name).toBe(false);
    }
    expect(isReadOnlyTool({ name: "list_x", annotations: {} })).toBe(true);
  });

  it("blocks destructive tools unless allow_destructive", () => {
    const tool = { name: "remove_user", annotations: { destructiveHint: true } };
    expect(checkTool(grant(), [], tool).allowed).toBe(false);
    expect(checkTool(grant({ allowDestructive: true }), [], tool).allowed).toBe(true);
  });

  it("blocked_tools wins over allow_destructive", () => {
    expect(checkTool(grant({ allowDestructive: true }), ["remove_*"], { name: "remove_user", annotations: { destructiveHint: true } }).allowed).toBe(false);
  });
});

describe("glob patterns", () => {
  it("treats regex characters in patterns literally", () => {
    expect(checkTool(grant({ blockedTools: ["admin.reset"] }), [], { name: "adminXreset" }).allowed).toBe(true);
    expect(checkTool(grant({ blockedTools: ["admin.reset"] }), [], { name: "admin.reset" }).allowed).toBe(false);
    expect(checkTool(grant({ blockedTools: ["run(sql)*"] }), [], { name: "run(sql)_now" }).allowed).toBe(false);
  });

  it("supports ? for a single character", () => {
    expect(checkTool(grant({ blockedTools: ["v?_delete"] }), [], { name: "v2_delete" }).allowed).toBe(false);
  });
});

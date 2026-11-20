import { describe, expect, it } from "vitest";
import { generateAccessKey, parseAccessKey, verifyAccessKey } from "../src/auth/access-keys";
import { parsePolicy } from "../src/policy/policy";
import type { GroupState } from "../src/registry/registry";
import { sha256Hex } from "../src/util/encoding";

function group(name: string, accessKeys: Record<string, unknown>): GroupState {
  return { group: name, servers: [], policy: parsePolicy(JSON.stringify({ access_keys: accessKeys })), loadedAt: 1, stale: false };
}

describe("access keys", () => {
  it("generates mcpk_<id>_<43 char secret> and stores only its sha256", async () => {
    const k = await generateAccessKey();
    expect(k.key).toMatch(/^mcpk_[a-f0-9]{12}_[A-Za-z0-9_-]{43}$/);
    expect(k.sha256).toBe(await sha256Hex(k.key));
    expect(parseAccessKey(k.key)?.keyId).toBe(k.keyId);
  });

  it("rejects malformed keys", () => {
    for (const bad of ["", "mcpk_", "mcpk_short_x", "Bearer mcpk_abcdefgh_" + "a".repeat(43), "mcpk_ABCDEFGH_" + "a".repeat(43)]) {
      expect(parseAccessKey(bad)).toBeUndefined();
    }
  });

  it("accepts a key whose hash matches", async () => {
    const k = await generateAccessKey();
    const caller = await verifyAccessKey(k.key, [group("personal", { [k.keyId]: { label: "laptop", sha256: k.sha256, servers: ["pm_tool"] } })]);
    expect(caller).toMatchObject({ kind: "key", keyId: k.keyId, label: "laptop", groups: ["personal"] });
  });

  it("rejects a key with the right id but wrong secret", async () => {
    const k = await generateAccessKey();
    const other = await generateAccessKey();
    const forged = `mcpk_${k.keyId}_${other.key.split("_").slice(2).join("_")}`;
    expect(await verifyAccessKey(forged, [group("personal", { [k.keyId]: { label: "x", sha256: k.sha256, servers: ["*"] } })])).toBeUndefined();
  });

  it("respects expires_at", async () => {
    const k = await generateAccessKey();
    const g = group("personal", { [k.keyId]: { label: "x", sha256: k.sha256, servers: ["*"], expires_at: "2027-01-01T00:00:00Z" } });
    expect(await verifyAccessKey(k.key, [g], Date.parse("2026-12-31T23:59:59Z"))).toBeDefined();
    expect(await verifyAccessKey(k.key, [g], Date.parse("2027-01-01T00:00:00Z"))).toBeUndefined();
  });

  it("is granted only in groups that list it", async () => {
    const k = await generateAccessKey();
    const caller = await verifyAccessKey(k.key, [
      group("personal", { [k.keyId]: { label: "x", sha256: k.sha256, servers: ["*"] } }),
      group("sunshine", {}),
    ]);
    expect(caller?.kind === "key" && caller.groups).toEqual(["personal"]);
  });

  it("a group with a broken policy grants nothing", async () => {
    const k = await generateAccessKey();
    const broken: GroupState = { group: "personal", servers: [], policy: { ok: false, error: "bad" }, loadedAt: 1, stale: false };
    expect(await verifyAccessKey(k.key, [broken])).toBeUndefined();
  });
});

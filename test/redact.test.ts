import { describe, expect, it } from "vitest";
import { redact, redactString } from "../src/util/redact";

describe("redact", () => {
  it("replaces sensitive keys wholesale", () => {
    expect(redact({ token: "abc", client_secret: "x", Authorization: "y", args: { a: 1 }, name: "jira" })).toEqual({
      token: "[redacted]",
      client_secret: "[redacted]",
      Authorization: "[redacted]",
      args: "[redacted]",
      name: "jira",
    });
  });

  it("scrubs credential-shaped strings", () => {
    const s = redactString("failed with Bearer abc.def-123 and mcpk_k1abcdef_" + "x".repeat(43) + " and ghp_ABCDEF123");
    expect(s).not.toMatch(/abc\.def|mcpk_|ghp_/);
  });

  it("recurses into arrays", () => {
    expect(redact([{ token: "abc" }, "Bearer zzz"])).toEqual([{ token: "[redacted]" }, "[redacted]"]);
    expect(redact({ list: [{ refresh_token: "r" }] })).toEqual({ list: [{ refresh_token: "[redacted]" }] });
  });

  it("leaves harmless values alone", () => {
    expect(redact({ server: "sunshine.jira", status: 401, ok: false })).toEqual({ server: "sunshine.jira", status: 401, ok: false });
  });
});

import { z } from "zod";

/**
 * `_policy` item, one per group (vault). Deny by default: a caller that is not listed gets
 * nothing. A missing or invalid policy denies everything for the group. There is no fallback.
 */

const SERVER_REF = /^(\*|[a-z0-9_]+)$/;
const KEY_ID = /^[a-z0-9]{8,32}$/;

const grantShape = {
  servers: z.array(z.string().regex(SERVER_REF, "server must be '*' or [a-z0-9_]+")),
  blocked_tools: z.array(z.string().min(1)).optional(),
  read_only: z.boolean().optional(),
  allow_destructive: z.boolean().optional(),
};

// .strict(): a typo such as "readonly" must not silently grant write access.
const userSchema = z.object(grantShape).strict();
const accessKeySchema = z
  .object({
    ...grantShape,
    label: z.string().min(1).max(100),
    sha256: z.string().regex(/^[a-f0-9]{64}$/, "sha256 must be 64 lowercase hex chars"),
    expires_at: z.iso.datetime({ offset: true }).optional(),
  })
  .strict();

const policySchema = z
  .object({
    users: z.record(z.string().email(), userSchema).optional(),
    access_keys: z.record(z.string().regex(KEY_ID, "key id must be 8-32 chars [a-z0-9]"), accessKeySchema).optional(),
  })
  .strict();

export interface Grant {
  servers: string[];
  blockedTools: string[];
  readOnly: boolean;
  allowDestructive: boolean;
}

export interface AccessKeyGrant extends Grant {
  label: string;
  sha256: string;
  expiresAt?: number;
}

export interface Policy {
  users: Record<string, Grant>;
  accessKeys: Record<string, AccessKeyGrant>;
}

export type PolicyResult = { ok: true; policy: Policy } | { ok: false; error: string };

function toGrant(g: z.infer<typeof userSchema>): Grant {
  return {
    servers: g.servers,
    blockedTools: g.blocked_tools ?? [],
    readOnly: g.read_only ?? false,
    allowDestructive: g.allow_destructive ?? false,
  };
}

export function parsePolicy(json: string | undefined): PolicyResult {
  if (json === undefined || json.trim() === "") return { ok: false, error: "_policy item or its `policy` field is missing" };
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return { ok: false, error: "_policy is not valid JSON" };
  }
  const parsed = policySchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return { ok: false, error: `_policy is invalid at ${issue?.path.join(".") || "(root)"}: ${issue?.message ?? "unknown error"}` };
  }
  const users: Record<string, Grant> = {};
  for (const [email, g] of Object.entries(parsed.data.users ?? {})) users[email.toLowerCase()] = toGrant(g);
  const accessKeys: Record<string, AccessKeyGrant> = {};
  for (const [id, k] of Object.entries(parsed.data.access_keys ?? {})) {
    accessKeys[id] = {
      ...toGrant(k),
      label: k.label,
      sha256: k.sha256,
      expiresAt: k.expires_at ? Date.parse(k.expires_at) : undefined,
    };
  }
  return { ok: true, policy: { users, accessKeys } };
}

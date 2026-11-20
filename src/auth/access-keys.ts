import type { Caller } from "../policy/caller";
import type { GroupState } from "../registry/registry";
import { timingSafeEqualString } from "../util/constant-time";
import { randomBytes, sha256Hex, toBase64Url, toHex } from "../util/encoding";

/**
 * Static access keys for Claude Code and scripts:
 *   Authorization: Bearer mcpk_<key_id>_<secret>
 * <secret> is 32 random bytes, base64url (43 chars). Only sha256(full key) is stored, in _policy.
 */

export const KEY_PREFIX = "mcpk_";
const KEY_FORMAT = /^mcpk_([a-z0-9]{8,32})_([A-Za-z0-9_-]{43})$/;

export function parseAccessKey(token: string): { keyId: string } | undefined {
  const m = KEY_FORMAT.exec(token);
  return m ? { keyId: m[1]! } : undefined;
}

export async function generateAccessKey(): Promise<{ key: string; keyId: string; sha256: string }> {
  const keyId = toHex(randomBytes(6));
  const key = `${KEY_PREFIX}${keyId}_${toBase64Url(randomBytes(32))}`;
  return { key, keyId, sha256: await sha256Hex(key) };
}

/**
 * Check a presented key against every group's _policy. The caller is granted only the groups
 * where the key id exists, the hash matches (constant time) and it has not expired.
 */
export async function verifyAccessKey(token: string, groups: GroupState[], now = Date.now()): Promise<Caller | undefined> {
  const parsed = parseAccessKey(token);
  if (!parsed) return undefined;
  const hash = await sha256Hex(token);
  const valid: string[] = [];
  let label = "";
  for (const g of groups) {
    if (!g.policy.ok) continue;
    const grant = g.policy.policy.accessKeys[parsed.keyId];
    if (!grant) continue;
    const matches = await timingSafeEqualString(hash, grant.sha256);
    if (!matches) continue;
    if (grant.expiresAt !== undefined && grant.expiresAt <= now) continue;
    valid.push(g.group);
    label ||= grant.label;
  }
  if (valid.length === 0) return undefined;
  return { kind: "key", id: `key:${parsed.keyId}`, keyId: parsed.keyId, label, groups: valid };
}

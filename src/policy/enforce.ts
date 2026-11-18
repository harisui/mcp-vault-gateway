import { matchesAny } from "../util/glob";
import type { Grant } from "./policy";

export interface ToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  [k: string]: unknown;
}

export interface ToolInfo {
  name: string;
  annotations?: ToolAnnotations;
}

export type ToolDecision = { allowed: true } | { allowed: false; reason: string };

/**
 * Name prefixes treated as read-only when a tool has no `readOnlyHint` annotation.
 * Used only for callers with `read_only: true`. Everything else is blocked for them.
 */
export const READ_ONLY_PREFIXES = ["get_", "list_", "search_", "read_", "describe_", "fetch_"] as const;

export function isReadOnlyTool(tool: ToolInfo): boolean {
  const hint = tool.annotations?.readOnlyHint;
  if (hint === true) return true;
  if (hint === false) return false;
  const name = tool.name.toLowerCase();
  return READ_ONLY_PREFIXES.some((p) => name.startsWith(p));
}

/**
 * Policy check for one tool, in order:
 * 1. item-level `blocked_tools` (from the 1Password item)
 * 2. caller-level `blocked_tools` (from `_policy`)
 * 3. `read_only` callers: only read-only tools (annotation, else name heuristic)
 * 4. `destructiveHint: true` needs `allow_destructive: true`
 * Server-level access is checked before this, by serverAllowed().
 */
export function checkTool(grant: Grant, itemBlocked: readonly string[], tool: ToolInfo): ToolDecision {
  const itemHit = matchesAny(tool.name, itemBlocked);
  if (itemHit) return { allowed: false, reason: `tool '${tool.name}' is blocked for this server (${itemHit})` };

  const callerHit = matchesAny(tool.name, grant.blockedTools);
  if (callerHit) return { allowed: false, reason: `tool '${tool.name}' is blocked by your policy (${callerHit})` };

  if (grant.readOnly && !isReadOnlyTool(tool)) {
    return { allowed: false, reason: `tool '${tool.name}' is not read-only and your access is read-only` };
  }

  if (tool.annotations?.destructiveHint === true && !grant.allowDestructive) {
    return { allowed: false, reason: `tool '${tool.name}' is destructive and your policy does not set allow_destructive` };
  }

  return { allowed: true };
}

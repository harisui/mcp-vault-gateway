import type { Grant, Policy } from "./policy";

/** Who is calling the gateway. Built by the auth layer, never from client input. */
export type Caller =
  | { kind: "user"; id: string; email: string }
  | {
      kind: "key";
      id: string;
      keyId: string;
      label: string;
      /** Groups whose `_policy` holds this key with a matching hash and no expiry. */
      groups: string[];
    };

export const callerLabel = (c: Caller): string => (c.kind === "user" ? c.email : `key:${c.label}`);

/** The caller's grant in one group's policy, or undefined (deny). */
export function grantFor(policy: Policy | undefined, group: string, caller: Caller): Grant | undefined {
  if (!policy) return undefined;
  if (caller.kind === "user") return policy.users[caller.email.toLowerCase()];
  if (!caller.groups.includes(group)) return undefined;
  return policy.accessKeys[caller.keyId];
}

export function serverAllowed(grant: Grant | undefined, name: string): boolean {
  if (!grant) return false;
  return grant.servers.includes("*") || grant.servers.includes(name);
}

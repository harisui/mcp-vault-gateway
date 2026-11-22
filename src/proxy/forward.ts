import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { Settings } from "../env";
import type { ServerEntry } from "../registry/types";
import { GatewayError } from "../util/errors";
import { errorInfo, log } from "../util/log";
import type { DResult } from "./downstream";
import type { ServerDO, ToolList } from "./server-do";
import { authHeaders, type Target } from "./target";

/** Downstream calls. Backed by ServerDO in production, faked in tests. */
export interface Downstream {
  listTools(target: Target): Promise<DResult<ToolList>>;
  callTool(target: Target, name: string, args: Record<string, unknown>): Promise<DResult<CallToolResult>>;
}

export function durableDownstream(ns: DurableObjectNamespace<ServerDO>): Downstream {
  const stub = (t: Target) => ns.get(ns.idFromName(t.serverId));
  return {
    listTools: (t) => stub(t).listTools(t) as Promise<DResult<ToolList>>,
    callTool: (t, name, args) => stub(t).callTool(t, name, args) as Promise<DResult<CallToolResult>>,
  };
}

export interface ForwardDeps {
  cfg: Settings;
  publicUrl: string;
  registry: { reloadItem(group: string, itemId: string): Promise<ServerEntry | undefined> };
  /** Returns the server with usable credentials (refreshes OAuth tokens when needed). */
  credentials(server: ServerEntry, opts?: { afterAuthFailure?: boolean }): Promise<ServerEntry>;
}

export function makeTarget(server: ServerEntry, cfg: Settings): Target {
  return {
    serverId: server.id,
    url: server.url!,
    headers: authHeaders(server),
    timeoutMs: cfg.downstreamTimeoutMs,
    maxResponseBytes: cfg.maxResponseBytes,
  };
}

export const connectUrl = (publicUrl: string, s: ServerEntry) => `${publicUrl}/connect/${s.group}/${s.name}`;

export const authFailedMessage = (publicUrl: string, s: ServerEntry) =>
  `Auth failed for ${s.id}. Update the key in 1Password or reconnect at ${connectUrl(publicUrl, s)}.`;

function failureMessage(s: ServerEntry, f: { kind: string; message: string }, cfg: Settings): string {
  switch (f.kind) {
    case "timeout":
      return `${s.id} did not respond within ${Math.round(cfg.downstreamTimeoutMs / 1000)} seconds.`;
    case "too_large":
      return `The response from ${s.id} is larger than the gateway allows (${cfg.maxResponseBytes} bytes).`;
    case "unreachable":
      return `Could not reach ${s.id}.`;
    default:
      return `${s.id} failed: ${f.message}`;
  }
}

/**
 * Run one downstream operation with the 401 rule: on 401, drop the cached credential, re-read
 * the item from 1Password, retry exactly once, then give up with a clear message.
 */
export async function forward<T>(deps: ForwardDeps, server: ServerEntry, op: (t: Target) => Promise<DResult<T>>): Promise<T> {
  const first = await op(makeTarget(await deps.credentials(server), deps.cfg));
  if (first.ok) return first.value;
  if (first.kind !== "auth") throw new GatewayError(failureMessage(server, first, deps.cfg));

  log("warn", "downstream.auth_failed", { server: server.id, retry: true });
  let fresh: ServerEntry | undefined;
  try {
    fresh = await deps.registry.reloadItem(server.group, server.itemId);
  } catch (e) {
    log("warn", "downstream.reload_failed", { server: server.id, error: errorInfo(e).message });
  }
  if (fresh && fresh.status === "ok") {
    const second = await op(makeTarget(await deps.credentials(fresh, { afterAuthFailure: true }), deps.cfg));
    if (second.ok) return second.value;
    if (second.kind !== "auth") throw new GatewayError(failureMessage(server, second, deps.cfg));
  }
  log("warn", "downstream.auth_failed", { server: server.id, retry: false });
  throw new GatewayError(authFailedMessage(deps.publicUrl, server));
}

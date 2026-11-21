import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { type Caller, callerLabel, grantFor, serverAllowed } from "../policy/caller";
import { checkTool } from "../policy/enforce";
import type { Grant } from "../policy/policy";
import { connectUrl, type Downstream, type ForwardDeps, forward } from "../proxy/forward";
import type { ToolList } from "../proxy/server-do";
import type { ToolsCache } from "../proxy/tools-cache";
import type { GroupState, Registry } from "../registry/registry";
import type { ServerEntry } from "../registry/types";
import { GatewayError } from "../util/errors";
import { type AuditEntry, audit } from "../util/log";

export interface Limiter {
  /** true = allowed. */
  hit(name: string, windowMs: number, limit: number): Promise<boolean>;
}

export interface GatewayDeps extends ForwardDeps {
  registry: Pick<Registry, "getAll" | "find" | "reloadItem">;
  downstream: Downstream;
  tools: Pick<ToolsCache, "get" | "put" | "description">;
  limiter: Limiter;
}

const SERVER_ID = /^[a-z0-9_]+\.[a-z0-9_]+$/;
const MINUTE = 60_000;

export interface ServerListing {
  server: string;
  status: string;
  reason?: string;
  description?: string;
  connect_url?: string;
}

/** The four meta-tools, for one caller. Policy is re-evaluated on every call. */
export class Gateway {
  constructor(
    private readonly deps: GatewayDeps,
    readonly caller: Caller,
  ) {}

  private get isAdmin(): boolean {
    return this.caller.kind === "user" && this.deps.cfg.adminEmails.includes(this.caller.email.toLowerCase());
  }

  private grant(state: GroupState): Grant | undefined {
    return grantFor(state.policy.ok ? state.policy.policy : undefined, state.group, this.caller);
  }

  /** Per-caller rate limit across all tool calls. */
  async rateLimit(): Promise<void> {
    const limit = this.deps.cfg.rateLimitPerMinute;
    if (!(await this.deps.limiter.hit(`rl:${this.caller.id}`, MINUTE, limit))) {
      throw new GatewayError(`Rate limit reached (${limit} calls per minute). Try again in a minute.`);
    }
  }

  async listServers(): Promise<{ servers: ServerListing[] }> {
    const out: ServerListing[] = [];
    for (const state of await this.deps.registry.getAll()) {
      if (this.isAdmin) {
        if (!state.policy.ok) out.push({ server: `${state.group}.*`, status: "error", reason: `policy: ${state.policy.error} (all access denied)` });
        if (state.error) out.push({ server: `${state.group}.*`, status: "error", reason: state.stale ? `1Password unavailable, serving cached data: ${state.error}` : state.error });
      }
      const grant = this.grant(state);
      for (const s of state.servers) {
        const visible = serverAllowed(grant, s.name) || (this.isAdmin && s.status === "invalid");
        if (!visible) continue;
        const entry: ServerListing = { server: s.id, status: s.status };
        if (s.reason) entry.reason = s.reason;
        if (s.status === "needs_connect") entry.connect_url = connectUrl(this.deps.publicUrl, s);
        if (s.status === "ok") {
          const d = await this.deps.tools.description(s.id);
          if (d) entry.description = d;
        }
        out.push(entry);
      }
    }
    return { servers: out };
  }

  async listTools(serverId: string): Promise<{ server: string; tools: Pick<Tool, "name" | "description" | "inputSchema" | "annotations">[] }> {
    const { server, grant } = await this.resolve(serverId);
    const list = await this.toolList(server);
    const tools = list.tools
      .filter((t) => checkTool(grant, server.blockedTools, t).allowed)
      .map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations }));
    return { server: server.id, tools };
  }

  async call(serverId: string, toolName: string, args: Record<string, unknown> | undefined): Promise<CallToolResult> {
    const started = Date.now();
    let outcome: AuditEntry["outcome"] = "error";
    try {
      const { server, grant } = await this.resolve(serverId);
      const payload = args ?? {};
      if (new TextEncoder().encode(JSON.stringify(payload)).byteLength > this.deps.cfg.maxRequestBytes) {
        throw new GatewayError(`Arguments are larger than the gateway allows (${this.deps.cfg.maxRequestBytes} bytes).`);
      }
      let tool = (await this.toolList(server)).tools.find((t) => t.name === toolName);
      if (!tool) tool = (await this.toolList(server, true)).tools.find((t) => t.name === toolName);
      if (!tool) {
        outcome = "denied";
        throw new GatewayError(`Tool '${toolName}' not found on ${server.id}. Use list_tools to see what is available.`);
      }
      const decision = checkTool(grant, server.blockedTools, tool);
      if (!decision.allowed) {
        outcome = "denied";
        throw new GatewayError(`Denied: ${decision.reason}.`);
      }
      const result = await forward(this.deps, server, (t) => this.deps.downstream.callTool(t, toolName, payload));
      outcome = result.isError ? "tool_error" : "ok";
      return result;
    } catch (e) {
      if (e instanceof GatewayError && e.message.startsWith("Auth failed")) outcome = "auth_failed";
      throw e;
    } finally {
      audit({
        caller: callerLabel(this.caller),
        server: SERVER_ID.test(serverId) ? serverId : "(invalid)",
        tool: /^[A-Za-z0-9_.:-]{1,128}$/.test(toolName) ? toolName : "(invalid)",
        outcome,
        latencyMs: Date.now() - started,
      });
    }
  }

  async refreshServers(): Promise<{ groups: { group: string; servers: number; stale: boolean; error?: string }[] }> {
    if (!(await this.deps.limiter.hit(`refresh:${this.caller.id}`, MINUTE, 1))) {
      throw new GatewayError("refresh_servers can run once per minute. Try again shortly.");
    }
    const states = await this.deps.registry.getAll({ force: true });
    return {
      groups: states
        .filter((s) => this.isAdmin || this.grant(s))
        .map((s) => ({ group: s.group, servers: s.servers.length, stale: s.stale, ...(s.error ? { error: s.error } : {}) })),
    };
  }

  /** Same message for unknown and forbidden servers, so callers can't probe what exists. */
  private async resolve(serverId: string): Promise<{ server: ServerEntry; grant: Grant }> {
    const notFound = new GatewayError(`Unknown server '${serverId}', or you do not have access. Use list_servers.`);
    if (!SERVER_ID.test(serverId)) throw notFound;
    const found = await this.deps.registry.find(serverId);
    if (!found) throw notFound;
    const grant = this.grant(found.state);
    if (!grant || !serverAllowed(grant, found.server.name)) throw notFound;
    const s = found.server;
    if (s.status === "needs_connect") throw new GatewayError(`${s.id} is not connected. Open ${connectUrl(this.deps.publicUrl, s)} in a browser to connect it.`);
    if (s.status !== "ok") throw new GatewayError(`${s.id} is ${s.status}${s.reason ? `: ${s.reason}` : ""}.`);
    return { server: s, grant };
  }

  private async toolList(server: ServerEntry, force = false): Promise<ToolList> {
    if (!force) {
      const cached = await this.deps.tools.get(server.id);
      if (cached) return cached;
    }
    const list = await forward(this.deps, server, (t) => this.deps.downstream.listTools(t));
    await this.deps.tools.put(server.id, list);
    return list;
  }
}

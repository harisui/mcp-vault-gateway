import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { sha256Hex } from "../util/encoding";
import { classify, connectDownstream, type DResult, type FailureBox } from "./downstream";
import type { Target } from "./target";

const IDLE_MS = 15 * 60_000;

export interface ToolList {
  tools: Tool[];
  description?: string;
}

/**
 * One instance per downstream server (`group.name`). Keeps the MCP session open between calls
 * so every tool call doesn't pay for a new initialize handshake.
 */
export class ServerDO extends DurableObject<Env> {
  private conn: { fp: string; client: Client; box: FailureBox } | undefined;

  async listTools(target: Target): Promise<DResult<ToolList>> {
    return this.run(target, async (client) => {
      const tools: Tool[] = [];
      let cursor: string | undefined;
      do {
        const page = await client.listTools(cursor ? { cursor } : undefined, { timeout: target.timeoutMs });
        tools.push(...page.tools);
        cursor = page.nextCursor;
      } while (cursor && tools.length < 2000);
      const info = client.getServerVersion();
      const description = (client.getInstructions() ?? info?.title ?? "").slice(0, 300) || undefined;
      return { tools, description };
    });
  }

  async callTool(target: Target, name: string, args: Record<string, unknown>): Promise<DResult<CallToolResult>> {
    return this.run(target, async (client) => (await client.callTool({ name, arguments: args }, undefined, { timeout: target.timeoutMs })) as CallToolResult);
  }

  async disconnect(): Promise<void> {
    await this.drop();
  }

  override async alarm(): Promise<void> {
    await this.drop();
  }

  private async run<T>(target: Target, fn: (client: Client) => Promise<T>): Promise<DResult<T>> {
    for (let attempt = 0; attempt < 2; attempt++) {
      let conn: { client: Client; box: FailureBox };
      try {
        conn = await this.connection(target);
      } catch (e) {
        const r = classify(e, this.conn?.box ?? {});
        await this.drop();
        return r;
      }
      conn.box.kind = undefined;
      conn.box.message = undefined;
      try {
        const value = await fn(conn.client);
        await this.ctx.storage.setAlarm(Date.now() + IDLE_MS);
        return { ok: true, value };
      } catch (e) {
        const r = classify(e, conn.box);
        await this.drop();
        if (r.kind === "session" && attempt === 0) continue;
        return r;
      }
    }
    return { ok: false, kind: "session", message: "downstream session could not be re-established" };
  }

  private async connection(target: Target): Promise<{ client: Client; box: FailureBox }> {
    const fp = await sha256Hex(JSON.stringify([target.url, target.headers]));
    if (this.conn?.fp === fp) return this.conn;
    await this.drop();
    const box: FailureBox = {};
    this.conn = { fp, client: await connectDownstream(target, box), box };
    return this.conn;
  }

  private async drop(): Promise<void> {
    const c = this.conn;
    this.conn = undefined;
    await c?.client.close().catch(() => undefined);
  }
}

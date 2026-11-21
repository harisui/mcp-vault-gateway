import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport, StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CfWorkerJsonSchemaValidator } from "@modelcontextprotocol/sdk/validation/cfworker";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { redactString } from "../util/redact";
import type { Target } from "./target";

export type FailureKind = "auth" | "timeout" | "too_large" | "session" | "unreachable" | "protocol";
export type DResult<T> = { ok: true; value: T } | { ok: false; kind: FailureKind; message: string };

/** Shared between the guarded fetch and the caller, so failures are classified reliably. */
export interface FailureBox {
  kind?: FailureKind;
  message?: string;
}

class GuardError extends Error {
  constructor(readonly kind: FailureKind, message: string) {
    super(message);
  }
}

function isEventStreamGet(init?: RequestInit): boolean {
  const method = (init?.method ?? "GET").toUpperCase();
  const accept = new Headers(init?.headers).get("Accept") ?? "";
  return method === "GET" && accept.includes("text/event-stream");
}

function limitBody(body: ReadableStream<Uint8Array>, max: number, box: FailureBox): ReadableStream<Uint8Array> {
  let total = 0;
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, ctl) {
        total += chunk.byteLength;
        if (total > max) {
          box.kind = "too_large";
          box.message = `response exceeded ${max} bytes`;
          ctl.error(new GuardError("too_large", box.message));
          return;
        }
        ctl.enqueue(chunk);
      },
    }),
  );
}

/**
 * fetch used by the MCP client transports:
 * - injects auth headers (only towards the configured origin),
 * - enforces the per-call timeout and the response size limit,
 * - never follows redirects (a redirect could leak injected credentials elsewhere),
 * - turns 401 into a typed failure for the retry logic.
 */
export function guardedFetch(target: Target, box: FailureBox): typeof fetch {
  const origin = new URL(target.url).origin;
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.origin !== origin) {
      box.kind = "protocol";
      box.message = "downstream tried to send the gateway to another origin";
      throw new GuardError("protocol", box.message);
    }
    const headers = new Headers(init?.headers);
    for (const [k, v] of Object.entries(target.headers)) headers.set(k, v);
    const signals = [init?.signal].filter((s): s is AbortSignal => Boolean(s));
    if (!isEventStreamGet(init)) signals.push(AbortSignal.timeout(target.timeoutMs));

    let res: Response;
    try {
      res = await fetch(url, { ...init, headers, redirect: "manual", signal: AbortSignal.any(signals) });
    } catch (e) {
      const timedOut = e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError");
      box.kind = timedOut ? "timeout" : "unreachable";
      box.message = timedOut ? `no response within ${target.timeoutMs} ms` : "could not reach the server";
      throw new GuardError(box.kind, box.message);
    }
    if (res.status === 401) {
      box.kind = "auth";
      box.message = "downstream returned 401";
      throw new GuardError("auth", box.message);
    }
    if (res.status >= 300 && res.status < 400) {
      box.kind = "protocol";
      box.message = `downstream answered with a redirect (${res.status}); redirects are not followed`;
      throw new GuardError("protocol", box.message);
    }
    const len = Number(res.headers.get("Content-Length") ?? "0");
    if (len > target.maxResponseBytes) {
      box.kind = "too_large";
      box.message = `response exceeded ${target.maxResponseBytes} bytes`;
      throw new GuardError("too_large", box.message);
    }
    if (!res.body) return res;
    return new Response(limitBody(res.body, target.maxResponseBytes, box), res);
  }) as typeof fetch;
}

/** Map any error from the MCP client to a failure kind and a message safe to return. */
export function classify(e: unknown, box: FailureBox): { ok: false; kind: FailureKind; message: string } {
  if (box.kind) return { ok: false, kind: box.kind, message: box.message ?? box.kind };
  if (e instanceof GuardError) return { ok: false, kind: e.kind, message: e.message };
  if (e instanceof StreamableHTTPError) {
    if (e.code === 401) return { ok: false, kind: "auth", message: "downstream returned 401" };
    if (e.code === 404) return { ok: false, kind: "session", message: "downstream session expired" };
    return { ok: false, kind: "protocol", message: `downstream HTTP ${e.code ?? "error"}` };
  }
  if (e instanceof McpError && e.code === -32001) return { ok: false, kind: "timeout", message: "downstream timed out" };
  const msg = e instanceof Error ? e.message : String(e);
  return { ok: false, kind: "protocol", message: redactString(msg).slice(0, 200) };
}

const CLIENT_INFO = { name: "mcp-vault-gateway", version: "0.1.0" };

/**
 * Connect to a downstream MCP server. Streamable HTTP first; legacy SSE only if the server
 * rejects Streamable HTTP with 404/405.
 */
export async function connectDownstream(target: Target, box: FailureBox): Promise<Client> {
  const fetchFn = guardedFetch(target, box);
  const opts = { jsonSchemaValidator: new CfWorkerJsonSchemaValidator() };
  const client = new Client(CLIENT_INFO, opts);
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(target.url), { fetch: fetchFn }), { timeout: target.timeoutMs });
    return client;
  } catch (e) {
    const legacy = e instanceof StreamableHTTPError && (e.code === 404 || e.code === 405) && !box.kind;
    if (!legacy) throw e;
  }
  const sse = new Client(CLIENT_INFO, opts);
  await sse.connect(new SSEClientTransport(new URL(target.url), { fetch: fetchFn }), { timeout: target.timeoutMs });
  return sse;
}

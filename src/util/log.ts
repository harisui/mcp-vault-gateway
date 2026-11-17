import { redact, redactString } from "./redact";

export type Level = "debug" | "info" | "warn" | "error";

/** Structured log line. Every field goes through redact(). Never pass raw secrets anyway. */
export function log(level: Level, event: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, event, ...(redact(fields) as object) });
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

export interface AuditEntry {
  caller: string;
  server: string;
  tool: string;
  outcome: "ok" | "denied" | "error" | "auth_failed" | "rate_limited" | "tool_error";
  latencyMs: number;
}

/** One line per `call`. Deliberately has no slot for arguments or results. */
export function audit(entry: AuditEntry): void {
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      type: "audit",
      caller: redactString(entry.caller),
      server: entry.server,
      tool: entry.tool,
      outcome: entry.outcome,
      latency_ms: Math.round(entry.latencyMs),
    }),
  );
}

/** Error summary that is safe to log: name and redacted message, never the stack. */
export function errorInfo(e: unknown): { name: string; message: string } {
  if (e instanceof Error) return { name: e.name, message: redactString(e.message).slice(0, 300) };
  return { name: "Unknown", message: redactString(String(e)).slice(0, 300) };
}

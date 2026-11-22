import { validateDownstreamUrl } from "../registry/item-parser";

const MAX_BYTES = 64 * 1024;

export class OAuthFlowError extends Error {
  override name = "OAuthFlowError";
  constructor(
    message: string,
    readonly code?: string,
  ) {
    super(message);
  }
}

/** Every URL learned from metadata must pass the same rules as downstream URLs. */
export function assertSafeUrl(value: unknown, what: string): string {
  if (typeof value !== "string") throw new OAuthFlowError(`${what} is missing from the server metadata`);
  const err = validateDownstreamUrl(value);
  if (err) throw new OAuthFlowError(`${what}: ${err}`);
  return value;
}

/** Small JSON fetch with a timeout and a size cap. Returns undefined on 404. */
export async function fetchJson(url: string, init: RequestInit = {}): Promise<{ status: number; body: Record<string, unknown> } | undefined> {
  const res = await fetch(url, { ...init, headers: { Accept: "application/json", ...(init.headers as Record<string, string>) }, signal: AbortSignal.timeout(10_000) });
  if (res.status === 404) return undefined;
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new OAuthFlowError(`response from ${new URL(url).host} is too large`);
  let body: Record<string, unknown> = {};
  try {
    body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    if (res.ok) throw new OAuthFlowError(`response from ${new URL(url).host} is not JSON`);
  }
  return { status: res.status, body };
}

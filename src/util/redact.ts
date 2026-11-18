/**
 * redact() makes a value safe to log. It is applied to every log line.
 *
 * - Object keys that look sensitive (tokens, secrets, keys, args, results, field values) are
 *   replaced wholesale, whatever their value.
 * - Strings are scanned for credential-shaped substrings (Bearer tokens, gateway access keys,
 *   1Password service account tokens, GitHub tokens, JWTs, long base64/hex runs).
 */

const REDACTED = "[redacted]";

const SENSITIVE_KEY =
  /(token|secret|password|passwd|authorization|cookie|api[-_]?key|private|credential|verifier|code$|^code|args|arguments|result|value|policy|session|signature|^key$|_key$)/i;

const SENSITIVE_STRING: RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /\bmcpk_[A-Za-z0-9_-]+/g,
  /\bops_[A-Za-z0-9_-]+/g,
  /\bgh[pousr]_[A-Za-z0-9]+/g,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g,
  /\b[A-Za-z0-9+/_-]{40,}={0,2}/g,
  /\b[a-f0-9]{32,}\b/gi,
];

export function redactString(s: string): string {
  let out = s;
  for (const re of SENSITIVE_STRING) out = out.replace(re, REDACTED);
  return out;
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 8) return REDACTED;
  if (typeof value === "string") return redactString(value);
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SENSITIVE_KEY.test(k) ? REDACTED : redact(v, depth + 1);
  }
  return out;
}

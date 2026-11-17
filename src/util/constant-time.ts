import { sha256, utf8 } from "./encoding";

/**
 * Constant-time comparison of two byte arrays of equal length.
 * Length is not secret here: callers compare fixed-size digests.
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  const subtle = crypto.subtle as SubtleCrypto & { timingSafeEqual?: (a: ArrayBufferView, b: ArrayBufferView) => boolean };
  if (typeof subtle.timingSafeEqual === "function") return subtle.timingSafeEqual(a, b);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Constant-time string comparison for secrets and hashes. Both sides are hashed first so the
 * comparison runs over fixed-length digests and leaks neither content nor length.
 */
export async function timingSafeEqualString(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([sha256(utf8(a)), sha256(utf8(b))]);
  return timingSafeEqualBytes(ha, hb);
}

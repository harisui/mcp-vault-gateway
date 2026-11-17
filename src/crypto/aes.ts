import { fromBase64Url, fromUtf8, randomBytes, toBase64Url, utf8 } from "../util/encoding";
import type { KeyPurpose, KeyRing } from "./keys";

export class DecryptError extends Error {
  override name = "DecryptError";
}

const IV_BYTES = 12; // 96-bit IV, fresh for every encryption.

/**
 * AES-256-GCM. Output: `v<keyVersion>.<base64url iv>.<base64url ciphertext+tag>`.
 * `aad` binds the ciphertext to its storage key so it cannot be moved to another key.
 */
export async function encrypt(ring: KeyRing, purpose: KeyPurpose, aad: string, plaintext: string): Promise<string> {
  const version = ring.activeVersion;
  const key = await ring.key(purpose, version);
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(aad) }, key, utf8(plaintext));
  return `v${version}.${toBase64Url(iv)}.${toBase64Url(new Uint8Array(ct))}`;
}

export async function decrypt(ring: KeyRing, purpose: KeyPurpose, aad: string, envelope: string): Promise<string> {
  const parts = envelope.split(".");
  const m = /^v([1-9][0-9]*)$/.exec(parts[0] ?? "");
  if (parts.length !== 3 || !m) throw new DecryptError("malformed envelope");
  const version = Number(m[1]);
  if (!ring.hasVersion(version)) throw new DecryptError(`no key for version v${version}`);
  let iv: Uint8Array, ct: Uint8Array;
  try {
    iv = fromBase64Url(parts[1]!);
    ct = fromBase64Url(parts[2]!);
  } catch {
    throw new DecryptError("malformed envelope");
  }
  if (iv.length !== IV_BYTES) throw new DecryptError("malformed envelope");
  try {
    const key = await ring.key(purpose, version);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: utf8(aad) }, key, ct);
    return fromUtf8(pt);
  } catch {
    throw new DecryptError("decryption failed");
  }
}

/** Parse the key version from an envelope without decrypting. Used during key rotation. */
export function envelopeVersion(envelope: string): number | undefined {
  const m = /^v([1-9][0-9]*)\./.exec(envelope);
  return m ? Number(m[1]) : undefined;
}

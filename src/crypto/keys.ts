import { fromBase64, utf8 } from "../util/encoding";

/** HKDF `info` labels. Each purpose gets its own key; the master key is never used directly. */
export type KeyPurpose = "kv-cache-v1" | "oauth-state-v1" | "session-v1";

export class ConfigError extends Error {
  override name = "ConfigError";
}

const MASTER_KEY_BYTES = 32; // AES-256. Longer keys add nothing; shorter ones are refused.
const HKDF_SALT = utf8("mcp-vault-gateway/hkdf-salt/v1");
const KEY_NAME = /^ENCRYPTION_KEY_V([1-9][0-9]*)$/;

/**
 * Versioned master keys loaded from ENCRYPTION_KEY_V1, ENCRYPTION_KEY_V2, ...
 * ACTIVE_KEY_VERSION selects the key used for new encryptions; any loaded version can decrypt.
 */
export class KeyRing {
  private readonly masters = new Map<number, CryptoKey>();
  private readonly derived = new Map<string, Promise<CryptoKey>>();

  private constructor(readonly activeVersion: number) {}

  static async fromEnv(env: Record<string, unknown>): Promise<KeyRing> {
    const raw = new Map<number, Uint8Array>();
    for (const [name, value] of Object.entries(env)) {
      const m = KEY_NAME.exec(name);
      if (!m) continue;
      if (typeof value !== "string" || !value.trim()) throw new ConfigError(`${name} is empty`);
      let bytes: Uint8Array;
      try {
        bytes = fromBase64(value);
      } catch {
        throw new ConfigError(`${name} is not valid base64`);
      }
      if (bytes.length !== MASTER_KEY_BYTES) {
        throw new ConfigError(`${name} must be exactly 32 bytes (generate with: openssl rand -base64 32)`);
      }
      raw.set(Number(m[1]), bytes);
    }
    if (raw.size === 0) throw new ConfigError("ENCRYPTION_KEY_V1 is not set");

    const active = Number((env.ACTIVE_KEY_VERSION as string | undefined) ?? "1");
    if (!Number.isInteger(active) || !raw.has(active)) {
      throw new ConfigError(`ACTIVE_KEY_VERSION=${String(env.ACTIVE_KEY_VERSION)} has no matching ENCRYPTION_KEY_V<n>`);
    }

    const ring = new KeyRing(active);
    for (const [version, bytes] of raw) {
      ring.masters.set(version, await crypto.subtle.importKey("raw", bytes, "HKDF", false, ["deriveKey"]));
    }
    return ring;
  }

  hasVersion(version: number): boolean {
    return this.masters.has(version);
  }

  /** AES-256-GCM key for one purpose, derived with HKDF-SHA-256. */
  key(purpose: KeyPurpose, version = this.activeVersion): Promise<CryptoKey> {
    const id = `${version}:${purpose}`;
    let k = this.derived.get(id);
    if (!k) {
      const master = this.masters.get(version);
      if (!master) return Promise.reject(new ConfigError(`unknown key version v${version}`));
      k = crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: utf8(purpose) },
        master,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
      this.derived.set(id, k);
    }
    return k;
  }
}

let cached: { fingerprint: string; ring: Promise<KeyRing> } | undefined;

/** KeyRing for this isolate. Rebuilt only if the key bindings change. */
export function getKeyRing(env: Record<string, unknown>): Promise<KeyRing> {
  const fingerprint = Object.keys(env)
    .filter((k) => KEY_NAME.test(k) || k === "ACTIVE_KEY_VERSION")
    .sort()
    .map((k) => `${k}=${String(env[k])}`)
    .join("\n");
  if (!cached || cached.fingerprint !== fingerprint) {
    const ring = KeyRing.fromEnv(env);
    ring.catch(() => (cached = undefined));
    cached = { fingerprint, ring };
  }
  return cached.ring;
}

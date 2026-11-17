import { describe, expect, it } from "vitest";
import { decrypt, encrypt, envelopeVersion } from "../src/crypto/aes";
import { ConfigError, KeyRing } from "../src/crypto/keys";
import { fromBase64Url, randomBytes, toBase64, toBase64Url } from "../src/util/encoding";
import { keyRing, newMasterKey } from "./helpers";

describe("AES-256-GCM envelope", () => {
  it("round-trips", async () => {
    const ring = await keyRing();
    const env = await encrypt(ring, "kv-cache-v1", "reg:personal", "hello 🔐");
    expect(env).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(await decrypt(ring, "kv-cache-v1", "reg:personal", env)).toBe("hello 🔐");
  });

  it("uses a fresh 96-bit IV every time", async () => {
    const ring = await keyRing();
    const a = await encrypt(ring, "kv-cache-v1", "k", "same");
    const b = await encrypt(ring, "kv-cache-v1", "k", "same");
    expect(a).not.toBe(b);
    expect(fromBase64Url(a.split(".")[1]!)).toHaveLength(12);
  });

  it("detects tampering with the ciphertext", async () => {
    const ring = await keyRing();
    const env = await encrypt(ring, "kv-cache-v1", "k", "secret data");
    const [v, iv, ct] = env.split(".");
    const bytes = fromBase64Url(ct!);
    bytes[0]! ^= 0x01;
    await expect(decrypt(ring, "kv-cache-v1", "k", `${v}.${iv}.${toBase64Url(bytes)}`)).rejects.toThrow("decryption failed");
  });

  it("detects tampering with the IV", async () => {
    const ring = await keyRing();
    const env = await encrypt(ring, "kv-cache-v1", "k", "secret data");
    const [v, , ct] = env.split(".");
    await expect(decrypt(ring, "kv-cache-v1", "k", `${v}.${toBase64Url(randomBytes(12))}.${ct}`)).rejects.toThrow();
  });

  it("binds ciphertext to its storage key via AAD", async () => {
    const ring = await keyRing();
    const env = await encrypt(ring, "kv-cache-v1", "reg:personal", "x");
    await expect(decrypt(ring, "kv-cache-v1", "reg:sunshine", env)).rejects.toThrow("decryption failed");
  });

  it("rejects malformed envelopes", async () => {
    const ring = await keyRing();
    for (const bad of ["", "v1", "v1.a", "x1.a.b", "v0.a.b", "v1.!!.b"]) {
      await expect(decrypt(ring, "kv-cache-v1", "k", bad)).rejects.toThrow();
    }
  });
});

describe("HKDF key separation", () => {
  it("keys for different purposes cannot decrypt each other", async () => {
    const ring = await keyRing();
    const env = await encrypt(ring, "kv-cache-v1", "k", "x");
    await expect(decrypt(ring, "oauth-state-v1", "k", env)).rejects.toThrow();
    await expect(decrypt(ring, "session-v1", "k", env)).rejects.toThrow();
  });

  it("different master keys (personal vs client Worker) cannot decrypt each other", async () => {
    const personal = await keyRing();
    const client = await keyRing();
    const env = await encrypt(personal, "kv-cache-v1", "k", "x");
    await expect(decrypt(client, "kv-cache-v1", "k", env)).rejects.toThrow();
  });
});

describe("master key validation", () => {
  it("refuses keys that are not exactly 32 bytes", async () => {
    await expect(KeyRing.fromEnv({ ENCRYPTION_KEY_V1: toBase64(randomBytes(16)) })).rejects.toBeInstanceOf(ConfigError);
    await expect(KeyRing.fromEnv({ ENCRYPTION_KEY_V1: toBase64(randomBytes(64)) })).rejects.toBeInstanceOf(ConfigError);
    await expect(KeyRing.fromEnv({ ENCRYPTION_KEY_V1: "not base64 !!" })).rejects.toBeInstanceOf(ConfigError);
    await expect(KeyRing.fromEnv({})).rejects.toBeInstanceOf(ConfigError);
  });

  it("refuses an ACTIVE_KEY_VERSION without a key", async () => {
    await expect(KeyRing.fromEnv({ ENCRYPTION_KEY_V1: newMasterKey(), ACTIVE_KEY_VERSION: "2" })).rejects.toBeInstanceOf(ConfigError);
  });
});

describe("key rotation", () => {
  it("encrypts with the active version and still decrypts older versions", async () => {
    const v1 = newMasterKey();
    const old = await KeyRing.fromEnv({ ENCRYPTION_KEY_V1: v1 });
    const oldEnv = await encrypt(old, "kv-cache-v1", "k", "old");

    const rotated = await KeyRing.fromEnv({ ENCRYPTION_KEY_V1: v1, ENCRYPTION_KEY_V2: newMasterKey(), ACTIVE_KEY_VERSION: "2" });
    const newEnv = await encrypt(rotated, "kv-cache-v1", "k", "new");
    expect(envelopeVersion(newEnv)).toBe(2);
    expect(await decrypt(rotated, "kv-cache-v1", "k", oldEnv)).toBe("old");
    expect(await decrypt(rotated, "kv-cache-v1", "k", newEnv)).toBe("new");
  });
});

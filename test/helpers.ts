import { KeyRing } from "../src/crypto/keys";
import { randomBytes, toBase64 } from "../src/util/encoding";

export const newMasterKey = (): string => toBase64(randomBytes(32));

export function keyRing(env: Record<string, string> = { ENCRYPTION_KEY_V1: newMasterKey() }): Promise<KeyRing> {
  return KeyRing.fromEnv(env);
}

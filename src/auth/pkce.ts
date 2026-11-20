import { randomBytes, sha256, toBase64Url } from "../util/encoding";

export function pkceVerifier(): string {
  return toBase64Url(randomBytes(32));
}

export async function pkceChallenge(verifier: string): Promise<string> {
  return toBase64Url(await sha256(verifier));
}

export function randomState(): string {
  return toBase64Url(randomBytes(24));
}

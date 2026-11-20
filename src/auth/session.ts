import { decrypt, encrypt } from "../crypto/aes";
import type { KeyRing } from "../crypto/keys";

/**
 * Browser session for the /connect pages, separate from MCP tokens. Encrypted (AES-GCM with the
 * HKDF `session-v1` key) so it can't be read or forged, `__Host-` so it is host-only and Secure.
 */

export const SESSION_COOKIE = "__Host-gw_session";
export const LOGIN_COOKIE = "__Host-gw_login";
const SESSION_TTL_S = 8 * 3600;
const LOGIN_TTL_S = 10 * 60;

export interface Session {
  email: string;
  exp: number;
}

export interface LoginState {
  state: string;
  verifier: string;
  next: string;
  exp: number;
}

function cookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

export const clearCookie = (name: string): string => cookie(name, "", 0);

export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.get("Cookie") ?? "";
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

async function readSealed<T extends { exp: number }>(req: Request, ring: KeyRing, name: string): Promise<T | undefined> {
  const raw = readCookie(req, name);
  if (!raw) return undefined;
  try {
    const value = JSON.parse(await decrypt(ring, "session-v1", name, raw)) as T;
    return value.exp > Date.now() ? value : undefined;
  } catch {
    return undefined;
  }
}

export async function sessionCookie(ring: KeyRing, email: string): Promise<string> {
  const value: Session = { email, exp: Date.now() + SESSION_TTL_S * 1000 };
  return cookie(SESSION_COOKIE, await encrypt(ring, "session-v1", SESSION_COOKIE, JSON.stringify(value)), SESSION_TTL_S);
}

export const readSession = (req: Request, ring: KeyRing) => readSealed<Session>(req, ring, SESSION_COOKIE);

export async function loginCookie(ring: KeyRing, s: Omit<LoginState, "exp">): Promise<string> {
  const value: LoginState = { ...s, exp: Date.now() + LOGIN_TTL_S * 1000 };
  return cookie(LOGIN_COOKIE, await encrypt(ring, "session-v1", LOGIN_COOKIE, JSON.stringify(value)), LOGIN_TTL_S);
}

export const readLoginState = (req: Request, ring: KeyRing) => readSealed<LoginState>(req, ring, LOGIN_COOKIE);

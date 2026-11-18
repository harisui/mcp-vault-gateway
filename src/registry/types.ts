/** A 1Password item as the gateway sees it (normalized from the SDK, also what gets cached). */
export interface RawField {
  id: string;
  title: string;
  /** Lowercased SDK field type: "text", "concealed", ... */
  type: string;
  value: string;
}

export interface RawItem {
  id: string;
  vaultId: string;
  title: string;
  tags: string[];
  version: number;
  /** ISO 8601, from the item overview. Used to skip re-fetching unchanged items. */
  updatedAt: string;
  fields: RawField[];
}

export type AuthType = "none" | "bearer" | "header" | "oauth";
export type ServerStatus = "ok" | "invalid" | "needs_connect" | "disabled" | "error";

export interface OAuthCredentials {
  clientId?: string;
  clientSecret?: string;
  scopes?: string;
  accessToken?: string;
  refreshToken?: string;
  /** Epoch milliseconds. */
  expiresAt?: number;
}

export interface ServerEntry {
  /** `<group>.<name>` */
  id: string;
  group: string;
  name: string;
  itemId: string;
  vaultId: string;
  status: ServerStatus;
  reason?: string;
  url?: string;
  authType?: AuthType;
  headerName?: string;
  token?: string;
  blockedTools: string[];
  oauth?: OAuthCredentials;
}

export const MCP_TAG = "mcp";
export const POLICY_TITLE = "_policy";

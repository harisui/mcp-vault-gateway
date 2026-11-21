import type { ServerEntry } from "../registry/types";

/** Everything the server Durable Object needs to reach one downstream server. */
export interface Target {
  serverId: string;
  url: string;
  /** Injected auth headers. Never logged. */
  headers: Record<string, string>;
  timeoutMs: number;
  maxResponseBytes: number;
}

/** Auth headers for a server, by auth_type. OAuth tokens must already be fresh. */
export function authHeaders(server: ServerEntry): Record<string, string> {
  switch (server.authType) {
    case "bearer":
      return { Authorization: `Bearer ${server.token}` };
    case "header":
      return { [server.headerName!]: server.token! };
    case "oauth":
      return server.oauth?.accessToken ? { Authorization: `Bearer ${server.oauth.accessToken}` } : {};
    default:
      return {};
  }
}

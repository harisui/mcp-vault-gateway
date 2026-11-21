/**
 * An error whose message is safe to show to Claude: no secrets, no stack traces.
 * Anything else that escapes a tool handler is replaced with a generic message.
 */
export class GatewayError extends Error {
  override name = "GatewayError";
}

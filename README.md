# MCP Vault Gateway

One MCP endpoint in front of all your MCP servers, running on Cloudflare Workers, with every credential kept in 1Password.

Claude lets each account connect only its own connectors. If you use Claude on several accounts, you end up configuring every MCP server again on each one. With this gateway you connect each account to **one** URL. The gateway finds your MCP servers in 1Password, injects the right credentials, and forwards the calls.

- **Adding a server = adding an item in 1Password.** No code change, no redeploy.
- **Claude never sees a downstream key.** Keys stay in 1Password and in the Worker's memory.
- **Deny by default.** A `_policy` item in each vault says who may use which servers and tools.
- **One codebase, separate trust zones.** Deploy it as several Workers (for example `personal` and `client`) that share nothing at runtime.

Setup takes about 30 minutes: see **[SETUP.md](SETUP.md)**.

---

## How it works

```
 Claude (any account)              Cloudflare Worker: mcp-personal-server
 ┌──────────────────┐   OAuth /    ┌───────────────────────────────────────────────┐
 │ custom connector │── access ──▶ │ /mcp  list_servers · list_tools · call ·      │
 │ or Claude Code   │    key       │       refresh_servers                         │
 └──────────────────┘              │                                               │
                                   │  policy check (deny by default, read_only,    │
                                   │  blocked_tools, destructiveHint)              │
                                   │        │                                      │
                                   │  registry ◀── encrypted KV cache (60 min)     │
                                   │        │            ▲                         │
                                   │        │            │ only changed items      │
                                   │        │      1Password SDK (Service Account  │
                                   │        │      token per vault)                │
                                   │        ▼                                      │
                                   │  ServerDO per server: MCP session, OAuth      │──▶ downstream MCP servers
                                   │  refresh lock, credential injection           │    (https only)
                                   └───────────────────────────────────────────────┘
```

1. **Vaults are groups.** Every Worker secret named `OP_TOKEN_<GROUP>` is a 1Password Service Account token that can see one vault. At startup the gateway lists these bindings, so a new vault is just a new secret.
2. **Items are servers.** Items tagged `mcp` are parsed into servers named `<group>.<name>` (for example `personal.pm_tool` or `sunshine.jira`). Invalid items are reported in `list_servers` and never take the gateway down.
3. **`_policy` is access control.** Each vault's `_policy` item maps GitHub emails and access keys to servers, `read_only`, `blocked_tools` and `allow_destructive`. A caller's access is the union over all groups. A missing or broken policy denies everything for that group.
4. **Claude sees four meta-tools**, not a flattened list of every downstream tool:

   | Tool | What it does |
   |---|---|
   | `list_servers` | Servers you may use, with status (`ok`, `invalid`, `needs_connect`, `disabled`, `error`) and a description when known |
   | `list_tools(server)` | That server's tools after policy filtering (cached 60 minutes) |
   | `call(server, tool, args)` | Policy check, credential injection, forward, and the result returned untouched |
   | `refresh_servers` | Reload vaults and policy now (once per minute per caller) |

5. **Downstream calls** go through a Durable Object per server. It keeps the MCP session open, injects `Authorization` or a custom header, enforces the timeout and size limits, refuses redirects and cross-origin requests, and on a **401** re-reads the item from 1Password and retries **once**.
6. **OAuth servers** are connected once in a browser at `/connect/<group>/<name>`: discovery (RFC 9728 and RFC 8414), dynamic client registration (RFC 7591) and PKCE S256. Tokens are written back to the 1Password item and refreshed under a per-server lock.

### Signing in to the gateway

| Client | How |
|---|---|
| Claude custom connector | OAuth 2.1 with PKCE and dynamic client registration (`@cloudflare/workers-oauth-provider`). After a consent page, you sign in with GitHub, and your **verified primary email** must appear in some `_policy.users`. Access tokens last 1 hour; refresh tokens rotate. |
| Claude Code and scripts | `Authorization: Bearer mcpk_<key_id>_<secret>`. Only the SHA-256 of the key is stored in `_policy`, compared in constant time, with optional `expires_at`. Generate keys with `npm run gen-key`. |

### Read-only callers

For a caller with `read_only: true`, a tool is allowed only if:

- its MCP annotations say `readOnlyHint: true`, or
- it has no `readOnlyHint` and its name starts with `get_`, `list_`, `search_`, `read_`, `describe_` or `fetch_`.

Everything else is blocked, including tools with `readOnlyHint: false`. Tools annotated `destructiveHint: true` are blocked for everyone unless their policy entry sets `"allow_destructive": true`. Item-level and caller-level `blocked_tools` globs always win.

### Caching and 1Password limits

1Password Service Accounts have tight limits (around 1,000 requests a day per account, and 1,000 reads and 100 writes an hour per token), so the gateway treats 1Password as a slow source of truth:

- Items and policy are cached in KV, **encrypted**, for `CACHE_TTL_SECONDS` (default 1 hour).
- A reload lists vaults first. If a vault's content version hasn't changed, that costs **one call**. Otherwise it lists items and fetches **only the changed ones**.
- If 1Password fails or rate-limits, the gateway keeps serving the last good cache (**stale-on-error**) and retries at most every 5 minutes.
- `OP_MAX_CALLS_PER_HOUR` (default 200) is a hard cap, counted in a Durable Object. Over the cap, the gateway serves from cache only.
- Signing in to 1Password takes about 3 seconds, so each Worker instance signs in once and reuses the client.

`GET /health` (no auth) answers only `ok` or `degraded`.

---

## Encryption

- One 256-bit master key per Worker: `ENCRYPTION_KEY_V1` (`openssl rand -base64 32`). It must be exactly 32 bytes, or the Worker refuses to run.
- The master key is never used directly. HKDF-SHA-256 derives one key per purpose: `kv-cache-v1`, `oauth-state-v1` and `session-v1`.
- AES-256-GCM via WebCrypto, with a fresh 96-bit IV for every encryption. The format is `v<keyVersion>.<iv>.<ciphertext>`. The storage key name is the AAD, so ciphertext can't be moved between keys.
- Rotation: add `ENCRYPTION_KEY_V2` and set `ACTIVE_KEY_VERSION=2`. Older versions still decrypt (see [SETUP.md](SETUP.md#9-key-rotation)).

---

## Threat model

### What is protected

- **Downstream credentials never reach Claude**, the tool results or the logs. They are injected only into requests to that server's own origin, and redirects are never followed.
- **Trust zones are isolated.** Each Worker has its own secrets, KV namespaces, Durable Objects, OAuth state, GitHub app and master key. Within a Worker, each vault has its own Service Account, so one leaked token exposes one vault.
- **Data at rest in KV is encrypted.** Cached items, tool lists, OAuth connect state and browser sessions are all encrypted. OAuth grants for Claude are stored by `workers-oauth-provider`, hashed and encrypted.
- **Access is deny-by-default** and evaluated on every call against the current policy.
- **Logs** go through `redact()`. Each `call` writes one audit line (time, caller, server, tool, outcome, latency) and never logs arguments or results.
- **Downstream URLs** must be `https://` with a DNS host name: no IP literals and no `localhost`.
- **HTML pages** send `Content-Security-Policy`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. `/mcp` sends no CORS headers.
- **Rate limits** apply per caller (default 120 calls a minute) and `refresh_servers` runs at most once a minute.

### What is not protected

- **Tool arguments and results pass through Claude and through the Worker.** The gateway hides credentials, not data.
- **Prompt injection.** A downstream server can return text that tries to steer Claude. The policy limits what Claude can do next, so keep client servers `read_only` where you can.
- **`read_only` trusts annotations.** A server that marks a write tool `readOnlyHint: true` defeats it. Use `blocked_tools` for servers you don't trust.
- **Policy changes are not instant.** They apply after `refresh_servers` or the cache TTL, plus up to about a minute of KV propagation.
- **Your Cloudflare, 1Password and GitHub accounts are the root of trust.** Use hardware-key 2FA on all three.

### If a secret leaks

| Secret | Impact | Response |
|---|---|---|
| `OP_TOKEN_<GROUP>` | Read (or read and write) of **that vault only**: every downstream credential in that group. Nothing in other vaults or the other Worker. | Revoke the token in 1Password, create a new one, `wrangler secret put`. Rotate the downstream keys stored in that vault. |
| `ENCRYPTION_KEY_V*` | Useless alone. Together with read access to that Worker's KV, it decrypts the cache, which holds that Worker's downstream credentials. | Rotate the key (SETUP §9) and delete the old one at once. The cache rebuilds from 1Password. |
| `GITHUB_CLIENT_SECRET` | Lets someone impersonate your GitHub OAuth app in a phishing flow. It does not let them sign in as you. | Regenerate it in GitHub, then `wrangler secret put`. |
| An access key `mcpk_...` | Exactly that key's policy (servers, `read_only`) until it expires or is removed. | Delete its entry from `_policy`, run `refresh_servers`. |
| A Claude OAuth token for the gateway | Your policy's access, for at most 1 hour (access token) or until the 30-day refresh grant ends. | Remove the email from `_policy` and run `refresh_servers`. |
| Your GitHub account | Whatever your email is granted in the policies. | Secure the account. Remove the email from `_policy` until you have. |
| Cloudflare account | Everything that Worker can reach, because deployed code can read its secrets. | Rotate every secret of every Worker in that account. |
| A downstream server is malicious | It sees the requests Claude sends to it, and nothing else. Credentials for other servers are never sent to it. | Disable the item (`enabled: false`) or remove it. |

---

## Project layout

```
src/
  index.ts            entry: routing, OAuth provider, /health
  app.ts              per-isolate wiring
  auth/               consent + GitHub login, access keys, browser session
  onepassword/        SDK client (WASM shim), call budget
  registry/           item parsing, encrypted cache, stale-on-error
  policy/             _policy parsing and enforcement
  proxy/              downstream MCP client, ServerDO, 401 retry, tool cache
  oauth-downstream/   /connect, discovery, DCR, PKCE, refresh
  crypto/             HKDF and AES-GCM with key versions
  mcp/                the four meta-tools and the /mcp endpoint
  util/               redact, constant-time compare, logging, HTML
scripts/
  build-op-shim.mjs   makes the 1Password SDK load on Workers
  generate-access-key.ts
spike/op-sdk-test/    Phase 0 spike: does the 1Password SDK run on Workers?
test/                 Vitest, running inside workerd
```

## Development

```bash
npm install
npm test            # vitest in the Workers runtime, no secrets needed
npm run typecheck
npm run dev         # wrangler dev --env personal (needs .dev.vars, see .dev.vars.example)
```

### Notes and limitations

- **The 1Password SDK targets Node.js.** Its WASM core loads itself from disk, which Workers don't allow. `scripts/build-op-shim.mjs` (run automatically by wrangler) rewrites it to import the `.wasm` as a pre-compiled module. The SDK is pinned to the version the shim was tested with. Re-test after upgrading.
- **Bundle size** is about 4.4 MB gzipped, mostly that WASM. You need the Workers Paid plan.
- **The first request after a cold start** that needs 1Password pays about 3 seconds for sign-in. Requests served from cache don't touch the SDK at all.
- **Legacy SSE** downstream servers are used only when Streamable HTTP is rejected with 404 or 405.

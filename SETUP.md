# Setup

A step-by-step checklist from an empty Cloudflare account to Claude talking to your MCP servers through the gateway.

You deploy the same code twice, as two separate Workers:

| Environment | Worker name | For |
|---|---|---|
| `personal` | `mcp-personal-server` | Your own products |
| `client` | `mcp-client-server` | Client systems under NDA |

Everything below is done **once per environment**. The two must never share a vault, a Service Account, a GitHub OAuth app, a KV namespace or an encryption key. If you only need one gateway, do the `personal` steps and skip `client`.

---

## 0. Before you start

- [ ] Cloudflare account on the **Workers Paid** plan. The 1Password SDK bundle is about 4.3 MB gzipped, which is over the 3 MB Free plan limit.
- [ ] Node.js 22.12 or newer.
- [ ] A 1Password Business or Teams account (Service Accounts are required).
- [ ] A GitHub account whose **verified primary email** you will list in the policy.

```bash
git clone https://github.com/harisui/mcp-vault-gateway.git
cd mcp-vault-gateway
npm install
npx wrangler login
```

---

## 1. 1Password: vaults and Service Accounts

Each vault is one **group** of MCP servers. Each vault gets its own Service Account that can see **only that vault**.

Example layout:

| Worker | Vault | Service Account | Worker secret |
|---|---|---|---|
| personal | `MCP Personal` | `mcp-gateway-personal` | `OP_TOKEN_PERSONAL` |
| client | `MCP Client - Sunshine` | `mcp-gateway-sunshine` | `OP_TOKEN_SUNSHINE` |
| client | `MCP Client - Southpaw` | `mcp-gateway-southpaw` | `OP_TOKEN_SOUTHPAW` |

The group name is the lowercased suffix of the secret: `OP_TOKEN_SUNSHINE` becomes `sunshine`, and its servers are called `sunshine.<name>`.

For each group:

- [ ] Create a **shared** vault (Service Accounts cannot use Personal, Private or Employee vaults).
- [ ] On 1Password.com, open **Developer** and create a **Service Account**.
- [ ] Give it access to **that one vault only**.
  - **Read** only, unless the vault holds `auth_type: oauth` servers.
  - **Read + Write** if it does: the gateway writes OAuth tokens back into those items.
- [ ] Copy the token (`ops_...`). 1Password shows it once. You will paste it in step 6.

### Item template (one item = one MCP server)

Create a **Secure Note** or **API Credential** item, add the tag **`mcp`**, and add these fields. Field labels must match exactly (case does not matter).

| Field label | Type | Required | Example |
|---|---|---|---|
| `name` | text | yes | `jira` (lowercase `a-z 0-9 _`, unique in the vault) |
| `url` | text | yes | `https://mcp.atlassian.com/v1/mcp` (https only, host name only, no IPs, no localhost) |
| `auth_type` | text | yes | `none`, `bearer`, `header` or `oauth` |
| `token` | password/concealed | for `bearer` and `header` | the API key |
| `header_name` | text | for `header` | `X-API-Key` |
| `enabled` | text | no | `true` (default) or `false` |
| `blocked_tools` | text | no | `delete_*, drop_*` |
| `client_id` | text | `oauth` only, if the server has no dynamic registration | |
| `client_secret` | password/concealed | same as above | |
| `scopes` | text | no | `read write` (space separated, keep minimal) |
| `access_token` | concealed | written by the gateway | **leave empty, never edit** |
| `refresh_token` | concealed | written by the gateway | **leave empty, never edit** |
| `expires_at` | text | written by the gateway | **leave empty, never edit** |

Items without the `mcp` tag are ignored. A broken item (bad URL, unknown `auth_type`, missing token, duplicate name) is skipped and shown in `list_servers` as `status: "invalid"` with the reason. It never breaks the other servers.

### `_policy` item (who may use what)

Each vault needs **one** item titled exactly **`_policy`**, tagged **`mcp`**, with a concealed field labelled **`policy`** containing JSON:

```json
{
  "users": {
    "you@example.com": {
      "servers": ["pm_tool", "ledger", "hr"],
      "blocked_tools": ["delete_*"],
      "read_only": false
    },
    "your-other-account@example.com": {
      "servers": ["pm_tool"],
      "read_only": true
    }
  },
  "access_keys": {}
}
```

Rules:

- **Deny by default.** Anyone not listed gets nothing.
- `"servers": ["*"]` means every server in this vault.
- `read_only: true` allows only tools marked `readOnlyHint: true`. Tools with no annotations fall back to their name: `get_*`, `list_*`, `search_*`, `read_*`, `describe_*` and `fetch_*` are allowed, and everything else is blocked.
- Tools marked `destructiveHint: true` are blocked unless the entry has `"allow_destructive": true`.
- Unknown keys are rejected (a typo like `"readonly"` must not silently grant write access).
- A missing or invalid `_policy` **denies everyone** in that vault. Admins (`ADMIN_EMAILS`) see the error in `list_servers`.
- Emails are your **GitHub verified primary email**, compared case-insensitively.

---

## 2. GitHub OAuth apps (one per Worker)

You sign in to the gateway with GitHub. The gateway only reads your verified primary email.

For each Worker:

- [ ] https://github.com/settings/developers → **OAuth Apps** → **New OAuth App**
- [ ] Application name: `MCP Personal Gateway` (or `MCP Client Gateway`)
- [ ] Homepage URL: `https://mcp-personal-server.<your-subdomain>.workers.dev`
- [ ] Authorization callback URL: `https://mcp-personal-server.<your-subdomain>.workers.dev/auth/github/callback`
- [ ] Generate a client secret and keep the Client ID and secret for step 6.

The same callback also covers `/auth/github/callback/session` (browser login for `/connect`), because GitHub allows sub-paths of the registered callback.

Your `workers.dev` subdomain is shown in the Cloudflare dashboard under **Workers & Pages**. If you use a custom domain, use it everywhere instead.

---

## 3. KV namespaces

Two per Worker: one for OAuth state (`OAUTH_KV`), one for the encrypted cache (`CACHE_KV`).

```bash
npx wrangler kv namespace create mcp-personal-oauth
npx wrangler kv namespace create mcp-personal-cache
npx wrangler kv namespace create mcp-client-oauth
npx wrangler kv namespace create mcp-client-cache
```

- [ ] Paste each printed `id` into `wrangler.jsonc`, replacing `<personal-oauth-kv-id>`, `<personal-cache-kv-id>`, `<client-oauth-kv-id>` and `<client-cache-kv-id>`.

Durable Objects need no setup. They are created on first deploy, separately for each Worker.

---

## 4. Plain settings in `wrangler.jsonc`

Under each environment's `vars`:

- [ ] `PUBLIC_URL`: the Worker's URL, for example `https://mcp-personal-server.<your-subdomain>.workers.dev` (no trailing slash).
- [ ] `ADMIN_EMAILS`: your email(s), comma separated. Admins see policy errors and 1Password errors in `list_servers`.
- Optional tuning (defaults shown in the file): `CACHE_TTL_SECONDS`, `TOOLS_CACHE_TTL_SECONDS`, `OP_MAX_CALLS_PER_HOUR`, `DOWNSTREAM_TIMEOUT_MS`, `MAX_REQUEST_BYTES`, `MAX_RESPONSE_BYTES`, `RATE_LIMIT_PER_MINUTE`.

---

## 5. (Optional) test locally

```bash
cp .dev.vars.example .dev.vars
# fill in .dev.vars: a fresh ENCRYPTION_KEY_V1, a test OP_TOKEN_*, and a GitHub OAuth app
# whose callback is http://localhost:8787/auth/github/callback
npm run dev                              # personal env on http://localhost:8787
curl http://localhost:8787/health        # "ok" once 1Password has loaded, else "degraded"
npm test                                 # unit tests, no secrets needed
```

---

## 6. Secrets

Run each command and paste the value when prompted. The generation command for each secret is next to it. Lines that pipe `openssl` straight into wrangler never show or store the key anywhere else.

### personal

```bash
# 256-bit master key (exactly 32 random bytes)
openssl rand -base64 32 | npx wrangler secret put ENCRYPTION_KEY_V1 --env personal

# GitHub OAuth app for the personal Worker (step 2)
npx wrangler secret put GITHUB_CLIENT_ID --env personal
npx wrangler secret put GITHUB_CLIENT_SECRET --env personal

# One per vault/group (step 1)
npx wrangler secret put OP_TOKEN_PERSONAL --env personal
```

### client

```bash
openssl rand -base64 32 | npx wrangler secret put ENCRYPTION_KEY_V1 --env client

npx wrangler secret put GITHUB_CLIENT_ID --env client
npx wrangler secret put GITHUB_CLIENT_SECRET --env client

npx wrangler secret put OP_TOKEN_SUNSHINE --env client
npx wrangler secret put OP_TOKEN_SOUTHPAW --env client
```

Notes:

- There is no `COOKIE_SECRET`. Browser sessions are encrypted with a key derived from `ENCRYPTION_KEY_V1` (HKDF label `session-v1`).
- Adding a vault later = one new `OP_TOKEN_<GROUP>` secret. Adding a server = one new 1Password item, with no secret and no redeploy.

---

## 7. Deploy

```bash
npm run deploy:personal     # wrangler deploy --env personal
npm run deploy:client       # wrangler deploy --env client
```

Then check:

```bash
curl https://mcp-personal-server.<your-subdomain>.workers.dev/health
```

The first request loads the 1Password SDK and signs in (a few seconds). After that, data is served from the encrypted cache.

---

## 8. Connect Claude

### Claude (web, desktop, mobile): custom connector

- [ ] Claude → **Settings** → **Connectors** → **Add custom connector**
- [ ] URL: `https://mcp-personal-server.<your-subdomain>.workers.dev/mcp`
- [ ] Click **Connect**. You'll see the gateway's consent page, then GitHub. Only emails in a `_policy` can finish.
- [ ] Repeat on every Claude account you use. They all share the same servers, and each account's access follows its own policy entry.

On Team or Enterprise plans, an Owner may need to add the connector for the organization first.

### Claude Code and scripts: access key

```bash
npm run gen-key -- --label claude-code-laptop --servers pm_tool,ledger --read-only --expires 2027-06-01
```

- [ ] Paste the printed JSON into the `access_keys` object of the vault's `_policy`.
- [ ] Store the printed key in your password manager. It is shown once and never saved.
- [ ] Add it to Claude Code:

```bash
claude mcp add --transport http personal-gateway \
  https://mcp-personal-server.<your-subdomain>.workers.dev/mcp \
  --header "Authorization: Bearer mcpk_..."
```

To revoke a key, delete its entry from `_policy` and run `refresh_servers` (or wait for the cache TTL).

### OAuth servers (`auth_type: oauth`)

- [ ] Open `https://<gateway>/connect/<group>/<name>` in a browser, for example `/connect/personal/crm`.
- [ ] Sign in with GitHub, then approve on the server's own login page.
- [ ] The gateway stores the tokens in the 1Password item and refreshes them automatically.
- [ ] If a refresh is ever rejected, `list_servers` shows `needs_connect` with the link to open again.

---

## 9. Key rotation

### Master encryption key (`ENCRYPTION_KEY_V1` → `V2`)

Everything encrypted with this key is a cache or short-lived state, so rotation cannot lose data. 1Password stays the source of truth.

1. Add the new key next to the old one:
   ```bash
   openssl rand -base64 32 | npx wrangler secret put ENCRYPTION_KEY_V2 --env personal
   ```
2. In `wrangler.jsonc`, set `"ACTIVE_KEY_VERSION": "2"` for that environment and deploy. New data is encrypted with v2, and v1 data is still readable.
3. Wait at least one cache TTL (60 minutes by default) so cached entries are rewritten with v2. Browser sessions last 8 hours, so wait that long if you don't want anyone signed out.
4. Remove the old key:
   ```bash
   npx wrangler secret delete ENCRYPTION_KEY_V1 --env personal
   ```
   Anything still encrypted with v1 becomes unreadable and is simply reloaded from 1Password.

If a key may be compromised, skip the waiting: rotate, delete the old key straight away and run `refresh_servers`.

### Other secrets

| Secret | How to rotate |
|---|---|
| `OP_TOKEN_<GROUP>` | Create a new Service Account token for the same vault, `wrangler secret put`, then revoke the old token in 1Password. |
| `GITHUB_CLIENT_SECRET` | Generate a new secret in the GitHub app, `wrangler secret put`, delete the old secret in GitHub. |
| Downstream API keys | Edit `token` in the 1Password item. The gateway picks it up on the next 401 or within the cache TTL, with no redeploy. |
| Access keys | Generate a new key, add it to `_policy`, switch clients over, then delete the old entry. |
| Gateway OAuth grants (Claude) | Remove the user from `_policy` and run `refresh_servers`: every tool call checks the current policy, so access stops once the cache has the new policy. Removing the connector in Claude also stops that account. |

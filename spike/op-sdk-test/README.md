# 1Password SDK on Workers – spike

Checks whether `@1password/sdk` runs on the Cloudflare Workers runtime.

The SDK core is a WASM module that Node loads with `fs.readFileSync` + `new WebAssembly.Module(bytes)`.
Workers do not allow compiling WASM from bytes at runtime, so `shim/build-shim.mjs` rewrites the core
into an ES module that imports `core_bg.wasm` as a pre-compiled module. `wrangler.jsonc` aliases
`@1password/sdk-core` to that shim.

## Run

```bash
npm install
cp .dev.vars.example .dev.vars   # put a test Service Account token in OP_TOKEN_TEST
npm run dev
curl http://localhost:8787/run
```

`/run` creates a client, lists vaults, lists items, reads a field and writes a field on a throwaway
item (`op-sdk-spike`), and returns the timing of each step. It never returns secret values.

`npm run size` prints the bundle size (about 4.1 MB gzipped, mostly the WASM core).

## Results (Phase 0)

Run with `wrangler dev`, real Service Account token, one vault:

| Step | Result | Time |
|---|---|---|
| Load SDK + instantiate WASM (shim) | ok | 8 ms |
| `createClient` (sign-in) | ok | ~3.5 s |
| `vaults.list` | ok | ~690 ms |
| `items.list` | ok | ~320 ms |
| create/write item | ok with a read+write token; a read-only token gets "not sufficient permissions" | ~680 ms |

Conclusions used by the gateway:

- Works on Workers only through the shim; the unmodified SDK cannot load its WASM there.
- Bundle is ~4.1 MB gzipped here (~4.4 MB in the gateway): Workers Paid plan required.
- Sign-in is slow and costs several 1Password requests, so the gateway signs in once per isolate
  and serves everything from an encrypted KV cache, touching 1Password only on reload.
- Only vaults with `auth_type: oauth` servers need a read+write Service Account.

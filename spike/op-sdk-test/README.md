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

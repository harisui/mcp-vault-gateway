// Rewrites @1password/sdk-core (Node build) into an ES module that Workers can load.
// Workers cannot compile WASM from bytes at runtime, so the .wasm is imported as a
// pre-compiled WebAssembly.Module instead of fs.readFileSync + new WebAssembly.Module.
import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const corePath = require.resolve("@1password/sdk-core");
const src = readFileSync(corePath, "utf8");

const loader = /const path = require\('path'\)[\s\S]*?const wasmModule = new WebAssembly\.Module\(bytes\);/;
if (!loader.test(src)) throw new Error("sdk-core loader block not found; SDK layout changed");

const body = src
  .replace("const { TextDecoder, TextEncoder } = require(`util`);", "")
  .replace(loader, "const wasmModule = __wasmModule;");

const names = [...src.matchAll(/^module\.exports\.([A-Za-z0-9_]+) = /gm)].map((m) => m[1]);
const out = `import __wasmModule from "./core_bg.wasm";
const module = { exports: {} };
let imports = {};
imports["__wbindgen_placeholder__"] = module.exports;
${body.replace(/^let imports = \{\};\s*\nimports\['__wbindgen_placeholder__'\] = module\.exports;/m, "")}
export const { ${[...new Set(names)].filter((n) => !n.startsWith("__wbg") && !n.startsWith("__wbindgen")).join(", ")} } = module.exports;
`;
const outDir = new URL("./", import.meta.url).pathname;
writeFileSync(join(outDir, "core.mjs"), out);
copyFileSync(join(dirname(corePath), "core_bg.wasm"), join(outDir, "core_bg.wasm"));
console.log("shim written:", names.length, "exports");

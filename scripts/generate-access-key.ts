/**
 * Generate a gateway access key.
 *
 *   npm run gen-key -- --label claude-code-laptop --servers pm_tool,ledger --read-only --expires 2027-06-01
 *
 * Prints the key ONCE and the JSON to paste into the `access_keys` section of a vault's _policy.
 * Nothing is written to disk. Store the key in your own password manager; it cannot be recovered.
 */
import { generateAccessKey } from "../src/auth/access-keys";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const label = arg("label") ?? "access-key";
const servers = (arg("servers") ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const readOnly = process.argv.includes("--read-only");
const expires = arg("expires");

if (servers.length === 0) {
  console.error("Pass --servers name1,name2 (or --servers '*'). Keys should be scoped to what they need.");
  process.exit(1);
}
if (expires && Number.isNaN(Date.parse(expires))) {
  console.error("--expires must be a date, e.g. 2027-06-01");
  process.exit(1);
}

const { key, keyId, sha256 } = await generateAccessKey();
const entry: Record<string, unknown> = { label, sha256, servers, read_only: readOnly };
if (expires) entry.expires_at = new Date(expires).toISOString();

console.log("\nAccess key (shown once, copy it now):\n");
console.log(`  ${key}\n`);
console.log('Add this under "access_keys" in the vault\'s _policy item:\n');
console.log(JSON.stringify({ [keyId]: entry }, null, 2));
console.log("\nUse it as:  Authorization: Bearer <key>\n");

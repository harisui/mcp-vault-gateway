// Phase 0 spike: can @1password/sdk run on the Workers runtime?
// GET /run exercises create client, list vaults, list items, read a field, write a field,
// and reports timings. No secret values are ever returned or logged.

interface Env {
  OP_TOKEN_TEST?: string;
  /** Title of a throwaway item the spike may write to. Created if missing. */
  OP_SPIKE_ITEM_TITLE?: string;
}

type Step = { step: string; ok: boolean; ms: number; detail?: unknown; error?: string };

const isolateStart = Date.now();
let warm = false;

async function timed<T>(steps: Step[], step: string, fn: () => Promise<T>, detail?: (v: T) => unknown): Promise<T | undefined> {
  const t0 = performance.now();
  try {
    const v = await fn();
    steps.push({ step, ok: true, ms: Math.round(performance.now() - t0), detail: detail?.(v) });
    return v;
  } catch (e) {
    const err = e as Error;
    steps.push({ step, ok: false, ms: Math.round(performance.now() - t0), error: `${err?.name ?? "Error"}: ${err?.message ?? String(e)}` });
    return undefined;
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname !== "/run") return new Response("GET /run", { status: 404 });

    const coldStart = !warm;
    warm = true;
    const steps: Step[] = [];

    const sdk = await timed(steps, "import_sdk_and_instantiate_wasm", () => import("@1password/sdk"));
    if (!sdk) return Response.json({ coldStart, steps }, { status: 500 });
    if (!env.OP_TOKEN_TEST) {
      steps.push({ step: "token", ok: false, ms: 0, error: "OP_TOKEN_TEST not set in .dev.vars" });
      return Response.json({ coldStart, steps }, { status: 500 });
    }

    const client = await timed(steps, "create_client", () =>
      sdk.createClient({ auth: env.OP_TOKEN_TEST!, integrationName: "mcp-vault-gateway-spike", integrationVersion: "0.0.1" }),
    );
    if (!client) return Response.json({ coldStart, steps }, { status: 500 });

    const vaults = await timed(steps, "list_vaults", () => client.vaults.list(), (v) => ({ count: v.length }));
    const vault = vaults?.[0];
    if (!vault) return Response.json({ coldStart, steps }, { status: 500 });

    const items = await timed(steps, "list_items", () => client.items.list(vault.id), (v) => ({ count: v.length }));
    const title = env.OP_SPIKE_ITEM_TITLE ?? "op-sdk-spike";
    let target: { id: string } | undefined = items?.find((i) => i.title === title);

    if (!target) {
      const created = await timed(steps, "create_spike_item", () =>
        client.items.create({
          vaultId: vault.id,
          title,
          category: sdk.ItemCategory.SecureNote,
          fields: [{ id: "spike_written_at", title: "spike_written_at", fieldType: sdk.ItemFieldType.Text, value: "init" }],
        }),
      );
      if (created) target = { id: created.id };
    }
    // Read-only tokens cannot create the spike item; fall back to any existing item so the
    // read and warm-latency steps still run.
    if (!target && items?.length) target = items[0];
    if (!target) {
      await timed(steps, "list_vaults_warm", () => client.vaults.list());
      return Response.json({ coldStart, isolateAgeMs: Date.now() - isolateStart, steps });
    }

    const item = await timed(steps, "get_item", () => client.items.get(vault.id, target!.id), (v) => ({ fields: v.fields.length, version: v.version }));
    await timed(steps, "read_one_field", async () => {
      const f = item?.fields.find((x) => x.id === "spike_written_at") ?? item?.fields[0];
      if (!f) throw new Error("item has no fields");
      return f.value.length;
    }, (len) => ({ valueLength: len }));

    if (item && item.title === title) {
      const stamp = new Date().toISOString();
      const fields = item.fields.some((f) => f.id === "spike_written_at")
        ? item.fields.map((f) => (f.id === "spike_written_at" ? { ...f, value: stamp } : f))
        : [...item.fields, { id: "spike_written_at", title: "spike_written_at", fieldType: sdk.ItemFieldType.Text, value: stamp }];
      await timed(steps, "write_one_field", () => client.items.put({ ...item, fields }), (v) => ({ version: v.version }));
    }

    // Second round on the same client to measure warm per-call latency.
    await timed(steps, "list_vaults_warm", () => client.vaults.list());
    await timed(steps, "get_item_warm", () => client.items.get(vault.id, target!.id));

    return Response.json({ coldStart, isolateAgeMs: Date.now() - isolateStart, steps });
  },
};

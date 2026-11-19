import type { FieldWrite, ItemOverviewInfo, OpClient, VaultInfo } from "../src/onepassword/client";
import { OpError } from "../src/onepassword/client";
import type { RawItem } from "../src/registry/types";

/** In-memory 1Password vault. Counts calls so tests can assert on the budget. */
export class FakeOp implements OpClient {
  calls: string[] = [];
  failWith: Error | undefined;
  vault: VaultInfo = { id: "vault1", title: "MCP Test", contentVersion: 1 };
  items: RawItem[] = [];

  constructor(items: RawItem[] = []) {
    this.items = items.map((i) => ({ ...i, vaultId: this.vault.id }));
  }

  private record(op: string) {
    this.calls.push(op);
    if (this.failWith) throw this.failWith;
  }

  /** Simulate an edit in 1Password: bumps item and vault versions. */
  edit(itemId: string, label: string, value: string) {
    const item = this.items.find((i) => i.id === itemId)!;
    const f = item.fields.find((x) => x.title === label);
    if (f) f.value = value;
    else item.fields.push({ id: label, title: label, type: "text", value });
    item.version++;
    item.updatedAt = new Date(Date.parse(item.updatedAt) + 1000).toISOString();
    this.vault.contentVersion = (this.vault.contentVersion ?? 0) + 1;
  }

  add(item: RawItem) {
    this.items.push({ ...item, vaultId: this.vault.id });
    this.vault.contentVersion = (this.vault.contentVersion ?? 0) + 1;
  }

  async listVaults(): Promise<VaultInfo[]> {
    this.record("listVaults");
    return [{ ...this.vault }];
  }

  async listItems(vaultId: string): Promise<ItemOverviewInfo[]> {
    this.record(`listItems:${vaultId}`);
    return this.items.map((i) => ({ id: i.id, title: i.title, tags: i.tags, updatedAt: i.updatedAt }));
  }

  async getItems(_vaultId: string, ids: string[]): Promise<RawItem[]> {
    this.record(`getItems:${ids.join(",")}`);
    return this.items.filter((i) => ids.includes(i.id)).map((i) => structuredClone(i));
  }

  async writeFields(_vaultId: string, itemId: string, fields: Record<string, FieldWrite>): Promise<RawItem> {
    this.record(`writeFields:${itemId}`);
    const item = this.items.find((i) => i.id === itemId);
    if (!item) throw new OpError("not found", "not_found");
    for (const [label, w] of Object.entries(fields)) this.edit(itemId, label, w.value);
    return structuredClone(item);
  }
}

import type { RawItem } from "../registry/types";

export interface VaultInfo {
  id: string;
  title: string;
  /** Changes whenever any item in the vault changes. Lets a reload skip listing items. */
  contentVersion?: number;
}

export interface ItemOverviewInfo {
  id: string;
  title: string;
  tags: string[];
  updatedAt: string;
}

export interface FieldWrite {
  value: string;
  concealed: boolean;
}

/**
 * What the gateway needs from 1Password. The real implementation wraps @1password/sdk;
 * tests use an in-memory fake. Every method is one or more budgeted 1Password calls.
 */
export interface OpClient {
  listVaults(): Promise<VaultInfo[]>;
  listItems(vaultId: string): Promise<ItemOverviewInfo[]>;
  getItems(vaultId: string, itemIds: string[]): Promise<RawItem[]>;
  /** Set (or add) fields by label on one item. Returns the updated item. */
  writeFields(vaultId: string, itemId: string, fields: Record<string, FieldWrite>): Promise<RawItem>;
}

export class OpError extends Error {
  override name = "OpError";
  constructor(
    message: string,
    readonly kind: "rate_limited" | "budget_exceeded" | "auth" | "not_found" | "other",
  ) {
    super(message);
  }
}

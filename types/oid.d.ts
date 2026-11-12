// Object identifiers: encoding, the name table, comparison.

import type { DerNode } from './types.js';

/** The name table: OID-table name -> dotted OID. */
export const DOTTED: Readonly<Record<string, string>>;

/** The OID's content bytes for a table name; an unknown name is refused. */
export function by_name(name: string): Uint8Array;

/** The table's name for these content bytes, or null. */
export function name_of(bytes: Uint8Array): string | null;

/** The table's one canonical name for a name or alias. */
export function canonical_name(name: string): string;

/** Content bytes -> dotted text ('1.2.840.113549'). */
export function to_string(bytes: Uint8Array): string;

/** Dotted text -> content bytes. */
export function from_string(text: string): Uint8Array;

/** The complete DER of the OID a table name stands for. */
export function encode(name: string): DerNode;

/** 'name (dotted)' when the table has a name, otherwise the dotted form. */
export function describe(bytes: Uint8Array): string;

/** Byte equality of two OIDs. */
export function equal(a: Uint8Array, b: Uint8Array): boolean;

/**
 * The key in `table` whose dotted value is this OID, or null. A table maps
 * names to dotted strings: `{ data: '1.2.840.113549.1.7.1' }`.
 */
export function name_in_table(bytes: Uint8Array, table: Readonly<Record<string, string>>): string | null;

/** The output size in bytes of a hash, by OID-table name; null if unknown. */
export function digest_size(name: string): number | null;

/** digest_size, refusing an unknown hash through `fail(code, detail)`. */
export function checked_digest_size(name: string, fail: (code: string, detail: string) => never): number;

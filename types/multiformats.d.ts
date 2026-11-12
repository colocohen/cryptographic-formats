// Multihash, multibase, unsigned varints and CIDs (the multiformats specs).

import type { BytesInput } from './types.js';

export interface Multihash {
  code: number;
  /** The table's name ('sha2-256'), or 'code-<n>' when unknown. */
  name: string;
  known: boolean;
  /** The declared digest length. */
  length: number;
  /** True when the digest is shorter than the hash's full output. */
  truncated: boolean;
  digest: Uint8Array;
  hex: string;
  /** The whole multihash. */
  bytes: Uint8Array;
}

export type Cid =
  | { version: 0; base: string; multihash: Multihash }
  | { version: 1; base: string; codec: number; multihash: Multihash };

export const CODES: Readonly<Record<number, { name: string; size: number | null }>>;
export const BASES: Readonly<Record<string, { name: string; base: string | null; upper?: boolean }>>;

export function decode(input: BytesInput): Multihash;
/** A multihash for a digest the caller computed, by the table's name. */
export function encode(name: string, digest: BytesInput): Uint8Array;
/** Whether a digest the caller computed is the one the multihash holds. */
export function digest_matches(mh: Multihash, computed: BytesInput): boolean;

/** Multibase: the prefix character names the base. */
export function base_decode(text: string): { base: string; bytes: Uint8Array };
export function base_encode(base: string, input: BytesInput): string;

export function cid_decode(text: string): Cid;
export function is_cid_v0(text: string): boolean;

export function read_varint(bytes: Uint8Array, at: number): { value: number; end: number };
export function write_varint(n: number): number[];

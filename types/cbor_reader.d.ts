// CBOR (RFC 8949), read under the deterministic rules of 4.2.1: shortest
// arguments, definite lengths, sorted and unique map keys.

import type { BytesInput } from './types.js';

/**
 * A decoded value. Maps come back as arrays of [key, value] pairs, in their
 * (sorted) order - CBOR keys need not be strings. Tags are { tag, value };
 * simple values without a JavaScript equivalent are { simple }.
 */
export type CborValue =
  | number
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | CborValue[]
  | Array<[CborValue, CborValue]>
  | { tag: number; value: CborValue }
  | { simple: number };

/** Major types. */
export const UNSIGNED: 0;
export const NEGATIVE: 1;
export const BYTES: 2;
export const TEXT: 3;
export const ARRAY: 4;
export const MAP: 5;
export const TAG: 6;
export const SIMPLE: 7;

export class Reader {
  constructor(buf: Uint8Array, pos: number, end: number);
  buf: Uint8Array;
  pos: number;
  end: number;

  remaining(): number;
  /** The next item's major type, or null at the end. */
  peek_type(): number | null;
  read_unsigned(): number;
  read_negative(): number;
  read_int(): number;
  read_bytes(): Uint8Array;
  read_text(): string;
  /** The item count; the items follow. */
  read_array_header(): number;
  /** The pair count; the pairs follow. */
  read_map_header(): number;
  /** The tag number; the tagged item follows. */
  read_tag(): number;
  read_bool(): boolean;
  read_value(depth?: number): CborValue;
  read_map(depth?: number): Array<[CborValue, CborValue]>;
  /** The complete encoding of the next item, consumed. */
  capture(): Uint8Array;
}

export function reader(input: BytesInput): Reader;
/** Runs `fn` over a Reader and refuses trailing bytes. */
export function read<T>(input: BytesInput, fn: (r: Reader) => T): T;
/** One complete item. */
export function decode(input: BytesInput): CborValue;

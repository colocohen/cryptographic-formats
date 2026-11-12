// CBOR (RFC 8949), written in the deterministic form of 4.2.1. Each function
// returns one encoded item as plain byte values; to_bytes converts.

import type { BytesInput } from './types.js';

/** An encoded item. */
export type CborNode = number[];

/**
 * What encode() takes. A map is `{ pairs: [[key, value], ...] }` - written
 * sorted - because CBOR keys are not only strings.
 */
export type CborInput =
  | number
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | CborInput[]
  | { pairs: Array<[CborInput, CborInput]> };

export function encode(v: CborInput): Uint8Array;
export function encode_value(v: CborInput, depth?: number): CborNode;
export function to_bytes(node: CborNode | BytesInput): Uint8Array;

/** The initial byte and argument for a major type. */
export function head(major: number, value: number): CborNode;
export function unsigned(n: number): CborNode;
export function negative(n: number): CborNode;
/** An integer, either sign. */
export function int(n: number): CborNode;
/** The shortest of half, single and double that holds the value exactly. */
export function float(value: number): CborNode;
export function bytes(value: Uint8Array | readonly number[]): CborNode;
export function text(value: string): CborNode;
export function array(members: CborNode[]): CborNode;
/** Pairs of encoded items, sorted by encoded key; duplicates refused. */
export function map(pairs: Array<[CborNode, CborNode]>): CborNode;
export function tag(number: number, encoded_value: CborNode): CborNode;
export function simple(value: number): CborNode;
export function bool(value: boolean): CborNode;
declare function null_(): CborNode;
declare function undefined_(): CborNode;
export { null_ as null, undefined_ as undefined };

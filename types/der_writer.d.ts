// Level 0: the DER writer. Each function returns the complete encoding of
// one value as a DerNode (plain byte values); to_bytes makes the Uint8Array
// once, at the end.

import type { DerNode, BytesInput } from './types.js';

/** Content a writer takes: a DerNode, or bytes. */
export type Content = DerNode | Uint8Array;

/** A time's components, as the readers return them. */
export interface TimeParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  /** GeneralizedTime only: fractional seconds as digits, no trailing zero. */
  fraction?: string | null;
}

export type When = Date | TimeParts;

export function to_bytes(node: DerNode | BytesInput): Uint8Array;
export function concat(parts: Content[]): DerNode;
/** One TLV with this identifier octet. */
export function tlv(tag: number, content: Content): DerNode;
export function encode_length(n: number): DerNode;
/** An OID arc in base-128. */
export function base128(n: number): DerNode;

/** Two's complement content, which must already be minimal. */
export function integer(content: Content): DerNode;
/** A magnitude, written as a non-negative INTEGER (a 00 added if needed). */
export function unsigned(magnitude: Content): DerNode;
export function enumerated(content: Content): DerNode;
declare function boolean_(value: boolean): DerNode;
declare function null_(): DerNode;
export { boolean_ as boolean, null_ as null };
export function real(value: number): DerNode;
export function octet_string(content: Content): DerNode;
export function bit_string(content: Content, unused?: number): DerNode;
/** From the OID's content bytes - see oid.by_name / oid.from_string. */
export function oid(encoding: Content): DerNode;
export function relative_oid(arcs: string | Array<number | string>): DerNode;
export function object_descriptor(text: string): DerNode;

export function utf8_string(text: string): DerNode;
export function printable_string(text: string): DerNode;
export function ia5_string(text: string): DerNode;
export function bmp_string(text: string): DerNode;
export function visible_string(text: string): DerNode;
export function numeric_string(text: string): DerNode;
export function t61_string(text: string): DerNode;
export function videotex_string(text: string): DerNode;
export function graphic_string(text: string): DerNode;
export function general_string(text: string): DerNode;
export function universal_string(text: string): DerNode;

export function utc_time(when: When): DerNode;
export function generalized_time(when: When, options?: { millis?: boolean }): DerNode;
/** RFC 5280's rule: UTCTime before 2050, GeneralizedTime from 2050. */
export function time(when: When): DerNode;
export function time_string(text: string): DerNode;
export function date(text: string): DerNode;

export function external(parts: {
  direct?: Content | null;
  indirect?: Content | null;
  descriptor?: string | null;
  encoding: 'single-ASN1-type' | 'octet-aligned' | 'arbitrary';
  value: Content;
}): DerNode;
export function embedded_pdv(identification: Content, value: Content): DerNode;
export function character_string(identification: Content, value: Content): DerNode;

export function sequence(parts: Content[]): DerNode;
/** A SET in the order given. */
export function set(parts: Content[]): DerNode;
/** A SET OF, sorted as DER requires. */
export function set_of(members: Content[]): DerNode;
export function explicit(n: number, content: Content): DerNode;
/** [n] IMPLICIT over a complete encoding: its tag is replaced. */
export function implicit(n: number, encoded: Content): DerNode;
export function application(n: number, content: Content, constructed?: boolean): DerNode;
declare function private_(n: number, content: Content, constructed?: boolean): DerNode;
export { private_ as private };

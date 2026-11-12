// Level 0: the field-table engine. A structure is declared as data -
// define('AlgorithmIdentifier', [{ name: 'algorithm', type: 'oid' }, ...]) -
// and read by name. What a read returns depends on the definitions, so its
// results are typed loosely: an object of the declared field names.

import type { Reader } from './der_reader.js';

/** One field of a SEQUENCE. */
export interface FieldSpec {
  name: string;
  /**
   * A builtin ('integer', 'oid', 'octet_string', 'bit_string', 'time',
   * 'any', 'raw', the string types...) or a defined type's name.
   */
  type: string;
  optional?: boolean;
  /** DEFAULT: an encoding equal to it is refused, as DER requires. */
  def?: unknown;
  /** The context tag's identifier octet, e.g. 0xA0. */
  tag?: number;
  mode?: 'explicit' | 'implicit';
  /** ANY DEFINED BY: the field holding the OID, and the table (defined_by). */
  defined?: string;
  table?: Record<string, string>;
  /** SIZE (min..max). */
  size?: number | [number, number];
  strict?: boolean;
  [other: string]: unknown;
}

/** A definition: a field list (SEQUENCE), or SEQUENCE OF / SET OF / CHOICE. */
export type Definition =
  | FieldSpec[]
  | { kind: 'sequence'; fields: FieldSpec[]; extensible?: boolean; options?: DefineOptions }
  | { kind: 'sequence_of' | 'set_of'; of: string; min?: number; unique?: boolean }
  | { kind: 'choice'; arms: FieldSpec[] }
  | { kind: string; [k: string]: unknown };

export interface DefineOptions {
  /** The `...` marker: fields beyond those declared are captured, not refused. */
  extensible?: boolean;
  /** AUTOMATIC TAGS. */
  automatic?: boolean;
}

/** What a read returns: the declared fields by name. */
export type Fields = Record<string, any>;

/** Registers a type; a second definition of a name is refused. Returns the name. */
export function define(name: string, definition: Definition, options?: DefineOptions): string;
export function defined(name: string): boolean;
export function definition_of(name: string): Exclude<Definition, FieldSpec[]>;
/** Clears every definition - for tests. */
export function reset(): void;

/** Reads a named type at the cursor. */
export function read_type(r: Reader, name: string): any;
/** Reads a SEQUENCE type's fields from a cursor already inside it. */
export function read_type_from(reader: Reader, name: string): Fields;
export function read_fields(r: Reader, fields: FieldSpec[], context?: unknown, name?: string): Fields;
/** The complete DER of the next value, consumed. */
export function capture(r: Reader): Uint8Array;

/**
 * An ANY DEFINED BY table keyed by OID - from names:
 * defined_by({ ecPublicKey: 'NamedCurve' }, oid).
 */
export function defined_by(mapping: Record<string, string>, oid_module: { by_name(name: string): Uint8Array }): Record<string, string>;

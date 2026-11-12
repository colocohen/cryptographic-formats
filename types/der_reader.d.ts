// Level 0: the strict DER cursor. Every structure this library reads is read
// with it, and it is exported for the ones it does not.

import type { BytesInput, Time } from './types.js';

/** A primitive value read under an implicit tag. */
export interface TaggedBytes {
  bytes: Uint8Array;
  /** The offset of its tag. */
  start: number;
}

export interface BitString {
  /** The content after the unused-bits octet. */
  bytes: Uint8Array;
  unused: number;
}

export interface AnyString {
  type: 'utf8' | 'printable' | 'ia5' | 'bmp' | 't61' | 'visible' | 'numeric' |
        'universal' | 'graphic' | 'general' | 'videotex';
  value: string;
}

export interface HighTag<R = Reader> {
  class_: number;
  number: number;
  constructed: boolean;
  /** For a constructed value. */
  content?: R;
  /** For a primitive one. */
  bytes?: Uint8Array;
}

export interface External {
  direct?: Uint8Array;
  indirect?: Uint8Array;
  descriptor?: string;
  encoding: 'single-ASN1-type' | 'octet-aligned' | 'arbitrary';
  value: Uint8Array;
}

export interface Presentation {
  /** The identification CHOICE's complete DER. */
  identification: Uint8Array;
  value: Uint8Array;
}

/**
 * A cursor over DER. Each read_* consumes one value; a constructed one
 * returns a Reader over its contents, which must itself be read to the end
 * (expect_end) - nothing is skipped silently.
 */
export class Reader {
  constructor(buf: Uint8Array, pos: number, end: number);
  buf: Uint8Array;
  pos: number;
  end: number;

  remaining(): number;
  /** The next identifier octet, or null at the end. */
  peek_tag(): number | null;
  /** Refuses anything left over. */
  expect_end(): void;
  /** The complete DER of the next value, consumed. */
  capture(): Uint8Array;
  /** The content of the next value, which must be [n], consumed. */
  capture_tagged(n: number): Uint8Array;

  read_sequence(): Reader;
  read_set(): Reader;
  /** A SET OF, with DER's sort order checked. */
  read_set_of(): Reader;
  read_explicit(n: number): Reader;
  /**
   * [n] IMPLICIT, where `base_tag` is the type it replaces: a Reader when
   * that type is constructed, the content bytes when it is primitive.
   */
  read_implicit(n: number, base_tag: 48 | 49): Reader;
  read_implicit(n: number, base_tag: number): Reader | TaggedBytes;
  read_application(n: number, constructed: true): Reader;
  read_application(n: number, constructed?: false): Uint8Array;
  read_private(n: number, constructed: true): Reader;
  read_private(n: number, constructed?: false): Uint8Array;
  read_high_tag(): HighTag;
  is_high_tag(): boolean;

  /** Two's complement content bytes, minimal. */
  read_integer(): Uint8Array;
  /** A non-negative INTEGER's magnitude, without the sign octet. */
  read_unsigned(): Uint8Array;
  read_enumerated(): Uint8Array;
  read_boolean(): boolean;
  read_null(): null;
  read_octet_string(): Uint8Array;
  read_bit_string(): BitString;
  /** The OID's content bytes; see oid.to_string and oid.name_of. */
  read_oid(): Uint8Array;
  read_relative_oid(): Uint8Array;
  read_real(): number;

  read_utf8_string(): string;
  read_printable_string(): string;
  read_ia5_string(): string;
  read_bmp_string(): string;
  read_t61_string(): string;
  read_visible_string(): string;
  read_numeric_string(): string;
  read_universal_string(): string;
  read_graphic_string(): string;
  read_general_string(): string;
  read_videotex_string(): string;
  read_object_descriptor(): string;
  /** Whichever string type comes next, and which it was. */
  read_any_string(): AnyString;

  read_utc_time(): Time;
  read_generalized_time(): Time;
  /** X.509's Time CHOICE: UTCTime or GeneralizedTime. */
  read_time(): Time;
  read_time_string(): string;
  read_date(): string;

  read_external(): External;
  read_embedded_pdv(): Presentation;
  read_character_string(): Presentation;
}

/** A Reader over the whole input. */
export function reader(input: BytesInput): Reader;

/** Runs `fn` over a Reader and refuses trailing bytes after it returns. */
export function read<T>(input: BytesInput, fn: (r: Reader) => T): T;

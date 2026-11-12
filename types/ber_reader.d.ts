// Level 0: the BER cursor - indefinite lengths and constructed strings. Only
// pkcs12.js uses it, for what Windows writes; it is exported for callers
// with other BER.

import type { BytesInput, Time } from './types.js';
import type { BitString, AnyString, HighTag, External, Presentation } from './der_reader.js';

export class Reader {
  constructor(buf: Uint8Array, pos: number, end: number);
  buf: Uint8Array;
  pos: number;
  end: number;

  remaining(): number;
  peek_tag(): number | null;
  /** Whether the cursor is at an end-of-contents marker. */
  at_eoc(): boolean;
  expect_end(): void;
  capture(): Uint8Array;

  read_sequence(): Reader;
  read_set(): Reader;
  read_set_of(): Reader;
  read_explicit(n: number): Reader;
  read_implicit(n: number, base_tag: 48 | 49): Reader;
  read_implicit(n: number, base_tag: number): Reader | { bytes: Uint8Array };
  read_application(n: number, constructed: true): Reader;
  read_application(n: number, constructed?: false): Uint8Array;
  read_private(n: number, constructed: true): Reader;
  read_private(n: number, constructed?: false): Uint8Array;
  read_high_tag(): HighTag<Reader>;
  is_high_tag(): boolean;

  read_integer(): Uint8Array;
  read_unsigned(): Uint8Array;
  read_enumerated(): Uint8Array;
  read_boolean(): boolean;
  read_null(): null;
  /** Primitive or constructed, concatenated. */
  read_octet_string(): Uint8Array;
  read_bit_string(): BitString;
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
  read_any_string(): AnyString;

  read_utc_time(): Time;
  read_generalized_time(): Time;
  read_time(): Time;
  read_time_string(): string;
  read_date(): string;

  read_external(): External;
  read_embedded_pdv(): Presentation;
  read_character_string(): Presentation;
}

export function reader(input: BytesInput): Reader;
export function read<T>(input: BytesInput, fn: (r: Reader) => T): T;

/** Whether the input uses anything DER forbids (an indefinite length...). */
export function is_ber(input: BytesInput): boolean;

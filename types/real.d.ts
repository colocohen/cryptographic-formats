// ASN.1 REAL (X.690 8.5).

/** The special-value content octets. */
export const PLUS_INFINITY: 64;
export const MINUS_INFINITY: 65;
export const NOT_A_NUMBER: 66;
export const MINUS_ZERO: 67;

/** Decodes REAL content octets. `pos` is for error offsets; `strict` is DER. */
export function decode(bytes: Uint8Array, pos: number, strict: boolean): number;

/** Encodes a number as REAL content octets, in DER's canonical form. */
export function encode(value: number): number[];

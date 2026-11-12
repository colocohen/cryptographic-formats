// ASN.1 universal tag numbers and the identifier-octet masks.

export const BOOLEAN: 1;
export const INTEGER: 2;
export const BIT_STRING: 3;
export const OCTET_STRING: 4;
export const NULL: 5;
export const OID: 6;
export const OBJECT_DESCRIPTOR: 7;
export const EXTERNAL: 8;
export const REAL: 9;
export const ENUMERATED: 10;
export const EMBEDDED_PDV: 11;
export const UTF8_STRING: 12;
export const RELATIVE_OID: 13;
export const TIME: 14;
export const NUMERIC_STRING: 18;
export const PRINTABLE_STRING: 19;
export const T61_STRING: 20;
export const VIDEOTEX_STRING: 21;
export const IA5_STRING: 22;
export const UTC_TIME: 23;
export const GENERALIZED_TIME: 24;
export const GRAPHIC_STRING: 25;
export const VISIBLE_STRING: 26;
export const GENERAL_STRING: 27;
export const UNIVERSAL_STRING: 28;
export const CHARACTER_STRING: 29;
export const BMP_STRING: 30;
export const DATE_NUMBER: 31;
export const SEQUENCE: 48;
export const SET: 49;

export const CLASS_UNIVERSAL: 0;
export const CLASS_APPLICATION: 64;
export const CLASS_CONTEXT: 128;
export const CLASS_PRIVATE: 192;
export const CLASS_MASK: 192;
export const CONSTRUCTED: 32;
export const NUMBER_MASK: 31;
export const HIGH_TAG_NUMBER: 31;
export const LENGTH_LONG_FORM: 128;
export const LENGTH_INDEFINITE: 128;
export const LENGTH_RESERVED: 255;

/** A readable name for an identifier octet: 'SEQUENCE', '[0] constructed'... */
export function name_of(tag: number): string;

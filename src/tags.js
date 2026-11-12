// The ONLY module the DER reader and the DER writer are permitted to share.
//
// An encoder verified only against its own decoder can be wrong in both
// directions and look correct - cryptographic-primitives's sig_to_der wrote a short-form
// length of 135 for P-521 and it went unnoticed for exactly as long as the
// matching parser was equally wrong. Shared logic reproduces that failure by
// construction: one bug in a shared length helper appears in both directions
// and cancels itself out on a round trip.
//
// Constants cannot cancel out. Logic can. So this file holds constants only,
// and nothing here computes anything.

// Universal class tags, primitive form.
var BOOLEAN           = 0x01;
var INTEGER           = 0x02;
var BIT_STRING        = 0x03;
var OCTET_STRING      = 0x04;
var NULL              = 0x05;
var ENUMERATED        = 0x0A;
var REAL              = 0x09;
var RELATIVE_OID      = 0x0D;
var OBJECT_DESCRIPTOR = 0x07;
var EXTERNAL          = 0x08;
var EMBEDDED_PDV      = 0x0B;
var CHARACTER_STRING  = 0x1D;
// X.680 (2015) additions. Rare, and part of the language.
var TIME              = 0x0E;
// ⚠ X.680 assigns DATE the tag NUMBER 31, and 31 is exactly the escape value
// X.690 8.1.2.4.1 reserves for the multi-octet form - bits 5 to 1 all ones.
//
// So a DATE cannot be encoded as the single byte 0x1F: that byte SAYS "the
// number follows". The real encoding is 1F 1F, and treating 0x1F as the tag
// produced a value this library's own reader refused as a high tag number.
//
// Found by the X.690 conformance sweep, and by nothing else - a case-by-case
// test would have had to know to look.
var DATE_NUMBER       = 31;
var OID               = 0x06;
var NUMERIC_STRING    = 0x12;
var UTF8_STRING       = 0x0C;
var PRINTABLE_STRING  = 0x13;
var IA5_STRING        = 0x16;
var VISIBLE_STRING    = 0x1A;
// T61String, also called TeletexString. Deprecated by RFC 5280 for new
// certificates and still present in plenty of old ones, where a name that
// cannot be read compares unequal to itself.
var T61_STRING        = 0x14;
// BMPString: UTF-16BE. PKCS#12 uses it for friendlyName, so a container
// reader without it cannot report what a key is called.
var BMP_STRING        = 0x1E;
var UNIVERSAL_STRING  = 0x1C;
// The three remaining string types RFC 5280 permits in a DirectoryString or
// a GeneralName. All deprecated, all present in certificates issued before
// they were - and a name that cannot be read compares unequal to itself.
var GRAPHIC_STRING    = 0x19;
var GENERAL_STRING    = 0x1B;
var VIDEOTEX_STRING   = 0x15;
var UTC_TIME          = 0x17;
var GENERALIZED_TIME  = 0x18;

// Universal class tags that are always constructed. The 0x20 bit is set.
var SEQUENCE          = 0x30;
var SET               = 0x31;

// Bit masks over the identifier octet.
var CLASS_MASK        = 0xC0;   // bits 8-7: which tag class
var CONSTRUCTED       = 0x20;   // bit 6:    constructed rather than primitive
var NUMBER_MASK       = 0x1F;   // bits 5-1: the tag number

var CLASS_UNIVERSAL   = 0x00;
var CLASS_APPLICATION = 0x40;
var CLASS_CONTEXT     = 0x80;
var CLASS_PRIVATE     = 0xC0;

// A tag number of 31 means the number continues into following octets.
// DER permits this; nothing in this library's scope uses it, and accepting a
// form we never emit widens the input surface for no gain. The reader
// refuses it by name rather than failing obscurely.
var HIGH_TAG_NUMBER   = 0x1F;

// Length octet sentinels.
var LENGTH_INDEFINITE = 0x80;   // BER only - DER requires a definite length
var LENGTH_RESERVED   = 0xFF;   // reserved by X.690, never valid
var LENGTH_LONG_FORM  = 0x80;   // bit 8 of the first length octet

// Names for error messages. Keeping the table beside the constants means a
// new tag cannot be added without a name.
var NAMES = {
  0x01: 'BOOLEAN',
  0x02: 'INTEGER',
  0x03: 'BIT STRING',
  0x04: 'OCTET STRING',
  0x05: 'NULL',
  0x07: 'ObjectDescriptor',
  0x08: 'EXTERNAL',
  0x09: 'REAL',
  0x0A: 'ENUMERATED',
  0x0B: 'EMBEDDED PDV',
  0x0D: 'RELATIVE-OID',
  0x0E: 'TIME',
  0x1D: 'CHARACTER STRING',

  0x06: 'OBJECT IDENTIFIER',
  0x0C: 'UTF8String',
  0x13: 'PrintableString',
  0x12: 'NumericString',
  0x14: 'T61String',
  0x16: 'IA5String',
  0x1A: 'VisibleString',
  0x15: 'VideotexString',
  0x19: 'GraphicString',
  0x1B: 'GeneralString',
  0x1C: 'UniversalString',
  0x1E: 'BMPString',
  0x17: 'UTCTime',
  0x18: 'GeneralizedTime',
  0x30: 'SEQUENCE',
  0x31: 'SET'
};

function name_of(tag) {
  if (NAMES[tag]) {
    return NAMES[tag] + ' (0x' + pad_hex(tag) + ')';
  }
  if ((tag & CLASS_MASK) === CLASS_CONTEXT) {
    return '[' + (tag & NUMBER_MASK) + '] (0x' + pad_hex(tag) + ')';
  }
  return '0x' + pad_hex(tag);
}

function pad_hex(b) {
  // ⚠ A TAG PAST THE END OF THE INPUT IS A TRUNCATION, NOT A CRASH.
  //
  // name_of is called from _read_tag while building an error message, so an
  // undefined byte here turned "the input ended" into a TypeError from deep
  // inside the tag table - a native error where the library's whole point is
  // that malformed input produces a FormatError.
  //
  // Found by a caller passing a reader whose cursor was past the end.
  if (b === undefined || b === null) {
    return '(end of input)';
  }

  var s = b.toString(16);
  return s.length === 1 ? '0' + s : s;
}

export {
  BOOLEAN,
  INTEGER,
  BIT_STRING,
  OCTET_STRING,
  NULL,
  ENUMERATED,
  REAL,
  RELATIVE_OID,
  OBJECT_DESCRIPTOR,
  EXTERNAL,
  EMBEDDED_PDV,
  CHARACTER_STRING,
  TIME,
  DATE_NUMBER,
  OID,
  UTF8_STRING,
  PRINTABLE_STRING,
  IA5_STRING,
  NUMERIC_STRING,
  VISIBLE_STRING,
  T61_STRING,
  BMP_STRING,
  UNIVERSAL_STRING,
  GRAPHIC_STRING,
  GENERAL_STRING,
  VIDEOTEX_STRING,
  UTC_TIME,
  GENERALIZED_TIME,
  SEQUENCE,
  SET,
  CLASS_MASK,
  CONSTRUCTED,
  NUMBER_MASK,
  CLASS_UNIVERSAL,
  CLASS_APPLICATION,
  CLASS_CONTEXT,
  CLASS_PRIVATE,
  HIGH_TAG_NUMBER,
  LENGTH_INDEFINITE,
  LENGTH_RESERVED,
  LENGTH_LONG_FORM,
  name_of
};

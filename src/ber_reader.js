// A BER reader. SEPARATE FROM der_reader.js AND IT MUST STAY SEPARATE.
//
// ⚠ WHY THIS FILE EXISTS, AND WHY IT IS NOT A FLAG ON THE OTHER ONE
//
// PKCS#12 containers in the wild are not reliably DER. Windows CryptoAPI,
// Java keytool and older OpenSSL all write indefinite lengths and
// constructed OCTET STRINGs, and a DER-only parser simply cannot open those
// files.
//
// The obvious shape - a `{ strict: false }` option on der_reader - is the one
// thing DECISIONS 2.2 forbids, because a leniency flag ends up switched on in
// somebody's production. A separate file cannot be switched on by accident:
// reaching for BER means importing a module whose name says BER.
//
// ⚠ AND IT MUST NOT IMPORT der_reader, EITHER.
//
// Not because of the encoder/decoder trap - two readers cannot cancel out -
// but because sharing would run the other way: a relaxation added here for
// PKCS#12 would silently reach the DER reader through the shared helper, and
// the strictness that is this library's entire reason for existing would
// leak away one convenience at a time.
//
// So the tag and length handling is written again. test/structure.test.js
// asserts that neither file imports the other.
//
// ⚠ MEASURED, NOT ASSUMED: current OpenSSL writes DEFINITE-length DER for
// PKCS#12, and the strict reader handles those files end to end. This reader
// is for the producers that do not - which is why pkcs12.js tries DER first
// and reports which one succeeded.
//
// WHAT THIS ACCEPTS THAT DER DOES NOT
//
//   indefinite lengths          0x80, terminated by two zero octets
//   constructed OCTET STRING    the value split into segments
//   constructed BIT STRING      same
//   non-minimal lengths         0x81 0x05 where 0x05 would do
//   BOOLEAN other than 0xFF     any non-zero octet means true
//
// Every one of those is a second encoding of one value. That is the price of
// opening the file, and pkcs12.js reports `encoding: 'ber'` in its output so
// a caller knows what they read.

import * as T from './tags.js';
import { make_fail } from './commons/fail.js';
import { to_bytes } from './commons/bytes.js';
import { latin1, decode_utf8 } from './commons/decode_text.js';
import * as REAL from './real.js';
import { decode_t61 } from './commons/t61.js';

var fail = make_fail('ber');

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

function Reader(buf, pos, end) {
  this.buf = buf;
  this.pos = pos;
  this.end = end;
}

Reader.prototype.remaining = function () {
  return this.end - this.pos;
};

Reader.prototype.peek_tag = function () {
  if (this.pos >= this.end) {
    return null;
  }
  return this.buf[this.pos];
};

// True when the cursor is on an end-of-contents marker: the two zero octets
// that close an indefinite-length value.
Reader.prototype.at_eoc = function () {
  return this.pos + 1 < this.end &&
         this.buf[this.pos] === 0x00 &&
         this.buf[this.pos + 1] === 0x00;
};

// ---------------------------------------------------------------------------
// Identifier and length
// ---------------------------------------------------------------------------

Reader.prototype._read_tag = function (expected) {
  if (this.pos >= this.end) {
    fail(this.pos, 'truncated',
      'expected ' + T.name_of(expected) + ', input ended');
  }

  var tag = this.buf[this.pos];

  if ((tag & T.NUMBER_MASK) === T.HIGH_TAG_NUMBER) {
    fail(this.pos, 'high-tag-number',
      'multi-octet tag number is not supported');
  }

  // The one place this reader is deliberately loose about tags: a
  // constructed string carries the same tag number with the constructed bit
  // set, and accepting it is half the reason this file exists.
  //
  // ⚠ EVERY STRING TYPE, not three of them. X.690 8.21 permits the
  // constructed form for ALL the character string types plus OCTET STRING
  // and BIT STRING - the list here held OCTET STRING, BIT STRING and
  // UTF8String only, which was whatever PKCS#12 happened to need.
  //
  // Found by a sweep that handed the same constructed PrintableString to
  // both readers and expected BER to take it.
  var constructed_form = expected | T.CONSTRUCTED;
  var is_string =
    expected === T.OCTET_STRING ||
    expected === T.BIT_STRING ||
    expected === T.UTF8_STRING ||
    expected === T.NUMERIC_STRING ||
    expected === T.PRINTABLE_STRING ||
    expected === T.T61_STRING ||
    expected === T.VIDEOTEX_STRING ||
    expected === T.IA5_STRING ||
    expected === T.GRAPHIC_STRING ||
    expected === T.VISIBLE_STRING ||
    expected === T.GENERAL_STRING ||
    expected === T.UNIVERSAL_STRING ||
    expected === T.BMP_STRING ||
    expected === T.OBJECT_DESCRIPTOR ||
    // X.690 8.21 also permits it for the two time types, which arrive
    // constructed from at least one Windows encoder.
    expected === T.UTC_TIME ||
    expected === T.GENERALIZED_TIME;

  if (tag !== expected && !(is_string && tag === constructed_form)) {
    fail(this.pos, 'unexpected-tag',
      'expected ' + T.name_of(expected) + ', got ' + T.name_of(tag));
  }

  this.pos += 1;
  return tag;
};

// Returns the length, or -1 for indefinite. Written out rather than shared
// with der_reader - see the note at the top.
Reader.prototype._read_length = function () {
  var start = this.pos;

  if (this.pos >= this.end) {
    fail(start, 'truncated', 'length octet missing');
  }

  var first = this.buf[this.pos];
  this.pos += 1;

  if ((first & 0x80) === 0) {
    return this._bound(start, first);
  }

  // The whole point of this reader.
  if (first === 0x80) {
    return -1;
  }

  if (first === 0xFF) {
    fail(start, 'reserved-length', '0xFF is a reserved length octet');
  }

  var count = first & 0x7F;

  if (count > 4) {
    fail(start, 'length-too-large',
      'length of ' + count + ' octets is beyond what this reader accepts');
  }
  if (this.pos + count > this.end) {
    fail(start, 'truncated', 'length field runs past the end');
  }

  // NOTE what is NOT checked here, and is checked in der_reader: a leading
  // zero, and a value under 128 written in the long form. Both are legal BER
  // and both are second encodings of one length. Accepting them is the cost
  // of opening the file.
  var value = 0;
  var i;
  for (i = 0; i < count; i++) {
    value = (value * 256) + this.buf[this.pos + i];
  }
  this.pos += count;

  return this._bound(start, value);
};

Reader.prototype._bound = function (start, length) {
  if (length > this.remaining()) {
    fail(start, 'length-exceeds-input',
      'declared length ' + length + ' exceeds ' + this.remaining() +
      ' remaining');
  }
  return length;
};

// Finds where an indefinite-length value ends, by walking its contents to
// the matching end-of-contents marker.
//
// This is why indefinite lengths are worse than they look: the end of a value
// cannot be known without parsing everything inside it, so a malformed inner
// value silently changes where the outer one stops.
Reader.prototype._find_eoc = function (from) {
  var p = from;
  var depth = 0;

  while (p < this.end) {
    if (this.buf[p] === 0x00 && p + 1 < this.end &&
        this.buf[p + 1] === 0x00) {
      if (depth === 0) {
        return p;
      }
      depth -= 1;
      p += 2;
      continue;
    }

    p += 1;                          // tag
    if (p >= this.end) { break; }

    var first = this.buf[p];
    p += 1;

    if (first === 0x80) {
      depth += 1;
      continue;
    }

    var len;
    if ((first & 0x80) === 0) {
      len = first;
    } else {
      var count = first & 0x7F;
      if (count > 4 || p + count > this.end) { break; }
      len = 0;
      var i;
      for (i = 0; i < count; i++) {
        len = (len * 256) + this.buf[p + i];
      }
      p += count;
    }
    p += len;
  }

  fail(from, 'unterminated-indefinite',
    'no end-of-contents marker found');
};

// Reads tag and length and returns a reader bounded to the content.
Reader.prototype._read_tlv = function (expected) {
  this._read_tag(expected);
  var length = this._read_length();

  if (length === -1) {
    var eoc = this._find_eoc(this.pos);
    var child = new Reader(this.buf, this.pos, eoc);
    this.pos = eoc + 2;              // past the two zero octets
    return child;
  }

  var definite = new Reader(this.buf, this.pos, this.pos + length);
  this.pos += length;
  return definite;
};

// ---------------------------------------------------------------------------
// Constructed types
// ---------------------------------------------------------------------------

Reader.prototype.read_sequence = function () {
  return this._read_tlv(T.SEQUENCE);
};

Reader.prototype.read_set = function () {
  return this._read_tlv(T.SET);
};

// BER does not order SET OF members, so there is nothing to check - the
// method exists so a module written against the DER reader's shape reads
// the same with either.
Reader.prototype.read_set_of = function () {
  return this._read_tlv(T.SET);
};

Reader.prototype.read_explicit = function (n) {
  return this._read_tlv(T.CLASS_CONTEXT | T.CONSTRUCTED | n);
};

Reader.prototype.read_implicit = function (n, base_tag) {
  var constructed = (base_tag & T.CONSTRUCTED) !== 0 ||
                    base_tag === T.SEQUENCE || base_tag === T.SET;
  var tag = T.CLASS_CONTEXT | n | (constructed ? T.CONSTRUCTED : 0);

  this._read_tag(tag);
  var length = this._read_length();

  if (length === -1) {
    var eoc = this._find_eoc(this.pos);
    var child = new Reader(this.buf, this.pos, eoc);
    this.pos = eoc + 2;
    return constructed ? child : { bytes: child.buf.subarray(child.pos, child.end) };
  }

  var sub = new Reader(this.buf, this.pos, this.pos + length);
  this.pos += length;

  return constructed
    ? sub
    : { bytes: this.buf.subarray(sub.pos, sub.end) };
};

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

Reader.prototype.read_integer = function () {
  this._read_tag(T.INTEGER);
  var length = this._read_length();

  if (length === -1) {
    fail(this.pos, 'indefinite-primitive',
      'a primitive value cannot have an indefinite length');
  }

  var bytes = this.buf.subarray(this.pos, this.pos + length);
  this.pos += length;

  if (bytes.length === 0) {
    fail(this.pos, 'empty-integer', 'INTEGER has no content octets');
  }
  // The canonical-form checks are deliberately absent: a non-minimal INTEGER
  // is legal BER.
  return bytes;
};

Reader.prototype.read_unsigned = function () {
  var bytes = this.read_integer();

  if ((bytes[0] & 0x80) !== 0) {
    fail(this.pos, 'negative-integer',
      'INTEGER is negative where an unsigned value is required');
  }
  if (bytes.length > 1 && bytes[0] === 0x00) {
    return bytes.subarray(1);
  }
  return bytes;
};

Reader.prototype.read_oid = function () {
  this._read_tag(T.OID);
  var length = this._read_length();

  if (length === -1) {
    fail(this.pos, 'indefinite-primitive',
      'an OBJECT IDENTIFIER cannot have an indefinite length');
  }

  var bytes = this.buf.subarray(this.pos, this.pos + length);
  this.pos += length;

  if (bytes.length === 0) {
    fail(this.pos, 'empty-oid', 'OBJECT IDENTIFIER has no content octets');
  }
  return bytes;
};

Reader.prototype.read_null = function () {
  this._read_tag(T.NULL);
  var length = this._read_length();

  if (length !== 0) {
    fail(this.pos, 'bad-null', 'NULL must have no content octets');
  }
  return null;
};

// BER lets ANY non-zero octet mean true, which gives true 255 encodings.
// Accepted here and refused in der_reader, which is the difference between
// the two files in one line.
Reader.prototype.read_boolean = function () {
  this._read_tag(T.BOOLEAN);
  var length = this._read_length();

  if (length !== 1) {
    fail(this.pos, 'bad-boolean', 'BOOLEAN needs exactly one content octet');
  }

  var v = this.buf[this.pos];
  this.pos += 1;
  return v !== 0x00;
};

// A constructed string is the value split into segments, each of which may
// itself be constructed. Reassembling it is the other half of why this file
// exists.
Reader.prototype.read_octet_string = function () {
  return this._read_string(T.OCTET_STRING, 0);
};

Reader.prototype._read_string = function (base, depth) {
  if (depth > 16) {
    fail(this.pos, 'string-too-deep',
      'constructed string nested more than 16 deep');
  }

  var tag = this.peek_tag();

  if (tag === base) {
    this._read_tag(base);
    var length = this._read_length();
    if (length === -1) {
      fail(this.pos, 'indefinite-primitive',
        'a primitive string cannot have an indefinite length');
    }
    var bytes = this.buf.subarray(this.pos, this.pos + length);
    this.pos += length;
    return bytes;
  }

  if (tag !== (base | T.CONSTRUCTED)) {
    fail(this.pos, 'unexpected-tag',
      'expected ' + T.name_of(base) + ', got ' +
      (tag === null ? 'end of input' : T.name_of(tag)));
  }

  var inner = this._read_tlv(base);
  var parts = [];
  var total = 0;

  while (inner.remaining() > 0) {
    var part = inner._read_string(base, depth + 1);
    parts.push(part);
    total += part.length;
  }

  var out = new Uint8Array(total);
  var at = 0;
  var i;
  for (i = 0; i < parts.length; i++) {
    out.set(parts[i], at);
    at += parts[i].length;
  }
  return out;
};

Reader.prototype.read_bit_string = function () {
  var bytes = this._read_string(T.BIT_STRING, 0);

  if (bytes.length === 0) {
    fail(this.pos, 'bad-bit-string',
      'BIT STRING is missing its unused-bits octet');
  }

  var unused = bytes[0];

  if (unused > 7) {
    fail(this.pos, 'bad-bit-string',
      'BIT STRING claims ' + unused + ' unused bits');
  }
  // The zero-padding check is absent: non-zero padding is legal BER.
  return { bytes: bytes.subarray(1), unused: unused };
};

Reader.prototype.read_bmp_string = function () {
  var bytes = this._read_string(T.BMP_STRING, 0);

  if (bytes.length % 2 !== 0) {
    fail(this.pos, 'bad-bmp-string',
      'BMPString is UTF-16, so its length must be even');
  }

  var s = '';
  var i;
  for (i = 0; i < bytes.length; i += 2) {
    s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
  }
  return s;
};

Reader.prototype.read_utf8_string = function () {
  return decode_utf8(this._read_string(T.UTF8_STRING, 0), fail, this.pos);
};


// ---------------------------------------------------------------------------
// The rest of the universal types
// ---------------------------------------------------------------------------
//
// ⚠ ADDED AFTER A SWEEP COUNTED THIS READER AGAINST THE DER ONE AND FOUND
//    THIRTEEN OF THIRTY-SEVEN.
//
// This file was written to open PKCS#12 containers and stopped there. That
// was defensible while nothing else used it - but it left a reader that
// cannot read a TIME, an ENUMERATED, or any string type but three, and a BER
// reader that cannot read BER is a trap for whoever reaches for it next.
//
// The relaxations are the same ones stated at the top of this file: every
// string type may arrive CONSTRUCTED, and no canonical-form rule is enforced.
// What is NOT relaxed is well-formedness: a truncated value, an indefinite
// length on a primitive, a length beyond the input are all still refused.

// A primitive value of a given tag, without DER's content rules. Used by the
// types whose BER form differs from their DER form only in what is checked.
Reader.prototype._read_primitive = function (tag) {
  this._read_tag(tag);
  var length = this._read_length();

  if (length === -1) {
    fail(this.pos, 'indefinite-primitive',
      'a primitive value cannot have an indefinite length');
  }

  var bytes = this.buf.subarray(this.pos, this.pos + length);
  this.pos += length;
  return bytes;
};

// ENUMERATED has INTEGER's content rules and its own tag. BER does not
// require the minimal form, so unlike der_reader this only checks that there
// is content at all.
Reader.prototype.read_enumerated = function () {
  var bytes = this._read_primitive(T.ENUMERATED);

  if (bytes.length === 0) {
    fail(this.pos, 'empty-integer', 'ENUMERATED has no content octets');
  }
  return bytes;
};

// ⚠ TIME IN BER IS LOOSER THAN IN DER, AND THE DIFFERENCE IS NOT COSMETIC.
//
// X.690 11.7 and 11.8 constrain UTCTime and GeneralizedTime in DER: seconds
// are mandatory, the zone must be Z, and fractional seconds are forbidden.
// BER permits all three - a local-time offset, an omitted seconds field, a
// fractional part.
//
// So these return the TEXT AS IT ARRIVED alongside the parsed value, because
// a BER time can carry information the parsed Date cannot hold: `+0100` is a
// different statement from `Z` even when both name the same instant, and a
// caller re-encoding one must not silently normalise it.
Reader.prototype.read_utc_time = function () {
  return ber_time(this, T.UTC_TIME, 2);
};

Reader.prototype.read_generalized_time = function () {
  return ber_time(this, T.GENERALIZED_TIME, 4);
};

// Either of the two, for a Time CHOICE.
Reader.prototype.read_time = function () {
  var tag = this.peek_tag();

  if (tag === T.UTC_TIME) {
    return this.read_utc_time();
  }
  if (tag === T.GENERALIZED_TIME) {
    return this.read_generalized_time();
  }

  fail(this.pos, 'unexpected-tag',
    'expected UTCTime or GeneralizedTime, got ' +
    (tag === null ? 'end of input' : T.name_of(tag)));
};

function ber_time(r, tag, year_digits) {
  var start = r.pos;
  var text = latin1(r._read_primitive(tag));

  //   YYMMDDHHMM[SS](Z | +HHMM | -HHMM)      UTCTime
  //   YYYYMMDDHH[MM[SS]][.fff](Z | offset)   GeneralizedTime
  var pattern = year_digits === 2
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$/
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(\.\d+)?(Z|[+-]\d{4})?$/;

  var m = pattern.exec(text);

  if (m === null) {
    fail(start, 'bad-time', 'malformed time "' + text + '"');
  }

  var year = parseInt(m[1], 10);

  if (year_digits === 2) {
    // RFC 5280 4.1.2.5.1: 50 and above is 1900s, below is 2000s. The rule
    // belongs to the profile rather than to BER, but every producer follows
    // it and a reader without it dates half its certificates to the 1900s.
    year += year >= 50 ? 1900 : 2000;
  }

  var month = parseInt(m[2], 10);
  var day = parseInt(m[3], 10);
  var hour = parseInt(m[4], 10);
  var minute = m[5] === undefined ? 0 : parseInt(m[5], 10);
  var second = m[6] === undefined || m[6].charAt(0) === '.'
    ? 0 : parseInt(m[6], 10);

  if (month < 1 || month > 12 || day < 1 || day > 31 ||
      hour > 23 || minute > 59 || second > 59) {
    fail(start, 'bad-time', 'time out of range: "' + text + '"');
  }

  var zone = m[year_digits === 2 ? 7 : 8];
  var offset = 0;

  if (zone !== undefined && zone !== 'Z' && zone !== undefined) {
    var sign = zone.charAt(0) === '-' ? -1 : 1;
    offset = sign * (parseInt(zone.substr(1, 2), 10) * 60 +
                     parseInt(zone.substr(3, 2), 10));
  }

  var ms = Date.UTC(year, month - 1, day, hour, minute, second) -
           offset * 60000;

  if (isNaN(ms)) {
    fail(start, 'bad-time', 'impossible date "' + text + '"');
  }

  return {
    date: new Date(ms),
    year: year,
    // ⚠ The text as it arrived. A BER time can say things a Date cannot
    // hold - a local offset rather than Z, an omitted seconds field - and a
    // caller re-encoding one must not normalise it away.
    text: text,
    zone: zone === undefined ? null : zone
  };
}

// --- the string types ------------------------------------------------------
//
// Every one of these may arrive CONSTRUCTED in BER, which _read_string
// already reassembles. The character sets are checked where DER checks them,
// because those are statements about the type rather than about the encoding
// rules BER relaxes.

Reader.prototype.read_printable_string = function () {
  return latin1(this._read_string(T.PRINTABLE_STRING, 0));
};

Reader.prototype.read_ia5_string = function () {
  var bytes = this._read_string(T.IA5_STRING, 0);
  var i;

  for (i = 0; i < bytes.length; i++) {
    if (bytes[i] > 0x7F) {
      fail(this.pos, 'bad-ia5-string',
        'IA5String is ASCII, and byte ' + i + ' is above 0x7F');
    }
  }
  return latin1(bytes);
};

Reader.prototype.read_numeric_string = function () {
  return latin1(this._read_string(T.NUMERIC_STRING, 0));
};

Reader.prototype.read_visible_string = function () {
  return latin1(this._read_string(T.VISIBLE_STRING, 0));
};

Reader.prototype.read_t61_string = function () {
  var start = this.pos;
  return decode_t61(this._read_string(T.T61_STRING, 0), fail, start);
};

Reader.prototype.read_videotex_string = function () {
  return latin1(this._read_string(T.VIDEOTEX_STRING, 0));
};

Reader.prototype.read_graphic_string = function () {
  return latin1(this._read_string(T.GRAPHIC_STRING, 0));
};

Reader.prototype.read_general_string = function () {
  return latin1(this._read_string(T.GENERAL_STRING, 0));
};

Reader.prototype.read_object_descriptor = function () {
  return latin1(this._read_string(T.OBJECT_DESCRIPTOR, 0));
};

Reader.prototype.read_universal_string = function () {
  var bytes = this._read_string(T.UNIVERSAL_STRING, 0);

  if (bytes.length % 4 !== 0) {
    fail(this.pos, 'bad-universal-string',
      'UniversalString is UCS-4, so its length must be a multiple of 4');
  }

  var s = '';
  var i;

  for (i = 0; i < bytes.length; i += 4) {
    var cp = (bytes[i] * 0x1000000) + (bytes[i + 1] << 16) +
             (bytes[i + 2] << 8) + bytes[i + 3];

    if (cp > 0xFFFF) {
      cp -= 0x10000;
      s += String.fromCharCode(0xD800 + (cp >> 10));
      s += String.fromCharCode(0xDC00 + (cp & 0x3FF));
    } else {
      s += String.fromCharCode(cp);
    }
  }

  return s;
};

// Whichever string type is present, with the tag it came in as - the same
// shape der_reader returns, so a caller can switch readers without switching
// call shapes.
Reader.prototype.read_any_string = function () {
  var tag = this.peek_tag();
  var base = tag === null ? null : (tag & ~T.CONSTRUCTED);

  var kinds = [
    [T.UTF8_STRING, 'utf8', 'read_utf8_string'],
    [T.PRINTABLE_STRING, 'printable', 'read_printable_string'],
    [T.IA5_STRING, 'ia5', 'read_ia5_string'],
    [T.BMP_STRING, 'bmp', 'read_bmp_string'],
    [T.T61_STRING, 't61', 'read_t61_string'],
    [T.VISIBLE_STRING, 'visible', 'read_visible_string'],
    [T.NUMERIC_STRING, 'numeric', 'read_numeric_string'],
    [T.UNIVERSAL_STRING, 'universal', 'read_universal_string'],
    [T.GRAPHIC_STRING, 'graphic', 'read_graphic_string'],
    [T.GENERAL_STRING, 'general', 'read_general_string'],
    [T.VIDEOTEX_STRING, 'videotex', 'read_videotex_string']
  ];
  var i;

  for (i = 0; i < kinds.length; i++) {
    if (base === kinds[i][0]) {
      return { type: kinds[i][1], value: this[kinds[i][2]]() };
    }
  }

  fail(this.pos, 'unexpected-tag',
    'expected a string type, got ' +
    (tag === null ? 'end of input' : T.name_of(tag)));
};

// --- the remaining types ---------------------------------------------------

// REAL, with BER's forms allowed: the decimal form and bases 8 and 16 are
// legal here and refused in DER. real.js takes a `strict` flag for exactly
// this.
Reader.prototype.read_real = function () {
  var start = this.pos;
  return REAL.decode(this._read_primitive(T.REAL), start, false);
};

Reader.prototype.read_relative_oid = function () {
  var bytes = this._read_primitive(T.RELATIVE_OID);

  if (bytes.length === 0) {
    fail(this.pos, 'empty-oid', 'RELATIVE-OID has no content octets');
  }
  if ((bytes[bytes.length - 1] & 0x80) !== 0) {
    fail(this.pos, 'truncated-oid', 'RELATIVE-OID ends mid sub-identifier');
  }
  return bytes;
};

Reader.prototype.read_time_string = function () {
  return latin1(this._read_primitive(T.TIME));
};

// DATE is tag NUMBER 31, which is the escape into the multi-octet form - so
// its identifier octets are 1F 1F. See the note in der_reader.js.
Reader.prototype.read_date = function () {
  if (this.pos + 1 >= this.end ||
      this.buf[this.pos] !== 0x1F || this.buf[this.pos + 1] !== 0x1F) {
    fail(this.pos, 'unexpected-tag',
      'expected DATE, whose identifier octets are 1F 1F');
  }

  this.pos += 2;
  var length = this._read_length();

  if (length === -1) {
    fail(this.pos, 'indefinite-primitive',
      'DATE cannot have an indefinite length');
  }

  var bytes = this.buf.subarray(this.pos, this.pos + length);
  this.pos += length;
  return latin1(bytes);
};

// APPLICATION and PRIVATE class tags.
Reader.prototype.read_application = function (n, constructed) {
  var tag = T.CLASS_APPLICATION | n | (constructed ? T.CONSTRUCTED : 0);
  return constructed ? this._read_tlv(tag) : this._read_primitive(tag);
};

Reader.prototype.read_private = function (n, constructed) {
  var tag = T.CLASS_PRIVATE | n | (constructed ? T.CONSTRUCTED : 0);
  return constructed ? this._read_tlv(tag) : this._read_primitive(tag);
};

// Multi-octet tag numbers, X.690 8.1.2.4. Refused on every ordinary path and
// read by a named method - the same arrangement as der_reader, and required
// by the sweep that keeps the two surfaces equal.
Reader.prototype.read_high_tag = function () {
  var start = this.pos;

  if (this.pos >= this.end) {
    fail(start, 'truncated', 'expected a tag, input ended');
  }

  var first = this.buf[this.pos];

  if ((first & T.NUMBER_MASK) !== T.HIGH_TAG_NUMBER) {
    fail(start, 'not-high-tag',
      'this is a low tag number; read it with the method for its type');
  }

  this.pos += 1;

  var number = 0;
  var octets = 0;

  while (true) {
    if (this.pos >= this.end) {
      fail(start, 'truncated', 'tag number runs past the end of the input');
    }

    var b = this.buf[this.pos];
    this.pos += 1;
    octets += 1;

    if (octets > 4) {
      fail(start, 'tag-number-too-large',
        'tag number of more than four octets');
    }

    number = (number * 128) + (b & 0x7F);

    if ((b & 0x80) === 0) {
      break;
    }
  }

  // ⚠ BER does NOT require the minimal form, so unlike der_reader this
  // accepts a leading 0x80 and a number the short form would have held.
  // That is the same relaxation this file makes everywhere else.
  var length = this._read_length();
  var constructed = (first & T.CONSTRUCTED) !== 0;

  var out = {
    class_: first & T.CLASS_MASK,
    number: number,
    constructed: constructed
  };

  if (length === -1) {
    var eoc = this._find_eoc(this.pos);
    out.content = new Reader(this.buf, this.pos, eoc);
    this.pos = eoc + 2;
    return out;
  }

  if (constructed) {
    out.content = new Reader(this.buf, this.pos, this.pos + length);
  } else {
    out.bytes = this.buf.subarray(this.pos, this.pos + length);
  }

  this.pos += length;
  return out;
};

Reader.prototype.is_high_tag = function () {
  return this.pos < this.end &&
         (this.buf[this.pos] & T.NUMBER_MASK) === T.HIGH_TAG_NUMBER;
};

// EXTERNAL, EMBEDDED PDV and CHARACTER STRING. The components come back
// uninterpreted for the same reason as in DER: what is inside depends on a
// negotiation this library cannot see.
Reader.prototype.read_external = function () {
  var seq = this._read_tlv(T.EXTERNAL);
  var out = { direct: null, indirect: null, descriptor: null,
              encoding: null, value: null };

  if (seq.peek_tag() === T.OID) {
    out.direct = seq.read_oid();
  }
  if (seq.peek_tag() === T.INTEGER) {
    out.indirect = seq.read_integer();
  }
  if (seq.peek_tag() === T.OBJECT_DESCRIPTOR) {
    out.descriptor = seq.read_object_descriptor();
  }

  var tag = seq.peek_tag();

  if (tag === 0xA0) {
    var inner = seq.read_explicit(0);
    out.encoding = 'single-ASN1-type';
    out.value = inner.capture();
    inner.expect_end();
  } else if (tag === 0x81) {
    out.encoding = 'octet-aligned';
    out.value = seq.read_implicit(1, T.OCTET_STRING).bytes;
  } else if (tag === 0x82) {
    out.encoding = 'arbitrary';
    out.value = seq.read_implicit(2, T.BIT_STRING).bytes;
  } else {
    fail(seq.pos, 'bad-external',
      'EXTERNAL has no recognised encoding choice');
  }

  seq.expect_end();
  return out;
};

Reader.prototype.read_embedded_pdv = function () {
  var seq = this._read_tlv(T.EMBEDDED_PDV);
  var identification = seq.capture();
  var value = seq.read_octet_string();
  seq.expect_end();
  return { identification: identification, value: value };
};

Reader.prototype.read_character_string = function () {
  var seq = this._read_tlv(T.CHARACTER_STRING);
  var identification = seq.capture();
  var value = seq.read_octet_string();
  seq.expect_end();
  return { identification: identification, value: value };
};

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

// Reads one complete value and returns its bytes. For an indefinite-length
// value the end-of-contents marker is included, because those bytes are part
// of the encoding as it arrived - and anything that hashes a captured region
// must see what was there.
Reader.prototype.capture = function () {
  var start = this.pos;

  if (this.pos >= this.end) {
    fail(this.pos, 'truncated', 'expected a value, input ended');
  }

  this.pos += 1;                     // tag
  var first = this.buf[this.pos];
  this.pos += 1;

  if (first === 0x80) {
    var eoc = this._find_eoc(this.pos);
    this.pos = eoc + 2;
    return this.buf.subarray(start, this.pos);
  }

  var length;
  if ((first & 0x80) === 0) {
    length = first;
  } else {
    var count = first & 0x7F;
    if (count > 4 || this.pos + count > this.end) {
      fail(start, 'truncated', 'length field runs past the end');
    }
    length = 0;
    var i;
    for (i = 0; i < count; i++) {
      length = (length * 256) + this.buf[this.pos + i];
    }
    this.pos += count;
  }

  if (this.pos + length > this.end) {
    fail(start, 'length-exceeds-input',
      'declared length ' + length + ' exceeds what remains');
  }

  this.pos += length;
  return this.buf.subarray(start, this.pos);
};

Reader.prototype.expect_end = function () {
  // An end-of-contents marker at this position closes an enclosing
  // indefinite value and is not trailing data.
  if (this.at_eoc()) {
    this.pos += 2;
  }
  if (this.pos < this.end) {
    fail(this.pos, 'trailing-bytes',
      (this.end - this.pos) + ' unconsumed byte(s)');
  }
};

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

function reader(input) {
  var bytes = to_bytes(input);
  return new Reader(bytes, 0, bytes.length);
}

function read(input, fn) {
  var r = reader(input);
  var out = fn(r);
  r.expect_end();
  return out;
}

// Whether a buffer uses anything BER permits and DER does not. Lets a caller
// - and pkcs12.js - report which encoding a file actually used, rather than
// silently normalising the difference away.
function is_ber(input) {
  var bytes = to_bytes(input);
  var i = 0;

  while (i < bytes.length) {
    var tag = bytes[i];

    // A constructed string tag: OCTET STRING, BIT STRING or UTF8String with
    // the constructed bit set.
    if (tag === 0x24 || tag === 0x23 || tag === 0x2C) {
      return true;
    }

    i += 1;
    if (i >= bytes.length) { break; }

    var first = bytes[i];
    i += 1;

    if (first === 0x80) {
      return true;                   // indefinite length
    }
    if ((first & 0x80) !== 0) {
      var count = first & 0x7F;
      if (count > 4 || i + count > bytes.length) { break; }
      // A leading zero, or a value under 128 in long form, is BER-only.
      if (bytes[i] === 0x00) { return true; }
      var len = 0;
      var j;
      for (j = 0; j < count; j++) {
        len = (len * 256) + bytes[i + j];
      }
      if (len < 128) { return true; }
      i += count;
      if ((tag & 0x20) === 0) { i += len; }
    } else {
      if ((tag & 0x20) === 0) { i += first; }
    }
  }

  return false;
}

export {
  reader,
  read,
  is_ber,
  Reader
};

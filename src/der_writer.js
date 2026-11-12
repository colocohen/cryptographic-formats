// A canonical DER writer. It emits exactly one encoding for any given value,
// which is the whole obligation: an encoder that can produce two encodings of
// one value has already lost the property the reader is defending.
//
// This file shares NOTHING with der_reader.js except the tag constants. That
// is deliberate and it is the central lesson of cryptographic-primitives's sig_to_der,
// which wrote a short-form length of 135 for P-521 - not DER at all - and
// went unnoticed for exactly as long as the matching parser was equally
// wrong. The pair round-tripped happily with each other. A shared length
// helper would reproduce that by construction: one bug, both directions, and
// a green test.
//
// So the length encoding below is written out again rather than imported, and
// it is verified against an external reference rather than against
// der_reader.

import * as T from './tags.js';

import { to_bytes, to_array, append } from './commons/bytes.js';
import { encode_utf8, ascii, code_points } from './commons/encode_text.js';
import * as REAL from './real.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('der');


// ---------------------------------------------------------------------------
// Length
// ---------------------------------------------------------------------------

// DER requires the shortest form that can hold the value: short form for
// anything under 128, and long form with no leading zero octet above that.
function encode_length(n) {
  if (n < 0) {
    fail('bad-length', 'length cannot be negative');
  }

  if (n < 128) {
    return [n];
  }

  // Collect the value big-endian, most significant octet first, with no
  // leading zero - a leading zero here is the non-minimal length the reader
  // refuses.
  var octets = [];
  var v = n;
  while (v > 0) {
    octets.unshift(v & 0xFF);
    v = Math.floor(v / 256);
  }

  if (octets.length > 4) {
    fail('length-too-large',
      'length of ' + n + ' needs ' + octets.length + ' octets');
  }

  return [0x80 | octets.length].concat(octets);
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

// Every writer function returns a plain array of octets. Arrays rather than
// typed arrays because the sizes are not known until assembly finishes and
// concatenation is the dominant operation; the single conversion happens once
// at the end, in to_bytes.
// ⚠ THE SAME Uint8Array TRAP AS concat(), IN THE OTHER HALF OF THE WRITER.
//
// `[].concat(uint8array)` appends the typed array as ONE ELEMENT. concat()
// was fixed when a certificate built from a parsed name came out at 90 bytes;
// this was not, because nothing had passed encoded bytes through explicit()
// yet.
//
// It surfaced building a CMP message, where the body IS an already-encoded
// CertReqMessages: `explicit(0, der)` produced a three-byte structure whose
// length said 179 and whose content was a single zero.
//
// The lesson is the one the duplication analysis keeps making: a bug fixed in
// one of two similar places is a bug still present in the other.
function tlv(tag, content) {
  var body = content instanceof Uint8Array
    ? Array.prototype.slice.call(content)
    : content;

  return [tag].concat(encode_length(body.length)).concat(body);
}

// ⚠ A Uint8Array HERE WAS SWALLOWED SILENTLY, AND THAT WAS A REAL BUG.
//
// `[].concat(uint8array)` appends the typed array AS A SINGLE ELEMENT rather
// than spreading it - Array.prototype.concat only spreads real arrays. So a
// caller passing already-encoded bytes into sequence() got a structure with
// one nonsense member and no error.
//
// Found the first time a certificate was built from a parsed name, where the
// attribute values arrive as encoded bytes. The result was a 90-byte
// certificate that openssl refused, and nothing in this library had
// complained.
//
// Typed arrays are now spread. That also makes `sequence([alreadyEncoded])`
// mean what it looks like, which is how every caller expects a writer tree
// to compose.
function concat(parts) {
  var out = [];
  var i;

  for (i = 0; i < parts.length; i++) {
    var part = parts[i];

    // Pushed, not concatenated: `out = out.concat(part)` was quadratic in
    // the number of parts (see commons/bytes.js append).
    append(out, part);
  }

  return out;
}



// ---------------------------------------------------------------------------
// Primitive types
// ---------------------------------------------------------------------------

// Takes the integer's content octets as they should appear, and verifies that
// they are already canonical rather than fixing them silently. A writer that
// repairs its input hides the fact that the caller built something wrong, and
// the caller may be building the same wrong thing somewhere this writer is
// not involved.
function integer(content) {
  var bytes = to_array(content);

  if (bytes.length === 0) {
    fail('empty-integer', 'INTEGER needs at least one content octet');
  }

  if (bytes.length > 1) {
    if (bytes[0] === 0x00 && (bytes[1] & 0x80) === 0) {
      fail('non-minimal-integer',
        'INTEGER content has a superfluous leading 0x00');
    }
    if (bytes[0] === 0xFF && (bytes[1] & 0x80) !== 0) {
      fail('non-minimal-integer',
        'INTEGER content has a superfluous leading 0xFF');
    }
  }

  return tlv(T.INTEGER, bytes);
}

// The counterpart to read_unsigned. Adds the 0x00 that DER requires when the
// high bit would otherwise read as a sign bit, and strips leading zeros that
// the caller supplied - here repair is correct, because the caller is handing
// over a magnitude rather than an encoding.
function unsigned(magnitude) {
  var bytes = to_array(magnitude);
  var i = 0;

  while (i < bytes.length - 1 && bytes[i] === 0x00) {
    i += 1;
  }
  bytes = bytes.slice(i);

  if (bytes.length === 0) {
    bytes = [0x00];
  }

  if ((bytes[0] & 0x80) !== 0) {
    bytes = [0x00].concat(bytes);
  }

  return tlv(T.INTEGER, bytes);
}

function enumerated(content) {
  var bytes = to_array(content);

  if (bytes.length === 0) {
    fail('empty-integer', 'ENUMERATED needs at least one content octet');
  }
  if (bytes.length > 1 && bytes[0] === 0x00 && (bytes[1] & 0x80) === 0) {
    fail('non-minimal-integer',
      'ENUMERATED content has a superfluous leading 0x00');
  }

  return tlv(T.ENUMERATED, bytes);
}

// ---------------------------------------------------------------------------
// The remaining string types
// ---------------------------------------------------------------------------
//
// ⚠ WRITING THESE IS A DELIBERATE ACT, NOT A CONVENIENCE.
//
// RFC 5280 deprecates T61String, VideotexString, GraphicString and
// GeneralString, and says new certificates must use UTF8String. They are
// READABLE here because certificates issued before that still carry them and
// a name that cannot be read compares unequal to itself.
//
// They are now WRITABLE because a reader without a writer is an asymmetry
// with a cost: a caller re-encoding a structure they read - to canonicalize
// it, to re-sign it, to move it between containers - could not reproduce a
// field this library had just handed them. That is a worse position than
// letting them write a deprecated type on purpose.
//
// The character sets are not enforced beyond the byte range, because the true
// ones are ISO 2022 escape-sequence encodings almost nobody implemented; in
// practice these fields hold Latin-1, which is what read_t61_string decodes.
function latin1_bytes(text, type) {
  var out = [];
  var i;

  for (i = 0; i < text.length; i++) {
    var c = text.charCodeAt(i);

    if (c > 0xFF) {
      fail('bad-' + type,
        type + ' holds one byte per character, and index ' + i +
        ' is above 0xFF. Use UTF8String, which RFC 5280 requires for new ' +
        'certificates anyway.');
    }
    out.push(c);
  }

  return out;
}

function t61_string(text) {
  return tlv(T.T61_STRING, latin1_bytes(text, 't61-string'));
}

function videotex_string(text) {
  return tlv(T.VIDEOTEX_STRING, latin1_bytes(text, 'videotex-string'));
}

function graphic_string(text) {
  return tlv(T.GRAPHIC_STRING, latin1_bytes(text, 'graphic-string'));
}

function general_string(text) {
  return tlv(T.GENERAL_STRING, latin1_bytes(text, 'general-string'));
}

// UCS-4, four bytes per code point, big endian - the only string type here
// that is not one byte or two per character.
function universal_string(text) {
  var cps = code_points(text, fail, 'bad-universal-string');
  var out = [];
  var i;

  for (i = 0; i < cps.length; i++) {
    var cp = cps[i];
    out.push((cp >> 24) & 0xFF, (cp >> 16) & 0xFF,
             (cp >> 8) & 0xFF, cp & 0xFF);
  }

  return tlv(T.UNIVERSAL_STRING, out);
}

// ---------------------------------------------------------------------------
// The structured types
// ---------------------------------------------------------------------------

// EXTERNAL and EMBEDDED PDV carry a value whose type is agreed out of band.
// The components go in as the caller assembled them, for the same reason the
// reader hands them back uninterpreted: what is inside depends on a
// negotiation this library cannot see.
//
//   EXTERNAL ::= SEQUENCE {
//        direct-reference       OBJECT IDENTIFIER OPTIONAL,
//        indirect-reference     INTEGER OPTIONAL,
//        data-value-descriptor  ObjectDescriptor OPTIONAL,
//        encoding               CHOICE {
//            single-ASN1-type  [0] ANY,
//            octet-aligned     [1] IMPLICIT OCTET STRING,
//            arbitrary         [2] IMPLICIT BIT STRING } }
function external(parts) {
  var fields = [];

  if (parts.direct !== undefined && parts.direct !== null) {
    fields.push(oid(parts.direct));
  }
  if (parts.indirect !== undefined && parts.indirect !== null) {
    fields.push(integer(parts.indirect));
  }
  if (parts.descriptor !== undefined && parts.descriptor !== null) {
    fields.push(object_descriptor(parts.descriptor));
  }

  if (parts.encoding === 'single-ASN1-type') {
    fields.push(explicit(0, to_array(parts.value)));
  } else if (parts.encoding === 'octet-aligned') {
    fields.push(implicit(1, octet_string(parts.value)));
  } else if (parts.encoding === 'arbitrary') {
    fields.push(implicit(2, bit_string(parts.value, 0)));
  } else {
    fail('bad-external',
      'the encoding must be single-ASN1-type, octet-aligned or arbitrary');
  }

  return tlv(T.EXTERNAL, concat(fields));
}

function embedded_pdv(identification, value) {
  return tlv(T.EMBEDDED_PDV, concat([
    to_array(identification),
    octet_string(value)
  ]));
}

function character_string(identification, value) {
  return tlv(T.CHARACTER_STRING, concat([
    to_array(identification),
    octet_string(value)
  ]));
}

// X.680 (2015) TIME and DATE. Text in the formats those clauses define; the
// grammar is the caller's to satisfy, which is why the reader returns a
// string rather than components.
function time_string(text) {
  return tlv(T.TIME, ascii(text));
}

// The identifier is 1F 1F - see the note on read_date. tlv() takes a single
// tag octet, so this assembles the header itself.
function date(text) {
  var content = ascii(text);
  return [0x1F, T.DATE_NUMBER].concat(encode_length(content.length))
    .concat(content);
}

// ---------------------------------------------------------------------------
// Other tag classes
// ---------------------------------------------------------------------------

// APPLICATION and PRIVATE class tags. Nothing on this library's format list
// uses one - PKIX is context tags throughout - but SNMP and plenty of ASN.1
// outside cryptography do, and a writer that cannot express them makes the
// reader's support useless for anything that has to reply.
//
// Constructed and primitive are separate arguments rather than inferred,
// because the bit is part of the tag and a caller who does not know which
// they need does not know what they are writing.
function application(n, content, constructed) {
  return class_tlv(T.CLASS_APPLICATION, n, content, constructed);
}

function private_(n, content, constructed) {
  return class_tlv(T.CLASS_PRIVATE, n, content, constructed);
}

function class_tlv(cls, n, content, constructed) {
  if (n < 0 || n > 30) {
    fail('high-tag-number',
      'tag number ' + n + ' needs the multi-octet form, which this writer ' +
      'does not produce');
  }

  return tlv(cls | n | (constructed ? T.CONSTRUCTED : 0), to_array(content));
}

function boolean_(value) {
  // DER fixes true at 0xFF. BER's "any non-zero octet" would give true 255
  // encodings.
  return tlv(T.BOOLEAN, [value ? 0xFF : 0x00]);
}

// The one DER form: binary, base 2, odd mantissa. See real.js.
function real(value) {
  return tlv(T.REAL, REAL.encode(value));
}

// A RELATIVE-OID's arcs are NOT packed the way an absolute OID's first two
// are, which is the difference that makes the two types distinct rather than
// a naming convention.
// One sub-identifier in base 128: high bit set on every octet but the last,
// and no leading zero group - the non-minimal form the reader refuses.
//
// Shared with oid.from_string, which encodes dotted text the same way. Both
// are ENCODERS, so sharing cannot hide a reader/writer disagreement; two
// copies could only drift.
function base128(n) {
  if (n === 0) {
    return [0x00];
  }

  var group = [];
  var v = n;
  while (v > 0) {
    group.unshift(v % 128);
    v = Math.floor(v / 128);
  }

  var out = [];
  var i;
  for (i = 0; i < group.length - 1; i++) {
    out.push(group[i] | 0x80);
  }
  out.push(group[group.length - 1]);
  return out;
}

function relative_oid(arcs) {
  var parts = typeof arcs === 'string' ? arcs.split('.') : arcs;
  var out = [];
  var i;

  if (parts.length === 0) {
    fail('empty-oid', 'a RELATIVE-OID needs at least one arc');
  }

  for (i = 0; i < parts.length; i++) {
    var n = typeof parts[i] === 'number' ? parts[i] : parseInt(parts[i], 10);

    if (!isFinite(n) || n < 0 || Math.floor(n) !== n) {
      fail('bad-oid-string', 'arc "' + parts[i] + '" is not a number');
    }

    append(out, base128(n));
  }

  return tlv(T.RELATIVE_OID, out);
}

function object_descriptor(text) {
  return tlv(T.OBJECT_DESCRIPTOR, ascii(text));
}

function null_() {
  return tlv(T.NULL, []);
}

function octet_string(content) {
  return tlv(T.OCTET_STRING, to_array(content));
}

// unused defaults to 0, which is the case for every key and signature this
// library encodes. A non-zero count requires the trailing bits to be zero,
// and that is checked rather than masked - see the note on integer().
function bit_string(content, unused) {
  var bytes = to_array(content);
  var u = unused === undefined ? 0 : unused;

  if (u < 0 || u > 7) {
    fail('bad-bit-string', 'unused bits must be 0 to 7, got ' + u);
  }

  if (bytes.length === 0 && u !== 0) {
    fail('bad-bit-string', 'empty BIT STRING cannot have unused bits');
  }

  if (u > 0) {
    var mask = (1 << u) - 1;
    if ((bytes[bytes.length - 1] & mask) !== 0) {
      fail('non-zero-padding',
        'BIT STRING trailing bits are not zero');
    }
  }

  return tlv(T.BIT_STRING, [u].concat(bytes));
}

// Takes the OID's encoding octets, which is what read_oid returns, so an OID
// read from one structure can be written into another without a round trip
// through a dotted string. oid.js converts from dotted form when a caller has
// one.
function oid(encoding) {
  var bytes = to_array(encoding);

  if (bytes.length === 0) {
    fail('empty-oid', 'OBJECT IDENTIFIER needs at least one content octet');
  }

  if ((bytes[bytes.length - 1] & 0x80) !== 0) {
    fail('truncated-oid', 'OBJECT IDENTIFIER ends mid sub-identifier');
  }

  var starting = true;
  var i;
  for (i = 0; i < bytes.length; i++) {
    if (starting && bytes[i] === 0x80) {
      fail('non-minimal-oid',
        'OBJECT IDENTIFIER sub-identifier has a leading 0x80');
    }
    starting = (bytes[i] & 0x80) === 0;
  }

  return tlv(T.OID, bytes);
}

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

// Encoders take JavaScript strings and verify them against the type's
// character set rather than substituting or dropping what does not fit.
// Silently replacing a character produces a string that is not the one the
// caller passed, and in an X.509 subject name that is a different identity.

function utf8_string(text) {
  return tlv(T.UTF8_STRING, encode_utf8(text, fail));
}

var PRINTABLE_OUT = /^[A-Za-z0-9 '()+,\-./:=?]*$/;

function printable_string(text) {
  if (!PRINTABLE_OUT.test(text)) {
    fail('bad-printable-string',
      'string contains characters PrintableString does not permit; ' +
      'use UTF8String');
  }
  return tlv(T.PRINTABLE_STRING, ascii(text));
}

function ia5_string(text) {
  var i;
  for (i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) > 0x7F) {
      fail('bad-ia5-string',
        'IA5String cannot hold the character at index ' + i);
    }
  }
  return tlv(T.IA5_STRING, ascii(text));
}

// UTF-16 BIG ENDIAN. Writing little endian, or writing UTF-8, produces a
// PKCS#12 whose friendlyName every other tool shows as mojibake.
function bmp_string(text) {
  var out = [];
  var i;

  for (i = 0; i < text.length; i++) {
    var unit = text.charCodeAt(i);
    out.push((unit >> 8) & 0xFF);
    out.push(unit & 0xFF);
  }

  return tlv(T.BMP_STRING, out);
}

function visible_string(text) {
  var i;
  for (i = 0; i < text.length; i++) {
    var c = text.charCodeAt(i);
    if (c < 0x20 || c > 0x7E) {
      fail('bad-visible-string',
        'VisibleString allows 0x20 to 0x7E only');
    }
  }
  return tlv(T.VISIBLE_STRING, ascii(text));
}

function numeric_string(text) {
  if (!/^[0-9 ]*$/.test(text)) {
    fail('bad-numeric-string', 'NumericString allows digits and space only');
  }
  return tlv(T.NUMERIC_STRING, ascii(text));
}



// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

// Takes a Date or a components object and writes the one DER form: seconds
// always present, Z always, never a fractional part, never a local offset.

function utc_time(when) {
  var t = components(when);

  if (t.year < 1950 || t.year > 2049) {
    fail('utc-time-out-of-range',
      'UTCTime can only express 1950 to 2049; ' + t.year +
      ' needs GeneralizedTime');
  }

  var yy = t.year >= 2000 ? t.year - 2000 : t.year - 1900;

  return tlv(T.UTC_TIME, ascii(
    two(yy) + two(t.month) + two(t.day) +
    two(t.hour) + two(t.minute) + two(t.second) + 'Z'));
}

// A fraction is written from `fraction` - a string of digits on a
// components object, or `options.millis` with a Date - and always in DER's
// one form: a full stop, then the digits with no trailing zero, and nothing
// at all when the fraction is zero. RFC 3161 timestamps need it; the X.509
// Time CHOICE below never passes one.
function generalized_time(when, options) {
  var t = components(when);
  var fraction = '';

  if (typeof t.fraction === 'string') {
    if (!/^\d+$/.test(t.fraction)) {
      fail('bad-time', 'the fraction must be decimal digits');
    }
    fraction = t.fraction;
  } else if (options && options.millis === true && when instanceof Date) {
    var ms = when.getUTCMilliseconds();
    fraction = (ms < 10 ? '00' : ms < 100 ? '0' : '') + ms;
  }

  fraction = fraction.replace(/0+$/, '');

  return tlv(T.GENERALIZED_TIME, ascii(
    four(t.year) + two(t.month) + two(t.day) +
    two(t.hour) + two(t.minute) + two(t.second) +
    (fraction === '' ? '' : '.' + fraction) + 'Z'));
}

// The X.509 Time CHOICE. RFC 5280 4.1.2.5 fixes which type to use by year, so
// the choice is not the caller's - making it here means a certificate written
// by this library cannot carry the wrong one.
function time(when) {
  var t = components(when);
  return t.year < 2050 ? utc_time(when) : generalized_time(when);
}

function components(when) {
  if (when instanceof Date) {
    if (isNaN(when.getTime())) {
      fail('bad-time', 'invalid Date');
    }
    return {
      year:   when.getUTCFullYear(),
      month:  when.getUTCMonth() + 1,
      day:    when.getUTCDate(),
      hour:   when.getUTCHours(),
      minute: when.getUTCMinutes(),
      second: when.getUTCSeconds()
    };
  }

  if (when && typeof when.year === 'number') {
    return when;
  }

  fail('bad-time', 'expected a Date or a components object');
}

function two(n) {
  return (n < 10 ? '0' : '') + n;
}

function four(n) {
  var s = String(n);
  while (s.length < 4) {
    s = '0' + s;
  }
  return s;
}

// ---------------------------------------------------------------------------
// Constructed types
// ---------------------------------------------------------------------------

function sequence(parts) {
  return tlv(T.SEQUENCE, concat(parts));
}

// SET OF requires its members sorted by their complete encodings, shorter
// first when one is a prefix of the other. Sorting here rather than trusting
// the caller means a correctly ordered SET OF is the only thing this writer
// can produce - the ordering is not an option the caller can get wrong.
function set_of(members) {
  var sorted = members.slice().sort(compare_encodings);
  return tlv(T.SET, concat(sorted));
}

function compare_encodings(a, b) {
  var n = Math.min(a.length, b.length);
  var i;
  for (i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

// A plain SET, for the rare structure that is SET rather than SET OF and
// whose member order is fixed by its definition.
function set(parts) {
  return tlv(T.SET, concat(parts));
}

// ---------------------------------------------------------------------------
// Context-specific tagging
// ---------------------------------------------------------------------------

// [n] EXPLICIT wraps an already-encoded value, keeping its original tag.
function explicit(n, content) {
  return tlv(T.CLASS_CONTEXT | T.CONSTRUCTED | n, content);
}

// [n] IMPLICIT replaces the value's tag with the context tag, keeping the
// constructed bit. The caller passes the encoded value; its first octet is
// the tag being replaced, so the length must be re-read to find where the
// content starts.
function implicit(n, encoded) {
  var bytes = to_array(encoded);
  var original_tag = bytes[0];
  var constructed = (original_tag & T.CONSTRUCTED) !== 0;

  // Skip tag, then the length field, to reach the content.
  var i = 1;
  var first = bytes[i];
  i += 1;
  if ((first & 0x80) !== 0) {
    i += (first & 0x7F);
  }

  var content = bytes.slice(i);
  var tag = T.CLASS_CONTEXT | n | (constructed ? T.CONSTRUCTED : 0);
  return tlv(tag, content);
}

export {
  base128,
  tlv,
  concat,
  to_bytes,
  encode_length,
  integer,
  unsigned,
  enumerated,
  boolean_ as boolean,
  null_ as null,
  real,
  relative_oid,
  object_descriptor,
  octet_string,
  bit_string,
  oid,
  utf8_string,
  printable_string,
  ia5_string,
  bmp_string,
  visible_string,
  t61_string,
  videotex_string,
  graphic_string,
  general_string,
  universal_string,
  external,
  embedded_pdv,
  character_string,
  time_string,
  date,
  application,
  private_ as private,
  numeric_string,
  utc_time,
  generalized_time,
  time,
  sequence,
  set,
  set_of,
  explicit,
  implicit
};

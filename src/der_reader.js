// A validating DER reader. Not BER: every encoding that BER permits and DER
// forbids is refused here, because two encodings of one value is how a
// signature comes to verify over two different byte strings.
//
// The shape of this API is the point. There is no way to reach a value except
// through a call that validates it and advances the cursor. A generic tree -
// tree.children[2].value - reaches a value with nothing having checked that
// children[2] is what the caller assumed, and every consumer writes its own
// walk. That is how node-forge shipped an RSA PKCS#1 signature forgery: the
// code that read DigestInfo walked the structure and never checked that
// nothing followed the fields it wanted.
//
// Every method here either returns a validated value or throws.

import * as T from './tags.js';

import { to_bytes } from './commons/bytes.js';
import { latin1, decode_utf8 } from './commons/decode_text.js';
import * as REAL from './real.js';
import { decode_t61 } from './commons/t61.js';
import { make_fail } from './commons/fail.js';

var fail = make_fail('der');


// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

// A reader is a cursor over a bounded region of the buffer. Reading a
// constructed value returns a NEW reader bounded to that value's content, so
// a nested structure can never read past its own end into its parent's bytes
// even if its declared length is wrong - the bound is checked once, when the
// child is created.

function Reader(buf, pos, end) {
  this.buf = buf;
  this.pos = pos;
  this.end = end;
}

Reader.prototype.remaining = function () {
  return this.end - this.pos;
};

// Look at the next identifier octet without consuming it. Needed for OPTIONAL
// fields, where the only way to know whether a field is present is to see
// which tag comes next.
Reader.prototype.peek_tag = function () {
  if (this.pos >= this.end) {
    return null;
  }
  return this.buf[this.pos];
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
    // Tag numbers above 30 continue into further octets. Valid DER, but
    // nothing in this library's scope uses one, and accepting a form we never
    // produce widens the input surface for no gain.
    fail(this.pos, 'high-tag-number',
      'multi-octet tag number is not supported');
  }

  if (tag !== expected) {
    fail(this.pos, 'unexpected-tag',
      'expected ' + T.name_of(expected) + ', got ' + T.name_of(tag));
  }

  this.pos += 1;
  return tag;
};

Reader.prototype._read_length = function () {
  var start = this.pos;

  if (this.pos >= this.end) {
    fail(start, 'truncated', 'length octet missing');
  }

  var first = this.buf[this.pos];
  this.pos += 1;

  // Short form: the length is the octet itself, 0 to 127.
  if ((first & T.LENGTH_LONG_FORM) === 0) {
    return this._bound(start, first);
  }

  if (first === T.LENGTH_INDEFINITE) {
    // BER's indefinite length, terminated by a pair of zero octets. DER
    // requires the length to be stated up front, and an indefinite length
    // means the end of a value is decided by its content - which is exactly
    // the ambiguity this reader exists to remove.
    fail(start, 'indefinite-length',
      'indefinite length is BER, not DER');
  }

  if (first === T.LENGTH_RESERVED) {
    fail(start, 'reserved-length', '0xFF is a reserved length octet');
  }

  var count = first & 0x7F;

  // Four octets addresses 4GB. A length that large is either a lie - caught
  // below by the bound check - or an input this reader was never going to
  // hold in memory anyway. Refusing here avoids assembling an absurd number
  // from a 126-octet field before discovering it cannot be satisfied.
  if (count > 4) {
    fail(start, 'length-too-large',
      'length of ' + count + ' octets is beyond what this reader accepts');
  }

  if (this.pos + count > this.end) {
    fail(start, 'truncated',
      'length field of ' + count + ' octets runs past the end');
  }

  if (this.buf[this.pos] === 0x00) {
    // A leading zero in the length field means the length was written wider
    // than it needed to be. Two encodings of one length is two encodings of
    // one value.
    fail(start, 'non-minimal-length',
      'length has a superfluous leading 0x00');
  }

  var value = 0;
  var i;
  for (i = 0; i < count; i++) {
    value = (value * 256) + this.buf[this.pos + i];
  }
  this.pos += count;

  // DER requires the short form wherever it suffices. Accepting 0x81 0x32 as
  // well as 0x32 for the value 50 is the BIP 66 failure in miniature: one
  // signature, two encodings, malleable transaction IDs.
  if (value < 128) {
    fail(start, 'non-minimal-length',
      'length ' + value + ' must use the short form');
  }

  return this._bound(start, value);
};

// The declared length must fit in what is actually left. This is the whole of
// the size check: no separate ceiling is needed, because the buffer's own
// length already bounds every value inside it. A declared length that exceeds
// the remaining bytes is a lie by definition, whatever its magnitude.
Reader.prototype._bound = function (start, length) {
  if (length > this.remaining()) {
    fail(start, 'length-exceeds-input',
      'declared length ' + length + ' exceeds ' + this.remaining() +
      ' remaining');
  }
  return length;
};

// Read tag and length, and return a reader bounded to the content.
Reader.prototype._read_tlv = function (expected) {
  this._read_tag(expected);
  var length = this._read_length();
  var child  = new Reader(this.buf, this.pos, this.pos + length);
  this.pos += length;
  return child;
};

// Read tag and length, and return the content bytes.
Reader.prototype._read_value = function (expected) {
  var start = this.pos;
  this._read_tag(expected);
  var length = this._read_length();
  var bytes  = this.buf.subarray(this.pos, this.pos + length);
  this.pos  += length;
  return { bytes: bytes, start: start };
};

// ---------------------------------------------------------------------------
// Constructed types
// ---------------------------------------------------------------------------

Reader.prototype.read_sequence = function () {
  return this._read_tlv(T.SEQUENCE);
};

// SET is read as a plain bounded reader. SET OF, which additionally requires
// its members to appear in sorted encoding order, is a separate method - see
// the note in DECISIONS 2.5. Conflating them would let an unordered SET OF
// through under the wrong name.
// A plain SET, whose members are distinct types. DER orders them by TAG -
// X.690 11.5 - which is a different rule from SET OF, where the ordering is
// by the members' complete encodings.
//
// The ordering is checked here rather than left to the caller because a SET
// out of order is a second encoding of the same value, and SETs appear
// inside signed structures.
Reader.prototype.read_set = function () {
  var set = this._read_tlv(T.SET);
  var previous = -1;
  var p = set.pos;

  while (p < set.end) {
    var tag = set.buf[p];

    var order = compare_set_tags(tag, previous);

    if (order < 0) {
      fail(p, 'set-not-ordered',
        'SET members are not in ascending tag order: ' + T.name_of(tag) +
        ' follows ' + T.name_of(previous));
    }

    // X.680 27.3: the components of a SET have DISTINCT tags - that is how
    // a reader tells them apart with no order to go on. Two with one tag is
    // not a SET at all, and the ordering check above let it through because
    // equal is not less.
    if (order === 0) {
      fail(p, 'duplicate-set-member',
        'two SET members share the tag ' + T.name_of(tag));
    }
    previous = tag;

    // Skip this member to reach the next tag.
    p += 1;
    if (p >= set.end) { break; }

    var first = set.buf[p];
    p += 1;

    if ((first & 0x80) !== 0) {
      var count = first & 0x7F;
      if (count > 4 || p + count > set.end) { break; }
      var len = 0;
      var i;
      for (i = 0; i < count; i++) {
        len = (len * 256) + set.buf[p + i];
      }
      p += count + len;
    } else {
      p += first;
    }
  }

  return set;
};

// SET OF: members of one type, ordered by their COMPLETE ENCODINGS
// compared as octet strings - X.690 11.6.
//
// ⚠ A SEPARATE METHOD BECAUSE IT IS A SEPARATE RULE. Modules were reading
// SET OF - CMS signedAttrs, attribute values, recipientInfos, PKCS#12 bag
// attributes - with read_set, which checks only that TAGS ascend. Every
// member of a SET OF has the same tag, so nothing was checked at all, and
// the duplicate-tag rule a real SET needs could not be added to read_set
// without breaking them. Now each reads with the method for what it is.
//
// The order matters most in signedAttrs: the signature covers the DER
// encoding, and a SET OF in another order is a second encoding of the
// same attributes.
Reader.prototype.read_set_of = function () {
  var set = this._read_tlv(T.SET);
  var probe = new Reader(set.buf, set.pos, set.end);
  var previous = null;

  while (probe.pos < probe.end) {
    var at = probe.pos;
    var member = probe.capture();

    if (previous !== null && compare(previous, member) > 0) {
      fail(at, 'set-of-not-ordered',
        'SET OF members are not in ascending encoding order');
    }
    previous = member;
  }

  return set;
};

// ⚠ DELIBERATELY NOT SHARED - see src/commons/README.md. The reader-side
// twin of der_writer's sort, kept separate so one mistake cannot make the
// writer emit an order that this accepts and nobody else does.
function compare(a, b) {
  var n = Math.min(a.length, b.length);
  var i;
  for (i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

// X.690 11.5 orders by tag class first, then by tag number. Comparing the
// identifier octets directly gets that wrong for context tags, whose class
// bits sit above the number.
function compare_set_tags(a, b) {
  if (b === -1) {
    return 1;
  }

  var class_a = a & T.CLASS_MASK;
  var class_b = b & T.CLASS_MASK;

  if (class_a !== class_b) {
    return class_a - class_b;
  }
  return (a & T.NUMBER_MASK) - (b & T.NUMBER_MASK);
}

// ---------------------------------------------------------------------------
// Primitive types
// ---------------------------------------------------------------------------

// Returned as bytes, not as a number. The original encoding is what canonical
// form is checked against, and a superfluous leading 0x00 is invisible once
// the value has become a number. cryptographic-primitives takes bytes in any case.
Reader.prototype.read_integer = function () {
  var v     = this._read_value(T.INTEGER);
  var bytes = v.bytes;

  if (bytes.length === 0) {
    fail(v.start, 'empty-integer', 'INTEGER has no content octets');
  }

  if (bytes.length > 1) {
    // DER integers are two's complement. A leading 0x00 is required only when
    // the next octet's high bit would otherwise read as a sign bit; a leading
    // 0xFF is required only when the next octet's high bit is clear. Anything
    // else is padding, and padding gives one value two encodings.
    if (bytes[0] === 0x00 && (bytes[1] & 0x80) === 0) {
      fail(v.start, 'non-minimal-integer',
        'INTEGER has a superfluous leading 0x00');
    }
    if (bytes[0] === 0xFF && (bytes[1] & 0x80) !== 0) {
      fail(v.start, 'non-minimal-integer',
        'INTEGER has a superfluous leading 0xFF');
    }
  }

  return bytes;
};

// Unsigned integers appear throughout - serial numbers, moduli, versions. A
// negative value where the structure means an unsigned quantity is malformed,
// and the leading 0x00 that DER requires for large unsigned values is
// stripped here so callers are not left to guess whether it is part of the
// value.
Reader.prototype.read_unsigned = function () {
  var start = this.pos;
  var bytes = this.read_integer();

  if ((bytes[0] & 0x80) !== 0) {
    fail(start, 'negative-integer',
      'INTEGER is negative where an unsigned value is required');
  }

  if (bytes.length > 1 && bytes[0] === 0x00) {
    return bytes.subarray(1);
  }
  return bytes;
};

// ENUMERATED has INTEGER's content rules and its own tag. Reading one with
// read_integer would refuse a valid structure on a tag mismatch, and reading
// an INTEGER with this would accept the wrong type - so it is a separate
// method rather than a relaxation of the other.
Reader.prototype.read_enumerated = function () {
  var v = this._read_value(T.ENUMERATED);
  var bytes = v.bytes;

  if (bytes.length === 0) {
    fail(v.start, 'empty-integer', 'ENUMERATED has no content octets');
  }
  if (bytes.length > 1) {
    if (bytes[0] === 0x00 && (bytes[1] & 0x80) === 0) {
      fail(v.start, 'non-minimal-integer',
        'ENUMERATED has a superfluous leading 0x00');
    }
    if (bytes[0] === 0xFF && (bytes[1] & 0x80) !== 0) {
      fail(v.start, 'non-minimal-integer',
        'ENUMERATED has a superfluous leading 0xFF');
    }
  }

  return bytes;
};

Reader.prototype.read_boolean = function () {
  var v = this._read_value(T.BOOLEAN);

  if (v.bytes.length !== 1) {
    fail(v.start, 'bad-boolean',
      'BOOLEAN must have exactly one content octet, got ' + v.bytes.length);
  }

  // BER lets any non-zero octet mean true. DER fixes true at 0xFF, so that
  // true has one encoding rather than 255.
  if (v.bytes[0] === 0x00) {
    return false;
  }
  if (v.bytes[0] === 0xFF) {
    return true;
  }
  fail(v.start, 'non-canonical-boolean',
    'BOOLEAN true must be 0xFF in DER, got 0x' + v.bytes[0].toString(16));
};

Reader.prototype.read_null = function () {
  var v = this._read_value(T.NULL);
  if (v.bytes.length !== 0) {
    fail(v.start, 'bad-null',
      'NULL must have no content octets, got ' + v.bytes.length);
  }
  return null;
};

Reader.prototype.read_octet_string = function () {
  // A constructed OCTET STRING - the value split across segments - is BER.
  // DER requires the primitive form, and accepting both gives one byte string
  // an unbounded number of encodings.
  if (this.peek_tag() === (T.OCTET_STRING | T.CONSTRUCTED)) {
    fail(this.pos, 'constructed-string',
      'constructed OCTET STRING is BER, not DER');
  }
  return this._read_value(T.OCTET_STRING).bytes;
};

// Returns the bit string's payload with the unused-bits octet removed, plus
// the count itself, because for some fields the count is meaningful and for
// others any non-zero value is malformed. The caller decides which it is.
Reader.prototype.read_bit_string = function () {
  if (this.peek_tag() === (T.BIT_STRING | T.CONSTRUCTED)) {
    fail(this.pos, 'constructed-string',
      'constructed BIT STRING is BER, not DER');
  }

  var v     = this._read_value(T.BIT_STRING);
  var bytes = v.bytes;

  if (bytes.length === 0) {
    fail(v.start, 'bad-bit-string',
      'BIT STRING is missing its unused-bits octet');
  }

  var unused = bytes[0];

  if (unused > 7) {
    fail(v.start, 'bad-bit-string',
      'BIT STRING claims ' + unused + ' unused bits, maximum is 7');
  }

  if (bytes.length === 1 && unused !== 0) {
    fail(v.start, 'bad-bit-string',
      'empty BIT STRING cannot have unused bits');
  }

  if (unused > 0) {
    // DER requires the unused bits to be zero. If they are not, the same bit
    // sequence has more than one encoding - the padding carries attacker
    // data that no consumer will look at.
    var mask = (1 << unused) - 1;
    if ((bytes[bytes.length - 1] & mask) !== 0) {
      fail(v.start, 'non-zero-padding',
        'BIT STRING unused bits are not zero');
    }
  }

  return { bytes: bytes.subarray(1), unused: unused };
};

// Returned as encoding bytes, not as a dotted string. Comparison against a
// known OID is then a byte comparison, and the original encoding is preserved
// so that a non-minimal one can be refused. oid.js provides the dotted form
// for error messages and output.
Reader.prototype.read_oid = function () {
  var v     = this._read_value(T.OID);
  var bytes = v.bytes;
  var i;

  if (bytes.length === 0) {
    fail(v.start, 'empty-oid', 'OBJECT IDENTIFIER has no content octets');
  }

  // Sub-identifiers are base-128, high bit set on every octet but the last.
  // The final octet of the whole value must therefore end a sub-identifier.
  if ((bytes[bytes.length - 1] & 0x80) !== 0) {
    fail(v.start, 'truncated-oid',
      'OBJECT IDENTIFIER ends mid sub-identifier');
  }

  // A sub-identifier starting with 0x80 has a leading zero in base 128 - the
  // same value written wider. One OID, two encodings.
  var starting = true;
  for (i = 0; i < bytes.length; i++) {
    if (starting && bytes[i] === 0x80) {
      fail(v.start, 'non-minimal-oid',
        'OBJECT IDENTIFIER sub-identifier has a leading 0x80');
    }
    starting = (bytes[i] & 0x80) === 0;
  }

  return bytes;
};

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

// All three string types are returned DECODED to a JavaScript string, unlike
// integers and OIDs, because there is no canonical-form question left once
// the character set has been validated - a PrintableString either holds
// permitted characters or it does not.
//
// The constructed form is BER and is refused, same as for OCTET STRING.

Reader.prototype.read_utf8_string = function () {
  if (this.peek_tag() === (T.UTF8_STRING | T.CONSTRUCTED)) {
    fail(this.pos, 'constructed-string',
      'constructed UTF8String is BER, not DER');
  }
  var v = this._read_value(T.UTF8_STRING);
  return decode_utf8(v.bytes, fail, v.start);
};

// X.680 table 10: A-Z a-z 0-9 space and ' ( ) + , - . / : = ?
// Nothing else. An ampersand or an underscore in a PrintableString is a
// different string type wearing the wrong tag, and X.509 name comparison
// depends on the type as well as the value.
//
// ⚠ THE CHARACTER-SET RULES ARE PREDICATES, read_* AND x509.attribute_text
// BOTH USE THEM. attribute_text asks first and so never throws for a value
// it then reads leniently: an exception, with its stack, cost 4-5us - five
// times the read (DECISIONS 41).
var PRINTABLE_BYTE = new Uint8Array(256);
(function () {
  var i;
  for (i = 0x41; i <= 0x5A; i++) { PRINTABLE_BYTE[i] = 1; }   // A-Z
  for (i = 0x61; i <= 0x7A; i++) { PRINTABLE_BYTE[i] = 1; }   // a-z
  for (i = 0x30; i <= 0x39; i++) { PRINTABLE_BYTE[i] = 1; }   // 0-9
  var marks = " '()+,-./:=?";
  for (i = 0; i < marks.length; i++) { PRINTABLE_BYTE[marks.charCodeAt(i)] = 1; }
}());

function is_printable(bytes) {
  for (var i = 0; i < bytes.length; i++) {
    if (PRINTABLE_BYTE[bytes[i]] === 0) { return false; }
  }
  return true;
}

function is_ia5(bytes) {
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] > 0x7F) { return false; }
  }
  return true;
}

function is_visible(bytes) {
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] < 0x20 || bytes[i] > 0x7E) { return false; }
  }
  return true;
}

function is_numeric(bytes) {
  for (var i = 0; i < bytes.length; i++) {
    if (!(bytes[i] === 0x20 || (bytes[i] >= 0x30 && bytes[i] <= 0x39))) { return false; }
  }
  return true;
}

// The four restricted 8-bit types share one shape: primitive only - a
// constructed one is BER - then every byte in the type's set, then the
// bytes as Latin-1.
function read_restricted(r, tag, ok, label, code, rule) {
  if (r.peek_tag() === (tag | T.CONSTRUCTED)) {
    fail(r.pos, 'constructed-string', 'constructed ' + label + ' is BER, not DER');
  }
  var v = r._read_value(tag);
  if (!ok(v.bytes)) {
    fail(v.start, code, label + ' ' + rule);
  }
  return latin1(v.bytes);
}

Reader.prototype.read_printable_string = function () {
  return read_restricted(this, T.PRINTABLE_STRING, is_printable, 'PrintableString',
    'bad-printable-string', 'contains characters outside its character set');
};

Reader.prototype.read_ia5_string = function () {
  return read_restricted(this, T.IA5_STRING, is_ia5, 'IA5String',
    'bad-ia5-string', 'contains a byte above 0x7F');
};



// BMPString is UTF-16 BIG ENDIAN, not UTF-8 and not UTF-16LE. PKCS#12 uses
// it for friendlyName, so a container reader without this cannot report what
// a key is called - and reading it as UTF-8 produces a string full of null
// bytes that looks like corruption rather than a wrong decoder.
Reader.prototype.read_bmp_string = function () {
  if (this.peek_tag() === (T.BMP_STRING | T.CONSTRUCTED)) {
    fail(this.pos, 'constructed-string',
      'constructed BMPString is BER, not DER');
  }

  var v = this._read_value(T.BMP_STRING);

  if (v.bytes.length % 2 !== 0) {
    fail(v.start, 'bad-bmp-string',
      'BMPString is UTF-16, so its length must be even, got ' +
      v.bytes.length);
  }

  var s = '';
  var i;

  for (i = 0; i < v.bytes.length; i += 2) {
    var unit = (v.bytes[i] << 8) | v.bytes[i + 1];

    // A lone surrogate cannot be re-encoded and would come back as U+FFFD,
    // so the value that was checked and the value that is used would differ.
    if (unit >= 0xD800 && unit <= 0xDBFF) {
      var low = i + 3 < v.bytes.length
        ? (v.bytes[i + 2] << 8) | v.bytes[i + 3]
        : 0;
      if (!(low >= 0xDC00 && low <= 0xDFFF)) {
        fail(v.start, 'lone-surrogate',
          'BMPString has a high surrogate with no low surrogate after it');
      }
      s += String.fromCharCode(unit) + String.fromCharCode(low);
      i += 2;
      continue;
    }
    if (unit >= 0xDC00 && unit <= 0xDFFF) {
      fail(v.start, 'lone-surrogate',
        'BMPString has a low surrogate with no high surrogate before it');
    }

    s += String.fromCharCode(unit);
  }

  return s;
};

// T61String, also called TeletexString. RFC 5280 deprecates it and real
// certificates from before that still carry it, so refusing to read one
// means a subject name that compares unequal to itself.
//
// Decoded as T.61 (commons/t61.js): its own table for the high half - 0xE9
// is "Ø" - and accents that come BEFORE their letter; an ISO 2022 escape
// sequence is refused. OpenSSL reads the same bytes as Latin-1 (0xE9 "é");
// x509.attribute_text with { lenient: true } does too. The two agree on
// ASCII. (This said "decoded as Latin-1" after the decoder had become
// T.61.)
Reader.prototype.read_t61_string = function () {
  if (this.peek_tag() === (T.T61_STRING | T.CONSTRUCTED)) {
    fail(this.pos, 'constructed-string',
      'constructed T61String is BER, not DER');
  }

  var v = this._read_value(T.T61_STRING);
  return decode_t61(v.bytes, fail, v.start);
};

// VisibleString is ASCII 0x20 to 0x7E: printable, no control characters.
Reader.prototype.read_visible_string = function () {
  return read_restricted(this, T.VISIBLE_STRING, is_visible, 'VisibleString',
    'bad-visible-string', 'contains a byte outside 0x20 to 0x7E');
};

// NumericString is digits and space, nothing else.
Reader.prototype.read_numeric_string = function () {
  return read_restricted(this, T.NUMERIC_STRING, is_numeric, 'NumericString',
    'bad-numeric-string', 'allows digits and space only');
};

// UniversalString is UCS-4: four bytes per code point, big endian. Rare, and
// the only one of these that is not a byte-per-character encoding.
Reader.prototype.read_universal_string = function () {
  var v = this._read_value(T.UNIVERSAL_STRING);

  if (v.bytes.length % 4 !== 0) {
    fail(v.start, 'bad-universal-string',
      'UniversalString is UCS-4, so its length must be a multiple of 4');
  }

  var s = '';
  var i;

  for (i = 0; i < v.bytes.length; i += 4) {
    var cp = (v.bytes[i] * 0x1000000) + (v.bytes[i + 1] << 16) +
             (v.bytes[i + 2] << 8) + v.bytes[i + 3];

    if (cp > 0x10FFFF) {
      fail(v.start, 'bad-universal-string',
        'code point above U+10FFFF at offset ' + i);
    }
    if (cp >= 0xD800 && cp <= 0xDFFF) {
      fail(v.start, 'bad-universal-string',
        'UniversalString encodes a surrogate code point');
    }

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

// GraphicString, GeneralString and VideotexString. All deprecated by RFC
// 5280 and all present in older certificates.
//
// Their true character sets are ISO 2022 escape-sequence encodings that
// almost nobody implemented; in practice these fields hold Latin-1, and that
// is what is decoded. A value with escape sequences in it comes back wrong
// and there is no way to tell from the bytes - the same caveat as T61String,
// and the same reason: refusing to read one means a subject name that
// compares unequal to itself.
Reader.prototype.read_graphic_string = function () {
  return latin1(this._read_value(T.GRAPHIC_STRING).bytes);
};

Reader.prototype.read_general_string = function () {
  return latin1(this._read_value(T.GENERAL_STRING).bytes);
};

Reader.prototype.read_videotex_string = function () {
  return latin1(this._read_value(T.VIDEOTEX_STRING).bytes);
};

// Reads whichever string type is present, for fields whose syntax is a
// DirectoryString CHOICE - an X.509 attribute value can be any of five.
// Returns the text and the tag it came in as, because in X.509 name
// comparison the TYPE is part of the value.
Reader.prototype.read_any_string = function () {
  var tag = this.peek_tag();

  if (tag === T.UTF8_STRING) {
    return { type: 'utf8', value: this.read_utf8_string() };
  }
  if (tag === T.PRINTABLE_STRING) {
    return { type: 'printable', value: this.read_printable_string() };
  }
  if (tag === T.IA5_STRING) {
    return { type: 'ia5', value: this.read_ia5_string() };
  }
  if (tag === T.BMP_STRING) {
    return { type: 'bmp', value: this.read_bmp_string() };
  }
  if (tag === T.T61_STRING) {
    return { type: 't61', value: this.read_t61_string() };
  }
  if (tag === T.VISIBLE_STRING) {
    return { type: 'visible', value: this.read_visible_string() };
  }
  if (tag === T.NUMERIC_STRING) {
    return { type: 'numeric', value: this.read_numeric_string() };
  }
  if (tag === T.UNIVERSAL_STRING) {
    return { type: 'universal', value: this.read_universal_string() };
  }
  if (tag === T.GRAPHIC_STRING) {
    return { type: 'graphic', value: this.read_graphic_string() };
  }
  if (tag === T.GENERAL_STRING) {
    return { type: 'general', value: this.read_general_string() };
  }
  if (tag === T.VIDEOTEX_STRING) {
    return { type: 'videotex', value: this.read_videotex_string() };
  }

  fail(this.pos, 'unexpected-tag',
    'expected a string type, got ' +
    (tag === null ? 'end of input' : T.name_of(tag)));
};

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

// DER fixes one form for each time type. X.690 11.7 and 11.8 remove
// everything BER allows: no local-time offsets, no omitted seconds, no
// fractional part that is zero or that ends in zero. Every relaxation there
// is another spelling of one instant.
//
// Returned as components plus a Date built with Date.UTC, never by parsing
// the string with the Date constructor - `new Date('990101...')` is
// implementation-defined and applies the local zone.

var UTC_PATTERN  = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
// ⚠ A FRACTION IS DER, AS LONG AS IT IS MINIMAL.
//
// X.690 11.7 says what the comment above says: a fractional part that is
// zero, or that ends in zero, is refused - which means one that does NOT is
// allowed. The first pattern allowed none at all, and RFC 3161 timestamps
// use them: its own example genTime is 19990609001326.34352Z. Every
// timestamp authority that writes milliseconds was refused.
var GEN_PATTERN  =
  /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d*[1-9]))?Z$/;

Reader.prototype.read_utc_time = function () {
  var v = this._read_value(T.UTC_TIME);
  var s = latin1(v.bytes);
  var m = UTC_PATTERN.exec(s);

  if (m === null) {
    fail(v.start, 'bad-utc-time',
      'UTCTime must be YYMMDDHHMMSSZ in DER, got "' + s + '"');
  }

  // RFC 5280 4.1.2.5.1: a two-digit year of 50 or more is 19xx, below 50 is
  // 20xx. Guessing differently puts a certificate a century out, and the
  // error looks like a clock problem rather than a parsing one.
  var yy = parseInt(m[1], 10);
  var year = yy >= 50 ? 1900 + yy : 2000 + yy;

  return build_time(year, m, v.start, 'UTCTime');
};

Reader.prototype.read_generalized_time = function () {
  var v = this._read_value(T.GENERALIZED_TIME);
  var s = latin1(v.bytes);
  var m = GEN_PATTERN.exec(s);

  if (m === null) {
    fail(v.start, 'bad-generalized-time',
      'GeneralizedTime must be YYYYMMDDHHMMSS[.fff]Z in DER, with no ' +
      'trailing zero in the fraction, got "' + s + '"');
  }

  var t = build_time(parseInt(m[1], 10), m, v.start, 'GeneralizedTime');

  // The fraction as written, digit for digit - a Date holds milliseconds
  // and RFC 3161 permits more, so the string is the exact value and the
  // Date is the nearest millisecond below it.
  t.fraction = m[7] === undefined ? null : m[7];

  if (t.fraction !== null) {
    var ms = parseInt((t.fraction + '00').substring(0, 3), 10);
    t.date = new Date(t.date.getTime() + ms);
  }

  return t;
};

// The X.509 Time CHOICE. RFC 5280 4.1.2.5 requires UTCTime through 2049 and
// GeneralizedTime from 2050, so which type appears is itself information -
// and a GeneralizedTime holding a pre-2050 date is a second encoding of a
// date that had a required form.
Reader.prototype.read_time = function () {
  var tag = this.peek_tag();

  if (tag === T.UTC_TIME) {
    return this.read_utc_time();
  }
  if (tag === T.GENERALIZED_TIME) {
    var start = this.pos;
    var t = this.read_generalized_time();

    // RFC 5280 4.1.2.5.2 and RFC 5652 11.3: the Time CHOICE carries whole
    // seconds. A fraction here is not a second spelling of a permitted
    // value - it is a value the profile cannot hold.
    if (t.fraction !== null) {
      fail(start, 'fractional-seconds',
        'a certificate or CMS Time carries whole seconds; this one has .' +
        t.fraction);
    }

    // ⚠ READ, AND MARKED - NOT REFUSED. CORRECTED AFTER A REAL ROOT FAILED.
    //
    // RFC 5280 says a CA MUST use UTCTime through 2049, and this used to
    // throw on a GeneralizedTime holding an earlier date. Then the system
    // trust store was run through x509.from_der, and "Certum Trusted Network
    // CA 2" - a root Mozilla still ships - was refused. Every TLS stack
    // accepts it.
    //
    // The refusal protected nothing. The worry with a second encoding is
    // that a re-encode changes the signed bytes, and this library never
    // re-encodes: tbs_bytes is the slice. So the date is read, and the
    // violation is RECORDED where a caller who cares can see it - x509.js
    // lists it in the certificate's `warnings`.
    if (t.year < 2050) {
      t.profile_violation = 'generalized-time-before-2050';
    }
    return t;
  }

  fail(this.pos, 'unexpected-tag',
    'expected UTCTime or GeneralizedTime, got ' + T.name_of(tag));
};

function build_time(year, m, pos, what) {
  var month  = parseInt(m[2], 10);
  var day    = parseInt(m[3], 10);
  var hour   = parseInt(m[4], 10);
  var minute = parseInt(m[5], 10);
  var second = parseInt(m[6], 10);

  if (month < 1 || month > 12) {
    fail(pos, 'bad-time', what + ' has month ' + month);
  }
  if (day < 1 || day > days_in_month(year, month)) {
    fail(pos, 'bad-time',
      what + ' has day ' + day + ' in a month with ' +
      days_in_month(year, month));
  }
  if (hour > 23) {
    fail(pos, 'bad-time', what + ' has hour ' + hour);
  }
  if (minute > 59) {
    fail(pos, 'bad-time', what + ' has minute ' + minute);
  }
  // 60 would be a leap second. X.690 does not provide for one and Date.UTC
  // would silently roll it into the next minute, so it is refused rather
  // than absorbed.
  if (second > 59) {
    fail(pos, 'bad-time', what + ' has second ' + second);
  }

  return {
    year: year, month: month, day: day,
    hour: hour, minute: minute, second: second,
    date: new Date(Date.UTC(year, month - 1, day, hour, minute, second))
  };
}

function days_in_month(year, month) {
  if (month === 2) {
    var leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  if (month === 4 || month === 6 || month === 9 || month === 11) {
    return 30;
  }
  return 31;
}

// ---------------------------------------------------------------------------
// Context-specific tagging
// ---------------------------------------------------------------------------

// [n] EXPLICIT wraps the original value: the context tag is constructed, and
// the real tag is inside. Returns a reader bounded to the wrapper's content.
Reader.prototype.read_explicit = function (n) {
  var tag = T.CLASS_CONTEXT | T.CONSTRUCTED | n;
  return this._read_tlv(tag);
};

// [n] IMPLICIT REPLACES the original tag, so the reader has no way to know
// from the bytes what is inside - the expected type must be supplied. This is
// why implicit tagging cannot be handled generically and why field tables
// carry the type: getting it wrong reads the right bytes as the wrong thing.
Reader.prototype.read_implicit = function (n, base_tag) {
  var constructed = (base_tag & T.CONSTRUCTED) !== 0;
  var tag = T.CLASS_CONTEXT | n | (constructed ? T.CONSTRUCTED : 0);

  var start = this.pos;
  this._read_tag(tag);
  var length = this._read_length();

  if (constructed) {
    var child = new Reader(this.buf, this.pos, this.pos + length);
    this.pos += length;
    return child;
  }

  var bytes = this.buf.subarray(this.pos, this.pos + length);
  this.pos += length;
  return { bytes: bytes, start: start };
};

// ---------------------------------------------------------------------------
// REAL
// ---------------------------------------------------------------------------

// The encoding lives in real.js, which is where its three forms and DER's
// restrictions on them are set out. Zero is the EMPTY content octets, which
// is the one value with no bytes at all.
Reader.prototype.read_real = function () {
  var v = this._read_value(T.REAL);
  return REAL.decode(v.bytes, v.start, true);
};

// ---------------------------------------------------------------------------
// RELATIVE-OID
// ---------------------------------------------------------------------------

// An OID fragment, relative to a base stated elsewhere in the protocol. Same
// base-128 encoding as an absolute OID, but WITHOUT the first two arcs being
// packed into one sub-identifier - which is exactly the difference that
// makes reading one with read_oid produce a plausible wrong answer.
Reader.prototype.read_relative_oid = function () {
  var v = this._read_value(T.RELATIVE_OID);
  var bytes = v.bytes;

  if (bytes.length === 0) {
    fail(v.start, 'empty-oid', 'RELATIVE-OID has no content octets');
  }
  if ((bytes[bytes.length - 1] & 0x80) !== 0) {
    fail(v.start, 'truncated-oid', 'RELATIVE-OID ends mid sub-identifier');
  }

  var starting = true;
  var i;
  for (i = 0; i < bytes.length; i++) {
    if (starting && bytes[i] === 0x80) {
      fail(v.start, 'non-minimal-oid',
        'RELATIVE-OID sub-identifier has a leading 0x80');
    }
    starting = (bytes[i] & 0x80) === 0;
  }

  return bytes;
};

// ---------------------------------------------------------------------------
// The structured and remaining types
// ---------------------------------------------------------------------------

// ObjectDescriptor is a GraphicString carrying a human-readable name for an
// object identifier.
Reader.prototype.read_object_descriptor = function () {
  return latin1(this._read_value(T.OBJECT_DESCRIPTOR).bytes);
};

// EXTERNAL and EMBEDDED PDV both carry a value whose type is agreed out of
// band, with an identification of that type alongside. Their inner structure
// depends on a negotiation this library cannot see, so the components are
// returned rather than interpreted - which is the same treatment ANY gets,
// and for the same reason.
//
//   EXTERNAL ::= SEQUENCE {
//        direct-reference       OBJECT IDENTIFIER OPTIONAL,
//        indirect-reference     INTEGER OPTIONAL,
//        data-value-descriptor  ObjectDescriptor OPTIONAL,
//        encoding               CHOICE {
//            single-ASN1-type  [0] ANY,
//            octet-aligned     [1] IMPLICIT OCTET STRING,
//            arbitrary         [2] IMPLICIT BIT STRING } }
Reader.prototype.read_external = function () {
  var seq = this._read_tlv(T.EXTERNAL);
  var out = {
    direct: null, indirect: null, descriptor: null,
    encoding: null, value: null
  };

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

// CHARACTER STRING carries a string in a character set identified alongside,
// which is why the bytes come back undecoded: only the identification says
// how to read them.
Reader.prototype.read_character_string = function () {
  var seq = this._read_tlv(T.CHARACTER_STRING);
  var identification = seq.capture();
  var value = seq.read_octet_string();
  seq.expect_end();
  return { identification: identification, value: value };
};

// X.680 (2015) TIME and DATE. Text, in the formats those clauses define.
// Returned as strings rather than parsed into components, because the TIME
// type's syntax is a whole grammar and nothing on this library's format list
// uses it - reading it is what matters, interpreting it is the caller's.
Reader.prototype.read_time_string = function () {
  return latin1(this._read_value(T.TIME).bytes);
};

// ⚠ DATE is tag number 31, which X.690 8.1.2.4.1 reserves as the escape into
// the multi-octet form - so it is the one universal type this reader cannot
// reach through _read_value, and the identifier is 1F 1F rather than 1F.
//
// Handled here rather than by relaxing the high-tag-number refusal: that
// refusal exists because a multi-octet tag can encode an arbitrarily large
// number, and opening it generally would be a different decision from
// supporting one specific type.
Reader.prototype.read_date = function () {
  var start = this.pos;

  if (this.pos + 1 >= this.end ||
      this.buf[this.pos] !== 0x1F || this.buf[this.pos + 1] !== 0x1F) {
    fail(this.pos, 'unexpected-tag',
      'expected DATE, whose identifier octets are 1F 1F');
  }

  this.pos += 2;
  var length = this._read_length();
  var bytes = this.buf.subarray(this.pos, this.pos + length);
  this.pos += length;

  return latin1(bytes);
};

// ---------------------------------------------------------------------------
// Multi-octet tag numbers
// ---------------------------------------------------------------------------

// ⚠ READ ON REQUEST, NEVER BY DEFAULT.
//
// X.690 8.1.2.4: a tag number of 31 or more is written as 0x1F followed by
// base-128 octets. This reader refuses that form everywhere else, and that
// refusal stays: nothing in this library's format list uses one, and a tag
// number arriving from an unknown structure is a value with no upper bound.
//
// But level 0 exists for structures this library does not describe, and a
// reader exported for that purpose which cannot express a tag the encoding
// permits sends its caller to a permissive parser. DATE already forced a
// special case for exactly this reason - its number is 31, the escape value
// itself.
//
// So it is a named method. A caller who reaches for it has decided to.
//
// Found by comparing against Lapo Luchini's decoder, which reads them.
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

    // A leading 0x80 is a superfluous zero group - the same non-minimal
    // form an OID sub-identifier is refused for, and for the same reason.
    if (octets === 1 && b === 0x80) {
      fail(start, 'non-minimal-tag',
        'the tag number has a leading 0x80');
    }

    if (octets > 4) {
      // Beyond four groups the number exceeds 2^28, which is past anything
      // an application assigns and past what this reader will hold.
      fail(start, 'tag-number-too-large',
        'tag number of more than four octets');
    }

    number = (number * 128) + (b & 0x7F);

    if ((b & 0x80) === 0) {
      break;
    }
  }

  if (number < 31) {
    // The low form would have held it, so writing it long is a second
    // encoding of the same tag.
    fail(start, 'non-minimal-tag',
      'tag number ' + number + ' fits the single-octet form');
  }

  var length = this._read_length();
  var constructed = (first & T.CONSTRUCTED) !== 0;

  var out = {
    class_: first & T.CLASS_MASK,
    number: number,
    constructed: constructed
  };

  if (constructed) {
    out.content = new Reader(this.buf, this.pos, this.pos + length);
  } else {
    out.bytes = this.buf.subarray(this.pos, this.pos + length);
  }

  this.pos += length;
  return out;
};

// Whether the value at the cursor uses the multi-octet form, so a caller can
// decide before committing to a reader.
// Consumes a context-tagged value and returns its CONTENT - the bytes after
// the header, with the tag and length gone.
//
// Used for IMPLICIT `raw` fields, where the caller will decide what the bytes
// are and the context tag carries no information they need.
Reader.prototype.capture_tagged = function (n) {
  var expected = T.CLASS_CONTEXT | n;
  var tag = this.peek_tag();

  if (tag === null) {
    fail(this.pos, 'truncated', 'expected [' + n + '], input ended');
  }

  if ((tag & ~T.CONSTRUCTED) !== expected) {
    fail(this.pos, 'unexpected-tag',
      'expected [' + n + '], got ' + T.name_of(tag));
  }

  this.pos += 1;
  var length = this._read_length();
  var bytes = this.buf.subarray(this.pos, this.pos + length);
  this.pos += length;

  return bytes;
};

Reader.prototype.is_high_tag = function () {
  return this.pos < this.end &&
         (this.buf[this.pos] & T.NUMBER_MASK) === T.HIGH_TAG_NUMBER;
};

// ---------------------------------------------------------------------------
// Other tag classes
// ---------------------------------------------------------------------------

// APPLICATION and PRIVATE class tags. Nothing in this library's format list
// uses one - PKIX is context tags throughout - but they appear in ASN.1
// outside cryptography, and a reader that cannot express them sends anyone
// who needs one to a permissive parser.
//
// Constructed and primitive are separate methods rather than one that
// guesses, because the constructed bit is part of the tag and a caller who
// does not know which they have does not know what they are reading.
Reader.prototype.read_application = function (n, constructed) {
  var tag = T.CLASS_APPLICATION | n | (constructed ? T.CONSTRUCTED : 0);
  return constructed
    ? this._read_tlv(tag)
    : this._read_primitive_class(tag);
};

Reader.prototype.read_private = function (n, constructed) {
  var tag = T.CLASS_PRIVATE | n | (constructed ? T.CONSTRUCTED : 0);
  return constructed
    ? this._read_tlv(tag)
    : this._read_primitive_class(tag);
};

Reader.prototype._read_primitive_class = function (tag) {
  var v = this._read_value(tag);
  return v.bytes;
};

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

// Reads one complete value and returns its bytes without interpreting them.
//
// The same operation fields.capture performs, exposed as a method so that
// code written against a reader does not have to know which module the
// helper lives in - ber_reader has it as a method, and a caller switching
// between the two should not have to switch call shapes as well.
//
// Needed wherever the ORIGINAL bytes matter: a signed portion, an ANY whose
// content depends on an OID read elsewhere.
Reader.prototype.capture = function () {
  var start = this.pos;

  if (this.pos >= this.end) {
    fail(this.pos, 'truncated', 'expected a value, input ended');
  }

  // ⚠ capture() takes whatever tag is there, which is the point - it is how
  // an ANY is read. But two universal tags are not values at all, and
  // accepting them means an ANY can swallow bytes that mean something else.
  //
  //   0x00  the end-of-contents marker. It only exists in BER, where it
  //         closes an indefinite length, and reading one here would consume
  //         the terminator of a structure this reader has already refused.
  //   0x0F  reserved by X.680 and assigned to nothing.
  //
  // Found by a clause-by-clause audit of X.690: every other refusal was in
  // place and these two were reachable through capture alone.
  var tag = this.buf[this.pos];

  if (tag === 0x00) {
    fail(this.pos, 'end-of-contents',
      'tag 0x00 is the BER end-of-contents marker, which is not a value');
  }
  if ((tag & T.CLASS_MASK) === T.CLASS_UNIVERSAL &&
      (tag & T.NUMBER_MASK) === 0x0F) {
    fail(this.pos, 'reserved-tag',
      'universal tag 15 is reserved by X.680 and assigned to nothing');
  }

  this._read_tag(tag);
  var length = this._read_length();
  this.pos += length;

  return this.buf.subarray(start, this.pos);
};

// ---------------------------------------------------------------------------
// Finishing
// ---------------------------------------------------------------------------

// Trailing data is the failure that a happy-path test never sees: every field
// the caller wanted was present and correct, and something else was there
// too. node-forge accepted forged RSA signatures because the DigestInfo
// parser stopped once it had what it came for.
Reader.prototype.expect_end = function () {
  if (this.pos < this.end) {
    fail(this.pos, 'trailing-bytes',
      (this.end - this.pos) + ' unconsumed byte(s)');
  }
};

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------


// The bare reader. Nothing calls expect_end for you, which is the correct
// behaviour when a caller is reading one value out of a larger buffer - but
// it means forgetting the call is possible. Prefer read() below.
function reader(input) {
  var bytes = to_bytes(input);
  return new Reader(bytes, 0, bytes.length);
}

// The form to reach for. The end check happens whether or not the callback
// remembers it, so trailing bytes after the top-level value are always
// caught.
function read(input, fn) {
  var r = reader(input);
  var result = fn(r);
  r.expect_end();
  return result;
}

export {
  reader,
  read,
  Reader,
  is_printable,
  is_ia5,
  is_visible,
  is_numeric
};

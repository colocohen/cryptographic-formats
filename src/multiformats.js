// multihash and multibase, the multiformats specifications.
//
// Both solve the same problem in different layers: a byte string that says
// what it is, so a consumer does not have to be told out of band.
//
//   multihash   <varint code><varint length><digest>
//   multibase   <one prefix character><base-encoded data>
//
// ⚠ NEITHER IS SELF-VALIDATING, AND BOTH LOOK AS IF THEY ARE.
//
// A multihash says "this is SHA-256, 32 bytes" and carries 32 bytes. It does
// NOT say those bytes are the SHA-256 of anything, and a consumer who reads
// the header as a guarantee has read a claim as a fact. Verifying means
// hashing the content and comparing, which is the caller's step - so
// `digest_matches` exists and nothing here calls it.
//
// The length field is the same trap one level down: it is a CLAIM about the
// digest that follows, and a multihash whose stated length disagrees with the
// bytes present is malformed. That IS checked, because it is a statement
// about the encoding rather than about the world.

import * as B from './base.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, bytes_equal } from './commons/bytes.js';
import { latin1 } from './commons/decode_text.js';

var fail = make_fail_here('multiformats');

// ---------------------------------------------------------------------------
// The tables
// ---------------------------------------------------------------------------

// From the multicodec table. Only the hash functions, and only the ones a
// consumer is likely to meet - the full table is several hundred entries of
// which most are not hashes at all.
//
// `size` is the function's NATURAL output length. A multihash may state a
// shorter one, which is a legitimate truncation, so the check is `<=` rather
// than equality - see read().
var CODES = {
  0x00: { name: 'identity', size: null },
  0x11: { name: 'sha1',     size: 20 },
  0x12: { name: 'sha2-256', size: 32 },
  0x13: { name: 'sha2-512', size: 64 },
  0x14: { name: 'sha3-512', size: 64 },
  0x15: { name: 'sha3-384', size: 48 },
  0x16: { name: 'sha3-256', size: 32 },
  0x17: { name: 'sha3-224', size: 28 },
  0x18: { name: 'shake-128', size: null },
  0x19: { name: 'shake-256', size: null },
  0x1a: { name: 'keccak-224', size: 28 },
  0x1b: { name: 'keccak-256', size: 32 },
  0x1c: { name: 'keccak-384', size: 48 },
  0x1d: { name: 'keccak-512', size: 64 },
  0x20: { name: 'sha2-384', size: 48 },
  0x22: { name: 'murmur3-x64-64', size: 8 },
  0xb220: { name: 'blake2b-256', size: 32 },
  0xb240: { name: 'blake2b-512', size: 64 },
  0xb260: { name: 'blake2s-256', size: 32 },
  0x1e: { name: 'blake3', size: 32 }
};

var BY_NAME = {};

(function () {
  var k;
  for (k in CODES) {
    if (Object.prototype.hasOwnProperty.call(CODES, k)) {
      BY_NAME[CODES[k].name] = parseInt(k, 10);
    }
  }
}());

// The multibase prefixes this library can actually encode or decode, which
// is the ones whose base it already has. A prefix outside this set is
// reported by name rather than guessed at.
var BASES = {
  '\u0000': { name: 'identity',    base: null },
  'f': { name: 'base16',        base: 'base16', upper: false },
  'F': { name: 'base16upper',   base: 'base16', upper: true },
  'b': { name: 'base32',        base: 'base32', upper: false, pad: false },
  'B': { name: 'base32upper',   base: 'base32', upper: true,  pad: false },
  'c': { name: 'base32pad',     base: 'base32', upper: false, pad: true },
  'C': { name: 'base32padupper', base: 'base32', upper: true, pad: true },
  'z': { name: 'base58btc',     base: 'base58' },
  'm': { name: 'base64',        base: 'base64', pad: false },
  'M': { name: 'base64pad',     base: 'base64', pad: true },
  'u': { name: 'base64url',     base: 'base64url', pad: false },
  'U': { name: 'base64urlpad',  base: 'base64url', pad: true }
};

// ---------------------------------------------------------------------------
// varint
// ---------------------------------------------------------------------------

// The unsigned LEB128 the multiformats specifications use: seven bits per
// octet, little endian, high bit set on every octet but the last.
//
// ⚠ NOT the same as DER's base-128, which is BIG endian - and reading one
// with the other gives a plausible wrong number rather than an error. They
// are two encodings of the same idea, and this library now contains both.
function read_varint(bytes, at) {
  var value = 0;
  var shift = 0;
  var i = at;

  while (i < bytes.length) {
    var b = bytes[i];
    i += 1;

    if (shift > 28) {
      // Beyond 2^35 the arithmetic stops being exact in a double, and a
      // value that comes back different from how it went in is worse than a
      // refusal.
      fail('varint-too-large',
        'varint at offset ' + at + ' is longer than this reader accepts');
    }

    value += (b & 0x7F) * Math.pow(2, shift);

    if ((b & 0x80) === 0) {
      // The multiformats specification requires the MINIMAL encoding: a
      // value written in more octets than it needs has a second spelling,
      // and a content address with two spellings is not an address.
      if (i - at > 1 && b === 0x00) {
        fail('non-minimal-varint',
          'varint at offset ' + at + ' has a superfluous trailing 0x00');
      }
      return { value: value, end: i };
    }

    shift += 7;
  }

  fail('truncated-varint',
    'varint at offset ' + at + ' runs past the end of the input');
}

function write_varint(n) {
  if (n < 0 || Math.floor(n) !== n) {
    fail('bad-varint', 'a varint is a non-negative integer');
  }

  var out = [];
  var v = n;

  while (v >= 0x80) {
    out.push((v % 128) | 0x80);
    v = Math.floor(v / 128);
  }
  out.push(v);
  return out;
}

// ---------------------------------------------------------------------------
// multihash
// ---------------------------------------------------------------------------

//   <varint code><varint length><digest>
function decode(input) {
  var bytes = to_bytes(input);

  if (bytes.length === 0) {
    fail('empty', 'a multihash has at least a code and a length');
  }

  var code = read_varint(bytes, 0);
  var length = read_varint(bytes, code.end);
  var digest = bytes.subarray(length.end);

  // ⚠ The stated length is a CLAIM about the bytes that follow, and this one
  // can be checked - unlike the claim that the digest is a digest OF
  // anything, which needs the content.
  if (digest.length !== length.value) {
    fail('length-mismatch',
      'the multihash states ' + length.value + ' digest bytes and carries ' +
      digest.length);
  }

  var known = CODES[code.value];

  if (known !== undefined && known.size !== null &&
      length.value > known.size) {
    // Shorter than the natural size is a legitimate truncation; LONGER is
    // not a digest that function can produce.
    fail('bad-digest-length',
      known.name + ' produces at most ' + known.size + ' bytes, and this ' +
      'multihash claims ' + length.value);
  }

  return {
    code:   code.value,
    name:   known === undefined ? 'code-' + code.value : known.name,
    known:  known !== undefined,
    length: length.value,
    // A truncation is worth surfacing: a 16-byte SHA-256 is a real thing and
    // has half the collision resistance of a full one.
    truncated: known !== undefined && known.size !== null &&
               length.value < known.size,
    digest: digest,
    hex:    hex(digest),
    bytes:  bytes
  };
}

function encode(name, digest) {
  var code = BY_NAME[name];

  if (code === undefined) {
    fail('unknown-hash', 'unrecognised hash function "' + name + '"');
  }

  var bytes = to_bytes(digest);
  var known = CODES[code];

  if (known.size !== null && bytes.length > known.size) {
    fail('bad-digest-length',
      name + ' produces at most ' + known.size + ' bytes, got ' +
      bytes.length);
  }

  var out = write_varint(code).concat(write_varint(bytes.length));
  var i;

  for (i = 0; i < bytes.length; i++) {
    out.push(bytes[i]);
  }

  return new Uint8Array(out);
}

// ⚠ THE CHECK A MULTIHASH DOES NOT DO FOR ITSELF.
//
// The header says "SHA-256, 32 bytes" and carries 32 bytes. It says nothing
// about those bytes being the SHA-256 of anything, and a consumer who reads
// the header as a guarantee has read a claim as a fact.
//
// The hashing is the caller's - this library performs no cryptography - and
// this is the comparison, which exists so that the step is named rather than
// forgotten.
function digest_matches(mh, computed) {
  return bytes_equal(mh.digest, to_bytes(computed));
}

// ---------------------------------------------------------------------------
// multibase
// ---------------------------------------------------------------------------

// The prefix character is part of the string, not metadata about it - so a
// decoder that strips it before looking is a decoder that has lost the one
// thing multibase adds.
function base_decode(text) {
  if (typeof text !== 'string' || text.length === 0) {
    fail('empty', 'a multibase string has at least a prefix');
  }

  var prefix = text.charAt(0);
  var spec = BASES[prefix];

  if (spec === undefined) {
    fail('unknown-base',
      'unrecognised multibase prefix "' + prefix + '"');
  }

  var body = text.substring(1);

  if (spec.base === null) {
    // The identity base: the bytes are the characters.
    var out = new Uint8Array(body.length);
    var i;
    for (i = 0; i < body.length; i++) {
      if (body.charCodeAt(i) > 0xFF) {
        fail('bad-identity',
          'the identity base carries bytes, and this string has a code ' +
          'point above 0xFF');
      }
      out[i] = body.charCodeAt(i);
    }
    return { base: spec.name, bytes: out };
  }

  if (body === '') {
    return { base: spec.name, bytes: new Uint8Array(0) };
  }

  // ⚠ The CASE is part of the encoding's identity here, not a convenience.
  // `f` and `F` are different multibase encodings, and accepting either
  // under both would give one byte string two multibase spellings - which
  // for a content address is the whole problem.
  if (spec.upper === true && body !== body.toUpperCase()) {
    fail('wrong-case',
      spec.name + ' is upper case, and this string is not');
  }
  if (spec.upper === false && body !== body.toLowerCase()) {
    fail('wrong-case',
      spec.name + ' is lower case, and this string is not');
  }

  // Checked on the string AS IT ARRIVED, before any normalisation - the
  // padding is restored below so base.js can stay strict, and checking
  // afterwards would test the restoration rather than the input.
  if (spec.pad === false && body.indexOf('=') !== -1) {
    fail('unexpected-padding',
      spec.name + ' is unpadded, and this string carries padding');
  }
  if (spec.pad === true && spec.base === 'base32' &&
      (body.length % 8) !== 0) {
    fail('missing-padding',
      spec.name + ' is padded, and this string is not a multiple of 8');
  }

  // base.js's base32 decoder expects the RFC 4648 upper-case alphabet, so a
  // lower-case multibase body is raised before it goes in. base64 and
  // base16 are case-sensitive alphabets in their own right and are passed
  // through unchanged.
  var normalized = body;

  if (spec.base === 'base32') {
    normalized = body.toUpperCase();
  } else if (spec.base === 'base16' && spec.upper === true) {
    normalized = body.toLowerCase();
  }

  // ⚠ base.js REFUSES an unpadded base32 or base64 string, which is correct
  // for RFC 4648 and wrong for multibase: 'b' and 'm' are defined as the
  // UNPADDED forms.
  //
  // The padding is restored here rather than relaxed there. Loosening the
  // base decoder would let an unpadded string through everywhere - in PEM,
  // in JWK - and the strictness is the point.
  // ⚠ NOT for base64url: base.js refuses padding on it outright, because RFC
  // 7515 defines base64url without any - so unlike base32 and base64, its
  // unpadded form is the ONLY form and there is nothing to restore.
  //
  // Three encodings, three different padding rules, and the difference is
  // not decoration: it is why 'm' and 'M' are separate multibase prefixes
  // while 'u' has no padded counterpart that this library will accept.
  if (spec.pad === false && spec.base !== 'base64url') {
    normalized = repad(normalized, spec.base === 'base32' ? 8 : 4);
  }


  var bytes;

  try {
    // base58 is not in base.js's codec table - it has no fixed bit-per-
    // character ratio, so it does not fit the generic encoder and has its
    // own pair of functions. Routing to them explicitly rather than adding
    // a fake codec entry keeps the generic path honest.
    bytes = spec.base === 'base58'
      ? B.base58_decode(normalized)
      : B.decode(spec.base, normalized);
  } catch (e) {
    fail('bad-encoding',
      spec.name + ': ' + e.message.replace(/^cryptographic-formats: base(58)?: /, ''));
  }

  return { base: spec.name, bytes: bytes };
}

// Restores the padding multibase omits, so base.js can stay strict.
function repad(text, group) {
  var short = text.length % group;

  if (short === 0) {
    return text;
  }

  var out = text;
  var i;
  for (i = short; i < group; i++) {
    out += '=';
  }
  return out;
}

function base_encode(base, input) {
  var prefix = null;
  var spec = null;
  var k;

  for (k in BASES) {
    if (Object.prototype.hasOwnProperty.call(BASES, k) &&
        BASES[k].name === base) {
      prefix = k;
      spec = BASES[k];
      break;
    }
  }

  if (spec === null) {
    fail('unknown-base', 'unrecognised multibase name "' + base + '"');
  }

  var bytes = to_bytes(input);

  if (spec.base === null) {
    return prefix + latin1(bytes);
  }

  var body = spec.base === 'base58'
    ? B.base58_encode(bytes)
    : B.encode(spec.base, bytes);

  if (spec.pad === false) {
    body = body.replace(/=+$/, '');
  }

  // ⚠ base.js emits base32 in UPPER case, which is RFC 4648's alphabet - and
  // multibase 'b' is the LOWER case one. The two are different multibase
  // encodings with different prefixes, so the case has to be forced here
  // rather than inherited.
  //
  // This was found by a round-trip check: base_encode produced a string
  // base_decode then refused for wrong case. Encoder and decoder disagreeing
  // about their own format is the failure this library is built to catch,
  // and it caught one of its own.
  if (spec.upper === true) {
    body = body.toUpperCase();
  } else if (spec.upper === false) {
    body = body.toLowerCase();
  }

  return prefix + body;
}

// ---------------------------------------------------------------------------
// Together
// ---------------------------------------------------------------------------

// A CIDv0 is a bare base58btc multihash with NO multibase prefix, which is
// the one place multiformats is not self-describing - it predates multibase.
// Recognised by shape: a base58 string beginning "Qm", 46 characters.
function is_cid_v0(text) {
  return typeof text === 'string' && text.length === 46 &&
         text.substring(0, 2) === 'Qm';
}

// Decodes either form, and says which it was.
function cid_decode(text) {
  if (is_cid_v0(text)) {
    return {
      version: 0,
      base:    'base58btc',
      // v0 has no multibase prefix and no codec: it is a raw multihash of
      // dag-pb content, and reading it as v1 would take the first byte of
      // the multihash as a version.
      multihash: decode(B.base58_decode(text))
    };
  }

  var decoded = base_decode(text);

  if (decoded.bytes.length === 0) {
    fail('empty', 'a CID has content');
  }

  var version = read_varint(decoded.bytes, 0);

  if (version.value !== 1) {
    fail('bad-cid-version',
      'CID version ' + version.value + ' is not one this module reads');
  }

  var codec = read_varint(decoded.bytes, version.end);

  return {
    version:   1,
    base:      decoded.base,
    codec:     codec.value,
    multihash: decode(decoded.bytes.subarray(codec.end))
  };
}

export {
  decode,
  encode,
  digest_matches,
  base_decode,
  base_encode,
  cid_decode,
  is_cid_v0,
  read_varint,
  write_varint,
  CODES,
  BASES
};

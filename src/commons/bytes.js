// Byte coercion and inspection, shared by every module.
//
// Nothing here is part of an encode/decode pair, which is why it can be
// shared freely. See commons/README for what may NOT be shared and why.

// Accepts a Uint8Array, a Node Buffer, an ArrayBuffer or a plain array, and
// returns a Uint8Array VIEWING the same memory where possible. A Buffer's
// byteOffset matters: `new Uint8Array(buffer)` on a Buffer that is a slice
// of a pool silently returns the whole pool, which is a bug that only shows
// up under load.

import { make_fail_here } from './fail.js';

var fail_int = make_fail_here('der');

function to_bytes(input) {
  if (input instanceof Uint8Array) {
    return input;
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.length);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (Object.prototype.toString.call(input) === '[object Array]') {
    return new Uint8Array(input);
  }
  throw new TypeError('cryptographic-formats: expected bytes');
}

// The writers assemble output as plain arrays, because sizes are not known
// until assembly finishes and concatenation is the dominant operation. One
// conversion happens at the end.
function to_array(input) {
  if (input instanceof Uint8Array ||
      (typeof Buffer !== 'undefined' && Buffer.isBuffer(input))) {
    return Array.prototype.slice.call(input);
  }
  if (Object.prototype.toString.call(input) === '[object Array]') {
    return input;
  }
  throw new TypeError('cryptographic-formats: expected bytes or an array');
}

function hex(bytes) {
  var s = '';
  var i;
  for (i = 0; i < bytes.length; i++) {
    var h = bytes[i].toString(16);
    s += (h.length === 1 ? '0' : '') + h;
  }
  return s;
}

function from_hex(text) {
  var clean = String(text).replace(/\s/g, '');

  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new TypeError('cryptographic-formats: not a hex string');
  }

  var out = new Uint8Array(clean.length / 2);
  var i;
  for (i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

// NOT constant time, and deliberately not presented as if it were. Every use
// in this library compares public values - serial numbers, key hashes,
// encodings - where an attacker learning the comparison length tells them
// nothing they did not send. Comparing a SECRET belongs in cryptographic-primitives, with
// a function that says so in its name.
function bytes_equal(a, b) {
  if (!a || !b || a.length !== b.length) {
    return false;
  }
  var i;
  for (i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

// Turns a small INTEGER's content octets into a number. Versions, iteration
// counts, path lengths - values a structure guarantees are small.
//
// Refuses anything larger rather than losing precision: a value that comes
// back different from how it went in is worse than a refusal, and beyond
// four octets the caller wanted the bytes anyway.
//
// ⚠ UNSIGNED, AND ONLY FOR BYTES FROM read_unsigned.
//
// read_unsigned strips the leading 0x00 DER puts in front of a value whose
// top bit is set, so its bytes cannot be read as two's complement - 0x80
// from there is 128. Bytes from read_integer CAN be negative, and reading
// 0xFF as 255 is how a skipCerts of -1 became "skip 255 certificates". Every
// count and version is now read with read_unsigned, which refuses a
// negative; the one field that may legitimately be negative (CMP's
// certReqId, where -1 means "none") uses signed_int_value.
//
// And a refusal here is a FormatError like every other: it was a TypeError,
// which the fuzzer found escaping from pkcs12 and tsp.
function int_value(bytes, what) {
  if (bytes.length > 4) {
    fail_int('integer-too-large', (what || 'value') + ' is ' +
      bytes.length + ' bytes, expected a small INTEGER');
  }
  var v = 0;
  var i;
  for (i = 0; i < bytes.length; i++) {
    v = (v * 256) + bytes[i];
  }
  return v;
}

// Two's complement, for bytes from read_integer.
function signed_int_value(bytes, what) {
  if (bytes.length > 4) {
    fail_int('integer-too-large', (what || 'value') + ' is ' +
      bytes.length + ' bytes, expected a small INTEGER');
  }
  var v = (bytes.length > 0 && (bytes[0] & 0x80) !== 0) ? -1 : 0;
  var i;
  for (i = 0; i < bytes.length; i++) {
    v = (v * 256) + bytes[i];
  }
  return v;
}

// The reverse, for writing a small INTEGER's magnitude. The caller wraps it
// with whatever sign handling the format needs.
function int_bytes(n) {
  var out = [];
  var v = n;
  while (v > 0) {
    out.unshift(v & 0xFF);
    v = Math.floor(v / 256);
  }
  return out.length === 0 ? [0] : out;
}

// The bit length of an unsigned big-endian integer: the position of its
// highest set bit.
//
// NOT the byte count times eight, which overstates by up to seven and would
// call a 1017-bit prime a 1024-bit one. Used wherever a key or a group is
// described by its size - DH parameters, DSA domains - and it is inspection
// rather than encoding, so it is safe to share.
function bit_length(bytes) {
  var i = 0;

  while (i < bytes.length && bytes[i] === 0) {
    i += 1;
  }
  if (i === bytes.length) {
    return 0;
  }

  var bits = (bytes.length - i - 1) * 8;
  var top = bytes[i];

  while (top > 0) {
    bits += 1;
    top = top >> 1;
  }

  return bits;
}

// ⚠ THE MINIMAL BIG-ENDIAN FORM OF AN UNSIGNED VALUE.
//
// DER carries integers stripped; JOSE and the raw signature forms carry them
// left-padded to a fixed width. Converting between the two means stripping in
// one direction and padding in the other, and BOTH jwk.js and signature.js
// needed the stripping half.
//
// One byte is always kept: the value zero is `00`, not an empty string.
//
// Safe to share - it is inspection, and a mistake makes every caller read the
// same wrong length, which the first real value exposes.
function strip_leading_zeros(bytes) {
  var i = 0;

  while (i < bytes.length - 1 && bytes[i] === 0) {
    i += 1;
  }

  return bytes.subarray(i);
}


// ⚠ APPEND IN PLACE - THE LINEAR WAY TO GROW A WRITER'S OCTET ARRAY.
//
// `out = out.concat(part)` in a loop copies everything built so far on
// every pass: n parts cost n^2/2 copies. A certificate with 4,000 SANs
// took 433ms that way, a KRL of 5,000 serials 294ms, 52KB of CBOR 139ms -
// against single milliseconds once each part is pushed onto the one array.
// A part may be an array of octets or a Uint8Array (which concat would
// have appended as ONE element - the trap der_writer's concat documents).
// Returns `out`, so calls chain. Direction-neutral, like concat_bytes.
function append(out, part) {
  var i;
  for (i = 0; i < part.length; i++) {
    out.push(part[i]);
  }
  return out;
}

// Joins byte strings. Direction-neutral: it neither encodes nor decodes, so
// it cannot be half of a pair that cancels out - which is why it may live
// here when der_writer's own `concat` (taking DER parts) stays in the writer.
function concat_bytes(list) {
  var total = 0;
  var i;

  for (i = 0; i < list.length; i++) {
    total += list[i].length;
  }

  var out = new Uint8Array(total);
  var at = 0;

  for (i = 0; i < list.length; i++) {
    out.set(list[i], at);
    at += list[i].length;
  }

  return out;
}

export {
  signed_int_value,
  append,
  concat_bytes,
  der_header,
  der_wrap,
  strip_leading_zeros,
  bit_length,
  to_bytes,
  to_array,
  hex,
  from_hex,
  bytes_equal,
  int_value,
  int_bytes
};

// ⚠ A DER HEADER, BUILT BY A READER.
//
// Three modules needed one and each wrote it out: cmp.js assembling the
// ProtectedPart, crmf.js restoring an implicitly-tagged SPKI, sct.js wrapping
// a TLS list in an OCTET STRING. All three are READERS, so they cannot import
// der_writer - the direction rule in commons/README.md forbids it, and for a
// good reason: a reader that shared its length encoder with the writer would
// have a bug that cancels out on a round trip.
//
// ⚠ AND THIS IS NOT THAT SHARING.
//
// der_writer's encode_length is the ENCODER, checked against asn1crypto and
// used to produce every structure this library writes. This is a small
// utility for a reader that needs to hand a nested value to another reader
// with its header restored - it produces a header for bytes that ALREADY
// EXIST and were already validated.
//
// The distinction matters: if this were wrong, the reader would hand the
// other reader a malformed value and it would be refused immediately. There
// is no round trip for a mistake to hide in.
//
// Kept minimal deliberately - four octets of length is 16MB, past anything a
// nested value in these formats reaches, and refusing beyond that is better
// than a general encoder living in commons where a writer might reach for it.
function der_header(tag, length) {
  if (length < 0) {
    throw new Error('cryptographic-formats: a length cannot be negative');
  }

  if (length < 0x80) {
    return [tag, length];
  }
  if (length < 0x100) {
    return [tag, 0x81, length];
  }
  if (length < 0x10000) {
    return [tag, 0x82, (length >> 8) & 0xFF, length & 0xFF];
  }
  if (length < 0x1000000) {
    return [tag, 0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF,
            length & 0xFF];
  }

  throw new Error(
    'cryptographic-formats: der_header is for nested values inside a structure ' +
    'already read; ' + length + ' bytes is past what one reaches. Use ' +
    'der_writer for encoding.');
}

// The same, wrapping bytes rather than returning the header alone.
function der_wrap(tag, content) {
  var header = der_header(tag, content.length);
  var out = new Uint8Array(header.length + content.length);

  out.set(header, 0);
  out.set(content, header.length);

  return out;
}

// OpenPGP, RFC 9580 - read: the ASCII armour, the cleartext signature
// framework, every packet, transferable keys, and the bytes each signature
// and each encryption layer is computed over.
//
// ⚠ AN OPENPGP FILE IS A STREAM OF PACKETS, AND THE SAME FEW MISTAKES
//   RECUR IN EVERY IMPLEMENTATION THAT GETS IT WRONG:
//
//   a signature is not over the data     It is over the data, then a
//                                        trailer: the signature's own
//                                        version through its hashed
//                                        subpackets, 0x04|0x06, 0xFF and a
//                                        length. verification_plan builds it.
//   a key signature hashes the key       As 0x99 + 2-octet length (v4) or
//   in a header it never had             0x9B + 4-octet length (v6) - not as
//                                        the packet appeared in the file.
//   unhashed subpackets are not signed   Anyone can add or change them. The
//                                        issuer key ID gpg writes is there.
//   text signatures are over CRLF        A text signature (type 0x01) is over
//                                        the text with CRLF line endings.
//   the CRC on the armour is optional    RFC 9580 6.1: it MUST NOT be a
//                                        reason to reject - reported, not
//                                        enforced.
//
// This library performs no cryptography: it returns what to hash, what to
// decrypt and with which algorithm, and the caller does it.

import * as B from './base.js';
import * as OID from './oid.js';
import * as IDS from './openpgp_ids.js';

import { to_bytes, hex, bytes_equal, concat_bytes } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';
import { decode_utf8 } from './commons/decode_text.js';
import { encode_utf8 } from './commons/encode_text.js';
import { crc24 } from './commons/crc24.js';

var fail = make_fail_here('openpgp');

// ---------------------------------------------------------------------------
// Octets
// ---------------------------------------------------------------------------

function Reader(bytes, start, end) {
  this.buf = bytes;
  this.pos = start || 0;
  this.end = end === undefined ? bytes.length : end;
}

Reader.prototype.remaining = function () { return this.end - this.pos; };

Reader.prototype.take = function (n, what) {
  if (n < 0 || this.pos + n > this.end) {
    fail('truncated', (what || 'a field') + ' needs ' + n + ' octets and ' +
      this.remaining() + ' remain');
  }
  var out = this.buf.subarray(this.pos, this.pos + n);
  this.pos += n;
  return out;
};

Reader.prototype.u8 = function (what) { return this.take(1, what)[0]; };

Reader.prototype.u16 = function (what) {
  var b = this.take(2, what);
  return (b[0] << 8) | b[1];
};

Reader.prototype.u32 = function (what) {
  var b = this.take(4, what);
  return ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
};

Reader.prototype.rest = function () { return this.take(this.remaining()); };

Reader.prototype.expect_end = function (what) {
  if (this.pos !== this.end) {
    fail('trailing-octets', (this.end - this.pos) + ' octet(s) after ' + what);
  }
};

// RFC 9580 3.2: a 2-octet bit count, then the magnitude. The count must be
// the value's real bit length - a different count is a second encoding of
// the same number, and fingerprints hash the encoding.
//
// `fixed`: also a fixed-width value with its leading zero octets kept and
// counted - GnuPG writes EdDSALegacy's R and S that way (one signature in
// 256 has R below 2^248 and says 256 bits). Those are v4 only, where RFC
// 9580 3.2's MUST-reject does not reach (it is for v6), signatures are not
// hashed, and the value is the same number. Returned minimal, and `out.fixed`
// says it was not (DECISIONS 31).
Reader.prototype.mpi = function (what, fixed) {
  var bits = this.u16(what);
  var v = this.take((bits + 7) >> 3, what);
  var actual = v.length === 0 ? 0 : (v.length - 1) * 8 + bit_length(v[0]);
  if (actual !== bits && fixed !== undefined && bits === v.length * 8) {
    fixed.padded = true;
    var z = 0;
    while (z < v.length && v[z] === 0) { z += 1; }
    return v.subarray(z);
  }
  if (actual !== bits) {
    fail('bad-mpi', (what || 'an MPI') + ' says ' + bits + ' bits and holds ' + actual);
  }
  return v;
};

function bit_length(b) {
  var n = 0;
  while (b > 0) { n += 1; b >>= 1; }
  return n;
}

function utf8(bytes, what) {
  return decode_utf8(bytes, function (pos, code, detail) {
    fail(code, (what || 'text') + ': ' + detail);
  }, 0);
}

// UTF-8 when it is, null when not - a User ID from an old implementation
// may be Latin-1, and its bytes are still what the signatures cover.
function utf8_or_null(bytes) {
  try { return utf8(bytes); } catch (e) { return null; }
}

// ---------------------------------------------------------------------------
// ASCII armour - RFC 9580 6
// ---------------------------------------------------------------------------

var ARMOR_TYPES = ['MESSAGE', 'PUBLIC KEY BLOCK', 'PRIVATE KEY BLOCK', 'SIGNATURE'];

function lines_of(text) {
  return String(text).split(/\r\n|\n|\r/);
}

// { type, headers: [[key, value]], data, checksum: 'ok'|'absent'|'mismatch' }
function armor_decode(text) {
  if (typeof text !== 'string') {
    fail('bad-input', 'armour is text');
  }
  var lines = lines_of(text);
  var i = 0;

  while (i < lines.length && lines[i].replace(/\s+$/, '') === '') { i++; }
  var m = i < lines.length && /^-----BEGIN PGP (.+)-----\s*$/.exec(lines[i]);

  if (!m) {
    fail('not-armored', 'OpenPGP armour starts with a -----BEGIN PGP ...----- line');
  }
  if (ARMOR_TYPES.indexOf(m[1]) === -1) {
    fail('unknown-armor-type', '"BEGIN PGP ' + m[1] + '" is not an armour type ' +
      'RFC 9580 6.2.1 defines' + (m[1] === 'SIGNED MESSAGE'
        ? ' - a cleartext signed message: cleartext_decode' : ''));
  }
  return read_armor(lines, i, m[1]);
}

function read_armor(lines, start, type) {
  var i = start + 1;
  var headers = [];

  for (; i < lines.length && lines[i].replace(/\s+$/, '') !== ''; i++) {
    var h = /^([^:\s]+): (.*)$/.exec(lines[i]);
    if (!h) {
      if (/^[A-Za-z0-9+\/=]+$/.test(lines[i])) {
        break;              // no headers and no blank line: tolerated (6.2.2)
      }
      fail('bad-armor-header', 'armour header line ' + (i + 1) + ' is not "Key: value"');
    }
    headers.push([h[1], h[2]]);
  }
  if (i < lines.length && lines[i].replace(/\s+$/, '') === '') { i++; }

  var body = '';
  var crc = null;
  var end_line = '-----END PGP ' + type + '-----';

  for (; i < lines.length; i++) {
    var l = lines[i].replace(/\s+$/, '');
    if (l === end_line) { break; }
    if (l.charAt(0) === '=' && l.length === 5) { crc = l.substr(1); continue; }
    if (crc !== null) {
      fail('bad-armor', 'data after the checksum line');
    }
    body += l.replace(/\s+/g, '');
  }
  if (i === lines.length) {
    fail('unterminated-armor', 'no ' + end_line + ' line');
  }

  var data = B.from_base64(body);
  var checksum = 'absent';

  if (crc !== null) {
    var want = B.from_base64(crc);
    var got = crc24(data);
    checksum = want.length === 3 &&
      ((want[0] << 16) | (want[1] << 8) | want[2]) === got ? 'ok' : 'mismatch';
  }

  for (var k = i + 1; k < lines.length; k++) {
    if (lines[k].replace(/\s+$/, '') !== '') {
      fail('trailing-text', 'text after the armour\'s END line');
    }
  }

  return { type: type, headers: headers, data: data, checksum: checksum };
}

// ---------------------------------------------------------------------------
// Cleartext signature framework - RFC 9580 7
// ---------------------------------------------------------------------------

// { text, signed_bytes, hashes, signature }. signed_bytes is what a text
// signature over this message covers: the dash-unescaped lines, trailing
// spaces and tabs removed, joined with CRLF, without the line ending before
// the signature (7.1).
function cleartext_decode(text) {
  var lines = lines_of(text);
  var i = 0;

  while (i < lines.length && lines[i].replace(/\s+$/, '') === '') { i++; }
  if (lines[i] === undefined || lines[i].replace(/\s+$/, '') !== '-----BEGIN PGP SIGNED MESSAGE-----') {
    fail('not-cleartext', 'a cleartext signed message starts ' +
      '-----BEGIN PGP SIGNED MESSAGE-----');
  }
  i++;

  // 7.1: the only header allowed is a well-formed Hash; any other, and the
  // signature MUST NOT validate.
  var hashes = [];
  for (; i < lines.length && lines[i].replace(/\s+$/, '') !== ''; i++) {
    var h = /^Hash: ([A-Z0-9-]+(,\s*[A-Z0-9-]+)*)\s*$/.exec(lines[i]);
    if (!h) {
      fail('bad-cleartext-header', 'only a well-formed "Hash:" header may ' +
        'precede a cleartext message (RFC 9580 7.1); this is "' + lines[i] + '"');
    }
    hashes = hashes.concat(h[1].split(/,\s*/));
  }
  i++;

  var body = [];
  for (; i < lines.length; i++) {
    if (lines[i].replace(/\s+$/, '') === '-----BEGIN PGP SIGNATURE-----') { break; }
    var l = lines[i];
    if (l.charAt(0) === '-') {
      if (l.substr(0, 2) !== '- ') {
        fail('bad-dash-escape', 'line ' + (i + 1) + ' starts with "-" and is ' +
          'not dash-escaped (RFC 9580 7.2)');
      }
      l = l.substr(2);
    }
    body.push(l);
  }
  if (i === lines.length) {
    fail('no-signature', 'the cleartext has no -----BEGIN PGP SIGNATURE----- block');
  }

  var signed = body.map(function (x) { return x.replace(/[ \t]+$/, ''); }).join('\r\n');

  return {
    text: body.join('\n'),
    signed_bytes: utf8_bytes(signed),
    hashes: hashes,
    signature: read_armor(lines, i, 'SIGNATURE')
  };
}

// UTF-8 of a string: the cleartext and a user ID given as text are hashed
// as their UTF-8 bytes.
function utf8_bytes(text) {
  return new Uint8Array(encode_utf8(text, fail));
}

// ---------------------------------------------------------------------------
// Packets - RFC 9580 4
// ---------------------------------------------------------------------------

// Packet types whose bodies may arrive in partial lengths (4.2.1.4).
var PARTIAL_OK = { 8: true, 9: true, 11: true, 18: true };

// Every packet in `input` (bytes, or armour text), parsed. options:
//   max_packets   a ceiling; default 100000
function packets_from_bytes(input, options) {
  var bytes = typeof input === 'string' ? armor_decode(input).data : to_bytes(input);
  var opts = options || {};
  var max = opts.max_packets === undefined ? 100000 : opts.max_packets;
  var r = new Reader(bytes);
  var out = [];

  while (r.remaining() > 0) {
    if (out.length >= max) {
      fail('too-many-packets', 'more than ' + max + ' packets');
    }
    out.push(read_packet(r));
  }
  return out;
}

function read_packet(r) {
  var start = r.pos;
  var b = r.u8('a packet header');

  if ((b & 0x80) === 0) {
    fail('bad-packet-header', 'octet ' + start + ' is 0x' + b.toString(16) +
      ', and every packet header has bit 7 set');
  }

  var tag;
  var body;
  var legacy = (b & 0x40) === 0;
  var partial = false;

  if (legacy) {
    tag = (b >> 2) & 0x0F;
    var lt = b & 3;
    var len = lt === 0 ? r.u8() : lt === 1 ? r.u16() : lt === 2 ? r.u32() : r.remaining();
    body = r.take(len, 'the packet body');
  } else {
    tag = b & 0x3F;
    var parts = [];
    for (;;) {
      var o = r.u8('a length');
      if (o < 192) { parts.push(r.take(o)); break; }
      if (o < 224) { parts.push(r.take(((o - 192) << 8) + r.u8() + 192)); break; }
      if (o === 255) { parts.push(r.take(r.u32())); break; }
      if (!PARTIAL_OK[tag]) {
        fail('bad-partial-length', 'partial body lengths are for data packets ' +
          'only (RFC 9580 4.2.1.4); this is type ' + tag);
      }
      var p = 1 << (o & 0x1F);
      if (parts.length === 0 && p < 512) {
        fail('bad-partial-length', 'the first partial length MUST be at least 512');
      }
      partial = true;
      parts.push(r.take(p));
    }
    body = parts.length === 1 ? parts[0] : concat_bytes(parts);
  }

  if (tag === 0) {
    fail('reserved-packet', 'Packet Type ID 0 MUST NOT be used');
  }

  var type = IDS.PACKET[tag];
  var packet = { tag: tag, type: type || 'unknown', legacy: legacy, partial: partial,
                 body: body, raw: r.buf.subarray(start, r.pos) };

  if (type === undefined) {
    if (tag < 40) {
      fail('unknown-critical-packet', 'packet type ' + tag + ' is critical and ' +
        'unknown: RFC 9580 4.3 says reject the whole sequence');
    }
    return packet;              // non-critical: kept, and to be ignored
  }

  var fields = PARSE[type](body, tag);
  var k;
  for (k in fields) {
    if (Object.prototype.hasOwnProperty.call(fields, k)) {
      if (Object.prototype.hasOwnProperty.call(packet, k)) {
        // A packet's own field named like the framing's would replace it.
        throw new Error('openpgp.js: ' + type + ' reads a field named ' + k);
      }
      packet[k] = fields[k];
    }
  }
  return packet;
}

var PARSE = {
  'public-key': read_key,
  'public-subkey': read_key,
  'secret-key': read_key,
  'secret-subkey': read_key,
  'signature': function (body) { return read_signature(body); },
  'user-id': function (body) { return { user_id: body, text: utf8_or_null(body) }; },
  'user-attribute': read_user_attribute,
  'literal': read_literal,
  'compressed': read_compressed,
  'one-pass-signature': read_one_pass,
  'pkesk': read_pkesk,
  'skesk': read_skesk,
  'seipd': read_seipd,
  'sed': function (body) {
    return { ciphertext: body, warning: 'a Symmetrically Encrypted Data packet: ' +
      'no integrity protection, and RFC 9580 5.7 says reject it' };
  },
  'mdc': function (body) {
    if (body.length !== 20) { fail('bad-mdc', 'an MDC is the 20 octets of SHA-1'); }
    return { mdc: body };
  },
  'marker': function (body) {
    if (body.length !== 3 || body[0] !== 0x50 || body[1] !== 0x47 || body[2] !== 0x50) {
      fail('bad-marker', 'a Marker packet is "PGP"');
    }
    return {};
  },
  'trust': function () { return {}; },
  'padding': function () { return {}; }
};

// ---------------------------------------------------------------------------
// Keys - RFC 9580 5.5
// ---------------------------------------------------------------------------

function read_key(body, tag) {
  var r = new Reader(body);
  var version = r.u8('the key version');
  var out = { version: version, subkey: tag === 7 || tag === 14, secret: tag === 5 || tag === 7 };

  if (version === 2 || version === 3) {
    out.created = r.u32();
    out.expires_days = r.u16();
    out.algorithm_id = r.u8();
  } else if (version === 4 || version === 6) {
    out.created = r.u32();
    out.algorithm_id = r.u8();
  } else {
    fail('unsupported-key-version', 'key version ' + version + '; 3, 4 and 6 are read');
  }

  var alg = IDS.PUBLIC_KEY[out.algorithm_id];
  out.algorithm = alg ? alg.name : null;

  var material_end = r.end;
  if (version === 6) {
    var n = r.u32('the key material length');
    material_end = r.pos + n;
    if (material_end > r.end) { fail('truncated', 'the key material length exceeds the packet'); }
  }

  if (alg === undefined) {
    if (out.secret && version !== 6) {
      fail('unknown-algorithm', 'algorithm ' + out.algorithm_id + ' in a v' +
        version + ' secret key: nothing says where its public part ends');
    }
    out.material = r.take(material_end - r.pos);
  } else {
    out.material = read_key_material(r, alg, version);
    if (version === 6 && r.pos !== material_end) {
      fail('bad-key-length', 'the key material length says ' +
        (material_end - (r.pos - (r.pos - material_end))) + ' and the fields disagree');
    }
    if ((version === 2 || version === 3) && alg.name.indexOf('rsa') !== 0) {
      fail('bad-v3-key', 'a version 3 key is RSA');
    }
  }

  var public_end = r.pos;
  out.public_body = body.subarray(0, public_end);
  out.public_key = library_key(out);

  // 5.5.4: what the fingerprint hashes, and with which hash.
  if (version === 6) {
    out.fingerprint_input = concat_bytes([new Uint8Array([0x9B]), u32(public_end), out.public_body]);
    out.fingerprint_hash = 'sha256';
  } else if (version === 4) {
    out.fingerprint_input = concat_bytes([new Uint8Array([0x99]), u16(public_end), out.public_body]);
    out.fingerprint_hash = 'sha1';
  } else {
    out.fingerprint_input = concat_bytes([out.material.n, out.material.e]);
    out.fingerprint_hash = 'md5';
    out.key_id = hex(out.material.n.subarray(out.material.n.length - 8));
  }

  if (out.secret) {
    read_secret(r, out, alg, version, tag);
  } else {
    r.expect_end('the public key');
  }
  return out;
}

function u16(n) { return new Uint8Array([(n >> 8) & 0xFF, n & 0xFF]); }
function u32(n) {
  return new Uint8Array([(n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF]);
}

function read_key_material(r, alg, version) {
  var m = {};
  var i;

  if (alg.native) {
    m.point = r.take(alg.native, 'the ' + alg.name + ' key');
    return m;
  }
  if (alg.fields) {
    for (i = 0; i < alg.fields.length; i++) { m[alg.fields[i]] = r.mpi(alg.fields[i]); }
    return m;
  }

  var oid_len = r.u8('the curve OID length');
  if (oid_len === 0 || oid_len === 0xFF) {
    fail('reserved-oid-length', 'curve OID lengths 0 and 255 are reserved (5.5.5.4)');
  }
  var oid = r.take(oid_len, 'the curve OID');
  var dotted = OID.to_string(oid);
  var curve = IDS.CURVE[dotted];
  m.oid = dotted;
  m.curve = curve ? curve.name : null;
  m.point = r.mpi('the curve point');

  if (curve) {
    check_point(m.point, curve, alg.name);
    if (version === 6 && curve.wire === 'prefixed') {
      fail('legacy-curve-in-v6', curve.name + ' MUST NOT be used in a version 6 key');
    }
  }

  if (alg.kdf) {
    var len = r.u8('the KDF parameters length');
    if (len !== 3) { fail('bad-kdf-params', 'ECDH KDF parameters are 3 octets after their length'); }
    var reserved = r.u8();
    if (reserved !== 1) { fail('bad-kdf-params', 'the KDF parameters start 0x01'); }
    var h = r.u8();
    var c = r.u8();
    m.kdf = { hash_id: h, hash: IDS.HASH[h] ? IDS.HASH[h].name : null,
              cipher_id: c, cipher: IDS.CIPHER[c] ? IDS.CIPHER[c].name : null };
  }
  return m;
}

// 11.2: SEC1 uncompressed (0x04 || x || y) for the NIST and Brainpool
// curves; 0x40 || native for the two legacy 25519 curves.
function check_point(p, curve, alg) {
  if (curve.wire === 'prefixed') {
    if (p.length !== curve.size + 1 || p[0] !== 0x40) {
      fail('bad-point', alg + ' on ' + curve.name + ' carries 0x40 then ' +
        curve.size + ' octets (11.2.2)');
    }
  } else if (p.length !== 1 + 2 * curve.size || p[0] !== 0x04) {
    fail('bad-point', curve.name + ' points are uncompressed SEC1, ' +
      (1 + 2 * curve.size) + ' octets');
  }
}

// The key in the shape spki.js, jwk.js and ssh.js use, where there is one.
function library_key(k) {
  var m = k.material;
  var a = k.algorithm;
  if (!m) { return null; }
  if (a === 'rsa' || a === 'rsa-encrypt-only' || a === 'rsa-sign-only') {
    return { algorithm: 'rsaEncryption', curve: null, point: null, rsa: { n: m.n, e: m.e } };
  }
  if (a === 'ed25519') { return { algorithm: 'Ed25519', curve: null, point: m.point }; }
  if (a === 'ed448') { return { algorithm: 'Ed448', curve: null, point: m.point }; }
  if (a === 'x25519') { return { algorithm: 'X25519', curve: null, point: m.point }; }
  if (a === 'x448') { return { algorithm: 'X448', curve: null, point: m.point }; }
  if (m.curve === 'ed25519Legacy') { return { algorithm: 'Ed25519', curve: null, point: m.point.subarray(1) }; }
  if (m.curve === 'curve25519Legacy') { return { algorithm: 'X25519', curve: null, point: m.point.subarray(1) }; }
  if (m.curve && IDS.CURVE[m.oid] && IDS.CURVE[m.oid].wire === 'sec1') {
    return { algorithm: 'ecPublicKey', curve: m.curve, point: m.point };
  }
  return null;
}

// 5.5.3: the S2K usage octet and what follows it.
function read_secret(r, out, alg, version, tag) {
  var usage = r.u8('the S2K usage octet');
  var p = { usage: usage };
  out.protection = p;

  if (version === 6 && usage === 255) {
    fail('bad-s2k-usage', 'a version 6 key MUST NOT use S2K usage 255 (MalleableCFB)');
  }

  if (usage !== 0) {
    var params_end = null;
    if (version === 6) {
      var count = r.u8('the S2K parameters length');
      params_end = r.pos + count;
    }
    if (usage === 253 || usage === 254 || usage === 255) {
      p.cipher_id = r.u8();
      if (usage === 253) { p.aead_id = r.u8(); }
      var s2k_end = null;
      if (version === 6) { s2k_end = r.pos + 1 + r.buf[r.pos]; r.u8(); }
      p.s2k = read_s2k(r);
      if (s2k_end !== null && r.pos !== s2k_end) {
        fail('bad-s2k', 'the S2K specifier\'s length disagrees with its fields');
      }
    } else {
      p.cipher_id = usage;      // the legacy form: the octet is the cipher
      p.s2k = { type: 'md5-legacy', hash: 'md5' };
    }
    var cipher = IDS.CIPHER[p.cipher_id];
    p.cipher = cipher ? cipher.name : null;
    if (usage === 253) {
      var aead = IDS.AEAD[p.aead_id];
      if (!aead) { fail('unknown-aead', 'AEAD algorithm ' + p.aead_id); }
      p.aead = aead.name;
      p.iv = r.take(aead.nonce, 'the AEAD nonce');
      // 5.5.3: HKDF info, and the AEAD's additional data.
      p.hkdf_info = new Uint8Array([0xC0 | tag, version, p.cipher_id, p.aead_id]);
      p.aad = concat_bytes([new Uint8Array([0xC0 | tag]), out.public_body]);
    } else if (!(p.s2k.type === 'gnu' && p.s2k.mode === 'gnu-dummy')) {
      if (!cipher) { fail('unknown-cipher', 'cipher ' + p.cipher_id); }
      p.iv = r.take(cipher.block, 'the CFB IV');
    }
    if (params_end !== null && r.pos !== params_end) {
      fail('bad-s2k', 'the S2K parameters length disagrees with its fields');
    }
    p.encrypted = r.rest();
    p.note = usage === 253 ? 'decrypt `encrypted` (the tag is its last ' +
      IDS.AEAD[p.aead_id].tag + ' octets) with ' + p.aead + ', the key HKDF-SHA256(s2k key, info hkdf_info), nonce iv, additional data aad'
      : usage === 254 ? 'decrypt with ' + p.cipher + '-CFB, iv; the plaintext ends with a SHA-1 of what precedes it'
      : 'decrypt with ' + p.cipher + '-CFB, iv; the plaintext ends with a 2-octet checksum (deprecated, malleable)';
    return;
  }

  // Not encrypted: the secret fields, then (v3, v4) a 2-octet checksum.
  var start = r.pos;
  out.secret_material = read_secret_material(r, alg, version, out);
  if (version !== 6) {
    var sum = 0;
    var i;
    for (i = start; i < r.pos; i++) { sum = (sum + r.buf[i]) & 0xFFFF; }
    if (r.u16('the secret key checksum') !== sum) {
      fail('bad-checksum', 'the secret key checksum does not match its fields');
    }
  }
  r.expect_end('the secret key');
}

function read_secret_material(r, alg, version, key) {
  if (!alg) { return { raw: r.take(r.remaining() - (version === 6 ? 0 : 2)) }; }
  if (alg.native) { return { scalar: r.take(alg.native, 'the secret key') }; }
  var m = {};
  var i;
  for (i = 0; i < alg.secret.length; i++) { m[alg.secret[i]] = r.mpi(alg.secret[i]); }
  if (key.material && key.material.curve === 'curve25519Legacy') {
    // 5.5.5.6.1.1: big-endian on the wire; native is the reverse.
    m.native = new Uint8Array(left_pad(m.scalar, 32)).reverse();
  }
  if (key.material && key.material.curve === 'ed25519Legacy') {
    m.native = new Uint8Array(left_pad(m.scalar, 32));
  }
  return m;
}

function left_pad(b, n) {
  if (b.length > n) { fail('bad-mpi', 'a value wider than ' + n + ' octets'); }
  var out = new Uint8Array(n);
  out.set(b, n - b.length);
  return out;
}

// 3.7.1: an S2K specifier.
function read_s2k(r) {
  var type = r.u8('the S2K type');
  var hash;

  if (type === 0 || type === 1 || type === 3) {
    hash = r.u8();
    var s = { type: type === 0 ? 'simple' : type === 1 ? 'salted' : 'iterated',
              hash_id: hash, hash: IDS.HASH[hash] ? IDS.HASH[hash].name : null };
    if (type !== 0) { s.salt = r.take(8, 'the S2K salt'); }
    if (type === 3) {
      var c = r.u8();
      s.coded_count = c;
      // The number of OCTETS hashed - not an iteration count.
      s.count = (16 + (c & 15)) * Math.pow(2, (c >> 4) + 6);
    }
    return s;
  }
  if (type === 4) {
    var a = { type: 'argon2', salt: r.take(16, 'the Argon2 salt'), passes: r.u8(),
              parallelism: r.u8(), encoded_memory: r.u8() };
    if (a.passes === 0 || a.parallelism === 0) {
      fail('bad-argon2', 'Argon2 passes and parallelism MUST be non-zero');
    }
    var min = 3 + Math.ceil(Math.log(a.parallelism) / Math.LN2);
    if (a.encoded_memory < min || a.encoded_memory > 31) {
      fail('bad-argon2', 'encoded memory ' + a.encoded_memory + ' is outside ' +
        min + '..31 (3.7.1.4)');
    }
    a.memory_kib = Math.pow(2, a.encoded_memory);
    return a;
  }
  if (type === 101) {
    // GnuPG's extension: a secret key that is not there (a stub) or is on
    // a card. Not RFC 9580's, and what `gpg --export-secret-subkeys` writes.
    hash = r.u8();
    var gnu = r.take(3, 'the GNU marker');
    if (gnu[0] !== 0x47 || gnu[1] !== 0x4E || gnu[2] !== 0x55) {
      fail('unknown-s2k', 'S2K type 101 without the "GNU" marker');
    }
    var mode = r.u8();
    var g = { type: 'gnu', hash_id: hash, mode: mode === 1 ? 'gnu-dummy' : mode === 2 ? 'divert-to-card' : mode };
    if (mode === 2) { g.serial = r.take(r.u8()); }
    return g;
  }
  fail('unknown-s2k', 'S2K type ' + type);
}

// ---------------------------------------------------------------------------
// Signatures - RFC 9580 5.2
// ---------------------------------------------------------------------------

function read_signature(body) {
  var r = new Reader(body);
  var version = r.u8('the signature version');
  var out = { version: version };

  if (version === 3) {
    if (r.u8() !== 5) { fail('bad-signature', 'a v3 signature hashes 5 octets'); }
    out.signature_type_id = r.u8();
    out.created = r.u32();
    out.issuer_key_id = hex(r.take(8));
    out.public_key_algorithm_id = r.u8();
    out.hash_id = r.u8();
    out.hashed_subpackets = [];
    out.unhashed_subpackets = [];
    out.hashed_portion = body.subarray(2, 7);
  } else if (version === 4 || version === 6) {
    out.signature_type_id = r.u8();
    out.public_key_algorithm_id = r.u8();
    out.hash_id = r.u8();
    var hl = version === 4 ? r.u16() : r.u32();
    var hashed = r.take(hl, 'the hashed subpackets');
    out.hashed_portion = body.subarray(0, r.pos);
    var ul = version === 4 ? r.u16() : r.u32();
    var unhashed = r.take(ul, 'the unhashed subpackets');
    out.hashed_subpackets = read_subpackets(hashed, true);
    out.unhashed_subpackets = read_subpackets(unhashed, false);
  } else {
    fail('unsupported-signature-version', 'signature version ' + version +
      '; 3, 4 and 6 are read');
  }

  out.left16 = r.take(2, 'the hash\'s left 16 bits');

  var hash = IDS.HASH[out.hash_id];
  out.hash = hash ? hash.name : null;
  out.weak = hash ? hash.weak === true : false;

  if (version === 6) {
    var sl = r.u8('the salt length');
    if (!hash || hash.salt === undefined || sl !== hash.salt) {
      fail('bad-salt', 'a v6 signature with ' + (out.hash || 'hash ' + out.hash_id) +
        ' carries a ' + (hash && hash.salt) + '-octet salt, and this says ' + sl);
    }
    out.salt = r.take(sl, 'the salt');
  }

  var alg = IDS.PUBLIC_KEY[out.public_key_algorithm_id];
  out.public_key_algorithm = alg ? alg.name : null;
  out.signature_type = IDS.SIGNATURE_TYPE[out.signature_type_id] || null;
  out.value = read_signature_value(r, alg);
  r.expect_end('the signature');

  summarize(out);
  return out;
}

function read_signature_value(r, alg) {
  if (!alg) { return { raw: r.rest() }; }
  var n = alg.name;
  if (n === 'rsa' || n === 'rsa-sign-only') {
    // ⚠ An MPI drops leading zero octets, so one RSA signature in 256 is
    // shorter than the modulus - and a verifier that wants the modulus's
    // length (node:crypto, WebCrypto) refuses it. Left-pad s to the key's
    // modulus length before verifying.
    return { s: r.mpi('the RSA signature') };
  }
  if (n === 'dsa' || n === 'ecdsa') { return { r: r.mpi('r'), s: r.mpi('s') }; }
  if (n === 'eddsa-legacy') {
    // 5.2.3.3.1: R and S as MPIs - the MPI drops leading zero octets, so
    // the 32-octet values are put back for a verifier.
    var fixed = { padded: false };
    var rr = r.mpi('R', fixed);
    var ss = r.mpi('S', fixed);
    return { r: rr, s: ss, raw: concat_bytes([left_pad(rr, 32), left_pad(ss, 32)]),
      padded: fixed.padded };
  }
  if (alg.signature) { return { raw: r.take(alg.signature, 'the ' + n + ' signature') }; }
  fail('not-a-signing-algorithm', n + ' does not sign');
}

// 5.2.3.7: a subpacket area.
function read_subpackets(bytes, hashed) {
  var r = new Reader(bytes);
  var out = [];

  while (r.remaining() > 0) {
    var o = r.u8('a subpacket length');
    var len = o < 192 ? o : o < 255 ? ((o - 192) << 8) + r.u8() + 192 : r.u32();
    if (len === 0) { fail('bad-subpacket', 'a subpacket has at least its type octet'); }
    var data = r.take(len, 'a subpacket');
    var critical = (data[0] & 0x80) !== 0;
    var id = data[0] & 0x7F;
    var spec = IDS.SUBPACKET[id];
    var sp = { id: id, name: spec ? spec.name : null, critical: critical,
               hashed: hashed, data: data.subarray(1) };
    if (spec) { sp.value = subpacket_value(spec, sp.data); }
    out.push(sp);
  }
  return out;
}

function subpacket_value(spec, d) {
  var r = new Reader(d);
  var v;
  switch (spec.as) {
  case 'time':
  case 'seconds':
    v = r.u32(spec.name); break;
  case 'bool':
    v = r.u8(spec.name);
    if (v > 1) { fail('bad-subpacket', spec.name + ' is 0 or 1'); }
    v = v === 1; break;
  case 'list':
    v = Array.prototype.slice.call(r.rest()); break;
  case 'pairs':
    if (d.length % 2 !== 0) { fail('bad-subpacket', spec.name + ' is pairs of octets'); }
    v = [];
    while (r.remaining() > 0) { v.push([r.u8(), r.u8()]); }
    break;
  case 'text':
    v = utf8(r.rest(), spec.name); break;
  case 'fingerprint':
    var fv = r.u8();
    var fp = r.rest();
    if ((fv === 4 && fp.length !== 20) || (fv === 6 && fp.length !== 32)) {
      fail('bad-subpacket', 'a version ' + fv + ' fingerprint is ' +
        (fv === 4 ? 20 : 32) + ' octets');
    }
    v = { version: fv, fingerprint: hex(fp) }; break;
  case 'notation':
    var flags = r.take(4);
    var nl = r.u16();
    var vl = r.u16();
    var name = utf8(r.take(nl), 'a notation name');
    var value = r.take(vl);
    r.expect_end('a notation');
    var human = (flags[0] & 0x80) !== 0;
    v = { name: name, human_readable: human, value: human ? utf8(value, 'a notation') : value };
    break;
  case 'reason':
    v = { code: r.u8(), reason: utf8(r.rest(), 'a revocation reason') }; break;
  case 'signature':
    v = read_signature(d); break;
  default:
    v = d;
  }
  if (spec.as !== 'signature' && spec.as !== 'notation' && spec.as !== 'list' &&
      spec.as !== 'pairs' && spec.as !== 'text' && spec.as !== 'raw' &&
      spec.as !== 'fingerprint' && spec.as !== 'reason') {
    r.expect_end(spec.name);
  }
  return v;
}

// The subpackets a verifier asks about, from the HASHED area - the last
// of each, as 5.2.3.9 suggests - and the issuer from either, saying which.
function summarize(sig) {
  var h = sig.hashed_subpackets;
  var i;
  sig.unknown_critical = [];

  for (i = 0; i < h.length; i++) {
    var sp = h[i];
    if (sp.critical && sp.name === null) { sig.unknown_critical.push(sp.id); }
    if (sp.name === null) { continue; }
    if (sp.name === 'key_flags') {
      sig.key_flags = flags_of(sp.data);
    } else if (sp.name === 'features') {
      sig.features = { seipd_v1: (sp.data[0] & 1) !== 0, seipd_v2: (sp.data[0] & 8) !== 0 };
    } else if (sp.name === 'issuer_key_id') {
      sig.issuer_key_id = hex(sp.data);
    } else if (sp.name !== 'notation' && sp.name !== 'embedded_signature') {
      sig[sp.name] = sp.value;
    }
  }

  // The unhashed issuer is advisory - which key to TRY, not who signed.
  var u = sig.unhashed_subpackets;
  for (i = 0; i < u.length; i++) {
    if (u[i].name === 'issuer_key_id' && sig.issuer_key_id === undefined) {
      sig.issuer_key_id = hex(u[i].data);
      sig.issuer_key_id_unhashed = true;
    }
    if (u[i].name === 'issuer_fingerprint' && sig.issuer_fingerprint === undefined) {
      sig.issuer_fingerprint = u[i].value;
      sig.issuer_fingerprint_unhashed = true;
    }
  }

  sig.notations = h.filter(function (x) { return x.name === 'notation'; })
    .map(function (x) { return x.value; });
  sig.embedded_signatures = h.concat(u).filter(function (x) { return x.name === 'embedded_signature'; })
    .map(function (x) { return x.value; });

  // 5.2.3.11: the creation time MUST be in the hashed area.
  if (sig.version !== 3 && sig.created === undefined) {
    fail('missing-creation-time', 'a v' + sig.version + ' signature carries its ' +
      'creation time in the hashed area (RFC 9580 5.2.3.11)');
  }
}

function flags_of(data) {
  var out = [];
  IDS.KEY_FLAGS.forEach(function (f) { if (data.length > 0 && (data[0] & f[0])) { out.push(f[1]); } });
  IDS.KEY_FLAGS_2.forEach(function (f) { if (data.length > 1 && (data[1] & f[0])) { out.push(f[1]); } });
  return out;
}

// ---------------------------------------------------------------------------
// What a signature is over - RFC 9580 5.2.4
// ---------------------------------------------------------------------------

// The bytes to hash with sig.hash, and what to compare. `target`:
//
//   { document }                     binary (0x00), text (0x01 - CRLF line
//                                    endings are applied here), standalone
//                                    and timestamp signatures take none
//   { key, user_id | user_attribute } certifications and their revocation
//   { key, subkey }                  subkey binding / primary key binding /
//                                    subkey revocation
//   { key }                          direct-key and key revocation
//   { signature }                    third-party confirmation
//
// Keys are the packets packets_from_bytes returned, public or secret: the
// public part is what is hashed.
function verification_plan(sig, target) {
  if (sig.unknown_critical && sig.unknown_critical.length > 0) {
    fail('unknown-critical-subpacket', 'subpacket ' + sig.unknown_critical.join(', ') +
      ' is critical and unknown: RFC 9580 5.2.5 says this signature MUST NOT validate');
  }
  if (sig.hash === null) {
    fail('unknown-hash', 'hash algorithm ' + sig.hash_id);
  }

  var t = target || {};
  var parts = [];
  var type = sig.signature_type_id;

  if (sig.version === 6) { parts.push(sig.salt); }

  if (type === 0x00) {
    parts.push(required(t.document, 'document'));
  } else if (type === 0x01) {
    parts.push(canonical_text(required(t.document, 'document')));
  } else if (type === 0x02 || type === 0x40) {
    // standalone and timestamp: nothing but the trailer
  } else if ((type >= 0x10 && type <= 0x13) || type === 0x30) {
    parts.push(key_hash_form(required(t.key, 'key'), sig.version));
    if (t.user_id !== undefined) {
      parts.push(user_hash_form(0xB4, user_id_bytes(t.user_id), sig.version));
    } else if (t.user_attribute !== undefined) {
      var ua = t.user_attribute;
      parts.push(user_hash_form(0xD1, ua.body instanceof Uint8Array ? ua.body : to_bytes(ua), sig.version));
    } else {
      fail('missing-target', 'a certification is over a key and a user_id or user_attribute');
    }
  } else if (type === 0x18 || type === 0x19 || type === 0x28) {
    parts.push(key_hash_form(required(t.key, 'key'), sig.version));
    parts.push(key_hash_form(required(t.subkey, 'subkey'), sig.version));
  } else if (type === 0x1F || type === 0x20) {
    parts.push(key_hash_form(required(t.key, 'key'), sig.version));
  } else if (type === 0x50) {
    var s = required(t.signature, 'signature');
    var confirmed = third_party_form(s);
    parts.push(new Uint8Array([0x88]), u32(confirmed.length), confirmed);
  } else {
    fail('unknown-signature-type', 'signature type 0x' + type.toString(16));
  }

  parts.push(trailer(sig));

  var out = {
    hash: sig.hash,
    bytes: concat_bytes(parts),
    left16: sig.left16,
    algorithm: sig.public_key_algorithm,
    signature: sig.value,
    note: 'hash bytes with ' + sig.hash + '; the digest\'s first two octets ' +
          'must equal left16 (a v6 verifier MUST check it); then verify ' +
          'signature over the digest with the signer\'s key' +
          (/^rsa/.test(sig.public_key_algorithm || '') ? '. RSA: left-pad signature.s to the modulus length first - an MPI drops leading zeros' : '')
  };
  if (sig.weak) {
    out.warning = sig.hash + ' is not collision resistant: RFC 9580 9.5 says ' +
      'MUST NOT be used for signatures that a verifier treats as valid';
  }
  return out;
}

function required(v, name) {
  if (v === undefined || v === null) {
    fail('missing-target', 'this signature type needs target.' + name);
  }
  return v;
}

// 5.2.4: the trailer after the signed data.
function trailer(sig) {
  if (sig.version === 3) {
    return sig.hashed_portion;       // type and creation time, 5 octets
  }
  return concat_bytes([sig.hashed_portion,
    new Uint8Array([sig.version, 0xFF]), u32(sig.hashed_portion.length)]);
}

// 5.2.4: a key as a signature hashes it.
function key_hash_form(key, sig_version) {
  var body = key.public_body;
  if (!(body instanceof Uint8Array)) {
    fail('bad-target', 'a key is a key packet, as packets_from_bytes returned it');
  }
  if (sig_version === 6) {
    return concat_bytes([new Uint8Array([0x9B]), u32(body.length), body]);
  }
  return concat_bytes([new Uint8Array([0x99]), u16(body.length), body]);
}

function user_hash_form(tag, bytes, sig_version) {
  if (sig_version === 3) { return bytes; }
  return concat_bytes([new Uint8Array([tag]), u32(bytes.length), bytes]);
}

function user_id_bytes(u) {
  if (typeof u === 'string') { return utf8_bytes(u); }
  if (u && u.user_id instanceof Uint8Array) { return u.user_id; }
  return to_bytes(u);
}

// 5.2.4: a confirmed signature's body, its unhashed area emptied.
function third_party_form(s) {
  var body = s.body || s.raw;
  if (!(body instanceof Uint8Array) || s.version === 3) {
    fail('bad-target', 'a third-party confirmation is over a v4 or v6 signature packet');
  }
  var r = new Reader(body);
  r.take(s.hashed_portion.length);
  var ul = s.version === 4 ? r.u16() : r.u32();
  r.take(ul);
  return concat_bytes([s.hashed_portion, new Uint8Array(s.version === 4 ? 2 : 4),
    body.subarray(r.pos)]);
}

// 5.2.4: line endings to CRLF.
function canonical_text(doc) {
  var b = typeof doc === 'string' ? utf8_bytes(doc) : to_bytes(doc);
  var out = [];
  var i;
  for (i = 0; i < b.length; i++) {
    if (b[i] === 0x0D) {
      out.push(0x0D, 0x0A);
      if (b[i + 1] === 0x0A) { i++; }
    } else if (b[i] === 0x0A) {
      out.push(0x0D, 0x0A);
    } else {
      out.push(b[i]);
    }
  }
  return new Uint8Array(out);
}

// The Key ID from a fingerprint the caller computed over fingerprint_input:
// v4, the last 8 octets; v6, the first 8 (5.5.4).
function key_id(key, fingerprint) {
  var fp = to_bytes(fingerprint);
  if (key.version === 3) { return key.key_id; }
  var want = key.version === 6 ? 32 : 20;
  if (fp.length !== want) {
    fail('bad-fingerprint', 'a v' + key.version + ' fingerprint is ' + want + ' octets');
  }
  return hex(key.version === 6 ? fp.subarray(0, 8) : fp.subarray(fp.length - 8));
}

// ---------------------------------------------------------------------------
// The other packets
// ---------------------------------------------------------------------------

function read_user_attribute(body) {
  var r = new Reader(body);
  var subs = [];
  while (r.remaining() > 0) {
    var o = r.u8();
    var len = o < 192 ? o : o < 255 ? ((o - 192) << 8) + r.u8() + 192 : r.u32();
    var data = r.take(len, 'a user attribute subpacket');
    var sub = { id: data[0], data: data.subarray(1) };
    if (sub.id === 1 && sub.data.length >= 16 && sub.data[0] === 0x10 && sub.data[1] === 0 &&
        sub.data[2] === 1) {
      sub.image = { encoding: sub.data[3] === 1 ? 'jpeg' : sub.data[3], data: sub.data.subarray(16) };
    }
    subs.push(sub);
  }
  return { subpackets: subs };
}

function read_literal(body) {
  var r = new Reader(body);
  var f = r.u8('the literal data format');
  var name = r.take(r.u8(), 'the file name');
  var date = r.u32('the date');
  var format = String.fromCharCode(f);
  if ('btul1'.indexOf(format) === -1) {
    fail('bad-literal', 'literal data format "' + format + '"');
  }
  return {
    format: format, filename: utf8_or_null(name), filename_bytes: name, date: date,
    data: r.rest(),
    // 5.9: not covered by any signature.
    note: 'format, filename and date are not signed - the data alone is'
  };
}

function read_compressed(body) {
  var id = body[0];
  if (body.length === 0 || IDS.COMPRESSION[id] === undefined) {
    fail('unknown-compression', 'compression algorithm ' + id);
  }
  return {
    algorithm: IDS.COMPRESSION[id], compressed: body.subarray(1),
    note: { uncompressed: 'the packets as they are',
            zip: 'raw DEFLATE (RFC 1951): inflateRawSync, with a size limit',
            zlib: 'zlib (RFC 1950): inflateSync, with a size limit',
            bzip2: 'BZip2' }[IDS.COMPRESSION[id]]
  };
}

function read_one_pass(body) {
  var r = new Reader(body);
  var version = r.u8();
  if (version !== 3 && version !== 6) {
    fail('unsupported-version', 'one-pass signature version ' + version);
  }
  var out = { version: version, signature_type_id: r.u8(), hash_id: r.u8(),
              public_key_algorithm_id: r.u8() };
  if (version === 6) {
    out.salt = r.take(r.u8(), 'the salt');
    out.issuer_fingerprint = hex(r.take(32));
  } else {
    out.issuer_key_id = hex(r.take(8));
  }
  var nested = r.u8();
  r.expect_end('the one-pass signature');
  // 5.4: zero means another one-pass signature follows; 1, this is the
  // last before the data.
  out.last = nested !== 0;
  out.hash = IDS.HASH[out.hash_id] ? IDS.HASH[out.hash_id].name : null;
  out.signature_type = IDS.SIGNATURE_TYPE[out.signature_type_id] || null;
  return out;
}

function read_pkesk(body) {
  var r = new Reader(body);
  var version = r.u8();
  var out = { version: version };

  if (version === 3) {
    out.key_id = hex(r.take(8));
  } else if (version === 6) {
    var n = r.u8();
    if (n > 0) {
      out.key_version = r.u8();
      out.fingerprint = hex(r.take(n - 1));
    } else {
      out.anonymous = true;
    }
  } else {
    fail('unsupported-version', 'PKESK version ' + version);
  }
  if (version === 3 && out.key_id === '0000000000000000') { out.anonymous = true; }

  out.algorithm_id = r.u8();
  var alg = IDS.PUBLIC_KEY[out.algorithm_id];
  out.algorithm = alg ? alg.name : null;
  var n2 = out.algorithm;

  if (n2 === 'rsa' || n2 === 'rsa-encrypt-only') {
    out.fields = { m: r.mpi('m^e') };
  } else if (n2 === 'elgamal') {
    out.fields = { gk: r.mpi('g^k'), myk: r.mpi('m*y^k') };
  } else if (n2 === 'ecdh') {
    out.fields = { ephemeral: r.mpi('the ephemeral point') };
    out.fields.wrapped = r.take(r.u8(), 'the wrapped key');
  } else if (n2 === 'x25519' || n2 === 'x448') {
    out.fields = { ephemeral: r.take(alg.native) };
    var len = r.u8();
    if (version === 3) {
      out.fields.cipher_id = r.u8();
      out.fields.wrapped = r.take(len - 1, 'the wrapped key');
    } else {
      out.fields.wrapped = r.take(len, 'the wrapped key');
    }
    // 5.1.6/5.1.7: HKDF over ephemeral || recipient || shared, no salt.
    out.kdf = { hash: n2 === 'x25519' ? 'sha256' : 'sha512',
                info: n2 === 'x25519' ? 'OpenPGP X25519' : 'OpenPGP X448',
                key_length: n2 === 'x25519' ? 16 : 32,
                wrap: n2 === 'x25519' ? 'aes128Wrap' : 'aes256Wrap' };
  } else {
    out.fields = { raw: r.rest() };
  }
  r.expect_end('the PKESK');
  return out;
}

function read_skesk(body) {
  var r = new Reader(body);
  var version = r.u8();
  var out = { version: version };

  if (version === 4) {
    out.cipher_id = r.u8();
    out.s2k = read_s2k(r);
    out.encrypted_key = r.remaining() > 0 ? r.rest() : null;
  } else if (version === 6) {
    var count_end = r.pos + 1 + r.buf[r.pos];
    r.u8();
    out.cipher_id = r.u8();
    out.aead_id = r.u8();
    var s2k_end = r.pos + 1 + r.buf[r.pos];
    r.u8();
    out.s2k = read_s2k(r);
    if (r.pos !== s2k_end) { fail('bad-s2k', 'the S2K length disagrees with its fields'); }
    var aead = IDS.AEAD[out.aead_id];
    if (!aead) { fail('unknown-aead', 'AEAD algorithm ' + out.aead_id); }
    out.aead = aead.name;
    out.iv = r.take(aead.nonce, 'the IV');
    if (r.pos !== count_end) { fail('bad-skesk', 'the field count disagrees with the fields'); }
    var rest = r.rest();
    if (rest.length < aead.tag) { fail('truncated', 'no room for the AEAD tag'); }
    out.encrypted_key = rest.subarray(0, rest.length - aead.tag);
    // Not `tag`: that is the packet's type number.
    out.auth_tag = rest.subarray(rest.length - aead.tag);
    // 5.3.2: HKDF-SHA256 info, and the additional data - the same octets.
    out.hkdf_info = new Uint8Array([0xC3, 6, out.cipher_id, out.aead_id]);
    out.aad = out.hkdf_info;
  } else {
    fail('unsupported-version', 'SKESK version ' + version);
  }
  out.cipher = IDS.CIPHER[out.cipher_id] ? IDS.CIPHER[out.cipher_id].name : null;
  return out;
}

function read_seipd(body) {
  var r = new Reader(body);
  var version = r.u8();

  if (version === 1) {
    return { version: 1, ciphertext: r.rest(),
             note: 'decrypt with the session key\'s cipher in CFB mode, IV all ' +
                   'zeros; then seipd_v1_open(plaintext, block size)' };
  }
  if (version !== 2) {
    fail('unsupported-version', 'SEIPD version ' + version);
  }

  var out = { version: 2, cipher_id: r.u8(), aead_id: r.u8(), chunk_size_octet: r.u8(),
              salt: r.take(32, 'the salt') };
  var cipher = IDS.CIPHER[out.cipher_id];
  var aead = IDS.AEAD[out.aead_id];
  if (!cipher || !aead) {
    fail('unknown-algorithm', 'cipher ' + out.cipher_id + ' / AEAD ' + out.aead_id);
  }
  if (out.chunk_size_octet > 16) {
    fail('bad-chunk-size', 'chunk size octets go up to 16 (4 MiB), 5.13.2');
  }
  out.cipher = cipher.name;
  out.aead = aead.name;
  out.chunk_size = Math.pow(2, out.chunk_size_octet + 6);

  // 5.13.2: info - the same octets are each chunk's additional data.
  out.hkdf_info = new Uint8Array([0xD2, 2, out.cipher_id, out.aead_id, out.chunk_size_octet]);
  out.key_length = cipher.key;
  out.iv_length = aead.nonce - 8;

  var data = r.rest();
  if (data.length < aead.tag) { fail('truncated', 'no room for the final tag'); }
  var stream = data.subarray(0, data.length - aead.tag);
  var chunks = [];
  var pos = 0;
  var total = 0;
  var step = out.chunk_size + aead.tag;

  while (pos < stream.length) {
    var piece = stream.subarray(pos, Math.min(pos + step, stream.length));
    if (piece.length <= aead.tag) { fail('truncated', 'a chunk shorter than its tag'); }
    chunks.push({ index: chunks.length,
                  ciphertext: piece.subarray(0, piece.length - aead.tag),
                  tag: piece.subarray(piece.length - aead.tag),
                  aad: out.hkdf_info });
    total += piece.length - aead.tag;
    pos += step;
  }
  out.chunks = chunks;
  // The final tag authenticates the empty string, with the total length.
  out.final = { index: chunks.length, tag: data.subarray(data.length - aead.tag),
                aad: concat_bytes([out.hkdf_info, u64(total)]) };
  out.note = 'derive key_length + iv_length octets with HKDF-SHA256(session key, ' +
    'salt, hkdf_info): key, then iv. Each chunk\'s nonce is seipd_v2_nonce(iv, index)';
  return out;
}

function u64(n) {
  var out = new Uint8Array(8);
  var v = n;
  var i;
  for (i = 7; i >= 0; i--) { out[i] = v % 256; v = Math.floor(v / 256); }
  return out;
}

// The nonce for a v2 SEIPD chunk: the HKDF-derived IV, then the chunk index
// as 8 big-endian octets (5.13.2).
function seipd_v2_nonce(iv, index) {
  return concat_bytes([to_bytes(iv), u64(index)]);
}

// A decrypted v1 SEIPD: the random prefix and its quick check, the packets,
// and - to hash with SHA-1 and compare - the MDC's input and value.
function seipd_v1_open(plaintext, block_size) {
  var p = to_bytes(plaintext);
  var bs = block_size;
  if (bs !== 8 && bs !== 16) { fail('bad-input', 'the block size is 8 or 16'); }
  if (p.length < bs + 2 + 22) { fail('truncated', 'too short for a prefix and an MDC'); }
  if (p[p.length - 22] !== 0xD3 || p[p.length - 21] !== 0x14) {
    fail('no-mdc', 'a v1 SEIPD plaintext ends with an MDC packet, 0xD3 0x14 and 20 octets');
  }
  return {
    // 5.13.1 / 13.4: the quick check says a key is wrong. It must not be
    // reported to a sender as such - it is an oracle.
    quick_check: p[bs - 2] === p[bs] && p[bs - 1] === p[bs + 1],
    mdc_input: p.subarray(0, p.length - 20),
    mdc: p.subarray(p.length - 20),
    packets: p.subarray(bs + 2, p.length - 22),
    note: 'SHA-1 of mdc_input must equal mdc, and only then are packets the message'
  };
}

// A session key from what the public key operation produced (5.1.3-5.1.5):
// for RSA and Elgamal, m after EME-PKCS1-v1_5 decoding; for ECDH, the
// unwrapped octets, padding included. v3 carries the cipher first; v6 not.
function session_key_from(decrypted, version, algorithm) {
  var d = to_bytes(decrypted);
  if (algorithm === 'ecdh') {
    var pad = d[d.length - 1];
    var j;
    if (pad === 0 || pad > 8 || pad > d.length) { fail('bad-padding', 'the ECDH session key padding'); }
    for (j = d.length - pad; j < d.length; j++) {
      if (d[j] !== pad) { fail('bad-padding', 'the ECDH session key padding'); }
    }
    d = d.subarray(0, d.length - pad);
  }
  var start = version === 3 ? 1 : 0;
  var key = d.subarray(start, d.length - 2);
  var sum = 0;
  var i;
  for (i = 0; i < key.length; i++) { sum = (sum + key[i]) & 0xFFFF; }
  if (((d[d.length - 2] << 8) | d[d.length - 1]) !== sum) {
    fail('bad-checksum', 'the session key checksum does not match');
  }
  var out = { session_key: key };
  if (version === 3) {
    out.cipher_id = d[0];
    out.cipher = IDS.CIPHER[d[0]] ? IDS.CIPHER[d[0]].name : null;
  }
  return out;
}

// 11.5: the ECDH KDF's parameters - what the KDF hashes after the shared
// secret - for a recipient ECDH key and its fingerprint.
function ecdh_kdf_param(key, fingerprint) {
  var m = key.material;
  if (key.algorithm !== 'ecdh' || !m || !m.kdf) {
    fail('bad-key', 'an ECDH key packet is needed');
  }
  var oid = OID.from_string(m.oid);
  return concat_bytes([new Uint8Array([oid.length]), oid,
    new Uint8Array([18, 3, 1, m.kdf.hash_id, m.kdf.cipher_id]),
    utf8_bytes('Anonymous Sender    '), to_bytes(fingerprint)]);
}

// ---------------------------------------------------------------------------
// Transferable keys - RFC 9580 10.1
// ---------------------------------------------------------------------------

// Every key in a packet sequence (a keyring has several): the primary key,
// its direct signatures, its users with theirs, its subkeys with theirs.
// Padding, marker and trust packets are skipped.
function keys_from_packets(packets) {
  var out = [];
  var cur = null;
  var last = null;
  var i;

  for (i = 0; i < packets.length; i++) {
    var p = packets[i];
    var t = p.type;
    if (t === 'padding' || t === 'marker' || t === 'trust' || t === 'unknown') { continue; }

    if (t === 'public-key' || t === 'secret-key') {
      cur = { primary: p, secret: t === 'secret-key', direct_signatures: [], users: [], subkeys: [] };
      last = cur.direct_signatures;
      out.push(cur);
      continue;
    }
    if (cur === null) {
      fail('bad-key-sequence', 'a transferable key starts with a primary key packet, ' +
        'and this starts with ' + t);
    }
    if (t === 'user-id' || t === 'user-attribute') {
      if (cur.subkeys.length > 0) {
        fail('bad-key-sequence', 'a user ID after a subkey (RFC 9580 10.1)');
      }
      var u = { packet: p, signatures: [] };
      if (t === 'user-id') { u.user_id = p.user_id; u.text = p.text; } else { u.user_attribute = p; }
      cur.users.push(u);
      last = u.signatures;
    } else if (t === 'public-subkey' || t === 'secret-subkey') {
      var s = { key: p, signatures: [] };
      cur.subkeys.push(s);
      last = s.signatures;
    } else if (t === 'signature') {
      last.push(p);
    } else {
      fail('bad-key-sequence', 'a ' + t + ' packet inside a transferable key');
    }
  }

  out.forEach(function (k) {
    if (k.primary.version !== 6 && k.users.length === 0) {
      fail('bad-key-sequence', 'a version ' + k.primary.version + ' key carries ' +
        'at least one user ID (RFC 9580 10.1.3)');
    }
  });
  return out;
}

export {
  armor_decode,
  cleartext_decode,
  packets_from_bytes,
  keys_from_packets,
  verification_plan,
  key_id,
  canonical_text,
  seipd_v1_open,
  seipd_v2_nonce,
  session_key_from,
  ecdh_kdf_param
};

// OpenPGP, RFC 9580 - write: armour, the cleartext framework, packets,
// keys, signatures, and the containers of an encrypted message.
//
// openpgp.js reads; this writes, with its own code for every structure -
// the trailer a signature hashes, the form a key is hashed in - so that a
// mistake in one is not cancelled by the same mistake in the other
// (commons/README.md). The RFC's appendix A and gpg are what both answer to.
//
// This library signs, hashes and encrypts nothing. Each step returns the
// bytes the caller's primitives work on:
//
//   var k = openpgp_build.key_packet({ version: 6, created, algorithm:
//             'ed25519', public_key });
//   var p = openpgp_build.signature_prepare({ version: 6, type: 'direct-key',
//             algorithm: 'ed25519', hash: 'sha512', salt: random(32),
//             hashed: [...], target: { key: k } });
//   var d = sha512(p.bytes);
//   var sig = openpgp_build.signature_assemble(p, d, ed25519.sign(d));

import * as B from './base.js';
import * as OID from './oid.js';
import * as IDS from './openpgp_ids.js';

import { to_bytes, to_array, concat_bytes, append } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';
import { encode_utf8 } from './commons/encode_text.js';
import { crc24 } from './commons/crc24.js';

var fail = make_fail_here('openpgp');

function utf8(s) { return encode_utf8(String(s), fail); }

function w16(n) { return [(n >> 8) & 0xFF, n & 0xFF]; }
function w32(n) { return [(n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF]; }

function w64(n) {
  var out = [];
  var v = n;
  var i;
  for (i = 0; i < 8; i++) { out.unshift(v % 256); v = Math.floor(v / 256); }
  return out;
}

// RFC 9580 3.2: the bit count, then the magnitude without leading zeros.
function mpi(bytes) {
  var b = to_array(bytes);
  while (b.length > 0 && b[0] === 0) { b = b.slice(1); }
  var bits = 0;
  if (b.length > 0) {
    var top = b[0];
    while (top > 0) { bits++; top >>= 1; }
    bits += (b.length - 1) * 8;
  }
  return w16(bits).concat(b);
}

function time_of(t, what) {
  var s = t instanceof Date ? Math.floor(t.getTime() / 1000) : t;
  if (typeof s !== 'number' || s < 0 || s > 0xFFFFFFFF || s % 1 !== 0) {
    fail('bad-time', (what || 'a time') + ' is whole seconds since the epoch, or a Date');
  }
  return s;
}

function id_or_fail(table, name, what) {
  var id = typeof name === 'number' ? name : IDS.id_of(table, name);
  if (id === null || table[id] === undefined) {
    fail('unknown-' + what, '"' + name + '" is not a known ' + what);
  }
  return id;
}

// ---------------------------------------------------------------------------
// Armour - RFC 9580 6
// ---------------------------------------------------------------------------

var ARMOR = { 'MESSAGE': 1, 'PUBLIC KEY BLOCK': 1, 'PRIVATE KEY BLOCK': 1, 'SIGNATURE': 1 };

// options: headers [[key, value]]; checksum - false by default, since RFC
// 9580 6.1 says SHOULD NOT, and MUST NOT for v6 material.
function armor_encode(type, data, options) {
  if (!ARMOR[type]) {
    fail('unknown-armor-type', 'the armour type is MESSAGE, PUBLIC KEY BLOCK, ' +
      'PRIVATE KEY BLOCK or SIGNATURE');
  }
  var opts = options || {};
  var bytes = to_bytes(data);
  var out = '-----BEGIN PGP ' + type + '-----\n';
  (opts.headers || []).forEach(function (h) {
    if (/[\r\n]/.test(h[0] + h[1]) || /[:\s]/.test(h[0])) {
      fail('bad-armor-header', 'an armour header is a key without spaces or colons, ' +
        'and a one-line value');
    }
    out += h[0] + ': ' + h[1] + '\n';
  });
  out += '\n';
  var b64 = B.to_base64(bytes);
  var i;
  for (i = 0; i < b64.length; i += 64) { out += b64.substr(i, 64) + '\n'; }
  if (opts.checksum === true) {
    var c = crc24(bytes);
    out += '=' + B.to_base64(new Uint8Array([(c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF])) + '\n';
  }
  return out + '-----END PGP ' + type + '-----\n';
}

// ---------------------------------------------------------------------------
// The cleartext framework - RFC 9580 7
// ---------------------------------------------------------------------------

// The bytes a cleartext signature is made over: trailing spaces and tabs
// removed from each line, CRLF between lines, no final line ending - sign
// these with a text (0x01) signature, then cleartext_encode.
function cleartext_signed_bytes(text) {
  var lines = String(text).split(/\r\n|\n|\r/);
  return new Uint8Array(utf8(lines.map(function (l) {
    return l.replace(/[ \t]+$/, '');
  }).join('\r\n')));
}

// The message: header, dash-escaped text, and the armoured signature(s).
// hashes: the legacy Hash header's values ('SHA256'...). RFC 9580 6.2.2.3:
// only for a v4 signature with a SHA-2 hash - and gpg requires it then, so
// pass it for one; never for v6.
function cleartext_encode(text, signature_packets, options) {
  var opts = options || {};
  var out = '-----BEGIN PGP SIGNED MESSAGE-----\n';
  if (opts.hashes && opts.hashes.length > 0) {
    out += 'Hash: ' + opts.hashes.join(',') + '\n';
  }
  out += '\n';
  var lines = String(text).split(/\r\n|\n|\r/);
  out += lines.map(function (l) { return l.charAt(0) === '-' ? '- ' + l : l; }).join('\n');
  out += '\n';
  return out + armor_encode('SIGNATURE', signature_packets, { checksum: opts.checksum });
}

// ---------------------------------------------------------------------------
// Packets - RFC 9580 4.2.1, the OpenPGP format only
// ---------------------------------------------------------------------------

function packet(type, body) {
  var tag = id_or_fail(IDS.PACKET, type, 'packet type');
  var b = to_array(body);
  var n = b.length;
  var len = n < 192 ? [n]
    : n < 8384 ? [((n - 192) >> 8) + 192, (n - 192) & 0xFF]
    : [255].concat(w32(n));
  return new Uint8Array([0xC0 | tag].concat(len, b));
}

function packets(list) {
  return concat_bytes(list.map(function (p) { return to_bytes(p); }));
}

// ---------------------------------------------------------------------------
// Keys - RFC 9580 5.5
// ---------------------------------------------------------------------------

// parts: { version: 4 | 6, created, algorithm (a name - 'ed25519',
// 'eddsa-legacy', 'ecdsa', 'ecdh', 'rsa', 'x25519'...), material - or
// public_key in the library's shape - subkey?, secret? }
//
// secret: { material } in the clear - the RSA d, p, q, u; the scalar; the
// native octets - or { usage, cipher, aead?, s2k, iv, encrypted } as the
// caller encrypted it.
//
// Returns the packet, and what a fingerprint and a signature hash.
function key_packet(parts) {
  var p = parts || {};
  var version = p.version;
  if (version !== 4 && version !== 6) {
    fail('unsupported-key-version', 'keys are written as version 4 or 6');
  }
  var alg_id = id_or_fail(IDS.PUBLIC_KEY, p.algorithm, 'public key algorithm');
  var alg = IDS.PUBLIC_KEY[alg_id];
  var material = key_material(alg, p.material || from_library(alg, p.public_key), version);

  var pub = [version].concat(w32(time_of(p.created, 'created')), [alg_id]);
  if (version === 6) { pub = pub.concat(w32(material.length)); }
  pub = pub.concat(material);

  var secret = p.secret !== undefined && p.secret !== null;
  var body = pub;
  if (secret) { body = pub.concat(secret_part(alg, p.secret, version, p.subkey, pub)); }

  var type = secret ? (p.subkey ? 'secret-subkey' : 'secret-key')
    : (p.subkey ? 'public-subkey' : 'public-key');
  var public_body = new Uint8Array(pub);

  return {
    packet: packet(type, body),
    body: new Uint8Array(body),
    public_body: public_body,
    version: version,
    fingerprint_input: new Uint8Array(version === 6
      ? [0x9B].concat(w32(pub.length), pub) : [0x99].concat(w16(pub.length), pub)),
    fingerprint_hash: version === 6 ? 'sha256' : 'sha1'
  };
}

// The library's key shape -> the fields this algorithm writes.
function from_library(alg, k) {
  if (!k) { fail('bad-key', 'give material, or public_key as spki.from_der returns it'); }
  if (alg.native) { return { point: k.point }; }
  if (alg.fields && k.rsa) { return { n: k.rsa.n, e: k.rsa.e }; }
  if (alg.name === 'eddsa-legacy' && k.algorithm === 'Ed25519') {
    return { curve: 'ed25519Legacy', point: concat_bytes([new Uint8Array([0x40]), to_bytes(k.point)]) };
  }
  if (alg.name === 'ecdh' && k.algorithm === 'X25519') {
    return { curve: 'curve25519Legacy', point: concat_bytes([new Uint8Array([0x40]), to_bytes(k.point)]) };
  }
  if (alg.curve && k.curve) { return { curve: k.curve, point: k.point }; }
  fail('bad-key', 'a ' + k.algorithm + ' key is not a ' + alg.name + ' key');
}

function key_material(alg, m, version) {
  if (alg.native) {
    var pt = to_array(m.point);
    if (pt.length !== alg.native) {
      fail('bad-key-length', 'a ' + alg.name + ' key is ' + alg.native + ' octets');
    }
    return pt;
  }
  if (alg.fields) {
    var out = [];
    alg.fields.forEach(function (f) {
      if (m[f] === undefined) { fail('bad-key', alg.name + ' needs ' + f); }
      append(out, mpi(m[f]));
    });
    return out;
  }
  var dotted = curve_oid(m.curve);
  var spec = IDS.CURVE[dotted];
  if (version === 6 && spec.wire === 'prefixed') {
    fail('legacy-curve-in-v6', m.curve + ' MUST NOT be used in a version 6 key');
  }
  var point = to_array(m.point);
  if (spec.wire === 'prefixed' ? (point.length !== 33 || point[0] !== 0x40)
      : (point.length !== 1 + 2 * spec.size || point[0] !== 0x04)) {
    fail('bad-point', m.curve + ' takes ' + (spec.wire === 'prefixed'
      ? '0x40 then 32 octets' : 'an uncompressed SEC1 point'));
  }
  var oid = to_array(OID.from_string(dotted));
  var res = [oid.length].concat(oid, mpi(point));
  if (alg.kdf) {
    var kdf = m.kdf || {};
    res = res.concat([3, 1, id_or_fail(IDS.HASH, kdf.hash || 'sha256', 'hash'),
      id_or_fail(IDS.CIPHER, kdf.cipher || 'aes128', 'cipher')]);
  }
  return res;
}

function curve_oid(name) {
  var k;
  for (k in IDS.CURVE) {
    if (Object.prototype.hasOwnProperty.call(IDS.CURVE, k) &&
        (IDS.CURVE[k].name === name || k === name)) { return k; }
  }
  fail('unknown-curve', 'curve "' + name + '" has no OpenPGP identifier');
}

// 5.5.3, written.
function secret_part(alg, s, version, subkey, pub) {
  if (s.encrypted !== undefined) {
    var usage = s.usage;
    if (usage !== 253 && usage !== 254) {
      fail('bad-s2k-usage', 'encrypted secret keys are written with usage 253 ' +
        '(AEAD) or 254 (CFB with SHA-1) - 255 and the legacy forms are malleable');
    }
    var params = [id_or_fail(IDS.CIPHER, s.cipher, 'cipher')];
    if (usage === 253) { params.push(id_or_fail(IDS.AEAD, s.aead, 'AEAD mode')); }
    var spec = to_array(s2k(s.s2k));
    if (version === 6) { params.push(spec.length); }
    params = params.concat(spec, to_array(s.iv));
    var head = [usage];
    if (version === 6) { head.push(params.length); }
    return head.concat(params, to_array(s.encrypted));
  }

  var m = s.material || {};
  var fields = [];
  if (alg.native) {
    fields = to_array(m.scalar);
    if (fields.length !== alg.native) { fail('bad-key-length', 'the secret is ' + alg.native + ' octets'); }
  } else {
    alg.secret.forEach(function (f) {
      if (m[f] === undefined) { fail('bad-key', 'the secret needs ' + f); }
      append(fields, mpi(m[f]));
    });
  }
  var out = [0].concat(fields);
  if (version !== 6) {
    var sum = 0;
    fields.forEach(function (b) { sum = (sum + b) & 0xFFFF; });
    out = out.concat(w16(sum));
  }
  return out;
}

// 3.7.1: an S2K specifier. Simple S2K is not written (3.7.2).
function s2k(spec) {
  var s = spec || {};
  if (s.type === 'iterated' || s.type === 'salted') {
    var salt = to_array(s.salt);
    if (salt.length !== 8) { fail('bad-s2k', 'the salt is 8 octets'); }
    var out = [s.type === 'iterated' ? 3 : 1, id_or_fail(IDS.HASH, s.hash, 'hash')].concat(salt);
    if (s.type === 'iterated') {
      var c = s.coded_count;
      if (typeof c !== 'number' || c < 0 || c > 255 || c % 1 !== 0) {
        fail('bad-s2k', 'coded_count is the octet 3.7.1.3 encodes - 255 for 65011712 octets');
      }
      out.push(c);
    }
    return new Uint8Array(out);
  }
  if (s.type === 'argon2') {
    var a = to_array(s.salt);
    if (a.length !== 16) { fail('bad-s2k', 'the Argon2 salt is 16 octets'); }
    if (!(s.passes > 0) || !(s.parallelism > 0)) {
      fail('bad-argon2', 'passes and parallelism are non-zero');
    }
    var min = 3 + Math.ceil(Math.log(s.parallelism) / Math.LN2);
    if (!(s.encoded_memory >= min && s.encoded_memory <= 31)) {
      fail('bad-argon2', 'encoded_memory is ' + min + '..31');
    }
    return new Uint8Array([4].concat(a, [s.passes, s.parallelism, s.encoded_memory]));
  }
  fail('bad-s2k', 'S2K type is iterated, salted or argon2');
}

function user_id_packet(text) {
  return packet('user-id', typeof text === 'string' ? utf8(text) : to_array(text));
}

// ---------------------------------------------------------------------------
// Signatures - RFC 9580 5.2
// ---------------------------------------------------------------------------

// A subpacket: { type: a name from the registry or a number, value,
// critical? }. Values:
//
//   created, signature_expires, key_expires    seconds (or a Date for created)
//   exportable, revocable, primary_user_id     true / false
//   preferred_ciphers, _hashes, _compression    names or ids
//   preferred_aead                             [[cipher, aead], ...]
//   issuer_key_id                              16 hex digits, or 8 octets
//   issuer_fingerprint, intended_recipient     { version, fingerprint }
//   key_flags                                  ['certify', 'sign', ...]
//   features                                   { seipd_v1, seipd_v2 }
//   notation                                   { name, value, human_readable }
//   revocation_reason                          { code, reason }
//   policy_uri, signers_user_id, ...           text
//   embedded_signature                         a signature packet's body
//   anything else                              its octets
//
// { type, raw } writes the octets given, for any type - a number not in the
// registry included.
function subpacket(sp) {
  var id = typeof sp.type === 'number' && sp.raw !== undefined ? sp.type
    : id_or_fail(IDS.SUBPACKET, sp.type, 'subpacket');
  var spec = IDS.SUBPACKET[id] || { name: null, as: 'raw' };
  var v = sp.value;
  var data;

  if (sp.raw !== undefined) {
    data = to_array(sp.raw);           // octets as they are, e.g. copied from a read signature
  } else if (spec.name === 'key_flags') {
    var f1 = 0;
    var f2 = 0;
    v.forEach(function (n) {
      var a = IDS.KEY_FLAGS.filter(function (f) { return f[1] === n; })[0];
      var b = IDS.KEY_FLAGS_2.filter(function (f) { return f[1] === n; })[0];
      if (a) { f1 |= a[0]; } else if (b) { f2 |= b[0]; } else { fail('unknown-key-flag', n); }
    });
    data = f2 ? [f1, f2] : [f1];
  } else if (spec.name === 'features') {
    data = [(v.seipd_v1 ? 1 : 0) | (v.seipd_v2 ? 8 : 0)];
  } else if (spec.name === 'issuer_key_id') {
    data = typeof v === 'string' ? to_array(B.from_hex(v)) : to_array(v);
    if (data.length !== 8) { fail('bad-subpacket', 'an issuer key ID is 8 octets'); }
  } else if (spec.as === 'time' || spec.as === 'seconds') {
    data = w32(time_of(v, spec.name));
  } else if (spec.as === 'bool') {
    data = [v ? 1 : 0];
  } else if (spec.as === 'list') {
    var table = spec.name === 'preferred_ciphers' ? IDS.CIPHER
      : spec.name === 'preferred_hashes' ? IDS.HASH : IDS.COMPRESSION;
    data = v.map(function (x) { return id_or_fail(table, x, 'algorithm'); });
  } else if (spec.as === 'pairs') {
    data = [];
    v.forEach(function (p) {
      data.push(id_or_fail(IDS.CIPHER, p[0], 'cipher'), id_or_fail(IDS.AEAD, p[1], 'AEAD mode'));
    });
  } else if (spec.as === 'fingerprint') {
    var fp = typeof v.fingerprint === 'string' ? to_array(B.from_hex(v.fingerprint)) : to_array(v.fingerprint);
    if (fp.length !== (v.version === 6 ? 32 : 20)) {
      fail('bad-subpacket', 'a version ' + v.version + ' fingerprint is ' + (v.version === 6 ? 32 : 20) + ' octets');
    }
    data = [v.version].concat(fp);
  } else if (spec.as === 'notation') {
    var name = utf8(v.name);
    var val = v.human_readable ? utf8(v.value) : to_array(v.value);
    data = [v.human_readable ? 0x80 : 0, 0, 0, 0].concat(w16(name.length), w16(val.length), name, val);
  } else if (spec.as === 'reason') {
    data = [v.code].concat(utf8(v.reason || ''));
  } else if (spec.as === 'text') {
    data = utf8(v);
  } else {
    data = to_array(v);
  }

  var all = [(sp.critical ? 0x80 : 0) | id].concat(data);
  var n = all.length;
  var len = n < 192 ? [n] : n < 8384 ? [((n - 192) >> 8) + 192, (n - 192) & 0xFF] : [255].concat(w32(n));
  return len.concat(all);
}

function subpackets(list) {
  var out = [];
  (list || []).forEach(function (sp) { append(out, subpacket(sp)); });
  return out;
}

// parts: { version: 4 | 6, type (a signature type name or id), algorithm
// (the signer's public key algorithm), hash, salt (v6: the caller's random
// octets, of the hash's salt size), hashed, unhashed (subpackets), target }
//
// target is what verification_plan takes - { document }, { key, user_id },
// { key, subkey }, { key } - with keys as key_packet or the reader returns
// them. Returns { bytes }: the caller hashes them, and signs the digest.
function signature_prepare(parts) {
  var p = parts || {};
  var version = p.version;
  if (version !== 4 && version !== 6) {
    fail('unsupported-signature-version', 'signatures are written as version 4 or 6');
  }
  var type = id_or_fail(IDS.SIGNATURE_TYPE, p.type, 'signature type');
  var alg = id_or_fail(IDS.PUBLIC_KEY, p.algorithm, 'public key algorithm');
  var hash = id_or_fail(IDS.HASH, p.hash, 'hash');
  var salt = [];

  if (version === 6) {
    salt = to_array(p.salt || []);
    if (salt.length !== IDS.HASH[hash].salt) {
      fail('bad-salt', 'a v6 signature with ' + IDS.HASH[hash].name + ' takes a ' +
        IDS.HASH[hash].salt + '-octet random salt');
    }
  }

  var hashed = subpackets(p.hashed);
  if (!(p.hashed || []).some(function (s) { return s.type === 'created' || s.type === 2; })) {
    fail('missing-creation-time', 'the hashed subpackets carry the creation time, 5.2.3.11');
  }
  var portion = [version, type, alg, hash].concat(version === 6 ? w32(hashed.length) : w16(hashed.length), hashed);
  var data = signed_data(type, version, p.target || {});
  var trailer = portion.concat([version, 0xFF], w32(portion.length));

  return {
    version: version, alg_id: alg, hash: IDS.HASH[hash].name, salt: salt,
    hashed_portion: portion, unhashed: subpackets(p.unhashed),
    bytes: new Uint8Array(salt.concat(data, trailer))
  };
}

// What precedes the trailer, by signature type (5.2.4).
function signed_data(type, version, t) {
  function key_form(k) {
    if (!k || !(k.public_body instanceof Uint8Array)) {
      fail('missing-target', 'a key, as key_packet or the reader returns it');
    }
    var b = to_array(k.public_body);
    return version === 6 ? [0x9B].concat(w32(b.length), b) : [0x99].concat(w16(b.length), b);
  }
  if (type === 0x00) { return to_array(need(t.document, 'document')); }
  if (type === 0x01) { return crlf(need(t.document, 'document')); }
  if (type === 0x02 || type === 0x40) { return []; }
  if ((type >= 0x10 && type <= 0x13) || type === 0x30) {
    var u = t.user_id !== undefined
      ? [0xB4, typeof t.user_id === 'string' ? utf8(t.user_id) : to_array(t.user_id.user_id || t.user_id)]
      : [0xD1, to_array(need(t.user_attribute, 'user_id or user_attribute').body || t.user_attribute)];
    return key_form(t.key).concat([u[0]], w32(u[1].length), u[1]);
  }
  if (type === 0x18 || type === 0x19 || type === 0x28) { return key_form(t.key).concat(key_form(t.subkey)); }
  if (type === 0x1F || type === 0x20) { return key_form(t.key); }
  fail('unsupported-signature-type', 'signature type 0x' + type.toString(16) + ' is not written here');
}

function need(v, name) {
  if (v === undefined || v === null) { fail('missing-target', 'target.' + name + ' is needed'); }
  return v;
}

// Text signatures are over CRLF line endings.
function crlf(doc) {
  var b = typeof doc === 'string' ? utf8(doc) : to_array(doc);
  var out = [];
  var i;
  for (i = 0; i < b.length; i++) {
    if (b[i] === 0x0D && b[i + 1] === 0x0A) { out.push(0x0D, 0x0A); i++; }
    else if (b[i] === 0x0D || b[i] === 0x0A) { out.push(0x0D, 0x0A); }
    else { out.push(b[i]); }
  }
  return out;
}

// The packet, from the digest of prepared.bytes and the signature over it:
// Ed25519, Ed448 and EdDSALegacy their native octets; ECDSA and DSA r || s
// at the curve's width; RSA its octets.
function signature_assemble(prepared, digest, signature) {
  var d = to_array(digest);
  var size = IDS.HASH[IDS.id_of(IDS.HASH, prepared.hash)].size;
  if (d.length !== size) {
    fail('bad-digest', prepared.hash + ' digests are ' + size + ' octets; this is ' + d.length);
  }
  var alg = IDS.PUBLIC_KEY[prepared.alg_id];
  var sig = to_array(signature);
  var value;

  if (alg.signature) {
    if (sig.length !== alg.signature) { fail('bad-signature-length', alg.name + ' signatures are ' + alg.signature + ' octets'); }
    value = sig;
  } else if (alg.name === 'eddsa-legacy') {
    if (sig.length !== 64) { fail('bad-signature-length', 'an Ed25519 signature is 64 octets'); }
    value = mpi(sig.slice(0, 32)).concat(mpi(sig.slice(32)));
  } else if (alg.name === 'ecdsa' || alg.name === 'dsa') {
    if (sig.length % 2 !== 0) { fail('bad-signature-length', 'r || s, each at the curve\'s width'); }
    value = mpi(sig.slice(0, sig.length / 2)).concat(mpi(sig.slice(sig.length / 2)));
  } else if (alg.name === 'rsa' || alg.name === 'rsa-sign-only') {
    value = mpi(sig);
  } else {
    fail('not-a-signing-algorithm', alg.name + ' does not sign');
  }

  var p = prepared;
  var unhashed = p.unhashed;
  var body = p.hashed_portion.concat(p.version === 6 ? w32(unhashed.length) : w16(unhashed.length),
    unhashed, d.slice(0, 2));
  if (p.version === 6) { body = body.concat([p.salt.length], p.salt); }
  return packet('signature', body.concat(value));
}

// ---------------------------------------------------------------------------
// Message packets
// ---------------------------------------------------------------------------

// 5.9: format 'b' or 'u'; filename and date are unsigned, and RFC 9580
// says leave them empty and zero.
function literal_packet(parts) {
  var p = parts || {};
  var format = p.format === undefined ? 'b' : p.format;
  if (format !== 'b' && format !== 'u') { fail('bad-literal', 'format is "b" or "u"'); }
  var name = utf8(p.filename || '');
  if (name.length > 255) { fail('bad-literal', 'the file name is at most 255 octets'); }
  return packet('literal', [format.charCodeAt(0), name.length].concat(name,
    w32(time_of(p.date === undefined ? 0 : p.date)), to_array(p.data)));
}

// The compressed octets are the caller's: raw DEFLATE for zip, zlib, BZip2.
function compressed_packet(algorithm, compressed) {
  return packet('compressed', [id_or_fail(IDS.COMPRESSION, algorithm, 'compression')]
    .concat(to_array(compressed)));
}

// 5.4. version 3 for a v4 signature, 6 for a v6 one. `last`: whether this
// is the last one-pass signature before the data (the "nested" octet, 1).
function one_pass_signature(parts) {
  var p = parts || {};
  var body = [p.version, id_or_fail(IDS.SIGNATURE_TYPE, p.type, 'signature type'),
    id_or_fail(IDS.HASH, p.hash, 'hash'), id_or_fail(IDS.PUBLIC_KEY, p.algorithm, 'public key algorithm')];
  if (p.version === 6) {
    var salt = to_array(p.salt);
    var fp = to_array(typeof p.issuer_fingerprint === 'string' ? B.from_hex(p.issuer_fingerprint) : p.issuer_fingerprint);
    if (fp.length !== 32) { fail('bad-fingerprint', 'a v6 one-pass signature names a 32-octet fingerprint'); }
    body = body.concat([salt.length], salt, fp);
  } else if (p.version === 3) {
    var id = to_array(typeof p.issuer_key_id === 'string' ? B.from_hex(p.issuer_key_id) : p.issuer_key_id);
    if (id.length !== 8) { fail('bad-key-id', 'a key ID is 8 octets'); }
    body = body.concat(id);
  } else {
    fail('unsupported-version', 'one-pass signatures are version 3 or 6');
  }
  return packet('one-pass-signature', body.concat([p.last === false ? 0 : 1]));
}

function padding_packet(random) { return packet('padding', to_array(random)); }

// ---------------------------------------------------------------------------
// Encrypted messages - RFC 9580 5.1, 5.3, 5.13
// ---------------------------------------------------------------------------

// What the public key algorithm encrypts (5.1.3, 5.1.5): v3 prefixes the
// cipher; both end with the 2-octet sum. ECDH pads to 8 (11.5).
function session_key_block(parts) {
  var p = parts || {};
  var key = to_array(p.session_key);
  var sum = 0;
  key.forEach(function (b) { sum = (sum + b) & 0xFFFF; });
  var out = (p.version === 3 ? [id_or_fail(IDS.CIPHER, p.cipher, 'cipher')] : []).concat(key, w16(sum));
  if (p.algorithm === 'ecdh') {
    var pad = 8 - (out.length % 8);
    var i;
    for (i = 0; i < pad; i++) { out.push(pad); }
  }
  return new Uint8Array(out);
}

// parts: { version: 3 | 6, key_id (v3) or fingerprint + key_version (v6;
// neither, anonymous), algorithm, fields } - fields as the reader returns
// them: { m } RSA, { ephemeral, wrapped } ECDH, { ephemeral, cipher (v3),
// wrapped } X25519.
function pkesk(parts) {
  var p = parts || {};
  var alg_id = id_or_fail(IDS.PUBLIC_KEY, p.algorithm, 'public key algorithm');
  var alg = IDS.PUBLIC_KEY[alg_id];
  var body;

  if (p.version === 3) {
    var id = p.key_id === undefined ? [0, 0, 0, 0, 0, 0, 0, 0]
      : to_array(typeof p.key_id === 'string' ? B.from_hex(p.key_id) : p.key_id);
    if (id.length !== 8) { fail('bad-key-id', 'a key ID is 8 octets'); }
    body = [3].concat(id);
  } else if (p.version === 6) {
    if (p.fingerprint === undefined) {
      body = [6, 0];
    } else {
      var fp = to_array(typeof p.fingerprint === 'string' ? B.from_hex(p.fingerprint) : p.fingerprint);
      body = [6, fp.length + 1, p.key_version === undefined ? (fp.length === 32 ? 6 : 4) : p.key_version].concat(fp);
    }
  } else {
    fail('unsupported-version', 'PKESK versions are 3 and 6');
  }
  body.push(alg_id);

  var f = p.fields || {};
  if (alg.name === 'rsa' || alg.name === 'rsa-encrypt-only') {
    body = body.concat(mpi(f.m));
  } else if (alg.name === 'ecdh') {
    var w = to_array(f.wrapped);
    body = body.concat(mpi(f.ephemeral), [w.length], w);
  } else if (alg.native && alg.encrypt) {
    var e = to_array(f.ephemeral);
    if (e.length !== alg.native) { fail('bad-key-length', 'the ephemeral key is ' + alg.native + ' octets'); }
    var wrapped = to_array(f.wrapped);
    var tail = p.version === 3 ? [id_or_fail(IDS.CIPHER, f.cipher, 'cipher')].concat(wrapped) : wrapped;
    body = body.concat(e, [tail.length], tail);
  } else {
    fail('not-an-encryption-algorithm', alg.name + ' does not encrypt');
  }
  return packet('pkesk', body);
}

// 5.3. v4: { cipher, s2k, encrypted_key? }; v6: { cipher, aead, s2k, iv,
// encrypted_key, auth_tag } - what was encrypted with skesk_v6_info's key.
function skesk(parts) {
  var p = parts || {};
  var cipher = id_or_fail(IDS.CIPHER, p.cipher, 'cipher');
  var spec = to_array(s2k(p.s2k));
  if (p.version === 4) {
    return packet('skesk', [4, cipher].concat(spec, p.encrypted_key ? to_array(p.encrypted_key) : []));
  }
  if (p.version !== 6) { fail('unsupported-version', 'SKESK versions are 4 and 6'); }
  var aead = id_or_fail(IDS.AEAD, p.aead, 'AEAD mode');
  var iv = to_array(p.iv);
  if (iv.length !== IDS.AEAD[aead].nonce) { fail('bad-iv', IDS.AEAD[aead].name + ' takes a ' + IDS.AEAD[aead].nonce + '-octet nonce'); }
  var fields = [cipher, aead, spec.length].concat(spec, iv);
  return packet('skesk', [6, fields.length].concat(fields, to_array(p.encrypted_key), to_array(p.auth_tag)));
}

// The HKDF info - and the AEAD's additional data, the same octets - for a
// v6 SKESK (5.3.2).
function skesk_v6_info(cipher, aead) {
  return new Uint8Array([0xC3, 6, id_or_fail(IDS.CIPHER, cipher, 'cipher'), id_or_fail(IDS.AEAD, aead, 'AEAD mode')]);
}

// v1 (5.13.1): what to SHA-1 for the MDC. `random` is block-size random
// octets; the two quick-check octets and the MDC header are added here.
// The plaintext to encrypt (CFB, zero IV) is these bytes then their SHA-1.
function seipd_v1_mdc_input(random, packets_bytes) {
  var r = to_array(random);
  if (r.length !== 8 && r.length !== 16) { fail('bad-input', 'the random prefix is a cipher block'); }
  return new Uint8Array(r.concat([r[r.length - 2], r[r.length - 1]], to_array(packets_bytes), [0xD3, 0x14]));
}

function seipd_v1(ciphertext) {
  return packet('seipd', [1].concat(to_array(ciphertext)));
}

// v2 (5.13.2): the parameters, and for each chunk the AAD and the nonce
// suffix - prepared before encrypting.
//
//   var s = seipd_v2_prepare({ cipher, aead, chunk_size_octet, salt,
//                              plaintext_length });
//   okm = HKDF-SHA256(session_key, s.salt, s.hkdf_info, s.key_length + s.iv_length)
//   each chunk i: aead(key, iv || s.chunk_nonce_suffix(i), s.aad, chunk)
//   final:        aead(key, iv || suffix(n), s.final_aad, empty) -> tag
function seipd_v2_prepare(parts) {
  var p = parts || {};
  var cipher = id_or_fail(IDS.CIPHER, p.cipher, 'cipher');
  var aead = id_or_fail(IDS.AEAD, p.aead, 'AEAD mode');
  var c = p.chunk_size_octet === undefined ? 16 : p.chunk_size_octet;
  if (c < 0 || c > 16) { fail('bad-chunk-size', 'the chunk size octet is 0..16'); }
  var salt = to_array(p.salt);
  if (salt.length !== 32) { fail('bad-salt', 'the salt is 32 random octets'); }
  var info = [0xD2, 2, cipher, aead, c];
  return {
    cipher_id: cipher, aead_id: aead, chunk_size_octet: c, salt: new Uint8Array(salt),
    chunk_size: Math.pow(2, c + 6),
    hkdf_info: new Uint8Array(info), aad: new Uint8Array(info),
    key_length: IDS.CIPHER[cipher].key, iv_length: IDS.AEAD[aead].nonce - 8,
    final_aad: new Uint8Array(info.concat(w64(p.plaintext_length || 0))),
    chunk_nonce_suffix: function (i) { return new Uint8Array(w64(i)); }
  };
}

// The packet: each chunk's ciphertext with its tag, then the final tag.
function seipd_v2_assemble(prepared, chunks, final_tag) {
  var p = prepared;
  var body = [2, p.cipher_id, p.aead_id, p.chunk_size_octet].concat(to_array(p.salt));
  chunks.forEach(function (c) { append(body, to_array(c)); });
  return packet('seipd', body.concat(to_array(final_tag)));
}

export {
  armor_encode,
  cleartext_signed_bytes,
  cleartext_encode,
  packet,
  packets,
  key_packet,
  s2k,
  user_id_packet,
  subpacket,
  signature_prepare,
  signature_assemble,
  literal_packet,
  compressed_packet,
  one_pass_signature,
  padding_packet,
  session_key_block,
  pkesk,
  skesk,
  skesk_v6_info,
  seipd_v1_mdc_input,
  seipd_v1,
  seipd_v2_prepare,
  seipd_v2_assemble
};

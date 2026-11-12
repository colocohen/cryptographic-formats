// SSH keys. THERE ARE TWO FORMATS AND THEY SHARE NOTHING BUT THE ALGORITHM
// NAMES.
//
//   RFC 4253 wire format    ssh-rsa, ecdsa-sha2-*, ssh-ed25519, and the
//                           security keys sk-ssh-ed25519@openssh.com,
//                           sk-ecdsa-sha2-nistp256@openssh.com
//                           length-prefixed strings, base64 in
//                           authorized_keys and .pub files
//
//   openssh-key-v1          the PRIVATE key file: its own magic string, a
//                           KDF, a cipher, a key count, and the public key
//                           repeated inside
//
// A parser for one will not read the other. Writing "SSH" as a single item on
// a scope list hides that, which is why the brief spells it out and why this
// module has two independent readers.
//
// Neither is ASN.1. The wire format is uint32 lengths and byte strings, big
// endian, and that is the whole of it - which makes it easy, and makes the
// mistake of reaching for the DER reader easy too.
//
// FINGERPRINTS live here, and the reason is that WHICH BLOB IS HASHED is the
// entire question. An SSH fingerprint hashes the RFC 4253 wire encoding, not
// the DER; hashing the wrong one produces a plausible fingerprint that
// matches nothing. The hash itself is one call into cryptographic-primitives - the value is
// in knowing what to feed it, so this module builds the blob and the caller
// hashes it.

import * as B from './base.js';
import * as PEM from './pem.js';
import { is_weak_hash } from './algorithm.js';
import * as CBOR from './cbor_reader.js';
import * as WEBAUTHN from './webauthn.js';

import { to_bytes, to_array, bytes_equal, hex, append } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';
import { latin1 } from './commons/decode_text.js';

var fail = make_fail_here('ssh');


// ---------------------------------------------------------------------------
// The wire encoding
// ---------------------------------------------------------------------------

// RFC 4251 section 5. Everything is a uint32 length followed by that many
// bytes. No tags, no types - the caller has to know what it is reading, which
// is why each key type is read by name after its algorithm string.

function Wire(bytes) {
  this.buf = bytes;
  this.pos = 0;
}

Wire.prototype.byte = function () {
  if (this.pos + 1 > this.buf.length) {
    fail('truncated', 'expected a byte at offset ' + this.pos);
  }
  this.pos += 1;
  return this.buf[this.pos - 1];
};

Wire.prototype.remaining = function () {
  return this.buf.length - this.pos;
};

Wire.prototype.uint32 = function () {
  if (this.pos + 4 > this.buf.length) {
    fail('truncated', 'expected a uint32 at offset ' + this.pos);
  }

  var v = (this.buf[this.pos] * 0x1000000) +
          (this.buf[this.pos + 1] << 16) +
          (this.buf[this.pos + 2] << 8) +
          this.buf[this.pos + 3];
  this.pos += 4;
  return v;
};

// uint64 - a certificate's serial and validity. Returned as the 8 bytes;
// as_seconds() reads a time from them.
Wire.prototype.uint64 = function () {
  if (this.pos + 8 > this.buf.length) {
    fail('truncated', 'expected a uint64 at offset ' + this.pos);
  }
  var out = this.buf.subarray(this.pos, this.pos + 8);
  this.pos += 8;
  return out;
};

Wire.prototype.string = function () {
  var start = this.pos;
  var n = this.uint32();

  if (this.pos + n > this.buf.length) {
    fail('length-exceeds-input',
      'string at offset ' + start + ' declares ' + n + ' bytes, ' +
      this.remaining() + ' remain');
  }

  var out = this.buf.subarray(this.pos, this.pos + n);
  this.pos += n;
  return out;
};

Wire.prototype.text = function () {
  var bytes = this.string();
  var s = '';
  var i;

  for (i = 0; i < bytes.length; i++) {
    if (bytes[i] > 0x7F) {
      fail('bad-text', 'expected ASCII, got a byte above 0x7F');
    }
    s += String.fromCharCode(bytes[i]);
  }
  return s;
};

// mpint, RFC 4251 section 5: a signed big-endian integer with the minimum
// number of bytes. The rules are DER's INTEGER rules in a different dress,
// and enforcing them matters for the same reason: a value written wider than
// it needs to be is a second encoding, and an SSH fingerprint hashes the
// encoding.
Wire.prototype.mpint = function () {
  var start = this.pos;
  var bytes = this.string();

  if (bytes.length === 0) {
    return bytes;                 // zero is the empty string
  }

  if (bytes.length > 1) {
    if (bytes[0] === 0x00 && (bytes[1] & 0x80) === 0) {
      fail('non-minimal-mpint',
        'mpint at offset ' + start + ' has a superfluous leading 0x00');
    }
    if (bytes[0] === 0xFF && (bytes[1] & 0x80) !== 0) {
      fail('non-minimal-mpint',
        'mpint at offset ' + start + ' has a superfluous leading 0xFF');
    }
  }

  return bytes;
};

Wire.prototype.expect_end = function () {
  if (this.pos < this.buf.length) {
    fail('trailing-bytes',
      (this.buf.length - this.pos) + ' unconsumed byte(s)');
  }
};

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

function w_uint32(n) {
  return [(n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF];
}

function w_string(bytes) {
  var b = to_array(bytes);
  return w_uint32(b.length).concat(b);
}

function w_uint64(bytes8) {
  var b = to_array(bytes8);
  if (b.length !== 8) {
    fail('bad-uint64', 'a uint64 is 8 bytes');
  }
  return b;
}

function w_text(s) {
  var out = [];
  var i;
  for (i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0x7F) {
      fail('bad-text', 'expected ASCII');
    }
    out.push(s.charCodeAt(i));
  }
  return w_string(out);
}

// The counterpart to mpint: adds the sign octet where SSH requires it and
// strips leading zeros the caller supplied.
function w_mpint(magnitude) {
  var b = to_array(magnitude);
  var i = 0;

  while (i < b.length && b[i] === 0x00) {
    i += 1;
  }
  b = b.slice(i);

  if (b.length === 0) {
    return w_string([]);
  }
  if ((b[0] & 0x80) !== 0) {
    b = [0x00].concat(b);
  }
  return w_string(b);
}

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

var EC_CURVES = {
  'nistp256': { oid: 'secp256r1', size: 32 },
  'nistp384': { oid: 'secp384r1', size: 48 },
  'nistp521': { oid: 'secp521r1', size: 66 }
};

// ⚠ SECURITY KEYS (FIDO: a YubiKey and the like) - PROTOCOL.u2f.
//
// Each is an ordinary key type with one field more, the `application` the
// authenticator was enrolled for ("ssh:" by default), after the key. So
// they are read and written as their base type and then that field - one
// reader, not a second copy of Ed25519 and ECDSA. Only P-256 exists: it is
// what FIDO authenticators do.
//
// The key comes back with `application`; an ordinary key has none, and a
// key given to a writer with one is written as the security-key type.
var SK_TYPES = {
  'sk-ssh-ed25519@openssh.com':         'ssh-ed25519',
  'sk-ecdsa-sha2-nistp256@openssh.com': 'ecdsa-sha2-nistp256'
};

// The security-key type for a base type, or null.
function sk_type_of(base) {
  var k;
  for (k in SK_TYPES) {
    if (Object.prototype.hasOwnProperty.call(SK_TYPES, k) && SK_TYPES[k] === base) {
      return k;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// RFC 4253 wire format
// ---------------------------------------------------------------------------

// Reads the raw wire encoding - the bytes inside the base64 of a .pub file.
// Returns the shared key shape, plus `wire`, which is what a fingerprint
// hashes.
function key_from_wire(input) {
  var bytes = to_bytes(input);
  var r = new Wire(bytes);
  var type = r.text();
  var out = read_key_fields(r, type);

  r.expect_end();

  out.ssh_type = type;
  out.wire = bytes;
  out.comment = null;
  return out;
}

// The fields after a key's type string - shared by a bare key and a
// certificate, whose key fields are the same ones after a nonce
// (PROTOCOL.certkeys).
function read_key_fields(r, type) {
  if (Object.prototype.hasOwnProperty.call(SK_TYPES, type)) {
    var key = read_key_fields(r, SK_TYPES[type]);
    key.application = r.text();
    return key;
  }

  if (type === 'ssh-ed25519') {
    var point = r.string();
    if (point.length !== 32) {
      fail('bad-key-length',
        'an Ed25519 key is 32 bytes, got ' + point.length);
    }
    return { algorithm: 'Ed25519', curve: null, point: point };
  }

  if (type === 'ssh-rsa') {
    // Note the ORDER: e comes before n, which is the reverse of every ASN.1
    // structure that carries them. Reading them the other way round produces
    // a key that is syntactically fine and cryptographically nonsense.
    var e = r.mpint();
    var n = r.mpint();
    return {
      algorithm: 'rsaEncryption', curve: null, point: null,
      rsa: { e: e, n: n }
    };
  }

  if (type.indexOf('ecdsa-sha2-') === 0) {
    var curve_name = type.substr('ecdsa-sha2-'.length);
    var curve = EC_CURVES[curve_name];

    if (curve === undefined) {
      fail('unknown-curve', 'unrecognised ECDSA curve "' + curve_name + '"');
    }

    // The curve name appears TWICE - in the algorithm string and again as its
    // own field - and the two must agree. A key naming nistp256 in one and
    // nistp384 in the other has no single answer to which curve it is on.
    var declared = r.text();
    if (declared !== curve_name) {
      fail('curve-mismatch',
        'the algorithm says ' + curve_name + ' but the curve field says ' +
        declared);
    }

    var ec_point = r.string();
    if (ec_point.length !== 1 + curve.size * 2) {
      fail('bad-key-length',
        curve_name + ' expects an uncompressed point of ' +
        (1 + curve.size * 2) + ' bytes, got ' + ec_point.length);
    }
    if (ec_point[0] !== 0x04) {
      fail('bad-point',
        'SSH carries uncompressed points only; prefix is 0x' +
        ec_point[0].toString(16));
    }

    return { algorithm: 'ecPublicKey', curve: curve.oid, point: ec_point };
  }

  fail('unknown-key-type', 'unrecognised SSH key type "' + type + '"');
}

// Reads a .pub file or an authorized_keys line: "type base64 comment".
function key_from_text(text) {
  if (typeof text !== 'string') {
    fail('bad-input', 'expected a string');
  }

  // authorized_keys lines may carry options before the type. Those are host
  // configuration rather than key material, so a line with them is refused
  // here rather than half-parsed.
  var line = text.replace(/^\s+|\s+$/g, '').split('\n')[0];
  var parts = line.split(/\s+/);

  if (parts.length < 2) {
    fail('bad-input',
      'expected "type base64 [comment]"; a line with authorized_keys ' +
      'options is not handled here');
  }

  var key = key_from_wire(B.decode('base64', parts[1]));

  // The type in the text and the type inside the blob must agree. Otherwise a
  // file can claim to hold one kind of key while holding another, and
  // anything that trusts the text label is looking at the wrong thing.
  if (parts[0] !== key.ssh_type) {
    fail('type-mismatch',
      'the line says "' + parts[0] + '" but the key is "' + key.ssh_type +
      '"');
  }

  key.comment = parts.length > 2 ? parts.slice(2).join(' ') : null;
  return key;
}

function key_to_wire(key) {
  var w = key_fields(key);
  return new Uint8Array(w_text(w.type).concat(w.fields));
}

// A key's SSH type and the fields after it - the bare key's, and a
// certificate's after its nonce. A key with an `application` is a security
// key: its base type's fields, then that.
function key_fields(key) {
  if (!key || typeof key.algorithm !== 'string') {
    fail('bad-key', 'expected a key object with an algorithm');
  }

  if (key.application !== undefined && key.application !== null) {
    if (typeof key.application !== 'string') {
      fail('bad-application', 'a security key\'s application is text - "ssh:" unless chosen');
    }
    var base = plain_key_fields(key);
    var sk = sk_type_of(base.type);
    if (sk === null) {
      fail('unsupported-algorithm', 'security keys are Ed25519 or P-256 (PROTOCOL.u2f); ' +
        'this is ' + base.type);
    }
    return { type: sk, fields: base.fields.concat(w_text(key.application)) };
  }
  return plain_key_fields(key);
}

function plain_key_fields(key) {
  if (key.algorithm === 'Ed25519') {
    if (!key.point || key.point.length !== 32) {
      fail('bad-key-length', 'an Ed25519 key is 32 bytes');
    }
    return { type: 'ssh-ed25519', fields: w_string(key.point) };
  }

  if (key.algorithm === 'rsaEncryption') {
    if (!key.rsa || !key.rsa.n || !key.rsa.e) {
      fail('bad-key', 'an RSA key needs n and e');
    }
    // e THEN n - the reverse of the ASN.1 order.
    return { type: 'ssh-rsa', fields: w_mpint(key.rsa.e).concat(w_mpint(key.rsa.n)) };
  }

  if (key.algorithm === 'ecPublicKey') {
    var name = ssh_curve(key.curve);
    return { type: 'ecdsa-sha2-' + name,
             fields: w_text(name).concat(w_string(key.point)) };
  }

  fail('unsupported-algorithm',
    'cannot write algorithm ' + key.algorithm + ' as an SSH key');
}

// secp256r1 -> nistp256: the SSH name for a curve, or a refusal.
function ssh_curve(oid_name) {
  var k;
  for (k in EC_CURVES) {
    if (Object.prototype.hasOwnProperty.call(EC_CURVES, k) &&
        EC_CURVES[k].oid === oid_name) {
      return k;
    }
  }
  fail('no-ssh-curve',
    'curve ' + oid_name + ' has no SSH name; SSH defines nistp256, ' +
    'nistp384 and nistp521 only');
}

function key_to_text(key, comment) {
  var wire = key_to_wire(key);
  var type = key.ssh_type || wire_type(wire);
  var out = type + ' ' + B.encode('base64', wire);

  if (comment) {
    out += ' ' + comment;
  }
  return out;
}

function wire_type(bytes) {
  return new Wire(to_bytes(bytes)).text();
}

// ---------------------------------------------------------------------------
// Signatures - RFC 4253 6.6, RFC 8332, RFC 5656 3.1.2, RFC 8709
// ---------------------------------------------------------------------------

// The hash each signature format signs with - the verifier's question.
var SIGNATURE_HASH = {
  'ssh-ed25519':         null,
  // A security key's: the authenticator's own algorithm over sk_signed_data.
  'sk-ssh-ed25519@openssh.com':                  null,
  'sk-ecdsa-sha2-nistp256@openssh.com':          'sha256',
  'webauthn-sk-ecdsa-sha2-nistp256@openssh.com': 'sha256',
  'ssh-rsa':             'sha1',
  'rsa-sha2-256':        'sha256',
  'rsa-sha2-512':        'sha512',
  'ecdsa-sha2-nistp256': 'sha256',
  'ecdsa-sha2-nistp384': 'sha384',
  'ecdsa-sha2-nistp521': 'sha512'
};

//   string  format       "ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp256"
//   string  blob         Ed25519: 64 bytes; RSA: the signature;
//                        ECDSA: mpint r, mpint s (RFC 5656 3.1.2)
//
// ECDSA comes back as `raw` too - r || s at the curve's width, the form
// node:crypto takes with dsaEncoding 'ieee-p1363' - because the mpints
// drop leading zeros and a verifier fed them directly gets a wrong length.
function read_signature_blob(bytes) {
  var r = new Wire(to_bytes(bytes));
  var format = r.text();
  var blob = r.string();

  if (!Object.prototype.hasOwnProperty.call(SIGNATURE_HASH, format)) {
    fail('unknown-signature-format', 'unrecognised signature format "' +
      format + '"');
  }

  var out = { format: format, hash: SIGNATURE_HASH[format],
              // ssh-rsa signs with SHA-1: OpenSSH refuses it by default
              // since 8.8. The rule is algorithm.js's.
              weak: is_weak_hash(SIGNATURE_HASH[format]), bytes: blob };

  var base = signature_base(format);
  if (base !== format) {
    out.sk = read_sk_fields(r, format);
  }
  r.expect_end();

  if (base === 'ssh-ed25519' && blob.length !== 64) {
    fail('bad-signature-length', 'an Ed25519 signature is 64 bytes');
  }

  if (base.indexOf('ecdsa-sha2-') === 0) {
    var size = EC_CURVES[base.substr('ecdsa-sha2-'.length)].size;
    var e = new Wire(blob);
    var rr = e.mpint();
    var ss = e.mpint();
    e.expect_end();
    out.raw = new Uint8Array(fixed(rr, size).concat(fixed(ss, size)));
  }
  return out;
}

// The plain format whose signature value a security key's carries:
// sk-ssh-ed25519@openssh.com -> ssh-ed25519; the format itself otherwise.
function signature_base(format) {
  var plain = format.replace(/^webauthn-/, '');
  return Object.prototype.hasOwnProperty.call(SK_TYPES, plain) ? SK_TYPES[plain] : format;
}

//   byte    flags      0x01 user present, 0x04 user verified (FIDO)
//   uint32  counter
// and for webauthn-: string origin, string clientData, string extensions.
//
// ⚠ THE FLAGS ARE WHAT verify-required AND no-touch-required ARE ABOUT. A
// signature without user_present is one made with no touch; OpenSSH refuses
// it unless the key or certificate says no-touch-required, and refuses one
// without user_verified (a PIN or biometric) when it says verify-required.
// The signature is valid either way - checking them is the verifier's.
var SK_USER_PRESENT = 0x01;
var SK_USER_VERIFIED = 0x04;

function read_sk_fields(r, format) {
  var flags = r.byte();
  var out = { flags: flags, counter: r.uint32(),
              user_present: (flags & SK_USER_PRESENT) !== 0,
              user_verified: (flags & SK_USER_VERIFIED) !== 0 };
  if (format.indexOf('webauthn-') === 0) {
    out.origin = r.text();
    out.client_data = r.string();
    out.extensions = r.string();
  }
  return out;
}

// ⚠ A SECURITY KEY DOES NOT SIGN THE DATA. It signs (PROTOCOL.u2f, and
// ssh-ecdsa-sk.c / ssh-ed25519-sk.c, which are the specification here)
//
//   byte[32]  SHA-256(application)
//   byte      flags
//   uint32    counter
//   byte[]    extensions          webauthn only; empty otherwise
//   byte[32]  SHA-256(message)
//
// where the message is sk_message() below. Ed25519 signs these bytes;
// ECDSA signs them with SHA-256, as for any ECDSA-SHA256 signature. The two
// digests are the caller's - this library hashes nothing.
function sk_signed_data(signature, application_digest, message_digest) {
  var sk = signature && signature.sk;
  if (!sk) {
    fail('not-security-key', 'this is a ' + (signature && signature.format) +
      ' signature, which signs the data itself');
  }
  var a = to_array(application_digest);
  var m = to_array(message_digest);
  if (a.length !== 32 || m.length !== 32) {
    fail('bad-digest', 'both digests are SHA-256, 32 bytes');
  }
  return new Uint8Array(a.concat([sk.flags]).concat(w_uint32(sk.counter))
    .concat(to_array(sk.extensions || [])).concat(m));
}

// What a security key's message digest is OF: the data - a certificate's
// tbs_bytes, SSHSIG's signed_data - or, for webauthn, the browser's
// clientData, once it is checked to carry that data as its challenge.
//
// clientData is JSON, but OpenSSH does not parse it and neither does this:
// it must START with exactly
//   {"type":"webauthn.get","challenge":"<base64url(data)>","origin":"<origin>"
// - so the challenge it signs is this data, and the origin is the one the
// signature names. Also from OpenSSH: no quote in the origin, the AD flag
// (0x40) clear, and the ED flag (0x80) set exactly when there are
// extensions.
function sk_message(signature, data) {
  var sk = signature && signature.sk;
  if (!sk) {
    fail('not-security-key', 'not a security key signature');
  }
  var d = to_bytes(data);
  if (sk.client_data === undefined) {
    return d;
  }
  if (sk.origin.indexOf('"') !== -1 || (sk.flags & 0x40) !== 0 ||
      ((sk.flags & 0x80) !== 0) !== (sk.extensions.length > 0)) {
    fail('bad-webauthn', 'a quote in the origin, or flags that disagree with the extensions');
  }
  var want = w_text('{"type":"webauthn.get","challenge":"' +
    B.encode('base64url', d).replace(/=+$/, '') + '","origin":"' + sk.origin + '"').slice(4);
  if (sk.client_data.length < want.length ||
      !bytes_equal(sk.client_data.subarray(0, want.length), new Uint8Array(want))) {
    fail('webauthn-challenge-mismatch', 'clientData does not carry this data as its ' +
      'challenge, with this origin - it was signed for something else');
  }
  return sk.client_data;
}

// An ECDSA r or s - a non-negative mpint - at the curve's fixed width.
function fixed(mpint, size) {
  var b = to_array(mpint);
  if (b.length > 0 && (b[0] & 0x80) !== 0) {
    fail('bad-signature', 'an ECDSA signature value is negative');
  }
  while (b.length > 0 && b[0] === 0) { b = b.slice(1); }
  if (b.length > size) {
    fail('bad-signature', 'an ECDSA signature value is wider than the curve');
  }
  while (b.length < size) { b.unshift(0); }
  return b;
}

// The writer's half: `signature` as the caller's library produced it -
// Ed25519's 64 bytes, RSA's, or ECDSA's r || s (ieee-p1363). `format` names
// the algorithm: the key's type, or rsa-sha2-256 / -512 for RSA.
//
// A security key's format takes { signature, flags, counter } - and, for
// webauthn-, origin, client_data and extensions - as the authenticator
// returned them; `signature` is as above for its base algorithm.
function signature_blob(format, signature) {
  if (!Object.prototype.hasOwnProperty.call(SIGNATURE_HASH, format)) {
    fail('unknown-signature-format', 'unrecognised signature format "' +
      format + '"');
  }
  var base = signature_base(format);
  var sk = null;
  if (base !== format) {
    sk = signature || {};
    if (typeof sk.flags !== 'number' || sk.flags < 0 || sk.flags > 255 || sk.flags % 1 !== 0 ||
        typeof sk.counter !== 'number' || sk.counter < 0 || sk.counter > 0xFFFFFFFF || sk.counter % 1 !== 0) {
      fail('bad-sk-signature', format + ' takes { signature, flags (a byte), counter (uint32) }');
    }
    signature = sk.signature;
  }
  var sig = to_array(signature);

  if (base.indexOf('ecdsa-sha2-') === 0) {
    var size = EC_CURVES[base.substr('ecdsa-sha2-'.length)].size;
    if (sig.length !== 2 * size) {
      fail('raw-signature-expected', format + ' takes r || s, ' + (2 * size) +
        ' bytes (dsaEncoding ieee-p1363) - this is ' + sig.length);
    }
    sig = w_mpint(sig.slice(0, size)).concat(w_mpint(sig.slice(size)));
  } else if (base === 'ssh-ed25519' && sig.length !== 64) {
    fail('bad-signature-length', 'an Ed25519 signature is 64 bytes');
  }
  var out = w_text(format).concat(w_string(sig));
  if (sk !== null) {
    out = out.concat([sk.flags]).concat(w_uint32(sk.counter));
    if (format.indexOf('webauthn-') === 0) {
      out = out.concat(w_text(sk.origin)).concat(w_string(sk.client_data))
        .concat(w_string(sk.extensions || []));
    }
  }
  return out;
}

// The formats a key may sign with.
function signature_formats(key_type) {
  if (key_type === 'ssh-rsa') {
    return ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'];
  }
  if (key_type === 'sk-ecdsa-sha2-nistp256@openssh.com') {
    return [key_type, 'webauthn-' + key_type];
  }
  return [key_type];
}

// ---------------------------------------------------------------------------
// SSHSIG - OpenSSH's file signatures (PROTOCOL.sshsig)
// ---------------------------------------------------------------------------

//   byte[6]  "SSHSIG"
//   uint32   version            1
//   string   publickey
//   string   namespace          "file", "git", "email" - what it is for
//   string   reserved
//   string   hash_algorithm     "sha256" or "sha512"
//   string   signature
//
// ⚠ THE SIGNATURE IS NOT OVER THE MESSAGE. It is over
//
//   byte[6] "SSHSIG", string namespace, string reserved,
//   string hash_algorithm, string H(message)
//
// - signed_data() below. And the NAMESPACE is the defence against a
// signature made for one purpose being accepted for another: a verifier
// that does not compare it with its own has none.
var SSHSIG_MAGIC = [0x53, 0x53, 0x48, 0x53, 0x49, 0x47];
var SSHSIG_LABEL = 'SSH SIGNATURE';
var SSHSIG_HASHES = { sha256: 32, sha512: 64 };

function sshsig_from_text(text) {
  return sshsig_from_wire(PEM.decode_one(text, SSHSIG_LABEL).der);
}

function sshsig_from_wire(input) {
  var bytes = to_bytes(input);
  var i;

  for (i = 0; i < 6; i++) {
    if (bytes[i] !== SSHSIG_MAGIC[i]) {
      fail('not-sshsig', 'an SSH signature starts "SSHSIG"');
    }
  }

  var r = new Wire(bytes);
  r.pos = 6;
  var version = r.uint32();

  if (version !== 1) {
    fail('unsupported-version', 'SSHSIG version ' + version + '; 1 is defined');
  }

  var key = key_from_wire(r.string());
  var namespace = r.text();
  var reserved = r.string();
  var hash = r.text();
  var signature = read_signature_blob(r.string());
  r.expect_end();

  if (namespace === '') {
    fail('empty-namespace', 'PROTOCOL.sshsig: the namespace MUST NOT be empty');
  }
  if (SSHSIG_HASHES[hash] === undefined) {
    fail('unsupported-hash', 'hash_algorithm is sha256 or sha512, not "' + hash + '"');
  }
  if (signature_formats(key.ssh_type).indexOf(signature.format) === -1) {
    fail('signature-key-mismatch', 'a ' + key.ssh_type + ' key does not sign ' +
      signature.format);
  }

  return {
    version: version, public_key: key, namespace: namespace,
    reserved: reserved, hash: hash, signature: signature, wire: bytes,
    note: 'hash the message with `hash`, pass the digest to signed_data, and ' +
          'verify signature over that with public_key - after checking ' +
          'namespace is the one you expect'
  };
}

// The bytes an SSHSIG signature is over. `sig` is what sshsig_from_* read,
// or { namespace, hash, reserved? } when signing; `digest` is H(message)
// with that hash, the caller's.
function sshsig_signed_data(sig, digest) {
  var d = to_array(digest);
  if (!sig || SSHSIG_HASHES[sig.hash] === undefined) {
    fail('unsupported-hash', 'hash is sha256 or sha512');
  }
  if (d.length !== SSHSIG_HASHES[sig.hash]) {
    fail('bad-digest', sig.hash + ' is ' + SSHSIG_HASHES[sig.hash] +
      ' bytes; this digest is ' + d.length);
  }
  if (typeof sig.namespace !== 'string' || sig.namespace === '') {
    fail('empty-namespace', 'the namespace says what the signature is for, ' +
      'and MUST NOT be empty');
  }
  return new Uint8Array(SSHSIG_MAGIC.concat(w_text(sig.namespace))
    .concat(w_string(sig.reserved || [])).concat(w_text(sig.hash))
    .concat(w_string(d)));
}

// The armoured signature, from what was signed and the signature itself.
//
//   var p = ssh.sshsig_prepare({ public_key, namespace: 'file',
//                                hash: 'sha512', digest: sha512(message) });
//   var text = ssh.sshsig_assemble(p, sign(key, p.bytes));
function sshsig_prepare(parts) {
  var p = parts || {};
  var bytes = sshsig_signed_data(p, p.digest);
  var key = key_to_wire(p.public_key);
  var type = wire_type(key);
  var format = p.format === undefined ? signature_formats(type)[0] : p.format;

  if (signature_formats(type).indexOf(format) === -1) {
    fail('signature-key-mismatch', 'a ' + type + ' key does not sign ' + format);
  }
  return { bytes: bytes, key: key, namespace: p.namespace,
           reserved: to_array(p.reserved || []), hash: p.hash, format: format };
}

function sshsig_assemble(prepared, signature) {
  var p = prepared;
  var wire = SSHSIG_MAGIC.concat(w_uint32(1)).concat(w_string(p.key))
    .concat(w_text(p.namespace)).concat(w_string(p.reserved))
    .concat(w_text(p.hash)).concat(w_string(signature_blob(p.format, signature)));
  // OpenSSH writes the armour at 70 columns.
  return PEM.encode(new Uint8Array(wire), SSHSIG_LABEL, 70);
}

// ---------------------------------------------------------------------------
// Certificates - PROTOCOL.certkeys
// ---------------------------------------------------------------------------

//   string    "<key type>-cert-v01@openssh.com"
//   string    nonce
//   ...       the key's fields, as in the bare key
//   uint64    serial
//   uint32    type                 1 user, 2 host
//   string    key id
//   string    valid principals     packed strings
//   uint64    valid after          seconds; 0 = always
//   uint64    valid before         seconds; 0xFFFF...FF = forever
//   string    critical options     packed (name, string data) pairs
//   string    extensions           likewise
//   string    reserved
//   string    signature key        the CA's key, wire format
//   string    signature            over everything before it
//
// ⚠ CRITICAL OPTIONS ARE CRITICAL: a verifier that does not understand one
// MUST refuse the certificate. They are returned by name so a verifier can
// do that; unknown_critical lists the ones OpenSSH does not define.
var CERT_SUFFIX = '-cert-v01@openssh.com';
var CERT_TYPES = { 1: 'user', 2: 'host' };
var KNOWN_CRITICAL = ['force-command', 'source-address', 'verify-required'];

// sk-ssh-ed25519@openssh.com -> sk-ssh-ed25519-cert-v01@openssh.com: the
// "@openssh.com" moves to the end, after the suffix.
function cert_type_of(key_type) {
  return key_type.replace(/@openssh\.com$/, '') + CERT_SUFFIX;
}

function key_type_of(cert_type) {
  var base = cert_type.substr(0, cert_type.length - CERT_SUFFIX.length);
  return Object.prototype.hasOwnProperty.call(SK_TYPES, base + '@openssh.com')
    ? base + '@openssh.com' : base;
}

function certificate_from_text(text) {
  var line = String(text).replace(/^\s+|\s+$/g, '').split('\n')[0];
  var parts = line.split(/\s+/);

  if (parts.length < 2) {
    fail('bad-input', 'expected "type base64 [comment]"');
  }

  var cert = certificate_from_wire(B.decode('base64', parts[1]));

  if (parts[0] !== cert.ssh_type) {
    fail('type-mismatch', 'the line says "' + parts[0] + '" but the ' +
      'certificate is "' + cert.ssh_type + '"');
  }
  cert.comment = parts.length > 2 ? parts.slice(2).join(' ') : null;
  return cert;
}

function certificate_from_wire(input) {
  var bytes = to_bytes(input);
  var r = new Wire(bytes);
  var cert_type = r.text();

  if (cert_type.length <= CERT_SUFFIX.length ||
      cert_type.substr(cert_type.length - CERT_SUFFIX.length) !== CERT_SUFFIX) {
    fail('not-certificate', '"' + cert_type + '" is not an OpenSSH ' +
      'certificate type');
  }

  var key_type = key_type_of(cert_type);
  var nonce = r.string();
  var key = read_key_fields(r, key_type);
  key.ssh_type = key_type;
  key.wire = new Uint8Array(w_text(key_type).concat(key_fields(key).fields));
  key.comment = null;

  var serial = r.uint64();
  var type = r.uint32();

  if (CERT_TYPES[type] === undefined) {
    fail('bad-certificate-type', 'certificate type ' + type + '; 1 (user) ' +
      'and 2 (host) are defined');
  }

  var key_id = r.text();
  var principals = read_list(r.string());
  var after = r.uint64();
  var before = r.uint64();
  var critical = read_options(r.string(), true);
  var extensions = read_options(r.string(), false);
  var reserved = r.string();
  var ca = key_from_wire(r.string());
  var tbs_end = r.pos;
  var signature = read_signature_blob(r.string());
  r.expect_end();

  if (signature_formats(ca.ssh_type).indexOf(signature.format) === -1) {
    fail('signature-key-mismatch', 'a ' + ca.ssh_type + ' CA key does not ' +
      'sign ' + signature.format);
  }

  return {
    ssh_type: cert_type,
    nonce: nonce,
    public_key: key,
    serial: serial,
    serial_hex: hex(serial),
    type: CERT_TYPES[type],
    key_id: key_id,
    // Empty means ANY principal - PROTOCOL.certkeys - which is why a
    // verifier must look rather than loop over it.
    principals: principals,
    valid_after: as_seconds(after, false),
    valid_before: as_seconds(before, true),
    critical_options: critical,
    unknown_critical: Object.keys(critical).filter(function (k) {
      return KNOWN_CRITICAL.indexOf(k) === -1;
    }),
    extensions: extensions,
    reserved: reserved,
    signature_key: ca,
    signature: signature,
    tbs_bytes: bytes.subarray(0, tbs_end),
    wire: bytes,
    comment: null
  };
}

// A uint64 time in seconds. 0xFFFFFFFFFFFFFFFF is "forever" - null.
function as_seconds(b, forever_allowed) {
  var all = true;
  var i;
  for (i = 0; i < 8; i++) { if (b[i] !== 0xFF) { all = false; } }
  if (all && forever_allowed) { return null; }
  if (b[0] !== 0 || b[1] > 0x1F) {
    fail('unsupported-time', 'a validity time beyond 2^53 seconds');
  }
  var v = 0;
  for (i = 0; i < 8; i++) { v = v * 256 + b[i]; }
  return v;
}

// Packed strings: principals.
function read_list(bytes) {
  var r = new Wire(bytes);
  var out = [];
  while (r.remaining() > 0) { out.push(r.text()); }
  return out;
}

// Packed (name, data) pairs. A critical option's data is a string holding
// a string; an extension's is usually empty. Names must be sorted and
// unique (PROTOCOL.certkeys) - two entries of one name are two answers.
function read_options(bytes, critical) {
  var r = new Wire(bytes);
  var out = {};
  var last = null;

  while (r.remaining() > 0) {
    var name = r.text();
    var data = r.string();
    if (last !== null && name <= last) {
      fail('unsorted-options', (critical ? 'critical options' : 'extensions') +
        ' must be in order and each once, PROTOCOL.certkeys');
    }
    last = name;
    if (data.length === 0) {
      out[name] = '';
    } else {
      var inner = new Wire(data);
      out[name] = inner.text();
      inner.expect_end();
    }
  }
  return out;
}

// The bytes a certificate's signature covers, and what assemble needs.
//
//   parts: { public_key, nonce (32 random bytes), serial (8 bytes), type
//            'user' | 'host', key_id, principals, valid_after, valid_before
//            (seconds, or null for forever), critical_options,
//            extensions ({ name: string data }), signature_key (the CA's
//            public key), format? }
function certificate_prepare(parts) {
  var p = parts || {};
  var k = key_fields(p.public_key);
  var nonce = to_array(p.nonce || []);

  if (nonce.length < 16) {
    fail('bad-nonce', 'the nonce is random, and OpenSSH writes 32 bytes - ' +
      'it is what keeps a CA from signing a chosen-prefix collision');
  }

  var type = p.type === 'user' ? 1 : p.type === 'host' ? 2 :
    fail('bad-certificate-type', 'type is "user" or "host"');
  var principals = [];
  (p.principals || []).forEach(function (x) { append(principals, w_text(x)); });
  var ca = key_to_wire(p.signature_key);
  var ca_type = wire_type(ca);
  var format = p.format === undefined ? signature_formats(ca_type)[0] : p.format;

  if (signature_formats(ca_type).indexOf(format) === -1) {
    fail('signature-key-mismatch', 'a ' + ca_type + ' CA key does not sign ' + format);
  }

  var body = w_text(cert_type_of(k.type)).concat(w_string(nonce)).concat(k.fields)
    .concat(w_uint64(p.serial || [0, 0, 0, 0, 0, 0, 0, 0])).concat(w_uint32(type))
    .concat(w_text(p.key_id || '')).concat(w_string(principals))
    .concat(time64(p.valid_after === undefined ? 0 : p.valid_after))
    .concat(time64(p.valid_before === undefined ? null : p.valid_before))
    .concat(w_string(options(p.critical_options)))
    .concat(w_string(options(p.extensions)))
    .concat(w_string([])).concat(w_string(ca));

  return { bytes: new Uint8Array(body), format: format, ssh_type: cert_type_of(k.type) };
}

function certificate_assemble(prepared, signature) {
  return new Uint8Array(to_array(prepared.bytes)
    .concat(w_string(signature_blob(prepared.format, signature))));
}

// seconds -> uint64; null is forever.
function time64(t) {
  if (t === null) { return [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; }
  if (typeof t !== 'number' || t < 0 || t % 1 !== 0 || t > 0x1FFFFFFFFFFFFF) {
    fail('bad-time', 'a validity time is whole seconds since the epoch, or null');
  }
  var out = [];
  var v = t;
  var i;
  for (i = 0; i < 8; i++) { out.unshift(v % 256); v = Math.floor(v / 256); }
  return out;
}

// { name: data } -> the packed form, sorted by name. Non-empty data is a
// string inside the string.
function options(map) {
  var names = Object.keys(map || {}).sort();
  var out = [];
  names.forEach(function (n) {
    var v = map[n];
    append(append(out, w_text(n)), v === '' ? w_string([]) : w_string(w_text(v)));
  });
  return out;
}

// Whether `when` (a Date, or seconds; default now) is inside the
// certificate's validity - valid_after <= when < valid_before.
function certificate_valid_at(cert, when) {
  var t = when === undefined ? Date.now() / 1000
    : when instanceof Date ? when.getTime() / 1000 : when;
  return t >= cert.valid_after && (cert.valid_before === null || t < cert.valid_before);
}

// ---------------------------------------------------------------------------
// openssh-key-v1
// ---------------------------------------------------------------------------

// A COMPLETELY DIFFERENT CONTAINER. Nothing above reads this and nothing here
// reads that.
//
//   "openssh-key-v1\0"
//   string   ciphername
//   string   kdfname
//   string   kdfoptions      (salt and rounds, when there is a KDF)
//   uint32   number of keys
//   string   publickey        (the RFC 4253 blob, repeated)
//   string   encrypted section

var MAGIC = 'openssh-key-v1\u0000';

var PRIVATE_LABEL = 'OPENSSH PRIVATE KEY';

// Reads the container and reports what it holds. When the key is encrypted
// this returns the KDF parameters and the ciphertext rather than the key -
// same shape as PBES2, and for the same reason.
// ⚠ THROUGH pem.js, NOT A SECOND PEM READER.
//
// This module had its own armour stripper - a line loop with its own idea
// of whitespace and of where a block ends - beside pem.js, which every
// other PEM in the library goes through. Two readers of one armour is two
// chances to disagree about which file is valid.
function private_from_pem(text) {
  var blocks;

  try {
    blocks = PEM.decode(String(text));
  } catch (e) {
    fail(e.code || 'bad-pem', e.message.replace(/^cryptographic-formats: \w+: /, ''));
  }

  var i;
  for (i = 0; i < blocks.length; i++) {
    if (blocks[i].label === PRIVATE_LABEL) {
      return private_from_bytes(blocks[i].der);
    }
  }

  fail('not-openssh-key',
    'no "-----BEGIN ' + PRIVATE_LABEL + '-----" found; a file saying ' +
    '"BEGIN RSA PRIVATE KEY" or "BEGIN PRIVATE KEY" is PKCS#1 or PKCS#8, ' +
    'not this format');
}

function private_from_bytes(input) {
  var bytes = to_bytes(input);
  var i;

  for (i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC.charCodeAt(i)) {
      fail('bad-magic',
        'this is not an openssh-key-v1 container');
    }
  }

  var r = new Wire(bytes.subarray(MAGIC.length));

  var cipher = r.text();
  var kdfname = r.text();
  var kdfoptions = r.string();
  var count = r.uint32();

  // OpenSSH has never written more than one, and the format's own tooling
  // does not read more. Accepting a count it cannot act on would mean
  // returning one key from a file that claims several.
  if (count !== 1) {
    fail('unsupported-key-count',
      'this container holds ' + count + ' keys; only one is supported');
  }

  var public_blob = r.string();
  var section = r.string();
  r.expect_end();

  var out = {
    format:    'openssh-key-v1',
    cipher:    cipher,
    kdf:       kdfname,
    encrypted: cipher !== 'none',
    public:    key_from_wire(public_blob),
    data:      section
  };

  if (out.encrypted) {
    read_kdf_options(out, kdfname, kdfoptions);
    return out;
  }

  if (kdfname !== 'none') {
    fail('inconsistent-container',
      'the cipher is "none" but the KDF is "' + kdfname + '"');
  }

  read_private_section(out, section);
  return out;
}

function read_kdf_options(out, kdfname, options) {
  if (kdfname !== 'bcrypt') {
    fail('unsupported-kdf',
      'unrecognised KDF "' + kdfname + '"');
  }

  var r = new Wire(options);
  out.salt = r.string();
  out.rounds = r.uint32();
  r.expect_end();

  // ⚠ bcrypt-pbkdf is NOT bcrypt and NOT PBKDF2. It is bcrypt's expensive key
  // schedule, with its own magic string, at 64 fixed rounds, inside a
  // PBKDF2-shaped loop. A caller who reaches for a bcrypt library or for
  // PBKDF2 will derive the wrong key and see a failure that looks like a
  // wrong passphrase.
  //
  // Saying so here is the whole value of reporting the parameters: the name
  // in the file is "bcrypt" and the algorithm is not.
  out.kdf_note =
    'bcrypt-pbkdf: bcrypt\'s key schedule at 64 rounds inside a ' +
    'PBKDF2-shaped loop. Not bcrypt, and not PBKDF2 - a library for either ' +
    'will derive the wrong key.';
}

// The decrypted (or never-encrypted) section. Its first two words are equal
// when the passphrase was right, which is the format's own check and the only
// signal a caller gets.
function read_private_section(out, section) {
  var r = new Wire(section);

  var check1 = r.uint32();
  var check2 = r.uint32();

  if (check1 !== check2) {
    fail('bad-passphrase',
      'the two check words differ, which means the passphrase was wrong or ' +
      'the data is corrupt');
  }

  var type = r.text();
  var priv = {};

  if (Object.prototype.hasOwnProperty.call(SK_TYPES, type)) {
    // The public fields, then what the authenticator needs to sign: the
    // private key itself never leaves it (PROTOCOL.u2f).
    priv = read_key_fields(r, type);
    priv.flags = r.byte();
    priv.key_handle = r.string();
    priv.reserved = r.string();

  } else if (type === 'ssh-ed25519') {
    var pub = r.string();
    var full = r.string();

    // The private string is the 32-byte seed followed by the 32-byte public
    // key, and the copy inside must match the copy outside.
    if (full.length !== 64) {
      fail('bad-key-length',
        'an Ed25519 private blob is 64 bytes, got ' + full.length);
    }
    if (!bytes_equal(pub, full.subarray(32))) {
      fail('key-mismatch',
        'the public key inside the private blob does not match the one ' +
        'beside it');
    }

    priv = { algorithm: 'Ed25519', point: pub, scalar: full.subarray(0, 32) };

  } else if (type === 'ssh-rsa') {
    // The private form's order differs from the public form's AGAIN: here it
    // is n then e, where the public wire blob is e then n.
    var n = r.mpint();
    var e = r.mpint();
    var d = r.mpint();
    var iqmp = r.mpint();
    var p = r.mpint();
    var q = r.mpint();

    priv = {
      algorithm: 'rsaEncryption',
      rsa: { n: n, e: e, d: d, p: p, q: q, qinv: iqmp }
    };

  } else if (type.indexOf('ecdsa-sha2-') === 0) {
    var curve_name = r.text();
    var curve = EC_CURVES[curve_name];

    if (curve === undefined) {
      fail('unknown-curve', 'unrecognised curve "' + curve_name + '"');
    }
    if ('ecdsa-sha2-' + curve_name !== type) {
      fail('curve-mismatch',
        'the algorithm says ' + type + ' but the curve field says ' +
        curve_name);
    }

    var point = r.string();
    var scalar = r.mpint();

    priv = {
      algorithm: 'ecPublicKey',
      curve: curve.oid,
      point: point,
      scalar: scalar
    };

  } else {
    fail('unknown-key-type', 'unrecognised key type "' + type + '"');
  }

  priv.comment = r.text();

  // The section is padded to the cipher's block size with 1, 2, 3... A
  // different pattern means the file was written by something that did not
  // follow the format, and checking costs nothing.
  var pad = 1;
  while (r.remaining() > 0) {
    if (r.buf[r.pos] !== pad) {
      fail('bad-padding',
        'padding should count 1, 2, 3...; found ' + r.buf[r.pos] +
        ' where ' + pad + ' was expected');
    }
    r.pos += 1;
    pad += 1;
  }

  // ⚠ THE PRIVATE SECTION REPEATS THE PUBLIC KEY, AND THE TWO MUST AGREE.
  //
  // Only the Ed25519 branch compared its internal copies; nothing compared
  // the private section with the PUBLIC blob in front of it. A file whose
  // public half names one key and whose private half holds another is a
  // file that fingerprints as somebody else's - so the private key's public
  // form is written out and compared with the container's, byte for byte.
  if (out.public && !bytes_equal(key_to_wire(priv), out.public.wire)) {
    fail('key-mismatch',
      'the private section holds a different key from the public blob ' +
      'that precedes it');
  }

  out.private = priv;
  out.comment = priv.comment;
}

// ---------------------------------------------------------------------------
// Writing a private key
// ---------------------------------------------------------------------------

// ⚠ THE PRIVATE SECTION, BEFORE ENCRYPTION - the bytes a caller encrypts.
//
//   uint32 check, uint32 check     equal: the format's passphrase check
//   string type, <key fields>      in the PRIVATE order, which differs from
//                                  the public wire order for RSA
//   string comment
//   padding 1, 2, 3 ...            to the cipher's block size
//
// `check` is 4 bytes the caller chooses - OpenSSH uses random ones, and so
// should an encrypted key, because they are known plaintext otherwise.
function private_section(key, check, comment, block) {
  var c = to_array(check);
  if (c.length !== 4) {
    fail('bad-check', 'the check value is 4 bytes');
  }

  var out = c.concat(c);

  if (key.application !== undefined && key.application !== null) {
    if (typeof key.flags !== 'number' || key.flags < 0 || key.flags > 255 || key.flags % 1 !== 0 ||
        !key.key_handle) {
      fail('bad-key', 'a security key\'s private half is flags (a byte) and key_handle');
    }
    out = out.concat(to_array(key_to_wire(key))).concat([key.flags])
      .concat(w_string(key.key_handle)).concat(w_string(key.reserved || []));
  } else if (key.algorithm === 'Ed25519') {
    if (!key.scalar || key.scalar.length !== 32) {
      fail('bad-key-length', 'an Ed25519 seed is 32 bytes');
    }
    out = out.concat(w_text('ssh-ed25519'))
      .concat(w_string(key.point))
      .concat(w_string(to_array(key.scalar).concat(to_array(key.point))));
  } else if (key.algorithm === 'rsaEncryption') {
    var r = key.rsa || {};
    if (!r.n || !r.e || !r.d || !r.p || !r.q || !r.qinv) {
      fail('bad-key', 'an RSA private key needs n, e, d, p, q and qinv');
    }
    // n, e - the reverse of the public blob's e, n.
    out = out.concat(w_text('ssh-rsa'))
      .concat(w_mpint(r.n)).concat(w_mpint(r.e)).concat(w_mpint(r.d))
      .concat(w_mpint(r.qinv)).concat(w_mpint(r.p)).concat(w_mpint(r.q));
  } else if (key.algorithm === 'ecPublicKey') {
    var wire = new Wire(key_to_wire(key));
    var type = wire.text();
    var name = wire.text();
    out = out.concat(w_text(type)).concat(w_text(name))
      .concat(w_string(key.point)).concat(w_mpint(key.scalar));
  } else {
    fail('unsupported-algorithm',
      'cannot write algorithm ' + key.algorithm + ' as an SSH private key');
  }

  out = out.concat(w_text(comment || ''));

  var pad = 1;
  while (out.length % block !== 0) {
    out.push(pad);
    pad += 1;
  }

  return new Uint8Array(out);
}

// An UNENCRYPTED openssh-key-v1 file, as text. `key` is the shape
// private_from_pem returns as `.private`, or the same fields built by hand.
//
// ⚠ Unencrypted means anyone with the file has the key. It is what
// `ssh-keygen -N ''` writes, and it is a decision.
function private_to_pem(key, options) {
  var opts = options || {};
  var section = private_section(key, opts.check || [0, 0, 0, 0],
    opts.comment, 8);
  return container(key, 'none', 'none', [], section);
}

// An ENCRYPTED key, in two steps around the caller's cryptography:
//
//   var p = ssh.private_prepare(key, { salt, rounds, check, comment });
//   var kiv = bcrypt_pbkdf(passphrase, p.salt, p.rounds, 48);  // key || iv
//   var ct = aes256ctr(kiv.subarray(0, 32), kiv.subarray(32), p.plaintext);
//   var pem = ssh.private_assemble(p, ct);
//
// aes256-ctr with bcrypt-pbkdf is what ssh-keygen writes. `rounds` is
// bcrypt-pbkdf's own count - 16 by default in ssh-keygen, and each round is
// expensive; do not port a PBKDF2 iteration count here.
function private_prepare(key, options) {
  var opts = options || {};
  var salt = to_bytes(opts.salt || new Uint8Array(0));

  if (salt.length < 16) {
    fail('bad-salt', 'the bcrypt-pbkdf salt is at least 16 bytes');
  }
  if (typeof opts.rounds !== 'number' || opts.rounds < 1 ||
      opts.rounds % 1 !== 0) {
    fail('bad-rounds', 'rounds is a positive integer - ssh-keygen uses 16');
  }
  if (!opts.check) {
    fail('bad-check',
      'an encrypted key needs 4 random check bytes - fixed ones are known ' +
      'plaintext at the start of the ciphertext');
  }

  return {
    key:       key,
    cipher:    'aes256-ctr',
    kdf:       'bcrypt',
    salt:      salt,
    rounds:    opts.rounds,
    key_length: 32,
    iv_length:  16,
    plaintext: private_section(key, opts.check, opts.comment, 16)
  };
}

function private_assemble(prepared, ciphertext) {
  var ct = to_bytes(ciphertext);

  if (ct.length !== prepared.plaintext.length) {
    fail('bad-ciphertext',
      'aes256-ctr preserves length: expected ' + prepared.plaintext.length +
      ' bytes, got ' + ct.length);
  }

  var options = w_string(prepared.salt).concat(w_uint32(prepared.rounds));

  return container(prepared.key, prepared.cipher, prepared.kdf, options, ct);
}

function container(key, cipher, kdf, kdf_options, section) {
  var bytes = [];
  var i;

  for (i = 0; i < MAGIC.length; i++) {
    bytes.push(MAGIC.charCodeAt(i));
  }

  bytes = bytes.concat(w_text(cipher)).concat(w_text(kdf))
    .concat(w_string(kdf_options)).concat(w_uint32(1))
    .concat(w_string(key_to_wire(key))).concat(w_string(section));

  // ssh-keygen wraps at 70 columns, and so does this - a file that diffs
  // against ssh-keygen's output in nothing but the key material.
  var b64 = B.encode('base64', new Uint8Array(bytes))
    .replace(/(.{70})/g, '$1\n').replace(/\n$/, '');

  return '-----BEGIN ' + PRIVATE_LABEL + '-----\n' + b64 + '\n' +
    '-----END ' + PRIVATE_LABEL + '-----\n';
}

// Decrypts nothing. Takes the plaintext section the caller produced and reads
// it - the same shape as PBES2, and the same reason.
function private_from_decrypted(container, plaintext) {
  var out = {
    format: container.format,
    cipher: container.cipher,
    kdf: container.kdf,
    encrypted: false,
    public: container.public
  };

  read_private_section(out, to_bytes(plaintext));
  return out;
}

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

// WHICH BLOB IS HASHED is the entire question.
//
// An SSH fingerprint hashes the RFC 4253 WIRE ENCODING - the bytes inside the
// base64 of a .pub file - not the DER, not the base64 text, and not the line
// including the comment. Hashing any of those produces a plausible
// fingerprint that matches nothing, and the mistake is invisible until
// somebody compares against ssh-keygen.
//
// The hash is one call into cryptographic-primitives. This module supplies the blob and
// formats the result, which is where the knowledge is.

function fingerprint_input(key) {
  if (key && key.wire instanceof Uint8Array) {
    return key.wire;
  }
  return key_to_wire(key);
}

// SHA256:<base64 without padding>, which is what modern ssh-keygen prints.
function fingerprint_sha256(digest) {
  var d = to_bytes(digest);

  if (d.length !== 32) {
    fail('bad-digest',
      'a SHA-256 digest is 32 bytes, got ' + d.length +
      ' - hash the output of fingerprint_input');
  }

  // base64, then the padding stripped. ssh-keygen prints it without.
  return 'SHA256:' + B.encode('base64', d).replace(/=+$/, '');
}

// The legacy form: lowercase hex, colon-separated, from an MD5 digest.
function fingerprint_md5(digest) {
  var d = to_bytes(digest);

  if (d.length !== 16) {
    fail('bad-digest',
      'an MD5 digest is 16 bytes, got ' + d.length);
  }

  var parts = [];
  var i;
  for (i = 0; i < d.length; i++) {
    var h = d[i].toString(16);
    parts.push(h.length === 1 ? '0' + h : h);
  }
  return 'MD5:' + parts.join(':');
}

// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Security-key attestation - `ssh-keygen -O write-attestation=FILE`
// ---------------------------------------------------------------------------
//
// PROTOCOL.u2f, "attestation", and ssh-sk.c's fill_attestation_blob:
//
//   string  "ssh-sk-attest-v01"
//   string  attestation certificate     DER; empty when there is none
//   string  enrollment signature
//   string  authenticator data          CBOR-encoded - a byte string
//   uint32  reserved flags              0
//   string  reserved                    empty
//
// v00, before OpenSSH 8.4, has no authenticator data. The three middle
// fields are libfido2's - fido_cred_x5c_ptr, fido_cred_sig_ptr,
// fido_cred_authdata_ptr, the last "a CBOR-encoded byte string, as obtained
// from the authenticator" (fido_cred_new(3)) - copied by sk-usbhid.c.
// OpenSSH does not interpret them; the format they come in is WebAuthn's,
// and webauthn.js reads it.
//
// ⚠ THE FILE DOES NOT SAY WHICH ATTESTATION FORMAT SIGNED. libfido2 knows
// (fido_cred_fmt) and OpenSSH does not keep it, so the plan offers both a
// key can produce - "packed" and "fido-u2f" - and the one that verifies is
// the one it was. Neither is guessed from the certificate.
function sk_attestation_from_bytes(input) {
  var bytes = to_bytes(input);
  var r = new Wire(bytes);
  var magic = r.string();
  var version = { 'ssh-sk-attest-v01': 'v01', 'ssh-sk-attest-v00': 'v00' }[
    latin1(magic)];
  if (version === undefined) {
    fail('not-sk-attestation', 'an attestation file starts ' +
      '"ssh-sk-attest-v01" (or v00)');
  }
  var certificate = r.string();
  var signature = r.string();
  var auth_cbor = version === 'v01' ? r.string() : null;
  var flags = r.uint32();
  var reserved = r.string();
  if (r.remaining() !== 0) {
    fail('trailing-bytes', r.remaining() + ' bytes after the attestation');
  }
  if (flags !== 0 || reserved.length !== 0) {
    fail('unsupported-sk-attestation', 'the reserved flags are 0 and the ' +
      'reserved string empty in every OpenSSH that writes this; anything ' +
      'else is a version this reader does not know');
  }
  // libfido2 takes the authenticator data only as a definite-length byte
  // string (fido_get_signed_hash), and so does this.
  var auth_bytes = auth_cbor === null || auth_cbor.length === 0 ? null
    : CBOR.read(auth_cbor, function (c) { return c.read_bytes(); });
  return {
    version: version,
    certificate: certificate.length === 0 ? null : certificate,
    signature: signature.length === 0 ? null : signature,
    auth_data_cbor: auth_cbor,
    auth_data_bytes: auth_bytes,
    auth_data: auth_bytes === null ? null : WEBAUTHN.auth_data_from_bytes(auth_bytes),
    note: version === 'v00'
      ? 'v00 keeps no authenticator data: the signature cannot be checked from this file'
      : 'the signature is checked with the certificate\'s key - or, with no ' +
        'certificate, the credential\'s own (self attestation) - over one of ' +
        'sk_attestation_plan\'s inputs'
  };
}

// What to verify, over what. `client_data_hash` is SHA-256 of the
// enrollment challenge - ssh-keygen's -O challenge=FILE, or the 32 random
// bytes it made - as libfido2's fido_cred_set_clientdata hashes it.
// `application_digest` (SHA-256 of the key's application) and `public_key`
// (the sk key, as key_from_text reads it) are checked against the
// authenticator data when given; null when not.
function sk_attestation_plan(att, options) {
  var o = options || {};
  var cdh = to_bytes(o.client_data_hash);
  if (cdh.length !== 32) {
    fail('bad-digest', 'the client data hash is SHA-256 of the challenge, 32 bytes');
  }
  if (att.auth_data === null) {
    fail('no-auth-data', att.note);
  }
  if (att.signature === null) {
    fail('not-attested', 'the authenticator returned no attestation signature');
  }
  var auth = att.auth_data;
  if (auth.credential === null) {
    fail('missing-credential', 'the authenticator data carries no credential');
  }
  var key = auth.credential.key;
  var inputs = [{ format: 'packed',
    bytes: WEBAUTHN.assertion_signing_input(att.auth_data_bytes, cdh) }];
  // U2F has no self attestation, and its keys are P-256 (W3C 8.6).
  if (att.certificate !== null && key.algorithm === 'ecPublicKey' && key.cose_curve === 1) {
    inputs.push({ format: 'fido-u2f', bytes: WEBAUTHN.u2f_signing_input(auth, cdh) });
  }
  var pk = o.public_key;
  return {
    inputs: inputs,
    signature: att.signature,
    certificate: att.certificate,
    self_attested: att.certificate === null,
    credential_key: key,
    credential_id: auth.credential.id,
    aaguid: auth.credential.aaguid_hex,
    rp_id_matches: o.application_digest === undefined ? null
      : bytes_equal(auth.rp_id_hash, to_bytes(o.application_digest)),
    key_matches: pk === undefined ? null
      : pk.algorithm === key.algorithm && bytes_equal(pk.point, key.point) &&
        (pk.curve === undefined || pk.curve === key.curve),
    note: 'ECDSA and RSA attestation keys sign with SHA-256; packed EdDSA ' +
      'signs the bytes. The format is not recorded - one input verifies.'
  };
}

// ---------------------------------------------------------------------------
// KRL - OpenSSH's key revocation list (PROTOCOL.krl); sshd's RevokedKeys
// ---------------------------------------------------------------------------

//   uint64  "SSHKRL\n\0"
//   uint32  format version       1
//   uint64  krl_version          rises with each change
//   uint64  generated_date       seconds
//   uint64  flags                none defined
//   string  reserved
//   string  comment
//   then sections: byte type, string data
//
// ⚠ SERIALS ARE 64 BITS, so they are hex here - 16 digits, as a
// certificate's serial_hex - and not numbers, which stop at 2^53. A CA that
// draws serials at random (many do) has them all above that.
//
// krl_to_bytes writes in one step: there is nothing to sign. The format has
// a signature section, but OpenSSH never checked it and from 9.4 refuses a
// KRL that has one (PROTOCOL.krl 6, which recommends an SSHSIG over the
// file instead) - so it is read and reported, and not written.
var KRL_MAGIC = [0x53, 0x53, 0x48, 0x4B, 0x52, 0x4C, 0x0A, 0x00];
var KRL_SECTIONS = { 1: 'certificates', 2: 'explicit_keys', 3: 'fingerprint_sha1',
                     4: 'signature', 5: 'fingerprint_sha256', 255: 'extension' };
var KRL_CERT_SECTIONS = { 0x20: 'serial_list', 0x21: 'serial_range', 0x22: 'serial_bitmap',
                          0x23: 'key_ids', 0x39: 'extension' };
var KRL_HASH_LENGTH = { fingerprint_sha1: 20, fingerprint_sha256: 32 };

function code_of(table, name, what) {
  var k;
  for (k in table) {
    if (Object.prototype.hasOwnProperty.call(table, k) && table[k] === name) {
      return parseInt(k, 10);
    }
  }
  fail('unknown-krl-section', '"' + name + '" is not a KRL ' + what);
}

// uint64 as 16 hex digits, and the little arithmetic serials need. Fixed
// width, so comparing two is comparing strings. Arithmetic, not an encoding,
// so the reader and the writer may both use it.
function u64_hex(bytes8) {
  return hex(bytes8);
}

function u64_add(h, n) {
  var hi = parseInt(h.substr(0, 8), 16);
  var lo = parseInt(h.substr(8), 16) + n;
  hi += Math.floor(lo / 0x100000000);
  lo = lo % 0x100000000;
  if (hi > 0xFFFFFFFF) {
    fail('bad-krl', 'a serial bitmap runs past 2^64');
  }
  return ('0000000' + hi.toString(16)).slice(-8) + ('0000000' + lo.toString(16)).slice(-8);
}

// b - a, when it fits in a safe integer.
function u64_diff(b, a) {
  var d = (parseInt(b.substr(0, 8), 16) - parseInt(a.substr(0, 8), 16)) * 0x100000000 +
          (parseInt(b.substr(8), 16) - parseInt(a.substr(8), 16));
  if (d > 0x1FFFFFFFFFFFFF) {
    fail('bad-krl-serial', 'a bitmap cannot span ' + a + ' to ' + b);
  }
  return d;
}

// A serial as a writer takes it: 16 hex digits (serial_hex), 8 bytes, or a
// safe integer. Not shorter hex - "10" would be ten to one reader and
// sixteen to another. Zero is refused, as OpenSSH refuses it.
function serial_in(v) {
  var h;
  if (typeof v === 'number' && v % 1 === 0 && v >= 0 && v <= 0x1FFFFFFFFFFFFF) {
    h = u64_add('0000000000000000', v);
  } else if (typeof v === 'string' && /^[0-9a-fA-F]{16}$/.test(v)) {
    h = v.toLowerCase();
  } else if (v instanceof Uint8Array && v.length === 8) {
    h = hex(v);
  } else {
    fail('bad-krl-serial', 'a serial is 16 hex digits (as serial_hex), 8 bytes, or ' +
      'a whole number - not ' + String(v));
  }
  if (h === '0000000000000000') {
    fail('bad-krl-serial', 'serial 0 cannot be revoked (OpenSSH refuses it)');
  }
  return h;
}

function hex_bytes(h) {
  var out = [];
  var i;
  for (i = 0; i < h.length; i += 2) { out.push(parseInt(h.substr(i, 2), 16)); }
  return out;
}

function krl_from_bytes(input) {
  var bytes = to_bytes(input);
  var r = new Wire(bytes);
  var i;

  for (i = 0; i < 8; i++) {
    if (bytes[i] !== KRL_MAGIC[i]) {
      fail('not-krl', 'a KRL starts "SSHKRL\\n\\0"');
    }
  }
  r.pos = 8;
  var version = r.uint32();
  if (version !== 1) {
    fail('unsupported-version', 'KRL format version ' + version + '; 1 is defined');
  }

  var out = {
    format_version: 1,
    krl_version: as_seconds(r.uint64(), false),
    generated_date: as_seconds(r.uint64(), false),
    flags: as_seconds(r.uint64(), false),
    reserved: r.string(),
    comment: r.text(),
    sections: []
  };

  while (r.remaining() > 0) {
    var at = r.pos;
    var code = r.byte();
    var type = KRL_SECTIONS[code];

    if (type === undefined) {
      fail('unknown-krl-section', 'KRL section type ' + code + ' (OpenSSH refuses it too)');
    }
    if (type === 'signature') {
      out.sections.push(krl_signature(r, bytes, at));
      continue;
    }
    if (out.sections.length > 0 && out.sections[out.sections.length - 1].type === 'signature') {
      fail('bad-krl', 'signature sections come last (PROTOCOL.krl 6)');
    }

    var data = new Wire(r.string());
    if (type === 'certificates') {
      out.sections.push(krl_certificates(data));
    } else if (type === 'explicit_keys') {
      var keys = [];
      while (data.remaining() > 0) { keys.push(key_from_wire(data.string())); }
      out.sections.push({ type: type, keys: krl_nonempty(keys, type) });
    } else if (type === 'extension') {
      out.sections.push(krl_extension(data, 'section'));
    } else {
      out.sections.push({ type: type, hashes: krl_hashes(data, type) });
    }
    data.expect_end();
  }

  out.signed = out.sections.some(function (s) { return s.type === 'signature'; });
  return out;
}

function krl_nonempty(list, what) {
  if (list.length === 0) {
    fail('bad-krl', 'a ' + what + ' section must hold at least one entry (PROTOCOL.krl)');
  }
  return list;
}

// Each its length, and in order - "numeric order, treating each hash as a
// big-endian integer". One out of place is not a list written by ssh-keygen.
function krl_hashes(data, type) {
  var out = [];
  var last = null;
  while (data.remaining() > 0) {
    var h = data.string();
    if (h.length !== KRL_HASH_LENGTH[type]) {
      fail('bad-krl', type + ' hashes are ' + KRL_HASH_LENGTH[type] + ' bytes, got ' + h.length);
    }
    if (last !== null && hex(h) <= last) {
      fail('unsorted-krl', type + ' hashes must be in ascending order, each once');
    }
    last = hex(h);
    out.push(h);
  }
  return krl_nonempty(out, type);
}

//   string name, boolean critical, string contents
// None is defined, so a critical one cannot be understood - and is refused,
// as PROTOCOL.krl and OpenSSH both require.
function krl_extension(data, where) {
  var name = data.text();
  var critical = data.byte();
  var contents = data.string();
  if (critical > 1) {
    fail('bad-krl', 'an extension\'s critical flag is a boolean, 0 or 1');
  }
  if (critical === 1) {
    fail('unsupported-critical-extension', 'the KRL ' + where + ' extension "' + name +
      '" is critical and not understood');
  }
  return { type: 'extension', name: name, critical: false, contents: contents };
}

//   string ca_key        empty: any CA
//   string reserved
//   then subsections: byte type, string data
function krl_certificates(data) {
  var ca = data.string();
  var out = { type: 'certificates', ca_key: ca.length === 0 ? null : key_from_wire(ca),
              reserved: data.string(), entries: [] };

  while (data.remaining() > 0) {
    var code = data.byte();
    var type = KRL_CERT_SECTIONS[code];
    if (type === undefined) {
      fail('unknown-krl-section', 'KRL certificate subsection type 0x' + code.toString(16));
    }
    var sub = new Wire(data.string());
    var e = { type: type };

    if (type === 'serial_list') {
      e.serials = [];
      while (sub.remaining() > 0) { e.serials.push(krl_serial(sub.uint64())); }
    } else if (type === 'serial_range') {
      e.min = krl_serial(sub.uint64());
      e.max = u64_hex(sub.uint64());
      if (e.max < e.min) {
        fail('bad-krl', 'a serial range ends before it starts: ' + e.min + ' to ' + e.max);
      }
    } else if (type === 'serial_bitmap') {
      e.offset = u64_hex(sub.uint64());
      var m = sub.mpint();
      if (m.length > 0 && (m[0] & 0x80) !== 0) {
        fail('bad-krl', 'a serial bitmap is a non-negative mpint');
      }
      e.serials = bitmap_serials(e.offset, m);
    } else if (type === 'key_ids') {
      e.key_ids = [];
      while (sub.remaining() > 0) { e.key_ids.push(sub.text()); }
      krl_nonempty(e.key_ids, 'key ID');
    } else {
      e = krl_extension(sub, 'certificate');
    }
    sub.expect_end();
    out.entries.push(e);
  }
  return out;
}

function krl_serial(b) {
  var h = u64_hex(b);
  if (h === '0000000000000000') {
    fail('bad-krl', 'serial 0 cannot be revoked (OpenSSH refuses the KRL)');
  }
  return h;
}

// Bit N of the big-endian integer is serial offset + N.
function bitmap_serials(offset, m) {
  var out = [];
  var n = m.length;
  var i, b;
  for (i = n - 1; i >= 0; i--) {
    for (b = 0; b < 8; b++) {
      if ((m[i] >> b) & 1) {
        var h = u64_add(offset, (n - 1 - i) * 8 + b);
        if (h === '0000000000000000') {
          fail('bad-krl', 'serial 0 cannot be revoked (OpenSSH refuses the KRL)');
        }
        out.push(h);
      }
    }
  }
  return out;
}

//   byte 4, string signature_key, string signature
// - two strings, not one. The signature is over the KRL from the magic to
// this section's signature_key, both included.
function krl_signature(r, bytes, at) {
  var key = key_from_wire(r.string());
  var end = r.pos;
  return {
    type: 'signature', signature_key: key,
    signature: read_signature_blob(r.string()),
    signed_bytes: bytes.subarray(0, end),
    note: 'OpenSSH never verified KRL signatures and from 9.4 refuses a KRL that has ' +
          'one - sshd will not load this file. Sign the file with SSHSIG instead.'
  };
}

// The KRL, written. `parts` has the shape krl_from_bytes returns:
//   { krl_version, generated_date (seconds), comment?, sections: [
//       { type: 'certificates', ca_key (a key, or null for any CA),
//         entries: [ { type: 'serial_list', serials: [...] },
//                    { type: 'serial_range', min, max },
//                    { type: 'serial_bitmap', offset, serials: [...] },
//                    { type: 'key_ids', key_ids: [...] } ] },
//       { type: 'explicit_keys', keys: [...] },
//       { type: 'fingerprint_sha256', hashes: [...] } ...] }
// Sections and entries are written in the order given - which choice of
// list, range or bitmap is the caller's, as it was ssh-keygen's.
function krl_to_bytes(parts) {
  var p = parts || {};
  if (p.flags !== undefined && p.flags !== 0) {
    fail('bad-krl', 'no KRL flags are defined');
  }
  var out = KRL_MAGIC.concat(w_uint32(1))
    .concat(hex_bytes(u64_add('0000000000000000', krl_number(p.krl_version, 'krl_version'))))
    .concat(hex_bytes(u64_add('0000000000000000', krl_number(p.generated_date, 'generated_date'))))
    .concat([0, 0, 0, 0, 0, 0, 0, 0])
    .concat(w_string(to_array(p.reserved || [])))
    .concat(w_text(p.comment || ''));

  (p.sections || []).forEach(function (sec) {
    var type = sec && sec.type;
    if (type === 'signature') {
      fail('unsupported-krl-signature', 'OpenSSH 9.4 and later refuse a KRL with a ' +
        'signature section; sign the file with SSHSIG');
    }
    var body;
    if (type === 'certificates') {
      body = krl_certificates_out(sec);
    } else if (type === 'explicit_keys') {
      body = [];
      krl_nonempty(sec.keys || [], type).forEach(function (k) {
        append(body, w_string(key_to_wire(k)));
      });
    } else if (type === 'fingerprint_sha1' || type === 'fingerprint_sha256') {
      body = [];
      var last = null;
      krl_nonempty(sec.hashes || [], type).forEach(function (h) {
        var b = to_array(h);
        if (b.length !== KRL_HASH_LENGTH[type] || (last !== null && hex(b) <= last)) {
          fail('unsorted-krl', type + ' takes ' + KRL_HASH_LENGTH[type] + '-byte hashes in ' +
            'ascending order, each once (PROTOCOL.krl 4)');
        }
        last = hex(b);
        append(body, w_string(b));
      });
    } else if (type === 'extension') {
      body = krl_extension_out(sec);
    } else {
      fail('unknown-krl-section', '"' + type + '" is not a KRL section');
    }
    append(append(out, [code_of(KRL_SECTIONS, type, 'section')]), w_string(body));
  });
  return new Uint8Array(out);
}

function krl_number(v, what) {
  if (typeof v !== 'number' || v % 1 !== 0 || v < 0 || v > 0x1FFFFFFFFFFFFF) {
    fail('bad-krl', what + ' is a whole number');
  }
  return v;
}

function krl_extension_out(e) {
  if (e.critical === true) {
    fail('unsupported-critical-extension', 'a critical extension no reader understands ' +
      'makes the KRL unreadable');
  }
  return w_text(e.name).concat([0]).concat(w_string(to_array(e.contents || [])));
}

function krl_certificates_out(sec) {
  var body = w_string(sec.ca_key === null || sec.ca_key === undefined ? [] : key_to_wire(sec.ca_key))
    .concat(w_string(to_array(sec.reserved || [])));

  (sec.entries || []).forEach(function (e) {
    var sub = [];
    if (e.type === 'serial_list') {
      krl_nonempty(e.serials || [], 'serial list').forEach(function (v) { append(sub, hex_bytes(serial_in(v))); });
    } else if (e.type === 'serial_range') {
      var min = serial_in(e.min);
      var max = serial_in(e.max);
      if (max < min) {
        fail('bad-krl', 'a serial range ends before it starts');
      }
      sub = hex_bytes(min).concat(hex_bytes(max));
    } else if (e.type === 'serial_bitmap') {
      var offset = serial_in(e.offset);
      var bits = [];
      krl_nonempty(e.serials || [], 'serial bitmap').forEach(function (v) {
        var h = serial_in(v);
        if (h < offset) {
          fail('bad-krl-serial', h + ' is below the bitmap offset ' + offset);
        }
        var n = u64_diff(h, offset);
        if (n > 8 * 1024 * 1024 * 8) {
          fail('bad-krl-serial', 'a bitmap that wide is a list or a range');
        }
        var byte = Math.floor(n / 8);
        while (bits.length <= byte) { bits.push(0); }
        bits[byte] |= 1 << (n % 8);
      });
      sub = hex_bytes(offset).concat(w_mpint(bits.reverse()));
    } else if (e.type === 'key_ids') {
      krl_nonempty(e.key_ids || [], 'key ID').forEach(function (id) { append(sub, w_text(id)); });
    } else if (e.type === 'extension') {
      sub = krl_extension_out(e);
    } else {
      fail('unknown-krl-section', '"' + e.type + '" is not a KRL certificate subsection');
    }
    append(append(body, [code_of(KRL_CERT_SECTIONS, e.type, 'certificate subsection')]), w_string(sub));
  });
  return body;
}


export {
  sk_attestation_from_bytes,
  sk_attestation_plan,
  sshsig_from_text,
  sshsig_from_wire,
  sk_signed_data,
  krl_from_bytes,
  krl_to_bytes,
  sk_message,
  sshsig_signed_data,
  sshsig_prepare,
  sshsig_assemble,
  certificate_from_text,
  certificate_from_wire,
  certificate_prepare,
  certificate_assemble,
  certificate_valid_at,
  private_to_pem,
  private_prepare,
  private_assemble,
  key_from_wire,
  key_from_text,
  key_to_wire,
  key_to_text,
  private_from_pem,
  private_from_bytes,
  private_from_decrypted,
  fingerprint_input,
  fingerprint_sha256,
  fingerprint_md5,
  EC_CURVES
};

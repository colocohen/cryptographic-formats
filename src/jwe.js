// JSON Web Encryption, RFC 7516.
//
// ⚠ A JWE HAS TWO ALGORITHMS AND THEY DO DIFFERENT JOBS.
//
//   alg   how the content encryption key travels: wrapped with RSA-OAEP,
//         derived with ECDH-ES, or supplied directly
//   enc   how the content is encrypted with that key: A256GCM, A128CBC-HS256
//
// Every other format in this library has one algorithm field, and treating
// these two as interchangeable is the mistake this module is shaped to
// prevent. A token naming `alg: dir` and `enc: A256GCM` is not "encrypted
// with dir"; `dir` says the recipient already has the key.
//
// ⚠ AND THE AAD IS THE PROTECTED HEADER AS IT APPEARS, IN ASCII.
//
// RFC 7516 section 5.1 step 14: the Additional Authenticated Data for the
// AEAD is the ASCII bytes of BASE64URL(protected header) - not the decoded
// header, not the JSON, and not a re-encoding of either. A producer whose
// JSON had different key order produces a different string, and a decryptor
// that rebuilt it would authenticate bytes that were never authenticated.
//
// This library performs no cryptography. It reports which two algorithms are
// named, hands over the exact AAD, IV, ciphertext and tag, and takes the
// plaintext back.

import * as B from './base.js';
import * as JSON_ from './json.js';
import { split_serialization, decode_part, ascii, check_crit, understood_names, union_headers,
         encode_header } from './jose.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, concat_bytes } from './commons/bytes.js';
import { check_iterations } from './commons/limits.js';
import { encode_utf8 } from './commons/encode_text.js';

var fail = make_fail_here('jwe');

// The header names crit may not smuggle past a check - see jose.js. Every
// name RFC 7516 and RFC 7518 define for JWE, not three of them.
var CRIT_REGISTERED = ['alg', 'enc', 'zip', 'jku', 'jwk', 'kid', 'x5u', 'x5c',
                       'x5t', 'x5t#S256', 'typ', 'cty', 'crit', 'epk', 'apu',
                       'apv', 'iv', 'tag', 'p2s', 'p2c'];

// No JWE extension is implemented here, so only the caller's names - passed
// in options.understood - can make a crit entry acceptable.
var UNDERSTOOD = [];

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

// RFC 7518 section 4. KEY MANAGEMENT, not content encryption.
//
// `wraps` says whether the encrypted_key field carries anything: `dir` and
// the plain ECDH-ES forms derive or supply the CEK, so their encrypted_key
// MUST be empty - and one that is not is a token whose key comes from two
// places.
var KEY_ALG = {
  // Read, because tokens using it exist; reported in the plan's warnings,
  // because decrypting it without a constant-time implicit-rejection path
  // is a padding oracle (Bleichenbacher 1998, and every year since).
  RSA1_5:            { wraps: true,  note: 'PKCS#1 v1.5, Bleichenbacher' },
  'RSA-OAEP':        { wraps: true },
  'RSA-OAEP-256':    { wraps: true },
  A128KW:            { wraps: true },
  A192KW:            { wraps: true },
  A256KW:            { wraps: true },
  dir:               { wraps: false },
  'ECDH-ES':         { wraps: false, ecdh: true },
  'ECDH-ES+A128KW':  { wraps: true, ecdh: true },
  'ECDH-ES+A192KW':  { wraps: true, ecdh: true },
  'ECDH-ES+A256KW':  { wraps: true, ecdh: true },
  A128GCMKW:         { wraps: true, iv_in_header: true },
  A192GCMKW:         { wraps: true, iv_in_header: true },
  A256GCMKW:         { wraps: true, iv_in_header: true },
  'PBES2-HS256+A128KW': { wraps: true, password: true },
  'PBES2-HS384+A192KW': { wraps: true, password: true },
  'PBES2-HS512+A256KW': { wraps: true, password: true }
};

// RFC 7518 section 5. CONTENT encryption. The key length is fixed by the
// algorithm, and a CEK of the wrong length is the most common way a
// hand-rolled decryptor fails.
var ENC_ALG = {
  'A128CBC-HS256': { key: 32, iv: 16, tag: 16, kind: 'cbc-hmac' },
  'A192CBC-HS384': { key: 48, iv: 16, tag: 24, kind: 'cbc-hmac' },
  'A256CBC-HS512': { key: 64, iv: 16, tag: 32, kind: 'cbc-hmac' },
  A128GCM:         { key: 16, iv: 12, tag: 16, kind: 'gcm' },
  A192GCM:         { key: 24, iv: 12, tag: 16, kind: 'gcm' },
  A256GCM:         { key: 32, iv: 12, tag: 16, kind: 'gcm' }
};

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

// `options.understood` - crit extensions the caller implements, see jose.js.
// `options.max_iterations` - the ceiling on p2c, see commons/limits.js.
function decode(input, options) {
  var opts = {
    understood:     understood_names(UNDERSTOOD, options, fail),
    max_iterations: options ? options.max_iterations : undefined
  };

  return split_serialization(input, to_bytes,
    function (text) { return decode_json(text, opts); },
    function (text) { return decode_compact(text, opts); });
}

//   BASE64URL(protected) . BASE64URL(encrypted_key) . BASE64URL(iv) .
//   BASE64URL(ciphertext) . BASE64URL(tag)
function decode_compact(text, opts) {
  var parts = text.split('.');

  if (parts.length !== 5) {
    fail('bad-compact',
      'a compact JWE has five dot-separated parts, found ' + parts.length +
      (parts.length === 3
        ? ' - three parts is a JWS, which is signed rather than encrypted'
        : ''));
  }

  return build({
    serialization:  'compact',
    protected_b64:  parts[0],
    header:         decode_protected(parts[0]),
    unprotected:    null,
    encrypted_key:  decode_part(parts[1], 'encrypted key', fail),
    iv:             decode_part(parts[2], 'iv', fail),
    ciphertext:     decode_part(parts[3], 'ciphertext', fail),
    tag:            decode_part(parts[4], 'tag', fail),
    aad_b64:        null
  }, opts);
}

function decode_json(text, opts) {
  var doc = JSON_.parse(text);

  var protected_b64 = JSON_.member(doc, 'protected');
  var iv = JSON_.member(doc, 'iv');
  var ciphertext = JSON_.member(doc, 'ciphertext');
  var tag = JSON_.member(doc, 'tag');

  if (typeof ciphertext !== 'string') {
    fail('bad-json-jwe', 'a JWE needs a ciphertext member');
  }

  var recipients = JSON_.member(doc, 'recipients');
  var aad_b64 = JSON_.member(doc, 'aad');

  var common = {
    protected_b64: typeof protected_b64 === 'string' ? protected_b64 : '',
    header:        typeof protected_b64 === 'string'
                     ? decode_protected(protected_b64) : {},
    unprotected:   JSON_.member(doc, 'unprotected') || null,
    iv:            typeof iv === 'string' ? decode_part(iv, 'iv', fail) : null,
    ciphertext:    decode_part(ciphertext, 'ciphertext', fail),
    tag:           typeof tag === 'string'
                     ? decode_part(tag, 'tag', fail) : null,
    aad_b64:       typeof aad_b64 === 'string' ? aad_b64 : null
  };

  if (Array.isArray(recipients)) {
    if (recipients.length === 0) {
      fail('bad-json-jwe', 'the recipients array is empty');
    }

    var out = [];
    var i;

    for (i = 0; i < recipients.length; i++) {
      var key = JSON_.member(recipients[i], 'encrypted_key');
      out.push(build(merge(common, {
        serialization: 'general',
        // A per-recipient header. NOT covered by the AEAD, same as a JWS
        // unprotected header - and kept separate for the same reason.
        per_recipient: JSON_.member(recipients[i], 'header') || null,
        encrypted_key: typeof key === 'string'
          ? decode_part(key, 'encrypted key', fail) : new Uint8Array(0),
        index: i
      }), opts));
    }

    return { serialization: 'general', recipients: out };
  }

  var flat_key = JSON_.member(doc, 'encrypted_key');

  return build(merge(common, {
    serialization: 'flattened',
    per_recipient: JSON_.member(doc, 'header') || null,
    encrypted_key: typeof flat_key === 'string'
      ? decode_part(flat_key, 'encrypted key', fail) : new Uint8Array(0)
  }), opts);
}

function decode_protected(b64) {
  if (b64 === '') {
    return {};
  }

  var header = JSON_.parse(decode_part(b64, 'protected header', fail));

  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    fail('bad-header', 'the protected header is not a JSON object');
  }

  return header;
}

function build(parts, opts) {
  var per = parts.per_recipient || null;

  // ⚠ THE JOSE HEADER IS THE UNION OF THREE, AND THEY MUST NOT OVERLAP.
  //
  // RFC 7516 7.2.1. The first version looked for alg in the protected header
  // and then the per-recipient one, and never in the SHARED unprotected
  // header - so a valid JSON JWE carrying alg there was refused as having no
  // alg at all. And nothing checked disjointness, so a kid in two places was
  // two answers.
  var all = union_headers([['protected', parts.header],
                           ['shared unprotected', parts.unprotected],
                           ['per-recipient', per]], fail);

  // alg may live in any of them - RFC 7516 section 7.2 permits it, because
  // different recipients wrap the same CEK differently. enc may NOT: it
  // describes the single ciphertext everybody shares.
  var alg = JSON_.member(all, 'alg');
  var enc = JSON_.member(parts.header, 'enc');

  if (per !== null && JSON_.has(per, 'enc')) {
    fail('enc-per-recipient',
      'enc appears in a per-recipient header. It describes the one ' +
      'ciphertext every recipient shares, so it belongs in the protected ' +
      'header where the AEAD covers it');
  }
  if (parts.unprotected !== null && JSON_.has(parts.unprotected, 'enc')) {
    fail('enc-unprotected',
      'enc appears in the unprotected header, where the AEAD does not cover ' +
      'it - a token could then name one content algorithm to a filter and ' +
      'another to a decryptor');
  }

  if (typeof alg !== 'string') {
    fail('missing-alg',
      'no alg: RFC 7516 section 4.1.1 requires it, in the protected or the ' +
      'per-recipient header');
  }
  if (typeof enc !== 'string') {
    fail('missing-enc',
      'no enc: a JWE names TWO algorithms - alg for the key, enc for the ' +
      'content - and this one has no enc');
  }

  var key_alg = KEY_ALG[alg];
  var enc_alg = ENC_ALG[enc];

  if (key_alg === undefined) {
    // Naming the confusion is worth doing: `alg: A256GCM` is somebody who
    // has put the content algorithm in the key field.
    var hint = ENC_ALG[alg] !== undefined
      ? ' - that is a CONTENT encryption algorithm, and belongs in enc'
      : '';
    fail('unknown-alg', 'unrecognised key management algorithm "' + alg +
      '"' + hint);
  }
  if (enc_alg === undefined) {
    var hint2 = KEY_ALG[enc] !== undefined
      ? ' - that is a KEY MANAGEMENT algorithm, and belongs in alg'
      : '';
    fail('unknown-enc', 'unrecognised content encryption algorithm "' + enc +
      '"' + hint2);
  }

  // ⚠ `dir` and plain `ECDH-ES` do not wrap anything, so encrypted_key MUST
  // be empty. One that is not is a token whose key comes from two places,
  // and a decryptor that used the wrong one would fail the tag - or, worse,
  // a decryptor that tried both would be an oracle.
  if (!key_alg.wraps && parts.encrypted_key.length !== 0) {
    fail('unexpected-encrypted-key',
      alg + ' supplies or derives the content key directly, so there is ' +
      'nothing to wrap - and yet this token carries ' +
      parts.encrypted_key.length + ' bytes of encrypted key');
  }
  if (key_alg.wraps && parts.encrypted_key.length === 0) {
    fail('missing-encrypted-key',
      alg + ' wraps the content key, and this token carries none');
  }

  // ⚠ Found by Wycheproof (#11, rejectsMissingCiphertext): an EMPTY
  // ciphertext parsed cleanly, because base64url of nothing is a valid empty
  // byte string and no length check applied.
  //
  // Every AEAD in RFC 7518 produces at least one ciphertext byte for at
  // least one plaintext byte, and a JWE encrypting nothing has no reason to
  // exist - but the real objection is that a decryptor handed an empty
  // ciphertext and a valid tag would authenticate the AAD alone and hand
  // back an empty plaintext, which reads as success.
  if (parts.ciphertext.length === 0) {
    fail('empty-ciphertext',
      'the ciphertext is empty. A decryptor would authenticate the AAD ' +
      'alone and return an empty plaintext, which reads as success');
  }

  // The same for the parts an AEAD cannot do without.
  if (parts.iv !== null && parts.iv.length === 0) {
    fail('missing-iv', jwe_missing('iv', enc));
  }
  if (parts.tag !== null && parts.tag.length === 0) {
    fail('missing-tag', jwe_missing('authentication tag', enc));
  }

  if (parts.iv !== null && parts.iv.length !== enc_alg.iv) {
    fail('bad-iv-length',
      enc + ' takes a ' + enc_alg.iv + '-byte IV, got ' + parts.iv.length);
  }
  if (parts.tag !== null && parts.tag.length !== enc_alg.tag) {
    fail('bad-tag-length',
      enc + ' produces a ' + enc_alg.tag + '-byte tag, got ' +
      parts.tag.length);
  }

  var crit = JSON_.member(parts.header, 'crit');
  if (crit !== undefined) {
    check_crit(crit, parts.header, CRIT_REGISTERED, opts.understood, fail);
  }

  // RFC 7516 4.1.3: zip changes what the plaintext IS, so it must be
  // integrity-protected - protected header only - and DEF is the one value.
  if (JSON_.has(all, 'zip')) {
    if (!JSON_.has(parts.header, 'zip')) {
      fail('zip-unprotected',
        'zip must be in the protected header, where the AEAD covers it');
    }
    if (JSON_.member(parts.header, 'zip') !== 'DEF') {
      fail('unknown-zip', 'the only registered zip value is "DEF"');
    }
  }

  var key_params = read_key_params(alg, key_alg, all, opts);

  return {
    serialization: parts.serialization,
    alg:           alg,
    enc:           enc,
    key_length:    enc_alg.key,
    kind:          enc_alg.kind,
    header:        parts.header,
    // Named so nobody merges them into the protected header. Neither is
    // covered by the AEAD.
    unprotected_unauthenticated: parts.unprotected,
    per_recipient_unauthenticated: per,
    zip:           JSON_.has(parts.header, 'zip') ? 'DEF' : null,
    key_params:    key_params,
    protected_b64: parts.protected_b64,
    aad_b64:       parts.aad_b64,
    encrypted_key: parts.encrypted_key,
    iv:            parts.iv,
    ciphertext:    parts.ciphertext,
    tag:           parts.tag,
    index:         parts.index === undefined ? 0 : parts.index
  };
}

// ⚠ THE PARAMETERS EACH KEY ALGORITHM NEEDS, CHECKED WHERE THEY ARE READ.
//
// These sat in the header unvalidated, and two of them are where real
// attacks live:
//
//   p2c   PBES2's iteration count, chosen by the sender and paid by the
//         recipient. Unbounded, it is a denial of service in one header
//         member (CVE-2022-36083 and relatives).
//   epk   ECDH-ES's ephemeral key. Missing, nothing can be derived; the
//         invalid-curve check on it is the caller's, with real arithmetic.
//
// Also: GCMKW's iv and tag, and PBES2's p2s - which is NOT the PBKDF2 salt.
// RFC 7518 4.8.1.1: the salt is UTF8(alg) || 0x00 || p2s, and handing a
// caller p2s as "the salt" derives a key that is valid and wrong.
function read_key_params(alg, key_alg, all, opts) {
  var out = { warnings: [] };

  if (key_alg.note !== undefined) {
    out.warnings.push(alg + ': ' + key_alg.note);
  }

  if (key_alg.ecdh) {
    var epk = JSON_.member(all, 'epk');

    if (!epk || typeof epk !== 'object' || Array.isArray(epk)) {
      fail('missing-epk', alg + ' needs the sender\'s ephemeral key in epk');
    }
    var kty = JSON_.member(epk, 'kty');
    if (kty !== 'EC' && kty !== 'OKP') {
      fail('bad-epk', 'epk must be an EC or OKP public key, got ' + kty);
    }
    if (JSON_.has(epk, 'd')) {
      fail('bad-epk', 'epk carries a private key (d)');
    }
    out.epk = epk;
    out.apu = optional_b64(all, 'apu');
    out.apv = optional_b64(all, 'apv');
  }

  if (key_alg.iv_in_header) {
    out.iv = decode_part(JSON_.member(all, 'iv'), 'iv header', fail);
    out.tag = decode_part(JSON_.member(all, 'tag'), 'tag header', fail);
    if (out.iv.length !== 12) {
      fail('bad-iv-length', alg + ' takes a 12-byte iv header parameter');
    }
    if (out.tag.length !== 16) {
      fail('bad-tag-length', alg + ' takes a 16-byte tag header parameter');
    }
  }

  if (key_alg.password) {
    var p2s = decode_part(JSON_.member(all, 'p2s'), 'p2s', fail);

    // RFC 7518 4.8.1.1: at least 8 octets.
    if (p2s.length < 8) {
      fail('bad-p2s', 'p2s must be at least 8 bytes, got ' + p2s.length);
    }

    out.p2s = p2s;
    out.p2c = check_iterations(JSON_.member(all, 'p2c'), opts, fail, 'p2c');
    out.salt = concat_bytes([new Uint8Array(encode_utf8(alg, fail)),
                             new Uint8Array([0]), p2s]);
    // The PBKDF2 PRF, named as everywhere else in this library;
    // algorithm.node_name(prf) is the hash node:crypto takes.
    out.prf = 'hmacWithSHA' + alg.substr(8, 3);
  }

  return out;
}

function optional_b64(h, name) {
  return JSON_.has(h, name)
    ? decode_part(JSON_.member(h, name), name, fail)
    : null;
}

function jwe_missing(what, enc) {
  return 'the ' + what + ' is empty, and ' + enc + ' cannot be decrypted ' +
    'without it';
}



// ---------------------------------------------------------------------------
// The AEAD input
// ---------------------------------------------------------------------------

// ⚠ THE ADDITIONAL AUTHENTICATED DATA, RFC 7516 section 5.1 step 14.
//
// The ASCII bytes of the base64url protected header AS IT APPEARS. Not the
// decoded header, not the JSON, and not a re-encoding of either - a producer
// whose JSON had different key order produces a different string, and a
// decryptor that rebuilt it would authenticate bytes that were never
// authenticated.
//
// With a JSON-serialization `aad` member the AAD is the protected header, a
// full stop, and the aad value - all still as the base64url strings.
function aad(jwe) {
  var text = jwe.protected_b64;

  if (jwe.aad_b64 !== null && jwe.aad_b64 !== undefined) {
    text = text + '.' + jwe.aad_b64;
  }

  return ascii(text, fail);
}

// Everything the caller needs to decrypt, with the two steps named. Returned
// together because doing one without the other is the failure: unwrapping the
// key and then decrypting with the wrong AAD fails the tag, and the message
// says nothing about which half was wrong.
function decryption_plan(jwe) {
  var key_alg = KEY_ALG[jwe.alg];

  return {
    // Step one: get the content encryption key.
    key_step: {
      alg:            jwe.alg,
      wrapped:        key_alg.wraps,
      encrypted_key:  jwe.encrypted_key,
      needs_password: key_alg.password === true,
      key_length:     jwe.key_length,
      // epk/apu/apv, GCMKW's iv and tag, or PBES2's salt and count - with
      // the salt already built from p2s the way RFC 7518 4.8.1.1 says.
      params:         jwe.key_params,
      warnings:       jwe.key_params.warnings,
      note: key_alg.wraps
        ? 'unwrap encrypted_key with ' + jwe.alg + ' to get a ' +
          jwe.key_length + '-byte content key'
        : jwe.alg === 'dir'
          ? 'the content key IS the shared key; there is nothing to unwrap'
          : 'derive the content key with ECDH-ES; there is nothing to unwrap'
    },
    // Step two: decrypt with it.
    content_step: {
      enc:        jwe.enc,
      kind:       jwe.kind,
      key_length: jwe.key_length,
      iv:         jwe.iv,
      ciphertext: jwe.ciphertext,
      tag:        jwe.tag,
      aad:        aad(jwe),
      note: 'the AAD is the ASCII of the base64url protected header AS IT ' +
            'APPEARS - rebuilding it from the parsed header authenticates ' +
            'bytes that were never authenticated'
    }
  };
}

// Whether a content key is the right length for the enc algorithm.
//
// The commonest way a hand-rolled decryptor fails: A128CBC-HS256 takes a
// 32-byte key, not 16 - the first half is the HMAC key and the second half
// is the AES key.
function check_key(jwe, cek) {
  var key = to_bytes(cek);

  if (key.length !== jwe.key_length) {
    var hint = jwe.kind === 'cbc-hmac'
      ? ' - a CBC-HMAC algorithm takes a DOUBLE-length key: the first half ' +
        'is the MAC key and the second half is the AES key'
      : '';
    fail('bad-key-length',
      jwe.enc + ' takes a ' + jwe.key_length + '-byte content key, got ' +
      key.length + hint);
  }

  return key;
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

// Serializes the header once and returns the AAD alongside, so the two can
// never disagree. A caller who built them separately could encrypt against
// one and emit the other, and the token would be self-consistent and
// undecryptable.
//
// `options.aad` is the JSON serialization's extra authenticated data. It
// changes the AAD the caller must use, so it is decided here, once, and
// carried in what prepare returns - a compact token cannot hold it.
function prepare(header, options) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    fail('bad-header', 'a header object is required');
  }

  var alg = JSON_.member(header, 'alg');
  var enc = JSON_.member(header, 'enc');

  if (alg !== undefined && typeof alg !== 'string') {
    fail('missing-alg', 'alg must be a string');
  }
  if (typeof enc !== 'string') {
    fail('missing-enc', 'the protected header needs an enc');
  }
  if (ENC_ALG[enc] === undefined) {
    fail('unknown-enc', 'unrecognised content encryption algorithm ' + enc);
  }

  var protected_b64 = encode_header(header, fail);
  var aad_b64 = null;

  if (options && options.aad !== undefined && options.aad !== null) {
    aad_b64 = B.encode('base64url', to_bytes(options.aad));
  }

  return {
    protected_b64: protected_b64,
    header:        header,
    alg:           alg === undefined ? null : alg,
    enc:           enc,
    key_length:    ENC_ALG[enc].key,
    iv_length:     ENC_ALG[enc].iv,
    tag_length:    ENC_ALG[enc].tag,
    aad_b64:       aad_b64,
    aad:           ascii(aad_b64 === null
                     ? protected_b64 : protected_b64 + '.' + aad_b64, fail)
  };
}

function compact(prepared, parts) {
  if (prepared.aad_b64 !== null && prepared.aad_b64 !== undefined) {
    fail('aad-in-compact',
      'a compact JWE has nowhere to carry extra AAD; use serialization: "json"');
  }
  if (prepared.alg === null) {
    fail('missing-alg', 'a compact JWE needs alg in the protected header');
  }

  var spec = check_content_parts(prepared, parts);
  var encrypted_key = check_wrapped(prepared.alg,
    parts.encrypted_key || new Uint8Array(0));

  return [
    prepared.protected_b64,
    B.encode('base64url', encrypted_key),
    B.encode('base64url', parts.iv),
    B.encode('base64url', to_bytes(parts.ciphertext)),
    B.encode('base64url', parts.tag)
  ].join('.');
}

// The JSON serializations, RFC 7516 7.2. With `parts.recipients` - a list
// of { encrypted_key, header } - it is the general form; without, the
// flattened form, with `parts.encrypted_key` and `parts.header`.
//
// `parts.unprotected` is the shared unprotected header. Every header is
// checked for disjointness against the others, the way decode checks it,
// so nothing this writes is something decode refuses.
function json(prepared, parts) {
  check_content_parts(prepared, parts);

  var out = {};

  if (prepared.protected_b64 !== '') {
    out.protected = prepared.protected_b64;
  }
  if (parts.unprotected) {
    if (JSON_.has(parts.unprotected, 'enc')) {
      fail('enc-unprotected', 'enc belongs in the protected header');
    }
    out.unprotected = parts.unprotected;
  }

  var recipients = Array.isArray(parts.recipients)
    ? parts.recipients
    : [{ encrypted_key: parts.encrypted_key, header: parts.header }];

  if (recipients.length === 0) {
    fail('no-recipients', 'json() needs at least one recipient');
  }

  var written = [];
  var i;

  for (i = 0; i < recipients.length; i++) {
    var rh = recipients[i].header || null;
    var all = union_headers([['protected', prepared.header],
                             ['shared unprotected', parts.unprotected || null],
                             ['per-recipient', rh]], fail);
    var alg = JSON_.member(all, 'alg');

    if (typeof alg !== 'string') {
      fail('missing-alg', 'recipient ' + i + ' has no alg in any header');
    }
    if (rh !== null && JSON_.has(rh, 'enc')) {
      fail('enc-per-recipient', 'enc belongs in the protected header');
    }

    var ek = check_wrapped(alg,
      recipients[i].encrypted_key || new Uint8Array(0));
    var entry = {};

    if (rh !== null) { entry.header = rh; }
    if (ek.length > 0) { entry.encrypted_key = B.encode('base64url', ek); }
    written.push(entry);
  }

  if (Array.isArray(parts.recipients)) {
    out.recipients = written;
  } else {
    if (written[0].header) { out.header = written[0].header; }
    if (written[0].encrypted_key) {
      out.encrypted_key = written[0].encrypted_key;
    }
  }

  if (prepared.aad_b64 !== null && prepared.aad_b64 !== undefined) {
    out.aad = prepared.aad_b64;
  }
  out.iv = B.encode('base64url', parts.iv);
  out.ciphertext = B.encode('base64url', to_bytes(parts.ciphertext));
  out.tag = B.encode('base64url', parts.tag);

  return out;
}

function check_content_parts(prepared, parts) {
  var spec = ENC_ALG[prepared.enc];

  if (!parts || typeof parts !== 'object') {
    fail('bad-input', 'the encrypted parts are required');
  }
  if (!parts.iv || parts.iv.length !== spec.iv) {
    fail('bad-iv-length',
      prepared.enc + ' takes a ' + spec.iv + '-byte IV');
  }
  if (!parts.tag || parts.tag.length !== spec.tag) {
    fail('bad-tag-length',
      prepared.enc + ' produces a ' + spec.tag + '-byte tag');
  }
  if (!parts.ciphertext || to_bytes(parts.ciphertext).length === 0) {
    fail('empty-ciphertext', 'the ciphertext is empty');
  }
  return spec;
}

function check_wrapped(alg, encrypted_key) {
  var key_alg = KEY_ALG[alg];

  if (key_alg === undefined) {
    fail('unknown-alg', 'unrecognised key management algorithm ' + alg);
  }

  var ek = to_bytes(encrypted_key);

  if (!key_alg.wraps && ek.length !== 0) {
    fail('unexpected-encrypted-key', alg + ' has nothing to wrap');
  }
  if (key_alg.wraps && ek.length === 0) {
    fail('missing-encrypted-key',
      alg + ' wraps the content key, and none was supplied');
  }
  return ek;
}

function merge(a, b) {
  var out = {};
  var k;
  for (k in a) {
    if (Object.prototype.hasOwnProperty.call(a, k)) { out[k] = a[k]; }
  }
  for (k in b) {
    if (Object.prototype.hasOwnProperty.call(b, k)) { out[k] = b[k]; }
  }
  return out;
}

// The second step, as in every builder here: prepare() gave the AAD and
// the sizes, the caller encrypted, and this writes the result.
//
//   var p   = jwe.prepare({ alg: 'A256KW', enc: 'A256GCM' });
//   // encrypt with p.aad; wrap the CEK
//   var tok = jwe.assemble(p, { encrypted_key, iv, ciphertext, tag });
//
// options.serialization: 'compact' (default) or 'json' - the JSON form is
// the one that can carry extra AAD, unprotected headers and several
// recipients.
function assemble(prepared, parts, options) {
  var form = options && options.serialization !== undefined
    ? options.serialization : 'compact';

  if (form === 'compact') {
    return compact(prepared, parts);
  }
  if (form === 'json') {
    return json(prepared, parts);
  }
  fail('bad-serialization', 'serialization is "compact" or "json"');
}

export {
  decode,
  aad,
  decryption_plan,
  check_key,
  prepare,
  assemble,
  KEY_ALG,
  ENC_ALG
};

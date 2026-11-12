// JSON Web Signature, RFC 7515.
//
// ⚠ FOUR WAYS TO GET THIS WRONG, AND THREE OF THEM LOOK LIKE SUCCESS.
//
// 1. `alg: none`. The canonical JOSE vulnerability: a token that names no
//    algorithm, and a verifier that reads its payload anyway. RFC 7515
//    section 6 defines the Unsecured JWS as a real thing, which is why it
//    cannot simply be refused at parse time - but nothing here hands over a
//    payload until the caller has said which algorithms they accept, and
//    "none" has to be on that list by name.
//
// 2. Merging the protected and unprotected headers. The unprotected header
//    is NOT COVERED BY THE SIGNATURE. A decoder that merges them into one
//    object lets an attacker set `kid`, or `jku`, or anything else, on a
//    token whose signature still verifies. They stay separate here, and the
//    unprotected half is named so that nobody reaches for it by accident.
//
// 3. Re-encoding the signing input. The bytes signed are the base64url
//    STRINGS AS THEY APPEAR IN THE DOCUMENT, not a re-encoding of the
//    decoded header and payload. A token whose producer wrote its JSON with
//    different whitespace, or its base64url with different padding, would
//    verify nowhere after a round trip through a decoder that rebuilt them.
//
// 4. Handling one serialization. There are three - compact, flattened JSON
//    and general JSON - and a verifier that reads only the first is one an
//    attacker can bypass by sending the second.
//
// This library decodes and reports. It does not verify: hashing the signing
// input and checking the signature is the caller's step with cryptographic-primitives.

import * as B from './base.js';
import * as JSON_ from './json.js';
import { split_serialization, decode_part, ascii, check_crit, understood_names, union_headers,
         encode_header } from './jose.js';
import * as JWK from './jwk.js';
import { make_fail_here } from './commons/fail.js';
import { to_bytes, concat_bytes } from './commons/bytes.js';
import { encode_utf8 } from './commons/encode_text.js';

var fail = make_fail_here('jws');

// The header names crit may not smuggle past a check - see jose.js.
//
// ⚠ ALL OF THEM, NOT FOUR. RFC 7515 4.1.11: crit MUST NOT name a header
// parameter defined by RFC 7515 or RFC 7518. The first list had alg, kid,
// jwk and crit, so a token with crit ["x5u"] passed a check meant to stop
// exactly that.
var CRIT_REGISTERED = ['alg', 'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t',
                       'x5t#S256', 'typ', 'cty', 'crit'];

// The extensions this module implements, and so may appear in crit.
//
//   b64   RFC 7797, the unencoded payload option
var UNDERSTOOD = ['b64'];

// Headers that name a key or certificate chain BY REFERENCE or BY VALUE,
// chosen by the signer. Verifying against any of them means trusting a key
// the attacker picked - see select_key.
//
// x5u was missing: it is jku for certificates, a URL to fetch a chain from,
// and the first version refused jku and let x5u through. x5c is NOT here -
// an embedded chain is safe once it is validated to a trust anchor, which is
// path validation and the caller's step, so it is reported rather than
// refused.
var EMBEDDED_KEY_HEADERS = ['jwk', 'jku', 'x5u'];

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

// RFC 7518 section 3.1. The signature LENGTH is fixed for the ECDSA
// algorithms, and checking it catches the most common confusion in this
// area: JOSE uses the raw r||s pair, where DER is 70-72 bytes for P-256.
var ALGORITHMS = {
  HS256: { kind: 'mac',   size: 32 },
  HS384: { kind: 'mac',   size: 48 },
  HS512: { kind: 'mac',   size: 64 },
  RS256: { kind: 'rsa',   size: null },
  RS384: { kind: 'rsa',   size: null },
  RS512: { kind: 'rsa',   size: null },
  PS256: { kind: 'rsa',   size: null },
  PS384: { kind: 'rsa',   size: null },
  PS512: { kind: 'rsa',   size: null },
  ES256: { kind: 'ecdsa', size: 64,  curve: 'P-256' },
  ES384: { kind: 'ecdsa', size: 96,  curve: 'P-384' },
  ES512: { kind: 'ecdsa', size: 132, curve: 'P-521' },
  ES256K: { kind: 'ecdsa', size: 64, curve: 'secp256k1' },
  EdDSA: { kind: 'eddsa', size: null },
  none:  { kind: 'none',  size: 0 }
};

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

// Reads any of the three serializations and reports which it found.
//
// The result deliberately does NOT have a `payload` property. Reaching the
// payload goes through payload(), which requires the caller to name the
// algorithms they accept - see the note at the top.
//
// `options.understood` lists crit extensions the CALLER implements - see
// jose.js. Without it, a token marking an unknown extension critical is
// refused, which is what RFC 7515 4.1.11 requires.
function decode(input, options) {
  var opts = { understood: understood_names(UNDERSTOOD, options, fail) };

  return split_serialization(input, to_bytes,
    function (text) { return decode_json(text, opts); },
    function (text) { return decode_compact(text, opts); });
}

//   BASE64URL(protected) . BASE64URL(payload) . BASE64URL(signature)
function decode_compact(text, opts) {
  var parts = text.split('.');

  if (parts.length !== 3) {
    fail('bad-compact',
      'a compact JWS has three dot-separated parts, found ' + parts.length +
      (parts.length === 5
        ? ' - five parts is a JWE, not a JWS'
        : ''));
  }

  var header = decode_protected(parts[0]);

  return build({
    serialization:  'compact',
    protected_b64:  parts[0],
    payload_b64:    parts[1],
    signature:      decode_part(parts[2], 'signature', fail),
    header:         header,
    unprotected:    null
  }, opts);
}

function decode_json(text, opts) {
  var doc = JSON_.parse(text);

  // The general form carries a `signatures` array; the flattened form has
  // the same members at the top level. RFC 7515 section 7.2.
  if (JSON_.has(doc, 'signatures')) {
    return decode_general(doc, opts);
  }
  return decode_flattened(doc, opts);
}

function decode_flattened(doc, opts) {
  var payload = JSON_.member(doc, 'payload');
  var protected_b64 = JSON_.member(doc, 'protected');
  var signature = JSON_.member(doc, 'signature');

  if (typeof signature !== 'string') {
    fail('bad-json-jws', 'a flattened JWS needs a signature member');
  }
  if (payload !== undefined && typeof payload !== 'string') {
    fail('bad-json-jws', 'payload must be a base64url string');
  }

  return build({
    serialization:  'flattened',
    protected_b64:  typeof protected_b64 === 'string' ? protected_b64 : '',
    payload_b64:    payload === undefined ? null : payload,
    signature:      decode_part(signature, 'signature', fail),
    header:         typeof protected_b64 === 'string'
                      ? decode_protected(protected_b64) : {},
    unprotected:    JSON_.member(doc, 'header') || null
  }, opts);
}

function decode_general(doc, opts) {
  var payload = JSON_.member(doc, 'payload');
  var sigs = JSON_.member(doc, 'signatures');

  if (!Array.isArray(sigs) || sigs.length === 0) {
    fail('bad-json-jws', 'the signatures array is empty');
  }

  var out = [];
  var i;

  for (i = 0; i < sigs.length; i++) {
    var s = sigs[i];
    var protected_b64 = JSON_.member(s, 'protected');
    var signature = JSON_.member(s, 'signature');

    if (typeof signature !== 'string') {
      fail('bad-json-jws',
        'signature ' + i + ' has no signature member');
    }

    out.push(build({
      serialization:  'general',
      protected_b64:  typeof protected_b64 === 'string' ? protected_b64 : '',
      payload_b64:    payload === undefined ? null : payload,
      signature:      decode_part(signature, 'signature', fail),
      header:         typeof protected_b64 === 'string'
                        ? decode_protected(protected_b64) : {},
      unprotected:    JSON_.member(s, 'header') || null,
      index:          i
    }, opts));
  }

  // RFC 7797 section 3: b64 MUST have the same value for every signature,
  // because there is one payload and it is either encoded or not. Two
  // signers disagreeing means one of them signed bytes that are not there.
  for (i = 1; i < out.length; i++) {
    if (out[i].b64 !== out[0].b64) {
      fail('b64-disagrees',
        'signature ' + i + ' says b64 ' + out[i].b64 + ' and signature 0 ' +
        'says ' + out[0].b64 + '; there is only one payload');
    }
  }

  // A general JWS with several signatures is ONE document with several
  // claims about it. Returning an array rather than picking one is the point:
  // a verifier must decide which signature it trusts, and picking the first
  // is a decision this library must not make on its behalf.
  return {
    serialization: 'general',
    signatures:    out,
    payload_b64:   payload === undefined ? null : payload
  };
}

function decode_protected(b64) {
  if (b64 === '') {
    // RFC 7515 allows an empty protected header when the unprotected one
    // carries everything - but then NOTHING is covered by the signature
    // except the payload, which is worth knowing.
    return {};
  }

  var bytes = decode_part(b64, 'protected header', fail);
  var header = JSON_.parse(bytes);

  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    fail('bad-header', 'the protected header is not a JSON object');
  }

  return header;
}

function build(parts, opts) {
  var alg = JSON_.member(parts.header, 'alg');

  if (parts.unprotected !== null &&
      JSON_.has(parts.unprotected, 'alg')) {
    // `alg` in the unprotected header is not covered by the signature, so a
    // token could name one algorithm to a filter and another to a verifier.
    // RFC 7515 section 4.1.1 makes alg mandatory and this rejects the
    // ambiguity rather than choosing a side.
    fail('alg-unprotected',
      'alg appears in the unprotected header, where it is not covered by ' +
      'the signature');
  }

  if (typeof alg !== 'string') {
    fail('missing-alg',
      'the protected header has no alg; RFC 7515 section 4.1.1 requires it');
  }

  // The two headers are one set split in two, and must not overlap - a kid
  // in both is two answers, and the unprotected one is the attacker's.
  union_headers([['protected', parts.header],
                 ['unprotected', parts.unprotected]], fail);

  var known = ALGORITHMS[alg];

  // ⚠ Found by Wycheproof (#35, rejectsMissingSignature): a token naming
  // RS256 with a ZERO-LENGTH signature. It parsed cleanly, because the
  // length check only fires for the fixed-size algorithms and RSA is not
  // one - so the token looked like an ordinary RS256 token carrying no
  // signature at all, which is `alg: none` wearing a different name.
  if (alg !== 'none' && parts.signature.length === 0) {
    fail('empty-signature',
      alg + ' names a signature algorithm, and this token carries no ' +
      'signature. Only alg none may have an empty signature, and that is ' +
      'an Unsecured JWS');
  }

  if (alg === 'none' && parts.signature.length !== 0) {
    fail('unexpected-signature',
      'alg none means Unsecured, and this token carries ' +
      parts.signature.length + ' signature bytes');
  }

  if (known !== undefined && known.size !== null &&
      parts.signature.length !== known.size) {
    var hint = parts.signature[0] === 0x30
      ? ' - this looks like DER, and JOSE uses the raw r||s pair'
      : '';
    fail('bad-signature-length',
      alg + ' signatures are ' + known.size + ' bytes, got ' +
      parts.signature.length + hint);
  }

  // RFC 7515 section 4.1.11: every name in `crit` MUST be understood, and
  // MUST be present in the protected header. A token that says "you must
  // understand X" and is processed by something that does not is a token
  // being processed against its own instructions.
  var crit = JSON_.member(parts.header, 'crit');

  if (crit !== undefined) {
    check_crit(crit, parts.header, CRIT_REGISTERED, opts.understood, fail);
  }

  var b64 = read_b64(parts.header, crit, fail);

  if (parts.unprotected !== null && JSON_.has(parts.unprotected, 'b64')) {
    fail('b64-unprotected',
      'b64 changes what the signature covers, so RFC 7797 section 3 puts it ' +
      'in the protected header only');
  }

  return {
    serialization:  parts.serialization,
    alg:            alg,
    header:         parts.header,
    // Named so nobody reaches for it thinking it is trustworthy. Merging it
    // into `header` is how a token gets its kid set by whoever relayed it.
    unprotected_unsigned: parts.unprotected,
    protected_b64:  parts.protected_b64,
    payload_b64:    parts.payload_b64,
    signature:      parts.signature,
    crit:           crit === undefined ? null : crit,
    // RFC 7797. When false, payload_b64 holds the payload segment AS IT
    // APPEARS - raw text, not base64url - and the signing input is built
    // over the raw bytes.
    b64:            b64,
    // Reported, not trusted: a chain the signer chose is safe only once the
    // caller has validated it to an anchor of their own.
    x5c:            JSON_.has(parts.header, 'x5c')
                      ? JSON_.member(parts.header, 'x5c') : null,
    index:          parts.index === undefined ? 0 : parts.index
  };
}

// ⚠ RFC 7797: b64 false means the payload is NOT base64url-encoded, and the
// signature covers the raw bytes. It changes the meaning of every other
// part, so the RFC requires it to be marked critical - a verifier that does
// not know b64 must refuse rather than check the signature over the wrong
// bytes and fail confusingly, or (worse) over bytes that happen to verify.
function read_b64(header, crit, fail_) {
  if (!JSON_.has(header, 'b64')) {
    return true;
  }

  var v = JSON_.member(header, 'b64');

  if (typeof v !== 'boolean') {
    fail_('bad-b64', 'b64 must be true or false, got ' + JSON.stringify(v));
  }
  if (v === false && (!Array.isArray(crit) || crit.indexOf('b64') === -1)) {
    fail_('b64-not-critical',
      'b64 false must be listed in crit (RFC 7797 section 6), or a verifier ' +
      'that does not implement it would check the wrong bytes');
  }
  return v;
}



// ---------------------------------------------------------------------------
// The signing input
// ---------------------------------------------------------------------------

// The bytes the signature covers: the base64url STRINGS AS THEY APPEAR,
// joined by a dot. Not a re-encoding of the decoded header and payload.
//
// This is the third failure listed at the top. A producer that wrote its
// header JSON with different key order, or different whitespace, produces a
// different base64url string - and a verifier that rebuilds it from the
// parsed object computes a hash over bytes that were never signed. The
// signature then fails on a perfectly good token.
//
// For a detached payload (RFC 7515 appendix F) the caller supplies it,
// because only they have it: base64url-encoded normally, and as the raw
// bytes (or text) when the token says b64 false.
//
// ⚠ With b64 false (RFC 7797) the signing input is ASCII(protected) || '.'
// || THE RAW PAYLOAD BYTES. Base64url-encoding them here would build a
// signing input the signer never signed.
function signing_input(jws, detached_payload) {
  var payload = jws.payload_b64;

  // A compact token's detached form is an EMPTY payload segment - which is
  // also how an empty payload looks. Supplying a payload says which it is.
  if (payload === '' && detached_payload !== undefined &&
      detached_payload !== null) {
    payload = null;
  }

  if (jws.b64 === false) {
    var raw;

    if (payload === null || payload === undefined) {
      if (detached_payload === undefined || detached_payload === null) {
        fail('detached-payload',
          'this JWS has a detached payload; supply the raw payload to ' +
          'build the signing input');
      }
      raw = typeof detached_payload === 'string'
        ? new Uint8Array(encode_utf8(detached_payload, fail))
        : to_bytes(detached_payload);
    } else {
      raw = new Uint8Array(encode_utf8(payload, fail));
    }

    return concat_bytes([ascii(jws.protected_b64 + '.', fail), raw]);
  }

  if (payload === null || payload === undefined) {
    if (detached_payload === undefined || detached_payload === null) {
      fail('detached-payload',
        'this JWS has a detached payload; supply it - as bytes, or as its ' +
        'base64url text - to build the signing input');
    }
    // Text is the payload segment as it would have travelled; bytes are the
    // payload itself, encoded here.
    payload = typeof detached_payload === 'string'
      ? detached_payload : B.encode('base64url', to_bytes(detached_payload));
  }

  return ascii(jws.protected_b64 + '.' + payload, fail);
}

// ---------------------------------------------------------------------------
// The payload
// ---------------------------------------------------------------------------

// ⚠ THE ONLY WAY TO THE PAYLOAD, AND IT REQUIRES A CHOICE.
//
// `accepted` is a list of algorithm names the caller is willing to trust. It
// is not optional and it has no default, because every default is wrong for
// somebody: a default of "everything" accepts `none`, and a default of "the
// usual ones" silently rejects a token an application legitimately uses.
//
// This does NOT verify the signature. It hands over bytes once the caller has
// said what they accept; hashing the signing input and checking the
// signature is their step with cryptographic-primitives, and read_verified below is the
// shape that makes the order obvious.
// `options.i_understand_embedded_key`: let a `jwk` in the PROTECTED header
// through - see embedded_key() below. Nothing else changes: jku, x5u, and a
// jwk in the unprotected header are refused still.
function payload(jws, accepted, options) {
  if (!Array.isArray(accepted) || accepted.length === 0) {
    fail('no-accepted-algorithms',
      'name the algorithms you accept: payload(jws, ["ES256"]). There is ' +
      'no default, because a default of "any" accepts alg none');
  }

  if (accepted.indexOf(jws.alg) === -1) {
    fail('algorithm-not-accepted',
      'this token is signed with ' + jws.alg + ', and the accepted list is ' +
      accepted.join(', ') +
      (jws.alg === 'none'
        ? ' - an Unsecured JWS carries no signature at all'
        : ''));
  }

  // ⚠ Found by Wycheproof (#32, rejectsAttackerProvidedEmbeddedJwk). A token
  // carrying `jwk` or `jku` names the key it wants verified against, and
  // reaching its payload means somebody is about to trust that.
  //
  // select_key already refused these, but a caller who never called
  // select_key - because the header also had a kid they looked up
  // themselves - reached the payload anyway. payload() is the gate, so the
  // check belongs here too.
  refuse_embedded_key(jws, embedded_allowed(options));

  if (jws.payload_b64 === null) {
    fail('detached-payload',
      'this JWS has a detached payload; the caller holds it');
  }

  if (jws.b64 === false) {
    return new Uint8Array(encode_utf8(jws.payload_b64, fail));
  }

  return decode_part(jws.payload_b64, 'payload', fail);
}

// jwk, jku, x5u - in EITHER header. The unprotected one is not covered by
// the signature at all, so a key named there is chosen by whoever relayed
// the token, not even by the signer.
function refuse_embedded_key(jws, protected_jwk_allowed) {
  var i;

  for (i = 0; i < EMBEDDED_KEY_HEADERS.length; i++) {
    var name = EMBEDDED_KEY_HEADERS[i];

    if ((JSON_.has(jws.header, name) && !(name === 'jwk' && protected_jwk_allowed === true)) ||
        (jws.unprotected_unsigned && JSON_.has(jws.unprotected_unsigned, name))) {
      fail('embedded-key',
        'this token carries its own key (' + name + '). Verifying against a ' +
        'key the signer chose is the attack this check exists for - supply ' +
        'your own set and look the key up by kid');
    }
  }
}

// Hands over the payload only after the caller has confirmed the signature.
//
// The library still does no cryptography: `verified` is a boolean the caller
// computed. What this adds is the ORDER - a caller writing
// read_verified(jws, algs, ok) cannot reach the payload before deciding
// whether ok is true, where a caller reading jws.payload directly can.
function read_verified(jws, accepted, verified, options) {
  if (verified !== true) {
    fail('not-verified',
      'the signature was not confirmed. Build the signing input, hash it, ' +
      'check the signature with cryptographic-primitives, and pass the result here');
  }
  return payload(jws, accepted, options);
}

// ⚠ A TOKEN SIGNED BY THE KEY IT CARRIES PROVES ONE THING: that its sender
// holds that key. Not who they are. Where that is the whole question, it is
// legitimate - RFC 8555 6.2: ACME's newAccount is signed by the account key
// it registers, and revokeCert may be signed by the certificate's own key -
// and the server then decides what the key is allowed to do. Anywhere else
// it is the attack refuse_embedded_key exists for (anyone can sign with a
// key of their own). Hence an option named for what the caller accepts,
// rather than a flag that sounds like a feature.
function embedded_allowed(options) {
  if (options === undefined || options === null) {
    return false;
  }
  if (typeof options !== 'object' ||
      (options.i_understand_embedded_key !== undefined &&
       options.i_understand_embedded_key !== true)) {
    fail('bad-options', 'the only option is i_understand_embedded_key: true');
  }
  return options.i_understand_embedded_key === true;
}

// The key a token carries in its protected `jwk` - the key to verify it
// with, once the caller has decided a self-signed token is what they want.
//
// Refused: a jwk only in the unprotected header (nothing signed it); a
// symmetric key or an HMAC algorithm (a MAC key sent in the clear is no
// secret); a key with private members (RFC 7515 4.1.3 says public; one with
// `d` is a leaked key); a key that does not suit alg, as select_key refuses.
function embedded_key(jws) {
  var key = JSON_.member(jws.header, 'jwk');

  if (key === undefined) {
    fail('no-embedded-key', jws.unprotected_unsigned &&
      JSON_.has(jws.unprotected_unsigned, 'jwk')
      ? 'the jwk is in the unprotected header, which the signature does not cover'
      : 'the protected header carries no jwk');
  }
  if (!key || typeof key !== 'object' || Array.isArray(key)) {
    fail('bad-jwk', 'the jwk header is a JSON object');
  }
  if (ALGORITHMS[jws.alg] !== undefined && ALGORITHMS[jws.alg].kind === 'mac') {
    fail('symmetric-embedded-key', jws.alg + ' is a MAC: a key sent with the ' +
      'token is a key everyone who saw the token has');
  }
  if (JWK.to_key(key).private !== false) {
    fail('private-embedded-key', 'the jwk carries private key members; ' +
      'a header key is public, and this one has leaked');
  }
  return check_key_suits(jws.alg, key);
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

// Builds the signing input for a token being created. The caller signs these
// bytes and passes the signature to compact(), flattened() or general().
//
// The header is serialized ONCE, here, and the resulting base64url string is
// what gets signed and what goes into the token - so the two can never
// disagree.
//
// A header with b64 false (RFC 7797) must also list b64 in crit, and the
// payload then travels as raw text: it must be valid UTF-8, because every
// serialization carries it inside a string.
function prepare(header, payload_bytes) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    fail('bad-header', 'a header object is required');
  }
  if (typeof JSON_.member(header, 'alg') !== 'string') {
    fail('missing-alg', 'the protected header needs an alg');
  }

  var crit = JSON_.member(header, 'crit');
  var b64 = read_b64(header, crit, fail);
  var protected_b64 = encode_header(header, fail);
  // A string is the payload's UTF-8, as the declaration has always said.
  var payload = typeof payload_bytes === 'string'
    ? new Uint8Array(encode_utf8(payload_bytes, fail)) : to_bytes(payload_bytes);
  var segment;
  var bytes;

  if (b64) {
    segment = B.encode('base64url', payload);
    bytes = ascii(protected_b64 + '.' + segment, fail);
  } else {
    segment = JSON_.utf8_to_string(payload);
    bytes = concat_bytes([ascii(protected_b64 + '.', fail), payload]);
  }

  return {
    protected_b64: protected_b64,
    payload_b64:   segment,
    header:        header,
    alg:           JSON_.member(header, 'alg'),
    b64:           b64,
    bytes:         bytes
  };
}

// `options.detached` leaves the payload out (RFC 7515 appendix F): the
// signature still covers it, and the recipient supplies it to signing_input.
function compact(prepared, signature, options) {
  check_signature(prepared.alg, signature);
  var detached = options && options.detached === true;

  // RFC 7797 section 5.2: an unencoded payload containing a period cannot
  // travel in the compact form, because the period IS the separator.
  if (prepared.b64 === false && !detached &&
      prepared.payload_b64.indexOf('.') !== -1) {
    fail('payload-contains-dot',
      'an unencoded payload with a "." cannot be carried in a compact JWS; ' +
      'detach it or use the JSON serialization');
  }

  return prepared.protected_b64 + '.' +
    (detached ? '' : prepared.payload_b64) + '.' +
    B.encode('base64url', to_bytes(signature));
}

function flattened(prepared, signature, unprotected, options) {
  check_signature(prepared.alg, signature);

  var out = {
    protected: prepared.protected_b64,
    payload:   prepared.payload_b64,
    signature: B.encode('base64url', to_bytes(signature))
  };

  if (options && options.detached === true) {
    delete out.payload;
  }

  if (unprotected) {
    out.header = checked_unprotected(prepared, unprotected);
  }

  return out;
}

// The general JSON serialization: one payload, several signatures. Each
// signer is { prepared, signature, header } where header is that signer's
// unprotected header.
//
// Every prepared value must carry the SAME payload segment - they were
// prepared over one payload or they were not, and a general JWS whose
// signers signed different payloads is several documents pretending to be
// one.
function general(signers, options) {
  if (!Array.isArray(signers) || signers.length === 0) {
    fail('no-signers', 'general_assemble() takes a non-empty list of signers');
  }

  var payload = signers[0].prepared.payload_b64;
  var b64 = signers[0].prepared.b64;
  var out = [];
  var i;

  for (i = 0; i < signers.length; i++) {
    var p = signers[i].prepared;

    if (p.payload_b64 !== payload || p.b64 !== b64) {
      fail('payload-mismatch',
        'signer ' + i + ' prepared a different payload from signer 0');
    }
    check_signature(p.alg, signers[i].signature);

    var entry = {
      protected: p.protected_b64,
      signature: B.encode('base64url', to_bytes(signers[i].signature))
    };
    if (signers[i].header) {
      entry.header = checked_unprotected(p, signers[i].header);
    }
    out.push(entry);
  }

  var doc = { signatures: out };
  if (!(options && options.detached === true)) {
    doc.payload = payload;
  }
  return doc;
}

function checked_unprotected(prepared, unprotected) {
  if (JSON_.has(unprotected, 'alg')) {
    fail('alg-unprotected',
      'alg belongs in the protected header, where the signature covers it');
  }
  if (JSON_.has(unprotected, 'b64')) {
    fail('b64-unprotected', 'b64 belongs in the protected header');
  }
  union_headers([['protected', prepared.header],
                 ['unprotected', unprotected]], fail);
  return unprotected;
}

function check_signature(alg, signature) {
  if (!(signature instanceof Uint8Array) &&
      !(typeof Buffer !== 'undefined' && Buffer.isBuffer(signature))) {
    fail('bad-signature', 'a signature byte string is required');
  }

  var known = ALGORITHMS[alg];

  if (known !== undefined && known.size !== null &&
      signature.length !== known.size) {
    var hint = signature[0] === 0x30
      ? ' - this looks like DER, and JOSE uses the raw r||s pair. Convert ' +
        'it before signing a JWS'
      : '';
    fail('bad-signature-length',
      alg + ' signatures are ' + known.size + ' bytes, got ' +
      signature.length + hint);
  }
}


// ---------------------------------------------------------------------------
// Key selection
// ---------------------------------------------------------------------------

// Finds the key a token names, in a JWK Set the caller supplied.
//
// ⚠ THE SET IS THE CALLER'S, NOT THE TOKEN'S. A token can carry `jwk` or
// `jku` in its header - a key, or a URL to fetch one from - and honouring
// either means verifying a signature against a key the signer chose. That is
// the whole attack, and this function takes a set as an argument for exactly
// that reason.
function select_key(jws, jwks) {
  var kid = JSON_.member(jws.header, 'kid');

  refuse_embedded_key(jws, false);

  var keys = JWK.set_from_json(jwks);
  var i;

  if (typeof kid !== 'string') {
    // No kid: legitimate when a set holds one key, and ambiguous otherwise.
    //
    // ⚠ AND THE ONE KEY STILL HAS TO SUIT THE ALGORITHM. The first version
    // returned it unchecked, so an HS256 token against a set holding one
    // RSA public key got that key back - the algorithm-confusion attack the
    // kid path below already refused. The check belongs to the key, not to
    // how it was found.
    if (keys.length === 1) {
      return check_key_suits(jws.alg, keys[0]);
    }
    fail('no-kid',
      'the token names no kid and the set holds ' + keys.length +
      ' keys, so there is no single answer');
  }

  for (i = 0; i < keys.length; i++) {
    if (JSON_.member(keys[i], 'kid') === kid) {
      return check_key_suits(jws.alg, keys[i]);
    }
  }

  return null;
}

// ⚠ Found by Wycheproof (#31, symmetry confusion): a token naming HS256 with
// a kid that identifies an EC key.
//
// The attack is that HMAC takes an arbitrary byte string as its key, so an
// attacker who knows a PUBLIC EC key can compute a valid HS256 tag over
// anything by using that public key's bytes as the secret. The token then
// verifies against a key everybody has.
//
// The defence is that an algorithm and a key type must agree, and it belongs
// here because this is where the two meet.
function check_key_suits(alg, key) {
  var kty = JSON_.member(key, 'kty');
  var known = ALGORITHMS[alg];

  // An algorithm this module does not know is one whose key type it cannot
  // check, and handing over a key anyway is the unchecked path again.
  if (known === undefined) {
    fail('unknown-algorithm',
      'cannot say which key suits "' + alg + '"; look the key up yourself ' +
      'if you implement it');
  }
  if (known.kind === 'none') {
    fail('no-key-for-none',
      'alg none has no signature, so there is no key to select');
  }

  var wanted = {
    mac:   'oct',
    rsa:   'RSA',
    ecdsa: 'EC',
    eddsa: 'OKP'
  }[known.kind];

  if (wanted !== undefined && kty !== wanted) {
    fail('key-type-mismatch',
      alg + ' takes a ' + wanted + ' key, and this one is ' + kty +
      (known.kind === 'mac'
        ? ' - an HMAC key is an arbitrary byte string, so a PUBLIC key used ' +
          'as one lets anybody who has it forge a valid tag'
        : ''));
  }

  // ES256 is P-256 and nothing else, which JWK already checks for a key on
  // its own. Here it catches a token asking for the wrong pairing.
  if (known.curve !== undefined &&
      JSON_.member(key, 'crv') !== known.curve) {
    fail('key-curve-mismatch',
      alg + ' requires crv ' + known.curve + ', and this key is on ' +
      JSON_.member(key, 'crv'));
  }

  // ⚠ Found by Wycheproof (#353 rejectWrongUse, #355 rejectWrongKeyOps): a
  // key marked for ENCRYPTION, used to verify a signature.
  //
  // RFC 7517 sections 4.2 and 4.3 say what these members mean, and jwk.js
  // already refuses a key whose `use` and `key_ops` contradict EACH OTHER.
  // What it cannot check is whether they permit THIS operation - only a
  // caller who knows what they are about to do can, and this is that place.
  var use = JSON_.member(key, 'use');

  if (use !== undefined && use !== null && use !== 'sig') {
    fail('key-not-for-signing',
      'this key is marked use "' + use + '", and verifying a signature is ' +
      'not that');
  }

  var ops = JSON_.member(key, 'key_ops');

  if (Array.isArray(ops) &&
      ops.indexOf('verify') === -1 && ops.indexOf('sign') === -1) {
    fail('key-not-for-signing',
      'key_ops is [' + ops.join(', ') + '], and neither permits verifying');
  }

  return key;
}

// The second step, as in every builder here: prepare() gave the bytes to
// sign, and this puts the signature back.
//
//   var p     = jws.prepare({ alg: 'ES256' }, payload);
//   var token = jws.assemble(p, sign(p.bytes));                 // compact
//   var doc   = jws.assemble(p, sig, { serialization: 'flattened',
//                                      header: { kid: 'k1' } });
//
// options: serialization 'compact' (default) or 'flattened'; `header`, the
// unprotected header (flattened only - compact has nowhere to put one);
// `detached`, to leave the payload out.
function assemble(prepared, signature, options) {
  var opts = options || {};
  var form = opts.serialization === undefined ? 'compact' : opts.serialization;

  if (form === 'compact') {
    if (opts.header !== undefined) {
      fail('header-in-compact',
        'a compact JWS has no unprotected header - use serialization: ' +
        '"flattened", or put it in the protected header');
    }
    return compact(prepared, signature, opts);
  }
  if (form === 'flattened') {
    return flattened(prepared, signature, opts.header, opts);
  }
  fail('bad-serialization', 'serialization is "compact" or "flattened"; ' +
    'several signers is general_assemble()');
}

// The general JSON serialization: several signers over one payload, each
// prepared with jws.prepare from the same payload.
//
//   jws.general_assemble([{ prepared, signature, header }, ...], options)
function general_assemble(signers, options) {
  return general(signers, options);
}

export {
  decode,
  signing_input,
  payload,
  read_verified,
  prepare,
  assemble,
  general_assemble,
  select_key,
  embedded_key,
  ALGORITHMS
};

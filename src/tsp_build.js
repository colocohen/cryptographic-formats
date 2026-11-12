// Building RFC 3161 timestamps: the request (the client side) and the
// response (the TSA side). tsp.js reads both.
//
// A timestamp token is a CMS
// SignedData whose content is a TSTInfo, so this module writes the TSTInfo
// and the response around the token, and cms_build signs - the same three
// steps as any CMS signature, with two things RFC 3161 adds:
//
//   var tst = tsp_build.tst_info({ policy, imprint, serial, gen_time, ... });
//   var p   = cms_build.prepare({ content: tst, content_type: 'tstInfo',
//               certificate: tsa, digest: 'sha256',
//               signature_algorithm: 'ecdsaWithSHA256',
//               content_digest: sha256(tst),
//               attributes: [tsp_build.signing_certificate_v2(
//                 sha256(tsa.der))] });
//   var der = tsp_build.response(cms_build.assemble(p, sign(p.bytes)));
//
// ⚠ THE TWO THINGS RFC 3161 ADDS, AND WHY EACH IS NOT OPTIONAL.
//
//   signingCertificateV2   2.4.2: the TSA certificate, by hash, among the
//                          SIGNED attributes. Without it, which certificate
//                          signed the token is up to whoever assembles the
//                          bag. signing_certificate_v2() writes the value.
//   the nonce              2.4.2: when the request carries one, the TSTInfo
//                          MUST echo it - or the response can be replayed
//                          to a different request.

import * as W from './der_writer.js';
import * as OID from './oid.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, int_bytes } from './commons/bytes.js';

import { status_info_to_der, general_name_to_der } from './pkix.js';

var fail = make_fail_here('tsp');

var STATUS = {
  granted: 0, grantedWithMods: 1, rejection: 2, waiting: 3,
  revocationWarning: 4, revocationNotification: 5
};

// RFC 3161 2.4.2, the failInfo bit positions. DELIBERATELY its own table
// rather than tsp.js's reading table turned round - see commons/README.
var FAILURE_BITS = {
  badAlg: 0, badRequest: 2, badDataFormat: 5, timeNotAvailable: 14,
  unacceptedPolicy: 15, unacceptedExtension: 16, addInfoNotAvailable: 17,
  systemFailure: 25
};

// ---------------------------------------------------------------------------

//   TSTInfo ::= SEQUENCE {
//      version         INTEGER { v1(1) },
//      policy          TSAPolicyId,
//      messageImprint  MessageImprint,
//      serialNumber    INTEGER,
//      genTime         GeneralizedTime,
//      accuracy        Accuracy OPTIONAL,
//      ordering        BOOLEAN DEFAULT FALSE,
//      nonce           INTEGER OPTIONAL,
//      tsa         [0] GeneralName OPTIONAL,
//      extensions  [1] IMPLICIT Extensions OPTIONAL }
//
// parts:
//   policy      dotted OID - the TSA's policy, or the one the request asked
//               for if the TSA honours it
//   imprint     { algorithm, hash } - from the request, unchanged
//               (tsp.request_from_der returns exactly this shape)
//   serial      bytes. Unique per TSA, up to 160 bits (RFC 3161 2.4.2)
//   gen_time    Date. Written with milliseconds when `millis` is true;
//               the fraction is in DER's one form either way
//   accuracy    { seconds, millis, micros } - optional
//   ordering    true only if the TSA can order every token it issues
//   nonce       bytes, from the request - REQUIRED when the request had one
//   tsa         a GeneralName, { dns: ... } or { directory: ... }
function tst_info(parts) {
  if (!parts || typeof parts !== 'object') {
    fail('bad-input', 'tst_info takes an object');
  }
  if (typeof parts.policy !== 'string' || !/^\d+(\.\d+)+$/.test(parts.policy)) {
    fail('bad-input', 'policy is a dotted OID');
  }
  if (!parts.imprint || typeof parts.imprint.algorithm !== 'string' ||
      !parts.imprint.hash) {
    fail('bad-input', 'imprint is { algorithm, hash }, as the request sent it');
  }

  var size = OID.digest_size(parts.imprint.algorithm);
  var hash = to_bytes(parts.imprint.hash);

  if (size !== null && hash.length !== size) {
    fail('bad-imprint', parts.imprint.algorithm + ' produces ' + size +
      ' bytes and the imprint is ' + hash.length);
  }

  var serial = to_bytes(parts.serial || new Uint8Array(0));

  if (serial.length === 0 || serial.length > 20) {
    fail('bad-serial', 'the serial is 1 to 20 bytes (160 bits), RFC 3161');
  }
  if (!(parts.gen_time instanceof Date)) {
    fail('bad-input', 'gen_time is a Date');
  }

  var fields = [
    W.integer([1]),
    W.oid(OID.from_string(parts.policy)),
    W.sequence([
      W.sequence([W.oid(OID.by_name(parts.imprint.algorithm)), W.null()]),
      W.octet_string(hash)
    ]),
    W.unsigned(serial),
    W.generalized_time(parts.gen_time, { millis: parts.millis === true })
  ];

  if (parts.accuracy) {
    var a = parts.accuracy;
    var acc = [];
    check_range(a.millis, 1, 999, 'millis');
    check_range(a.micros, 1, 999, 'micros');
    if (a.seconds) { acc.push(W.unsigned(int_bytes(a.seconds))); }
    if (a.millis) { acc.push(W.implicit(0, W.unsigned(int_bytes(a.millis)))); }
    if (a.micros) { acc.push(W.implicit(1, W.unsigned(int_bytes(a.micros)))); }
    if (acc.length === 0) {
      fail('bad-accuracy', 'an accuracy of zero says nothing; omit it');
    }
    fields.push(W.sequence(acc));
  }

  // DEFAULT FALSE: written only when true.
  if (parts.ordering === true) {
    fields.push(W.boolean(true));
  }

  if (parts.nonce !== undefined && parts.nonce !== null) {
    fields.push(W.unsigned(to_bytes(parts.nonce)));
  }

  if (parts.tsa) {
    // [0] EXPLICIT - GeneralName is a CHOICE, which cannot be implicit.
    fields.push(W.explicit(0, general_name_to_der(parts.tsa)));
  }

  return W.to_bytes(W.sequence(fields));
}

function check_range(v, lo, hi, name) {
  if (v !== undefined && v !== null && v !== 0 &&
      (typeof v !== 'number' || v < lo || v > hi || v % 1 !== 0)) {
    fail('bad-accuracy', name + ' is ' + lo + ' to ' + hi);
  }
}

// The VALUE of a signingCertificateV2 attribute (RFC 5035), for
// cms_build's `attributes: [{ type: 'signingCertificateV2', value }]`.
//
//   SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }
//   ESSCertIDv2 ::= SEQUENCE {
//      hashAlgorithm  AlgorithmIdentifier DEFAULT {algorithm id-sha256},
//      certHash       OCTET STRING, ... }
//
// `cert_hash` is the hash of the TSA certificate's DER, with `hash`
// (default sha256, which DER then omits).
function signing_certificate_v2(cert_hash, hash) {
  var h = hash === undefined ? 'sha256' : hash;
  var bytes = to_bytes(cert_hash);
  var size = OID.digest_size(h);

  if (size === null || bytes.length !== size) {
    fail('bad-cert-hash', 'the certificate hash must be a ' + h + ' digest');
  }

  var id = [];
  if (h !== 'sha256') {
    id.push(W.sequence([W.oid(OID.by_name(h))]));
  }
  id.push(W.octet_string(bytes));

  return {
    type:  'signingCertificateV2',
    value: W.to_bytes(W.sequence([W.sequence([W.sequence(id)])]))
  };
}

//   TimeStampResp ::= SEQUENCE {
//      status          PKIStatusInfo,
//      timeStampToken  TimeStampToken OPTIONAL }
//
//   PKIStatusInfo ::= SEQUENCE {
//      status        PKIStatus,
//      statusString  PKIFreeText OPTIONAL,
//      failInfo      PKIFailureInfo OPTIONAL }
//
// response(token) for a grant; response(null, { status: 'rejection',
// failure: ['badAlg'], text: 'why' }) for a refusal - which carries no token,
// because a rejection with a token is a message contradicting itself.
function response(token, options) {
  var opts = options || {};
  var status = opts.status || (token ? 'granted' : 'rejection');

  if (STATUS[status] === undefined) {
    fail('bad-status', 'unknown status ' + status);
  }

  var granted = status === 'granted' || status === 'grantedWithMods';

  if (granted && !token) {
    fail('bad-input', status + ' needs the token');
  }
  if (!granted && token) {
    fail('bad-input', 'a ' + status + ' carries no token');
  }

  var bits = (opts.failure || []).map(function (name) {
    if (FAILURE_BITS[name] === undefined) {
      fail('unknown-failure', 'unknown failInfo "' + name + '"');
    }
    return FAILURE_BITS[name];
  });

  var out = [status_info_to_der(STATUS[status], opts.text, bits)];
  if (token) {
    out.push(to_bytes(token));
  }

  return W.to_bytes(W.sequence(out));
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

// A TimeStampReq, from a hash the CALLER computed - the client side, here
// with the rest of what this module writes; tsp.request_from_der reads it.
// Saying which bytes to
// hash is the useful part: the imprint is over the DATA, not over any
// structure around it.
//
// The nonce is not generated here, for the same reason nothing else in this
// library generates randomness: a value that looks random and is not is worse
// than none, and only the caller knows what source they trust.
function request(parts) {
  if (!parts || !parts.hash) {
    fail('bad-input',
      'a message imprint is required: hash the DATA with the algorithm you ' +
      'name, and pass the digest');
  }

  var alg = parts.algorithm || 'sha256';
  var size = OID.checked_digest_size(alg, fail);

  if (parts.hash.length !== size) {
    fail('bad-imprint-length',
      alg + ' produces ' + size + ' bytes, and this imprint is ' +
      parts.hash.length + '. A timestamp over the wrong digest is a valid ' +
      'timestamp over something else.');
  }

  var fields = [
    W.integer([0x01]),
    W.sequence([
      W.sequence([W.oid(OID.by_name(alg)), W.null()]),
      W.octet_string(parts.hash)
    ])
  ];

  if (parts.policy) {
    fields.push(W.oid(OID.from_string(parts.policy)));
  }

  if (parts.nonce) {
    // The nonce ties the response to this request. RFC 3161 2.4.1 makes the
    // TSA echo it, and a caller who does not check it can be handed a
    // captured response from any time in the past.
    fields.push(W.integer(to_array_bytes(parts.nonce)));
  }

  // certReq DEFAULT FALSE, so TRUE is written and FALSE is omitted.
  if (parts.cert_req) {
    fields.push(W.boolean(true));
  }

  return W.to_bytes(W.sequence(fields));
}

function to_array_bytes(v) {
  if (v instanceof Uint8Array) {
    return Array.prototype.slice.call(v);
  }
  if (typeof v === 'number') {
    var b = int_bytes(v);
    // An INTEGER whose top bit is set needs a leading zero, or it reads as
    // negative - and a nonce that comes back different is a nonce that never
    // matches.
    if (b[0] & 0x80) {
      return [0].concat(b);
    }
    return b;
  }
  return Array.prototype.slice.call(to_bytes(v));
}

export {
  request,
  tst_info,
  signing_certificate_v2,
  response,
  STATUS,
  FAILURE_BITS
};

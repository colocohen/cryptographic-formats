// Building OCSP - RFC 6960. Requests (the client side, request() and
// cert_id_inputs()) and responses (the responder side). ocsp.js reads both.
// Same two-call shape as every builder here, because this library does not
// sign:
//
//   var tbs = ocsp_build.prepare({ responder, produced_at, responses, ... });
//   var sig = sign(tbs.signature_algorithm, responder_key, tbs.bytes);
//   var der = ocsp_build.assemble(tbs, sig);
//
// ⚠ THREE THINGS A RESPONDER GETS WRONG THAT A CLIENT CANNOT DETECT.
//
// 1. Answering about the wrong certificate. Each SingleResponse names its
//    certificate by CertID - hashes of the issuer's name and key plus the
//    serial - and it must be the CertID the client sent, byte for byte,
//    hash algorithm included. Build it from the request (`cert_id` as
//    ocsp.request_from_der returned it), not from your own idea of it.
//
// 2. `unknown` for a certificate you issued. RFC 6960 2.2: unknown means
//    "I do not know about this certificate". A responder that says unknown
//    for its own issuance is failing open in some clients.
//
// 3. Echoing the nonce. A request with a nonce expects it back, and a
//    response without it is replayable. `nonce` is written as the request
//    sent it.
//
// And error responses - tryLater, internalError and the rest - are UNSIGNED
// and carry no certificate status at all: error_response() writes one.

import * as W from './der_writer.js';
import * as OID from './oid.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes } from './commons/bytes.js';

import './pkix.js';
import { algorithm_to_der, assemble_signed } from './pkix.js';
import { x509_name_to_der as name_to_der, REASONS } from './pkix.js';

var fail = make_fail_here('ocsp');

// RFC 6960 4.2.1. 4 is unassigned.
var STATUS = {
  successful:       0,
  malformedRequest: 1,
  internalError:    2,
  tryLater:         3,
  sigRequired:      5,
  unauthorized:     6
};

// ---------------------------------------------------------------------------

//   ResponseData ::= SEQUENCE {
//      version              [0] EXPLICIT Version DEFAULT v1,
//      responderID              ResponderID,
//      producedAt               GeneralizedTime,
//      responses                SEQUENCE OF SingleResponse,
//      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
//
// parts:
//   responder     { name: <Name> } or { key_hash: <SHA-1 of the responder
//                 key's BIT STRING value - x509_build.key_id_input> }
//   produced_at   Date
//   responses     [{ cert_id, status: 'good'|'revoked'|'unknown',
//                    revoked_at, reason, this_update, next_update }]
//   nonce         the request's nonce bytes, to echo
//   algorithm     the signature algorithm, as for every builder
//   certificates  DER certificates to include - the delegated responder
//                 certificate, when the responder is not the CA itself
function prepare(parts) {
  if (!parts || typeof parts !== 'object') {
    fail('bad-input', 'prepare takes an object describing the response');
  }
  if (!parts.signature_algorithm) {
    fail('bad-input', 'prepare needs { signature_algorithm }');
  }
  if (!(parts.produced_at instanceof Date)) {
    fail('bad-input', 'prepare needs { produced_at: Date }');
  }
  if (!Array.isArray(parts.responses) || parts.responses.length === 0) {
    fail('bad-input', 'a successful response answers at least one CertID');
  }

  var fields = [];

  // DEFAULT v1 is omitted, as DER requires.
  fields.push(responder_id(parts.responder));
  fields.push(W.generalized_time(parts.produced_at));
  fields.push(W.sequence(parts.responses.map(single_response)));

  if (parts.nonce !== undefined && parts.nonce !== null) {
    fields.push(W.explicit(1, W.sequence([
      W.sequence([
        W.oid(OID.by_name('ocsp_nonce')),
        W.octet_string(W.octet_string(to_bytes(parts.nonce)))
      ])
    ])));
  }

  // Validated now, so a bad name fails at build() and not at assemble().
  algorithm_to_der(parts.signature_algorithm);

  return {
    bytes:        W.to_bytes(W.sequence(fields)),
    signature_algorithm:    parts.signature_algorithm,
    certificates: parts.certificates || []
  };
}

//   ResponderID ::= CHOICE {
//      byName   [1] Name,
//      byKey    [2] KeyHash }
//
// EXPLICIT - the RFC 6960 module is written with explicit tags.
function responder_id(r) {
  if (!r || typeof r !== 'object') {
    fail('bad-input', 'responder is { name } or { key_hash }');
  }
  if (r.key_hash !== undefined) {
    var kh = to_bytes(r.key_hash);
    if (kh.length !== 20) {
      fail('bad-key-hash',
        'byKey is the SHA-1 of the responder key, 20 bytes - RFC 6960 4.2.1');
    }
    return W.explicit(2, W.octet_string(kh));
  }
  if (r.name !== undefined) {
    return W.explicit(1, name_to_der(r.name));
  }
  fail('bad-input', 'responder is { name } or { key_hash }');
}

//   SingleResponse ::= SEQUENCE {
//      certID                       CertID,
//      certStatus                   CertStatus,
//      thisUpdate                   GeneralizedTime,
//      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
//      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
//
//   CertStatus ::= CHOICE {
//      good        [0]     IMPLICIT NULL,
//      revoked     [1]     IMPLICIT RevokedInfo,
//      unknown     [2]     IMPLICIT UnknownInfo }
function single_response(s, i) {
  if (!s || !s.cert_id) {
    fail('bad-input', 'response ' + i + ' needs the cert_id it answers');
  }
  if (!(s.this_update instanceof Date)) {
    fail('bad-input', 'response ' + i + ' needs this_update');
  }

  var status;

  if (s.status === 'good') {
    status = W.implicit(0, W.null());
  } else if (s.status === 'unknown') {
    status = W.implicit(2, W.null());
  } else if (s.status === 'revoked') {
    if (!(s.revoked_at instanceof Date)) {
      fail('bad-input', 'a revoked response needs revoked_at');
    }

    var info = [W.generalized_time(s.revoked_at)];

    if (s.reason !== undefined && s.reason !== null) {
      if (REASONS[s.reason] === undefined) {
        fail('unknown-reason', 'unrecognised reason "' + s.reason + '"');
      }
      info.push(W.explicit(0, W.enumerated([REASONS[s.reason]])));
    }

    status = W.implicit(1, W.sequence(info));
  } else {
    fail('bad-status',
      'status is good, revoked or unknown - and unknown means "not mine"');
  }

  if (s.next_update !== undefined && s.next_update !== null &&
      !(s.next_update instanceof Date && s.next_update > s.this_update)) {
    fail('bad-input', 'next_update must be a Date after this_update');
  }

  var fields = [cert_id_to_der(s.cert_id), status,
                W.generalized_time(s.this_update)];

  if (s.next_update) {
    fields.push(W.explicit(0, W.generalized_time(s.next_update)));
  }

  return W.sequence(fields);
}

// The CertID exactly as the request carried it: what ocsp.request_from_der
// returns - { hash, name_hash, key_hash, serial } - or the raw DER, which is
// echoed untouched and is the safest way to answer about precisely what was
// asked.
function cert_id_to_der(id) {
  if (id instanceof Uint8Array) {
    return id;
  }
  if (id.der instanceof Uint8Array) {
    return id.der;
  }
  if (!id.name_hash || !id.key_hash || !id.serial) {
    fail('bad-input',
      'a CertID needs name_hash, key_hash and serial - compute the hashes ' +
      'yourself: name_hash over the issuer\'s DER Name, key_hash over the ' +
      'BIT STRING CONTENT of its SPKI, not the whole SPKI. cert_id_inputs() ' +
      'returns both');
  }
  return W.sequence([
    W.sequence([W.oid(OID.by_name(id.hash || 'sha1')), W.null()]),
    W.octet_string(to_bytes(id.name_hash)),
    W.octet_string(to_bytes(id.key_hash)),
    W.integer(to_bytes(id.serial))
  ]);
}

// ---------------------------------------------------------------------------

//   OCSPResponse ::= SEQUENCE {
//      responseStatus         OCSPResponseStatus,
//      responseBytes      [0] EXPLICIT ResponseBytes OPTIONAL }
//
//   ResponseBytes ::= SEQUENCE {
//      responseType   OBJECT IDENTIFIER,     -- id-pkix-ocsp-basic
//      response       OCTET STRING }         -- BasicOCSPResponse
//
//   BasicOCSPResponse ::= SEQUENCE {
//      tbsResponseData      ResponseData,
//      signatureAlgorithm   AlgorithmIdentifier,
//      signature            BIT STRING,
//      certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
function assemble(tbs, signature) {
  var signed = assemble_signed(tbs, signature, fail);

  // assemble_signed writes SEQUENCE { tbs, alg, sig }. BasicOCSPResponse
  // adds certs inside the same SEQUENCE, so it is opened and extended
  // rather than wrapped - the signed bytes are unchanged either way.
  var basic = signed;

  if (tbs.certificates.length > 0) {
    var body = strip_sequence(signed);
    basic = W.to_bytes(W.sequence([
      body,
      W.explicit(0, W.sequence(tbs.certificates.map(to_bytes)))
    ]));
  }

  return W.to_bytes(W.sequence([
    W.enumerated([STATUS.successful]),
    W.explicit(0, W.sequence([
      W.oid(OID.by_name('ocsp_basic')),
      W.octet_string(basic)
    ]))
  ]));
}

function strip_sequence(der) {
  var len_octet = der[1];
  var header = len_octet < 0x80 ? 2 : 2 + (len_octet & 0x7F);
  return der.subarray(header);
}

// An unsigned error response: the status alone. RFC 6960 2.3 - these are
// not signed, which is why a client must never read one as an answer.
function error_response(status) {
  if (STATUS[status] === undefined || status === 'successful') {
    fail('bad-status', 'an error status is one of ' +
      Object.keys(STATUS).filter(function (k) {
        return k !== 'successful';
      }).join(', '));
  }
  return W.to_bytes(W.sequence([W.enumerated([STATUS[status]])]));
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

// An OCSPRequest - the client side, unsigned, as almost every client
// sends it; ocsp.request_from_der reads it. The two hashes are computed by the caller from the
// issuer's certificate - this library performs no cryptography, and saying
// which bytes to hash is the useful part:
//
//   name_hash = H(the issuer's subject Name, as it appears in the DER)
//   key_hash  = H(the BIT STRING content of the issuer's SPKI, not the
//                 whole SPKI)
//
// Hashing the whole SubjectPublicKeyInfo instead of its BIT STRING content
// is the classic mistake here, and it produces a request no responder
// recognises.
function request(parts) {
  if (!parts || !parts.requests || parts.requests.length === 0) {
    fail('bad-input', 'at least one CertID is required');
  }

  var entries = [];
  var i;

  for (i = 0; i < parts.requests.length; i++) {
    entries.push(W.sequence([cert_id_to_der(parts.requests[i])]));
  }

  var tbs = [W.sequence(entries)];

  if (parts.nonce) {
    tbs.push(W.explicit(2, W.sequence([
      W.sequence([
        W.oid(OID.by_name('ocsp_nonce')),
        W.octet_string(W.octet_string(parts.nonce))
      ])
    ])));
  }

  return W.to_bytes(W.sequence([W.sequence(tbs)]));
}

// ⚠ THE BYTES A CertID HASHES - so nobody has to work them out.
//
// RFC 6960 4.1.1: issuerNameHash is the hash of the issuer's DER-encoded
// NAME (the issuer field of the certificate being asked about, which is the
// CA's subject), and issuerKeyHash is the hash of the CA key's BIT STRING
// VALUE - not the whole SubjectPublicKeyInfo. Hashing the SPKI is the
// classic mistake, and it produces a CertID no responder has ever heard of.
//
// `issuer` and `cert` are what x509.from_der returned. Hash `name` and `key`
// with the same algorithm, then pass { hash, name_hash, key_hash, serial }
// to request().
function cert_id_inputs(issuer, cert) {
  return {
    name:   W.to_bytes(name_to_der(cert.issuer)),
    key:    issuer.public_key.point,
    serial: cert.serial
  };
}

export {
  prepare,
  request,
  cert_id_inputs,
  assemble,
  error_response,
  STATUS
};

// OCSP, RFC 6960. "Has this certificate been revoked?"
//
// Request and response ENCODING only. Carrying either over HTTP is the
// caller's job - the moment a transport appears in here, the boundary has
// been lost.
//
// ⚠ THREE WAYS TO GET THIS WRONG, ALL OF WHICH LOOK LIKE SUCCESS:
//
// 1. A response whose responseStatus is not `successful` carries NO status
//    for any certificate. `tryLater` and `internalError` are the responder
//    saying "ask again", and treating either as "not revoked" is the failure
//    this protocol exists to prevent. So the status is surfaced first and a
//    non-successful response has no `basic` to read.
//
// 2. `unknown` IS NOT `good`. It means the responder has no record of the
//    certificate, which for a responder that should know is a red flag, not
//    a clearance. The three states are returned as distinct strings so that
//    `status === 'good'` is the only thing that reads as good.
//
// 3. The CertID in the response must match the one asked about. A responder
//    answering about a DIFFERENT certificate produces a perfectly valid
//    "good" for something nobody asked about. cert_id_matches exists for
//    this and the parser does not do it silently, because only the caller
//    knows what was asked.
//
// ⚠ OCSP USES GeneralizedTime EVERYWHERE, unlike X.509, which uses the Time
// CHOICE and requires UTCTime before 2050. Reading these fields with the
// X.509 rule would refuse every OCSP response ever produced.

import * as DER from './der_reader.js';
import * as W from './der_writer.js';
import * as F from './fields.js';
import * as OID from './oid.js';
import * as CRL from './crl.js';
import * as ALG from './algorithm.js';
import { name_to_der as pkix_name_to_der } from './pkix.js';

// Imported for its type definitions: RDNSequence, Extension and Extensions.
import * as X509 from './x509.js';


import { to_bytes, hex, bytes_equal, int_value } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('ocsp');


// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

//   CertID ::= SEQUENCE {
//        hashAlgorithm   AlgorithmIdentifier,
//        issuerNameHash  OCTET STRING,   -- hash of the issuer's DER name
//        issuerKeyHash   OCTET STRING,   -- hash of the issuer's public key
//        serialNumber    CertificateSerialNumber }
//
// The two hashes are what tie a request to an issuer without carrying the
// issuer's certificate. Computing them is the caller's step - this library
// performs no cryptography - and ocsp_build takes them already computed.
F.define('CertID', [
  { name: 'hashAlgorithm', type: 'AlgorithmIdentifier' },
  { name: 'nameHash',      type: 'octet_string' },
  { name: 'keyHash',       type: 'octet_string' },
  { name: 'serial',        type: 'integer' }
]);

F.define('OCSPRequestEntry', [
  { name: 'certID',     type: 'CertID' },
  { name: 'extensions', tag: 0xA0, mode: 'explicit', type: 'Extensions',
    optional: true }
]);

F.define('OCSPRequestList',
  { kind: 'sequence_of', of: 'OCSPRequestEntry' });

F.define('TBSRequest', [
  { name: 'version',    tag: 0xA0, mode: 'explicit', type: 'unsigned',
    optional: true, def: null },
  { name: 'requestor',  tag: 0xA1, mode: 'explicit', type: 'raw',
    optional: true },
  { name: 'requests',   type: 'OCSPRequestList' },
  { name: 'extensions', tag: 0xA2, mode: 'explicit', type: 'Extensions',
    optional: true }
]);

F.define('OCSPRequest', [
  { name: 'tbs',       type: 'TBSRequest' },
  { name: 'signature', tag: 0xA0, mode: 'explicit', type: 'raw',
    optional: true }
]);

// RFC 6960 section 4.2.1. A response whose status is not successful(0) has no
// responseBytes at all - there is nothing to read and nothing to trust.
var RESPONSE_STATUS = [
  'successful', 'malformedRequest', 'internalError', 'tryLater',
  null, 'sigRequired', 'unauthorized'
];

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

function request_from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var req = F.read_type(r, 'OCSPRequest');

    if (req.tbs.version !== null && int_value(req.tbs.version) !== 0) {
      fail('bad-version',
        'OCSP request version ' + int_value(req.tbs.version));
    }

    var out = [];
    var i;

    for (i = 0; i < req.tbs.requests.length; i++) {
      out.push(read_cert_id(req.tbs.requests[i].certID));
    }

    if (out.length === 0) {
      fail('empty-request', 'the request asks about no certificates');
    }

    return {
      requests: out,
      nonce:    find_nonce(req.tbs.extensions),
      signed:   req.signature !== undefined,
      der:      bytes
    };
  });
}

function read_cert_id(id) {
  var alg = OID.name_of(id.hashAlgorithm.algorithm);

  return {
    hash:      alg === null ? OID.describe(id.hashAlgorithm.algorithm) : alg,
    name_hash: id.nameHash,
    key_hash:  id.keyHash,
    serial:    id.serial,
    serial_hex: hex(id.serial)
  };
}

// RFC 8954. The nonce ties a response to a request, so that a captured
// "good" from last year cannot be replayed. Reported rather than checked -
// only the caller knows which nonce they sent.
function find_nonce(extensions) {
  if (extensions === undefined) {
    return null;
  }

  var want;
  try {
    want = OID.by_name('ocsp_nonce');
  } catch (e) {
    return null;
  }

  var i;
  for (i = 0; i < extensions.length; i++) {
    if (OID.equal(extensions[i].extnID, want)) {
      return DER.read(extensions[i].extnValue, function (r) {
        return r.read_octet_string();
      });
    }
  }
  return null;
}


// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

function response_from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var resp = r.read_sequence();

    var code = resp.read_enumerated();
    var n = code.length === 1 ? code[0] : -1;
    var status = RESPONSE_STATUS[n] === undefined || RESPONSE_STATUS[n] === null
      ? 'status-' + n
      : RESPONSE_STATUS[n];

    // A non-successful response carries no responseBytes and says nothing
    // about any certificate. Returning it with `basic: null` rather than
    // throwing lets the caller distinguish "the responder declined" from "the
    // bytes were malformed" - but there is nothing here to read as good.
    if (status !== 'successful') {
      resp.expect_end();
      return {
        status: status,
        basic:  null,
        der:    bytes
      };
    }

    var wrapper = resp.read_explicit(0);
    var rb = wrapper.read_sequence();
    var type = rb.read_oid();
    var body = rb.read_octet_string();
    rb.expect_end();
    wrapper.expect_end();
    resp.expect_end();

    var type_name = OID.name_of(type);

    if (type_name !== 'ocsp_basic') {
      fail('unsupported-response-type',
        'response type ' + OID.describe(type) + ' is not id-pkix-ocsp-basic');
    }

    return {
      status: status,
      basic:  read_basic(body),
      der:    bytes
    };
  });
}

function read_basic(input) {
  return DER.read(input, function (r) {
    var basic = r.read_sequence();

    // Captured BEFORE parsing, so the bytes are the ones that were signed.
    var tbs_bytes = F.capture(basic);
    var tbs = DER.read(tbs_bytes, read_response_data);

    var sig_alg = F.read_type(basic, 'AlgorithmIdentifier');
    var sig = basic.read_bit_string();

    var certs = [];

    // [0] EXPLICIT SEQUENCE OF Certificate. A responder that is not the CA
    // itself includes its own delegated certificate here, and without it the
    // signature cannot be checked at all.
    if (basic.peek_tag() === 0xA0) {
      var wrapper = basic.read_explicit(0);
      var list = wrapper.read_sequence();
      while (list.remaining() > 0) {
        certs.push(F.capture(list));
      }
      wrapper.expect_end();
    }

    basic.expect_end();

    if (sig.unused !== 0) {
      fail('bad-signature',
        'the signature BIT STRING has ' + sig.unused + ' unused bits');
    }

    return {
      responder:     tbs.responder,
      produced_at:   tbs.produced_at,
      responses:     tbs.responses,
      nonce:         tbs.nonce,
      certificates:  certs,
      signature:     sig.bytes,
      signature_algorithm: OID.name_of(sig_alg.algorithm) ||
                     OID.describe(sig_alg.algorithm),
      // The scheme and hash, and every PSS parameter - see algorithm.js.
      signature_params: ALG.describe_signature(sig_alg, sig.bytes, fail),
      tbs_bytes:     tbs_bytes
    };
  });
}

function read_response_data(r) {
  var data = r.read_sequence();

  if (data.peek_tag() === 0xA0) {
    var v = data.read_explicit(0);
    var version = v.read_integer();
    v.expect_end();
    if (int_value(version) !== 0) {
      fail('bad-version', 'OCSP response version ' + int_value(version));
    }
  }

  //   ResponderID ::= CHOICE {
  //        byName [1] Name,
  //        byKey  [2] KeyHash }
  //
  // Both are EXPLICIT, because Name is itself a CHOICE.
  var responder;
  var tag = data.peek_tag();

  if (tag === 0xA1) {
    var by_name = data.read_explicit(1);
    responder = { by: 'name', name: F.read_type(by_name, 'RDNSequence') };
    by_name.expect_end();
  } else if (tag === 0xA2) {
    var by_key = data.read_explicit(2);
    responder = { by: 'key', key_hash: by_key.read_octet_string() };
    by_key.expect_end();
  } else {
    fail('bad-responder-id',
      'expected [1] byName or [2] byKey, got tag 0x' +
      (tag === null ? '(end)' : tag.toString(16)));
  }

  // GeneralizedTime, not the X.509 Time CHOICE. Reading it with the X.509
  // rule would refuse every OCSP response ever produced, because that rule
  // requires UTCTime before 2050.
  var produced_at = data.read_generalized_time();

  var list = data.read_sequence();
  var responses = [];

  while (list.remaining() > 0) {
    responses.push(read_single(list));
  }

  if (responses.length === 0) {
    fail('empty-response', 'the response covers no certificates');
  }

  var nonce = null;

  if (data.peek_tag() === 0xA1) {
    var ext_wrapper = data.read_explicit(1);
    var exts = F.read_type(ext_wrapper, 'Extensions');
    ext_wrapper.expect_end();
    nonce = find_nonce(exts);
  }

  data.expect_end();

  return {
    responder:   responder,
    produced_at: produced_at,
    responses:   responses,
    nonce:       nonce
  };
}

function read_single(list) {
  var single = list.read_sequence();
  var id = read_cert_id(F.read_type(single, 'CertID'));

  //   CertStatus ::= CHOICE {
  //        good    [0] IMPLICIT NULL,
  //        revoked [1] IMPLICIT RevokedInfo,
  //        unknown [2] IMPLICIT UnknownInfo }
  //
  // Three DISTINCT states. `unknown` is not `good`: it means the responder
  // has no record, which for a responder that should know is a red flag
  // rather than a clearance.
  var tag = single.peek_tag();
  var status;
  var revoked_at = null;
  var reason = null;

  if (tag === 0x80) {
    single.read_implicit(0, 0x05);
    status = 'good';

  } else if (tag === 0xA1) {
    var info = single.read_implicit(1, 0x30);
    revoked_at = info.read_generalized_time();

    if (info.peek_tag() === 0xA0) {
      var wrapper = info.read_explicit(0);
      var code = wrapper.read_enumerated();
      wrapper.expect_end();
      var n = code.length === 1 ? code[0] : -1;
      reason = CRL_REASONS[n] === undefined || CRL_REASONS[n] === null
        ? 'reason-' + n
        : CRL_REASONS[n];
    }
    info.expect_end();
    status = 'revoked';

  } else if (tag === 0x82) {
    single.read_implicit(2, 0x05);
    status = 'unknown';

  } else {
    fail('bad-cert-status',
      'expected [0] good, [1] revoked or [2] unknown, got tag 0x' +
      (tag === null ? '(end)' : tag.toString(16)));
  }

  var this_update = single.read_generalized_time();
  var next_update = null;

  if (single.peek_tag() === 0xA0) {
    var nu = single.read_explicit(0);
    next_update = nu.read_generalized_time();
    nu.expect_end();
  }

  if (single.peek_tag() === 0xA1) {
    single.read_explicit(1);      // singleExtensions, not interpreted
  }

  single.expect_end();

  return {
    cert_id:     id,
    status:      status,
    revoked_at:  revoked_at,
    reason:      reason,
    this_update: this_update,
    next_update: next_update
  };
}

// RFC 5280's reason codes, read with crl.js's table - one reader table for
// the two formats that carry them. (There were two copies.)
var CRL_REASONS = CRL.REASONS;

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

// Whether two CertIDs name the same certificate.
//
// This is not done automatically during parsing, because only the caller
// knows what they asked about. A responder answering about a DIFFERENT
// certificate produces a perfectly valid "good" for something nobody asked
// about, and nothing in the bytes says so.
function cert_id_matches(a, b) {
  return a.hash === b.hash &&
         bytes_equal(a.name_hash, b.name_hash) &&
         bytes_equal(a.key_hash, b.key_hash) &&
         a.serial_hex === b.serial_hex;
}

// Finds the single response covering a CertID, or null.
function find(response, cert_id) {
  if (response.basic === null) {
    return null;
  }

  var i;
  for (i = 0; i < response.basic.responses.length; i++) {
    if (cert_id_matches(response.basic.responses[i].cert_id, cert_id)) {
      return response.basic.responses[i];
    }
  }
  return null;
}

// Whether a single response is still within its stated validity.
//
// A response with no nextUpdate is one the responder considers always
// current, which RFC 6960 4.2.2.1 permits - so this returns true for one,
// unlike the CRL case where a missing nextUpdate means the list cannot be
// checked at all.
function is_current(single, when) {
  var t = when === undefined ? new Date() : when;

  if (!(t instanceof Date) || isNaN(t.getTime())) {
    fail('bad-time', 'expected a Date');
  }
  if (t.getTime() < single.this_update.date.getTime()) {
    return false;
  }
  if (single.next_update === null) {
    return true;
  }
  return t.getTime() <= single.next_update.date.getTime();
}

// ---------------------------------------------------------------------------





export {
  request_from_der,
  response_from_der,
  cert_id_matches,
  find,
  is_current,
  RESPONSE_STATUS
};

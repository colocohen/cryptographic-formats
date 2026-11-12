// Time-Stamp Protocol, RFC 3161. "This existed at this time", signed by a
// timestamp authority.
//
// Long-term signature validity depends on it: a signature made with a key
// that later expired is only meaningful if the time of signing is attested by
// somebody other than the signer. A `signingTime` attribute in a CMS message
// is whatever the signer's clock said, signed by the signer - which is not
// the same claim at all, and is why cms.js names that field
// `signing_time_claimed`.
//
// ⚠ A TIMESTAMP TOKEN IS A CMS SignedData whose encapsulated content is a
// TSTInfo. So almost all of this is cms.js, and what remains is the three
// checks a caller has to make and would otherwise have to know to make:
//
// 1. THE STATUS. A TimeStampResp whose status is not granted(0) or
//    grantedWithMods(1) carries NO TOKEN. Reading past a rejection is how a
//    caller ends up with "no timestamp" and treats it as "timestamped".
//
// 2. THE MESSAGE IMPRINT. The TSTInfo repeats the hash it was asked about,
//    and a token whose imprint does not match what the caller hashed is a
//    valid timestamp OVER SOMETHING ELSE. Nothing in the bytes says so.
//
// 3. THE NONCE. RFC 3161 2.4.1: when the request carried one, the response
//    MUST carry the same. Without the check, a captured response from last
//    year can be replayed.
//
// This library performs no cryptography: it builds the request, reads the
// response, and reports what to compare. Verifying the token's signature is
// cms.js plus cryptographic-primitives.

import * as DER from './der_reader.js';
import * as W from './der_writer.js';
import * as F from './fields.js';

// Imported for its side effect: pkix.js defines AlgorithmIdentifier,
// RDNSequence, Extension and the other structures PKIX shares.
import './pkix.js';
import * as OID from './oid.js';
import * as CMS from './cms.js';
import * as X509 from './x509.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, bytes_equal, int_value, int_bytes } from './commons/bytes.js';

var fail = make_fail_here('tsp');

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

// RFC 3161 section 2.4.2. Only the first two carry a token.
var STATUS = [
  'granted',              // 0
  'grantedWithMods',      // 1
  'rejection',            // 2
  'waiting',              // 3
  'revocationWarning',    // 4
  'revocationNotification' // 5
];

// The failInfo BIT STRING, RFC 3161 2.4.2. Sparse by design - the numbers
// are the bit positions the RFC assigns and the gaps are unassigned.
var FAILURE = {
  0:  'badAlg',
  2:  'badRequest',
  5:  'badDataFormat',
  14: 'timeNotAvailable',
  15: 'unacceptedPolicy',
  16: 'unacceptedExtension',
  17: 'addInfoNotAvailable',
  25: 'systemFailure'
};

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------


//   MessageImprint ::= SEQUENCE {
//        hashAlgorithm  AlgorithmIdentifier,
//        hashedMessage  OCTET STRING }
F.define('MessageImprint', [
  { name: 'algorithm', type: 'AlgorithmIdentifier' },
  { name: 'hash',      type: 'octet_string' }
]);

//   TimeStampReq ::= SEQUENCE {
//        version         INTEGER { v1(1) },
//        messageImprint  MessageImprint,
//        reqPolicy       TSAPolicyId OPTIONAL,
//        nonce           INTEGER OPTIONAL,
//        certReq         BOOLEAN DEFAULT FALSE,
//        extensions  [0] IMPLICIT Extensions OPTIONAL }
F.define('TimeStampReq', [
  { name: 'version',    type: 'unsigned' },
  { name: 'imprint',    type: 'MessageImprint' },
  { name: 'policy',     type: 'oid', optional: true },
  { name: 'nonce',      type: 'integer', optional: true },
  { name: 'certReq',    type: 'boolean', optional: true, def: false },
  { name: 'extensions', tag: 0xA0, mode: 'implicit', type: 'Extensions',
    optional: true }
]);

//   Accuracy ::= SEQUENCE {
//        seconds   INTEGER OPTIONAL,
//        millis    [0] INTEGER OPTIONAL,
//        micros    [1] INTEGER OPTIONAL }
F.define('Accuracy', [
  { name: 'seconds', type: 'unsigned', optional: true },
  { name: 'millis',  tag: 0x80, mode: 'implicit', type: 'unsigned',
    optional: true },
  { name: 'micros',  tag: 0x81, mode: 'implicit', type: 'unsigned',
    optional: true }
]);

//   TSTInfo ::= SEQUENCE {
//        version         INTEGER { v1(1) },
//        policy          TSAPolicyId,
//        messageImprint  MessageImprint,
//        serialNumber    INTEGER,
//        genTime         GeneralizedTime,
//        accuracy        Accuracy OPTIONAL,
//        ordering        BOOLEAN DEFAULT FALSE,
//        nonce           INTEGER OPTIONAL,
//        tsa         [0] EXPLICIT GeneralName OPTIONAL,
//        extensions  [1] IMPLICIT Extensions OPTIONAL }
//
// ⚠ genTime is GeneralizedTime ALWAYS, like OCSP and unlike X.509. Reading it
// with the X.509 Time rule - which requires UTCTime before 2050 - would
// refuse every timestamp token ever issued.
F.define('TSTInfo', [
  { name: 'version',    type: 'unsigned' },
  { name: 'policy',     type: 'oid' },
  { name: 'imprint',    type: 'MessageImprint' },
  { name: 'serial',     type: 'integer' },
  { name: 'genTime',    type: 'generalized_time' },
  { name: 'accuracy',   type: 'Accuracy', optional: true },
  { name: 'ordering',   type: 'boolean', optional: true, def: false },
  { name: 'nonce',      type: 'integer', optional: true },
  { name: 'tsa',        tag: 0xA0, mode: 'explicit', type: 'raw',
    optional: true },
  { name: 'extensions', tag: 0xA1, mode: 'implicit', type: 'Extensions',
    optional: true }
]);


function request_from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var req = F.read_type(r, 'TimeStampReq');
    var version = int_value(req.version, 'TimeStampReq version');

    if (version !== 1) {
      fail('bad-version', 'a TimeStampReq is version 1, got ' + version);
    }

    return {
      version:   version,
      algorithm: OID.name_of(req.imprint.algorithm.algorithm) ||
                 OID.to_string(req.imprint.algorithm.algorithm),
      hash:      req.imprint.hash,
      policy:    req.policy === undefined ? null
                 : OID.to_string(req.policy),
      nonce:     req.nonce === undefined ? null : req.nonce,
      cert_req:  req.certReq,
      der:       bytes
    };
  });
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

//   TimeStampResp ::= SEQUENCE {
//        status          PKIStatusInfo,
//        timeStampToken  TimeStampToken OPTIONAL }
//
// ⚠ A response whose status is not granted or grantedWithMods HAS NO TOKEN,
// and `token` is null rather than something a caller can read past.
function response_from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var resp = r.read_sequence();
    var info = read_status(resp);

    var out = {
      status:      info.status,
      status_text: info.text,
      failure:     info.failure,
      token:       null,
      tst:         null,
      der:         bytes
    };

    if (resp.remaining() > 0) {
      var token_bytes = resp.capture();

      if (!info.granted) {
        // A rejection carrying a token is a message contradicting itself.
        fail('token-with-rejection',
          'the status is ' + info.status + ' but a token is present');
      }

      out.token = token_bytes;
      out.cms = CMS.from_der(token_bytes);
      out.tst = read_tst_info(out.cms);
    } else if (info.granted) {
      fail('granted-without-token',
        'the status is ' + info.status + ' and no token is present');
    }

    resp.expect_end();
    return out;
  });
}

//   PKIStatusInfo ::= SEQUENCE {
//        status        PKIStatus,
//        statusString  PKIFreeText OPTIONAL,
//        failInfo      PKIFailureInfo OPTIONAL }
function read_status(r) {
  var si = r.read_sequence();
  var code = int_value(si.read_unsigned(), 'PKIStatus');
  var status = STATUS[code] === undefined ? 'status-' + code : STATUS[code];

  var text = null;
  var failure = null;

  if (si.peek_tag() === 0x30) {
    var free = si.read_sequence();
    var parts = [];
    while (free.remaining() > 0) {
      parts.push(free.read_utf8_string());
    }
    text = parts.join(' ');
  }

  if (si.remaining() > 0) {
    var bits = si.read_bit_string();
    failure = read_failure(bits);
  }

  si.expect_end();

  return {
    status:  status,
    text:    text,
    failure: failure,
    // granted(0) and grantedWithMods(1) are the only two that carry a token.
    granted: code === 0 || code === 1
  };
}

function read_failure(bits) {
  var out = [];
  var i;

  for (i = 0; i < bits.bytes.length * 8; i++) {
    var byte = Math.floor(i / 8);
    var bit = 7 - (i % 8);

    if (((bits.bytes[byte] >> bit) & 1) === 1) {
      out.push(FAILURE[i] === undefined ? 'bit-' + i : FAILURE[i]);
    }
  }

  return out.length === 0 ? null : out;
}

// The TSTInfo inside the token's encapsulated content.
function read_tst_info(cms) {
  if (cms.content_type !== 'tstInfo') {
    fail('not-a-timestamp',
      'the token encapsulates ' + cms.content_type + ', not a TSTInfo');
  }
  if (cms.content === null) {
    // A detached TSTInfo would be a timestamp whose content nobody has.
    fail('detached-tstinfo',
      'the token has no encapsulated content, so there is no TSTInfo to read');
  }

  return DER.read(cms.content, function (r) {
    var tst = F.read_type(r, 'TSTInfo');
    var version = int_value(tst.version, 'TSTInfo version');

    if (version !== 1) {
      fail('bad-version', 'a TSTInfo is version 1, got ' + version);
    }

    return {
      version:   version,
      policy:    OID.to_string(tst.policy),
      algorithm: OID.name_of(tst.imprint.algorithm.algorithm) ||
                 OID.to_string(tst.imprint.algorithm.algorithm),
      hash:      tst.imprint.hash,
      serial:    tst.serial,
      serial_hex: hex(tst.serial),
      time:      tst.genTime,
      accuracy:  read_accuracy(tst.accuracy),
      ordering:  tst.ordering,
      nonce:     tst.nonce === undefined ? null : tst.nonce
    };
  });
}

// The stated precision of genTime. A token with no accuracy states no
// precision, which RFC 3161 permits and which is worth surfacing rather than
// defaulting to zero - "accurate to within nothing stated" is not "accurate
// to the second".
function read_accuracy(a) {
  if (a === undefined) {
    return null;
  }

  return {
    seconds: a.seconds === undefined ? 0 : int_value(a.seconds, 'seconds'),
    millis:  a.millis === undefined ? 0 : int_value(a.millis, 'millis'),
    micros:  a.micros === undefined ? 0 : int_value(a.micros, 'micros')
  };
}

// ---------------------------------------------------------------------------
// The three checks
// ---------------------------------------------------------------------------

// Whether a response's token actually attests the thing that was asked about.
//
// Returns a report rather than a boolean, because a caller who gets `false`
// needs to know WHICH check failed: a mismatched imprint and a replayed
// response are different problems with different responses.
//
// ⚠ None of this is done automatically during parsing, because only the
// caller holds the request and the data.
// ⚠ WHICH CERTIFICATE SIGNED THIS TOKEN - BY HASH, AND SIGNED.
//
// RFC 3161 2.4.2 (and RFC 5816 for V2): the token MUST carry a
// signingCertificate or signingCertificateV2 attribute naming the TSA
// certificate by its hash, among the SIGNED attributes. Without it the
// certificate that "signed" the token is whichever one an attacker put in
// the bag with a matching key - the substitution ESS exists to stop. This
// module read neither attribute.
//
//   ESSCertID   ::= SEQUENCE { certHash Hash (SHA-1), issuerSerial OPTIONAL }
//   ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256,
//                              certHash OCTET STRING, issuerSerial OPTIONAL }
//
// Returns [{ hash, cert_hash }] - the first entry is the signer's - or null.
// The caller hashes the TSA certificate's DER with `hash` and compares.
function ess_cert_ids(response) {
  if (response.token === null) {
    return null;
  }

  var attrs = response.cms.signers[0].signed_attrs || [];
  var i;

  for (i = 0; i < attrs.length; i++) {
    var name = attrs[i].name;
    if (name !== 'signingCertificate' && name !== 'signingCertificateV2') {
      continue;
    }
    var v2 = name === 'signingCertificateV2';

    return DER.read(attrs[i].value, function (r) {
      var set = r.read_set_of();
      var sc = set.read_sequence();
      var certs = sc.read_sequence();
      var out = [];

      while (certs.remaining() > 0) {
        var id = certs.read_sequence();
        var hash = 'sha1';

        if (v2 && id.peek_tag() === 0x30) {
          var alg = F.read_type(id, 'AlgorithmIdentifier');
          hash = OID.name_of(alg.algorithm) || OID.to_string(alg.algorithm);
        } else if (v2) {
          hash = 'sha256';
        }

        out.push({ hash: hash, cert_hash: id.read_octet_string(),
                   version: v2 ? 2 : 1 });

        while (id.remaining() > 0) {
          id.capture();          // issuerSerial: reported by hash alone
        }
      }

      while (sc.remaining() > 0) {
        sc.capture();            // policies
      }
      set.expect_end();

      if (out.length === 0) {
        fail('empty-signing-certificate',
          'a signingCertificate attribute that names no certificate');
      }
      return out;
    });
  }

  return null;
}

function check(response, request, options) {
  var opts = options || {};
  var problems = [];

  if (response.token === null) {
    return {
      ok: false,
      problems: ['the response carries no token: status is ' +
                 response.status +
                 (response.failure ? ' (' + response.failure.join(', ') + ')'
                                   : '')]
    };
  }

  var tst = response.tst;

  // 1. The imprint. A token whose imprint does not match is a perfectly
  //    valid timestamp OVER SOMETHING ELSE.
  if (request !== undefined && request !== null) {
    if (tst.algorithm !== request.algorithm) {
      problems.push('the token used ' + tst.algorithm +
        ' and the request asked for ' + request.algorithm);
    } else if (!bytes_equal(tst.hash, request.hash)) {
      problems.push('the message imprint does not match the request: this ' +
        'token attests a different message');
    }

    // 2. The nonce. RFC 3161 2.4.1: present in the request means it MUST be
    //    echoed. Without the check a captured response can be replayed.
    if (request.nonce !== null && request.nonce !== undefined) {
      if (tst.nonce === null) {
        problems.push('the request carried a nonce and the token does not ' +
          'echo it, so this response cannot be tied to this request');
      } else if (!bytes_equal(tst.nonce, request.nonce)) {
        problems.push('the nonce does not match: this response answers a ' +
          'different request, possibly a captured one');
      }
    }
  }

  // 3. The certificate binding - RFC 3161 2.4.2. Checked for presence here;
  //    the hash comparison needs a hash, and is the caller's, with
  //    ess_cert_ids(response)[0].
  if (ess_cert_ids(response) === null) {
    problems.push('the token has no signingCertificate or ' +
      'signingCertificateV2 attribute, so nothing signed says which ' +
      'certificate is the TSA\'s (RFC 3161 2.4.2)');
  }

  // 4. The policy, when the caller named one they require.
  if (opts.policy !== undefined && tst.policy !== opts.policy) {
    problems.push('the token was issued under policy ' + tst.policy +
      ' and ' + opts.policy + ' was required');
  }

  return { ok: problems.length === 0, problems: problems };
}

// The bytes and comparison a caller needs to verify the token's signature.
//
// Delegated to cms.js: a timestamp token IS a CMS SignedData, and having two
// implementations of the signedAttrs substitution would be exactly the trap
// that module's comment warns about.
function verification_plan(response) {
  if (response.token === null) {
    fail('no-token', 'this response carries no token to verify');
  }
  if (response.cms.signers.length !== 1) {
    // RFC 3161 2.4.2: a timestamp token has exactly one signer. Several
    // would leave "which one is the TSA" as a question with no answer.
    fail('bad-signer-count',
      'a timestamp token has one SignerInfo, this has ' +
      response.cms.signers.length);
  }

  return CMS.verification_plan(response.cms, response.cms.signers[0]);
}

// The TSA's certificate, when the token carries one.
//
// ⚠ RFC 3161 2.3: the certificate MUST have the timeStamping extended key
// usage, and it MUST be critical. A certificate without it is not a TSA
// certificate, whatever its subject says - and accepting one means accepting
// a timestamp from anybody the CA ever issued to.
function tsa_certificate(response) {
  if (response.token === null) {
    return null;
  }

  var cert = CMS.certificate_for(response.cms, response.cms.signers[0]);

  if (cert === null) {
    return null;
  }

  var eku = X509.extension(cert, 'ext_extKeyUsage');

  if (eku === null) {
    fail('not-a-tsa-certificate',
      'the signing certificate has no extended key usage; RFC 3161 2.3 ' +
      'requires timeStamping, and without it this is not a TSA certificate');
  }
  if (!eku.critical) {
    fail('not-a-tsa-certificate',
      'the extended key usage is not critical; RFC 3161 2.3 requires it to ' +
      'be, so that a relying party cannot ignore it');
  }
  if (!eku.parsed.some(function (p) { return p.name === 'timeStamping'; })) {
    fail('not-a-tsa-certificate',
      'the extended key usage is [' + eku.parsed.map(function (p) { return p.name || p.id; })
        .join(', ') + '] and does not include timeStamping');
  }

  return cert;
}

// ---------------------------------------------------------------------------




export {
  ess_cert_ids,
  request_from_der,
  response_from_der,
  check,
  verification_plan,
  tsa_certificate,
  STATUS,
  FAILURE
};

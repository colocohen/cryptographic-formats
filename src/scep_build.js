// Building SCEP messages - RFC 8894.
//
// The server's answer, a CertRep, in the two steps every signed builder here
// takes:
//
//   // SUCCESS only: the certificates, in a degenerate SignedData - which
//   // the caller then encrypts to the requester (cms_enveloped_build)
//   var inner = scep_build.cert_rep_content([issued, ca]);
//
//   var p = scep_build.cert_rep_prepare({ certificate: ra_cert, digest: 'sha256',
//     signature_algorithm: 'sha256WithRSAEncryption',
//     transaction_id: req.transaction_id, recipient_nonce: req.sender_nonce,
//     sender_nonce: random(16), pki_status: 'SUCCESS',
//     enveloped: enveloped_der, content_digest: sha256(enveloped_der) });
//   var der = scep_build.cert_rep_assemble(p, sign(p.bytes), { certificates: [ra_cert] });
//
// And a client's request, for symmetry and for tests: request_prepare, with
// issuer_and_subject and issuer_and_serial for what CertPoll, GetCert and
// GetCRL encrypt.
//
// The layers below are cms_build's and cms_enveloped_build's; this module
// writes the SCEP attributes and refuses the combinations RFC 8894 forbids.
// The nonce is the caller's - this library makes no randomness.

import * as W from './der_writer.js';
import * as OID from './oid.js';
import * as X509 from './x509.js';
import * as CMS_BUILD from './cms_build.js';
import { x509_name_to_der, issuer_and_serial_to_der } from './pkix.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes } from './commons/bytes.js';

var fail = make_fail_here('scep');

// The writer's own tables (see commons/README): RFC 8894 3.2.1.2 - .4, and
// 3.5.2's GetCACaps keywords.
var MESSAGE_TYPES = { CertRep: 3, RenewalReq: 17, PKCSReq: 19, CertPoll: 20,
                      GetCert: 21, GetCRL: 22 };
var PKI_STATUS = { SUCCESS: 0, FAILURE: 2, PENDING: 3 };
var FAIL_INFO = { badAlg: 0, badMessageCheck: 1, badRequest: 2, badTime: 3,
                  badCertId: 4 };
var CAPABILITIES = ['AES', 'DES3', 'GetNextCACert', 'POSTPKIOperation',
  'Renewal', 'SHA-1', 'SHA-256', 'SHA-512', 'SCEPStandard'];

// ---------------------------------------------------------------------------
// The signed message
// ---------------------------------------------------------------------------

// The CA's or RA's answer.
//
//   pki_status       'SUCCESS' | 'FAILURE' | 'PENDING'
//   fail_info        FAILURE only, and required with it: 'badRequest'...
//   fail_info_text   optional (RFC 8894 6)
//   enveloped        SUCCESS only, and required with it: the
//                    pkcsPKIEnvelope's DER (cms_enveloped_build)
//   content_digest   of `enveloped` - or, with none, of the empty string:
//                    the message then signs `data` with no eContent
//   transaction_id, recipient_nonce   the request's
//   sender_nonce     the caller's 16 random bytes
function cert_rep_prepare(parts) {
  var p = parts || {};
  var status = PKI_STATUS[p.pki_status];
  if (status === undefined) {
    fail('bad-pki-status', 'pki_status is SUCCESS, FAILURE or PENDING');
  }
  if (p.pki_status === 'FAILURE') {
    if (FAIL_INFO[p.fail_info] === undefined) {
      fail('missing-fail-info', 'a FAILURE says why: fail_info is one of ' +
        Object.keys(FAIL_INFO).join(', ') + ' (RFC 8894 3.3.2.2)');
    }
  } else if (p.fail_info !== undefined && p.fail_info !== null) {
    fail('fail-info-without-failure', 'fail_info goes with FAILURE, and this is ' +
      p.pki_status);
  }
  var has_envelope = p.enveloped !== undefined && p.enveloped !== null;
  // ⚠ SUCCESS WITH NOTHING, OR A REFUSAL WITH CONTENT - either is two
  // answers. RFC 8894 3.3.2.2-3: FAILURE and PENDING MUST omit it.
  if (p.pki_status === 'SUCCESS' && !has_envelope) {
    fail('missing-envelope', 'a SUCCESS carries the certificates, encrypted: pass ' +
      '{ enveloped }');
  }
  if (p.pki_status !== 'SUCCESS' && has_envelope) {
    fail('unexpected-envelope', 'a ' + p.pki_status + ' omits the pkcsPKIEnvelope ' +
      '(RFC 8894 3.3.2)');
  }
  if (p.recipient_nonce === undefined || p.recipient_nonce === null) {
    fail('missing-recipient-nonce', 'a CertRep echoes the request\'s sender_nonce as ' +
      'recipient_nonce - it is how the client knows this answers its request');
  }

  var attrs = common_attributes(p, 'CertRep');
  attrs.push(attr('scep_pkiStatus', W.printable_string(String(status))));
  attrs.push(attr('scep_recipientNonce', W.octet_string(nonce(p.recipient_nonce,
    'recipient_nonce'))));
  if (p.pki_status === 'FAILURE') {
    attrs.push(attr('scep_failInfo', W.printable_string(String(FAIL_INFO[p.fail_info]))));
  }
  if (p.fail_info_text !== undefined && p.fail_info_text !== null) {
    attrs.push(attr('scep_failInfoText', W.utf8_string(String(p.fail_info_text))));
  }
  return signed(p, attrs, has_envelope);
}

// A client's request: PKCSReq, RenewalReq, CertPoll, GetCert or GetCRL -
// always with its envelope.
function request_prepare(parts) {
  var p = parts || {};
  if (MESSAGE_TYPES[p.message_type] === undefined || p.message_type === 'CertRep') {
    fail('bad-message-type', 'a request is PKCSReq, RenewalReq, CertPoll, GetCert or ' +
      'GetCRL; a CertRep is cert_rep_prepare\'s');
  }
  if (p.enveloped === undefined || p.enveloped === null) {
    fail('missing-envelope', 'a ' + p.message_type + ' carries its request in a ' +
      'pkcsPKIEnvelope: pass { enveloped }');
  }
  return signed(p, common_attributes(p, p.message_type), true);
}

// transactionID, messageType and senderNonce - every message's (RFC 8894
// 3.2.1).
function common_attributes(p, type) {
  if (typeof p.transaction_id !== 'string' || p.transaction_id === '') {
    fail('missing-transaction-id', 'transaction_id is text - for a request, conventionally ' +
      'a hash of the public key; for a response, the request\'s');
  }
  return [
    attr('scep_messageType', W.printable_string(String(MESSAGE_TYPES[type]))),
    attr('scep_transactionID', W.printable_string(p.transaction_id)),
    attr('scep_senderNonce', W.octet_string(nonce(p.sender_nonce, 'sender_nonce')))
  ];
}

// ⚠ 16 BYTES, RANDOM, THE CALLER'S. RFC 8894 3.2.1.5. A shorter one is
// refused here - the reader only warns, for old clients, but nothing new
// should be written that way.
function nonce(v, what) {
  if (!(v instanceof Uint8Array)) {
    fail('bad-nonce', what + ' is bytes - 16 random ones');
  }
  if (v.length !== 16) {
    fail('bad-nonce', what + ' is 16 bytes (RFC 8894 3.2.1.5), got ' + v.length);
  }
  return v;
}

function attr(name, value_der) {
  return { type: OID.to_string(OID.by_name(name)), value: W.to_bytes(value_der) };
}

// cms_build's SignerInfo, with the SCEP attributes. `certificate` may be DER
// or as x509.from_der returned it. With no envelope, the content is absent:
// `data` with no eContent, as RFC 8894 3.3.2 has FAILURE and PENDING.
function signed(p, attrs, has_envelope) {
  var cert = p.certificate instanceof Uint8Array ? X509.from_der(p.certificate) : p.certificate;
  var spec = { certificate: cert, digest: p.digest,
               signature_algorithm: p.signature_algorithm,
               content_type: 'data', content_digest: p.content_digest,
               signing_time: p.signing_time, attributes: attrs };
  if (has_envelope) {
    spec.content = to_bytes(p.enveloped);
  } else {
    spec.detached = true;
  }
  return CMS_BUILD.prepare(spec);
}

// ---------------------------------------------------------------------------
// What an envelope holds
// ---------------------------------------------------------------------------

// CertPoll's: IssuerAndSubject ::= SEQUENCE { issuer Name, subject Name } -
// the issuer being the CA's subject (RFC 8894 3.3.3).
function issuer_and_subject(issuer, subject) {
  return W.to_bytes(W.sequence([x509_name_to_der(issuer), x509_name_to_der(subject)]));
}

// GetCert's and GetCRL's: an IssuerAndSerialNumber.
function issuer_and_serial(issuer, serial) {
  return W.to_bytes(issuer_and_serial_to_der({ issuer: issuer, serial: to_bytes(serial) }, fail));
}

// ---------------------------------------------------------------------------
// GetCACaps
// ---------------------------------------------------------------------------

// The GetCACaps answer, one keyword per line. A keyword RFC 8894 does not
// name is refused: a client that reads it as something else is worse off
// than one that never sees it.
function capabilities_text(list) {
  if (!Array.isArray(list) || list.length === 0) {
    fail('bad-capabilities', 'pass the keywords this server supports');
  }
  list.forEach(function (k) {
    if (CAPABILITIES.indexOf(k) === -1) {
      fail('unknown-capability', '"' + k + '" is not a GetCACaps keyword RFC 8894 names: ' +
        CAPABILITIES.join(', '));
    }
  });
  return list.join('\n');
}

// A CA plus an RA, for GetCACert (RFC 8894 4.2.1.2,
// application/x-x509-ca-ra-cert), and a SUCCESS's certificates: the
// degenerate SignedData cms_build already writes. A single CA certificate is
// sent as its DER (application/x-x509-ca-cert).
var cert_rep_content = CMS_BUILD.bundle;
// cms_build's, under the names that pair with each prepare.
var cert_rep_assemble = CMS_BUILD.assemble;
var request_assemble = CMS_BUILD.assemble;

export {
  cert_rep_prepare,
  cert_rep_assemble,
  request_prepare,
  request_assemble,
  cert_rep_content,
  issuer_and_subject,
  issuer_and_serial,
  capabilities_text,
  CAPABILITIES
};

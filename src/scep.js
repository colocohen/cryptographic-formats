// SCEP - RFC 8894. Reading a pkiMessage, and what its envelope holds.
//
// A SCEP message is three layers, and every one of them is already a format
// this library reads:
//
//   SignedData (cms.js)          signed by the requester - self-signed on a
//                                first request - or by the CA / RA
//     signedAttrs                the SCEP attributes: this module
//     content: EnvelopedData     (cms_enveloped.js) encrypted to the CA or
//                                to the requester
//       the decrypted bytes      a PKCS#10 request (csr.js), an
//                                IssuerAndSubject, an IssuerAndSerialNumber,
//                                or a degenerate SignedData of certificates
//
// So this module reads the attributes, checks that the message is one SCEP
// defines, and hands back the envelope's DER; inner() reads what the caller
// decrypted. No cryptography, no state: whether the transaction ID is one it
// has seen, whether the recipientNonce is the nonce it sent, whether the
// challengePassword is right, whether to issue - all the caller's.
//
// ⚠ THE SIGNATURE IS ONLY AS GOOD AS ITS KEY. A PKCSReq is signed by a
// certificate the client made for itself: it proves possession of the key
// in the request, not who the client is. That is the challengePassword's
// job (csr.from_der's challenge_password) - or the existing certificate's,
// for a RenewalReq.

import * as DER from './der_reader.js';
import * as OID from './oid.js';
import * as CMS from './cms.js';
import * as CSR from './csr.js';
import * as F from './fields.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex } from './commons/bytes.js';

import './pkix.js';

var fail = make_fail_here('scep');

// RFC 8894 3.2.1.2 - the reader's own table (the builder keeps its own; see
// commons/README).
var MESSAGE_TYPES = {
  3: 'CertRep', 17: 'RenewalReq', 19: 'PKCSReq', 20: 'CertPoll',
  21: 'GetCert', 22: 'GetCRL'
};

// 3.2.1.3 and 3.2.1.4.
var PKI_STATUS = { 0: 'SUCCESS', 2: 'FAILURE', 3: 'PENDING' };
var FAIL_INFO = { 0: 'badAlg', 1: 'badMessageCheck', 2: 'badRequest',
                  3: 'badTime', 4: 'badCertId' };

// GetCACaps keywords, RFC 8894 3.5.2 (table 7). "Update" was in the drafts
// and is not here; a server that sends it gets it back under `unknown`.
var CAPABILITIES = ['AES', 'DES3', 'GetNextCACert', 'POSTPKIOperation',
  'Renewal', 'SHA-1', 'SHA-256', 'SHA-512', 'SCEPStandard'];

// The attributes, by OID name: which string type each value is.
var ATTRIBUTES = {
  scep_messageType:    'printable',
  scep_pkiStatus:      'printable',
  scep_failInfo:       'printable',
  scep_senderNonce:    'octets',
  scep_recipientNonce: 'octets',
  scep_transactionID:  'printable',
  scep_failInfoText:   'utf8'
};

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

function from_der(input) {
  var bytes = to_bytes(input);
  var signed = CMS.from_der(bytes);
  var warnings = [];

  // ⚠ ONE SIGNER. RFC 8894 3.2: the message is signed by the sender. Two
  // signers is two senders, and a server reading the attributes of one
  // while verifying the other has verified nothing about what it acts on.
  if (signed.signers.length !== 1) {
    fail('not-one-signer', 'a SCEP message has exactly one signer, this has ' +
      signed.signers.length);
  }
  if (signed.content_type !== 'data') {
    fail('bad-content-type', 'a SCEP message signs `data` - the pkcsPKIEnvelope - not ' +
      signed.content_type);
  }

  var signer = signed.signers[0];
  if (signer.signed_attrs === null) {
    fail('no-signed-attributes', 'the SCEP attributes travel as signed attributes, and ' +
      'this message has none');
  }
  var attrs = read_attributes(signer.signed_attrs);

  if (attrs.scep_messageType === undefined) {
    fail('missing-attribute', 'messageType is required (RFC 8894 3.2.1)');
  }
  var code = /^[0-9]{1,3}$/.test(attrs.scep_messageType)
    ? parseInt(attrs.scep_messageType, 10) : null;
  if (code === null) {
    fail('bad-message-type', 'messageType is a decimal number, got "' +
      attrs.scep_messageType + '"');
  }
  var type = MESSAGE_TYPES[code] === undefined ? null : MESSAGE_TYPES[code];
  if (type === null) {
    warnings.push({ code: 'unknown-message-type',
      detail: 'messageType ' + code + ' is not one RFC 8894 defines' });
  }

  // RFC 8894 3.2.1: every message carries these three.
  ['scep_transactionID', 'scep_senderNonce'].forEach(function (n) {
    if (attrs[n] === undefined) {
      fail('missing-attribute', n.replace('scep_', '') + ' is required (RFC 8894 3.2.1)');
    }
  });
  if (attrs.scep_senderNonce.length !== 16) {
    warnings.push({ code: 'nonce-length', detail: 'senderNonce is ' +
      attrs.scep_senderNonce.length + ' bytes; RFC 8894 3.2.1.5 makes it 16 - old ' +
      'clients vary' });
  }

  var out = {
    signed: signed,
    signer: signer,
    message_type: type,
    message_type_code: code,
    transaction_id: attrs.scep_transactionID,
    sender_nonce: attrs.scep_senderNonce,
    recipient_nonce: attrs.scep_recipientNonce === undefined ? null : attrs.scep_recipientNonce,
    pki_status: null,
    fail_info: null,
    fail_info_code: null,
    fail_info_text: attrs.scep_failInfoText === undefined ? null : attrs.scep_failInfoText,
    // The pkcsPKIEnvelope: the EnvelopedData's ContentInfo DER, for
    // cms_enveloped.from_der - or null where SCEP omits it.
    enveloped: signed.detached || signed.content === null || signed.content.length === 0
      ? null : signed.content,
    warnings: warnings,
    note: ''
  };

  if (type === 'CertRep') {
    read_cert_rep(attrs, out);
  } else if (attrs.scep_pkiStatus !== undefined || attrs.scep_failInfo !== undefined) {
    fail('status-in-request', 'pkiStatus and failInfo belong to a CertRep, not a ' +
      (type || 'message of type ' + code));
  } else if (type !== null && out.enveloped === null) {
    fail('missing-envelope', 'a ' + type + ' carries its request in a pkcsPKIEnvelope, ' +
      'and this one has none');
  }

  out.note = type === 'CertRep'
    ? 'Verify the signature (cms.verification_plan) against the CA or RA certificate ' +
      'you trust, and that recipient_nonce is the sender_nonce you sent, before acting ' +
      'on the status. The envelope is encrypted to your request\'s key.'
    : 'Verify the signature (cms.verification_plan) with the signer\'s certificate - ' +
      'self-signed on a first request, so it proves only possession of the key. ' +
      'Who the client is, is the challengePassword\'s job or, for a renewal, the ' +
      'existing certificate\'s. Then decrypt `enveloped` and read it with inner().';
  return out;
}

//   CertRep: pkiStatus and recipientNonce, always; failInfo with FAILURE;
//   the envelope with SUCCESS only (RFC 8894 3.3.2).
function read_cert_rep(attrs, out) {
  if (attrs.scep_pkiStatus === undefined || attrs.scep_recipientNonce === undefined) {
    fail('missing-attribute', 'a CertRep carries pkiStatus and recipientNonce (RFC 8894 3.2.1)');
  }
  var status = PKI_STATUS[attrs.scep_pkiStatus];
  if (status === undefined || !/^[0-9]$/.test(attrs.scep_pkiStatus)) {
    fail('unknown-pki-status', 'pkiStatus "' + attrs.scep_pkiStatus + '" is not SUCCESS (0), ' +
      'FAILURE (2) or PENDING (3) - and what to do with the answer depends on which');
  }
  out.pki_status = status;

  if (status === 'FAILURE') {
    if (attrs.scep_failInfo === undefined) {
      fail('missing-attribute', 'a FAILURE carries failInfo (RFC 8894 3.3.2.2)');
    }
    out.fail_info_code = attrs.scep_failInfo;
    out.fail_info = FAIL_INFO[attrs.scep_failInfo] === undefined ? null : FAIL_INFO[attrs.scep_failInfo];
    if (out.fail_info === null) {
      out.warnings.push({ code: 'unknown-fail-info',
        detail: 'failInfo "' + attrs.scep_failInfo + '" is not one RFC 8894 names' });
    }
  } else if (attrs.scep_failInfo !== undefined) {
    fail('fail-info-without-failure', 'failInfo goes with FAILURE, and this is ' + status);
  }

  // ⚠ SUCCESS AND NOTHING TO SHOW FOR IT, or a refusal carrying content -
  // either is two answers. RFC 8894 3.3.2.2-3: FAILURE and PENDING MUST omit
  // the envelope; SUCCESS is the envelope.
  if (status === 'SUCCESS' && out.enveloped === null) {
    fail('missing-envelope', 'a SUCCESS carries the certificate in a pkcsPKIEnvelope, and ' +
      'this one has none');
  }
  if (status !== 'SUCCESS' && out.enveloped !== null) {
    fail('unexpected-envelope', 'a ' + status + ' omits the pkcsPKIEnvelope (RFC 8894 ' +
      '3.3.2), and this one carries one');
  }
}

// Each SCEP attribute: once, one value, the right type. Anything else is a
// message with two answers to one question.
function read_attributes(list) {
  var out = {};
  var i;
  for (i = 0; i < list.length; i++) {
    var name = OID.name_of(list[i].oid);
    var kind = name === null ? undefined : ATTRIBUTES[name];
    if (kind === undefined) {
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(out, name)) {
      fail('duplicate-attribute', name.replace('scep_', '') + ' appears twice');
    }
    out[name] = DER.read(list[i].value, read_value(kind, name));
  }
  return out;
}

function read_value(kind, name) {
  return function (r) {
    var set = r.read_set_of();
    var v = kind === 'printable' ? set.read_printable_string()
      : kind === 'octets' ? set.read_octet_string()
      : set.read_utf8_string();
    if (set.remaining() > 0) {
      fail('multi-valued-attribute', name.replace('scep_', '') + ' has one value ' +
        '(RFC 8894 3.2.1)');
    }
    return v;
  };
}

// ---------------------------------------------------------------------------
// What the envelope holds
// ---------------------------------------------------------------------------

// The decrypted pkcsPKIEnvelope, by message type (a name or the number):
//
//   PKCSReq, RenewalReq   { kind: 'csr', csr }               csr.from_der
//   CertPoll              { kind: 'issuer-and-subject', issuer, subject }
//   GetCert, GetCRL       { kind: 'issuer-and-serial', issuer, serial, serial_hex }
//   CertRep               { kind: 'certificates', certificates, crls }
//                         - a degenerate SignedData, each DER; GetCRL's
//                         answer is its crls
function inner(message_type, bytes) {
  var type = typeof message_type === 'number' ? MESSAGE_TYPES[message_type] : message_type;
  var b = to_bytes(bytes);

  if (type === 'PKCSReq' || type === 'RenewalReq') {
    return { kind: 'csr', csr: CSR.from_der(b) };
  }
  if (type === 'CertPoll') {
    //   IssuerAndSubject ::= SEQUENCE { issuer Name, subject Name }
    return DER.read(b, function (r) {
      var seq = r.read_sequence();
      var out = { kind: 'issuer-and-subject', issuer: F.read_type(seq, 'RDNSequence'),
                  subject: F.read_type(seq, 'RDNSequence') };
      seq.expect_end();
      return out;
    });
  }
  if (type === 'GetCert' || type === 'GetCRL') {
    var ias = DER.read(b, function (r) { return F.read_type(r, 'IssuerAndSerialNumber'); });
    return { kind: 'issuer-and-serial', issuer: ias.issuer, serial: ias.serial,
             serial_hex: hex(ias.serial) };
  }
  if (type === 'CertRep') {
    var bundle = CMS.from_der(b);
    if (!bundle.degenerate) {
      fail('not-degenerate', 'a CertRep\'s envelope holds a certificates-only SignedData, ' +
        'with no signers (RFC 8894 3.3.2.1)');
    }
    return { kind: 'certificates', certificates: bundle.certificates, crls: bundle.crls };
  }
  fail('unknown-message-type', 'no envelope content is defined for "' + message_type + '"');
}

// ---------------------------------------------------------------------------
// GetCACaps
// ---------------------------------------------------------------------------

// The server's GetCACaps answer: one keyword per line (RFC 8894 3.5.2),
// split into those RFC 8894 names and the rest. Case as written: the RFC's
// keywords are case-sensitive in practice, and a client compares them so.
function capabilities_from_text(text) {
  var out = { known: [], unknown: [] };
  String(text).split(/\r?\n/).forEach(function (line) {
    var k = line.trim();
    if (k === '') { return; }
    (CAPABILITIES.indexOf(k) !== -1 ? out.known : out.unknown).push(k);
  });
  return out;
}

export {
  from_der,
  inner,
  capabilities_from_text,
  CAPABILITIES,
  MESSAGE_TYPES,
  PKI_STATUS,
  FAIL_INFO
};

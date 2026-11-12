// CMP - Certificate Management Protocol, RFC 4210.
//
// ⚠ THE ENVELOPE THAT CARRIES CRMF OVER A NETWORK.
//
// crmf.js reads a certificate REQUEST. This reads the message that carries
// one - and the reply, and the confirmation, and the revocation, and the
// twenty-three other things a certificate's life involves:
//
//   PKIMessage ::= SEQUENCE {
//        header      PKIHeader,
//        body        PKIBody,          -- a 27-way CHOICE
//        protection  [0] BIT STRING OPTIONAL,
//        extraCerts  [1] SEQUENCE OF Certificate OPTIONAL }
//
// This is what 3GPP uses: every cellular base station enrols this way, and
// EJBCA and industrial PKI speak it too.
//
// ⚠ THE PROTECTION IS THE PART THAT MATTERS, AND IT IS UNUSUAL.
//
// A CMP message is protected by a MAC or a signature over a structure that
// DOES NOT APPEAR IN THE FILE:
//
//   ProtectedPart ::= SEQUENCE { header PKIHeader, body PKIBody }
//
// The message holds header and body as separate fields; the protection
// covers a SEQUENCE containing both. So the protected bytes have to be
// ASSEMBLED - a header slice, a body slice, and a SEQUENCE wrapper computed
// from their lengths.
//
// That is unusual enough to be worth stating plainly: it is the one place in
// this library where the signed range is built rather than sliced. The
// pieces are still slices - `header_bytes` and `body_bytes` are exact - and
// only the two-byte-or-so wrapper is computed, which is why it can be done
// here at all.
//
// ⚠ AND THE PASSWORD-BASED MAC IS WHERE DEPLOYMENTS GO WRONG.
//
// Most CMP enrolment starts with a shared secret, and the MAC parameters -
// salt, iteration count, hash - are chosen by whoever sent the message. A
// receiver that uses them without looking is running a KDF with an attacker-
// chosen iteration count. The parameters are reported, and an iteration
// count low enough to be useless is a `problem`.

import * as DER from './der_reader.js';
import * as F from './fields.js';
import * as OID from './oid.js';
import * as X509 from './x509.js';
import * as CRMF from './crmf.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, int_value, signed_int_value, der_header }
  from './commons/bytes.js';

import './pkix.js';
import './x509.js';

var fail = make_fail_here('cmp');

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

//   PKIHeader ::= SEQUENCE {
//        pvno                 INTEGER,
//        sender               GeneralName,
//        recipient            GeneralName,
//        messageTime      [0] GeneralizedTime OPTIONAL,
//        protectionAlg    [1] AlgorithmIdentifier OPTIONAL,
//        senderKID        [2] OCTET STRING OPTIONAL,
//        recipKID         [3] OCTET STRING OPTIONAL,
//        transactionID    [4] OCTET STRING OPTIONAL,
//        senderNonce      [5] OCTET STRING OPTIONAL,
//        recipNonce       [6] OCTET STRING OPTIONAL,
//        freeText         [7] PKIFreeText OPTIONAL,
//        generalInfo      [8] SEQUENCE OF InfoTypeAndValue OPTIONAL }
//
// ⚠ sender AND recipient ARE GeneralName, WHICH IS A CHOICE - so they are
// EXPLICITLY tagged wherever they appear tagged, and read raw here because
// x509.js's reader takes a cursor rather than bytes.
F.define('PKIHeader', [
  { name: 'pvno',          type: 'unsigned' },
  { name: 'sender',        type: 'raw' },
  { name: 'recipient',     type: 'raw' },
  { name: 'messageTime',   tag: 0xA0, mode: 'explicit',
    type: 'generalized_time', optional: true },
  { name: 'protectionAlg', tag: 0xA1, mode: 'explicit',
    type: 'AlgorithmIdentifier', optional: true },
  { name: 'senderKID',     tag: 0xA2, mode: 'explicit',
    type: 'octet_string', optional: true },
  { name: 'recipKID',      tag: 0xA3, mode: 'explicit',
    type: 'octet_string', optional: true },
  { name: 'transactionID', tag: 0xA4, mode: 'explicit',
    type: 'octet_string', optional: true },
  { name: 'senderNonce',   tag: 0xA5, mode: 'explicit',
    type: 'octet_string', optional: true },
  { name: 'recipNonce',    tag: 0xA6, mode: 'explicit',
    type: 'octet_string', optional: true },
  { name: 'freeText',      tag: 0xA7, mode: 'explicit', type: 'raw',
    optional: true },
  { name: 'generalInfo',   tag: 0xA8, mode: 'explicit',
    type: 'InfoTypeAndValues', optional: true }
]);

//   InfoTypeAndValue ::= SEQUENCE {
//        infoType   OBJECT IDENTIFIER,
//        infoValue  ANY DEFINED BY infoType OPTIONAL }
//
// The header's generalInfo, and the bodies of genm and genp, are lists of
// these. The value is kept whole, and decoded for the types RFC 9483 has a
// server read or write (see info_entry).
F.define('InfoTypeAndValue', [
  { name: 'infoType',  type: 'oid' },
  { name: 'infoValue', type: 'raw', optional: true }
]);
F.define('InfoTypeAndValues', { kind: 'sequence_of', of: 'InfoTypeAndValue' });

//   PBMParameter ::= SEQUENCE {
//        salt                OCTET STRING,
//        owf                 AlgorithmIdentifier,
//        iterationCount      INTEGER,
//        mac                 AlgorithmIdentifier }
F.define('PBMParameter', [
  { name: 'salt',           type: 'octet_string' },
  { name: 'owf',            type: 'AlgorithmIdentifier' },
  { name: 'iterationCount', type: 'unsigned' },
  { name: 'mac',            type: 'AlgorithmIdentifier' }
]);

//   PKIStatusInfo ::= SEQUENCE {
//        status        PKIStatus,
//        statusString  PKIFreeText OPTIONAL,
//        failInfo      PKIFailureInfo OPTIONAL }
//
// ⚠ statusString WAS `raw`, and an optional raw field matches ANY tag - so
// a status with failInfo and no text had its BIT STRING taken for the
// string, and the failure bits vanished. Every test wrote a statusString,
// and none saw it. PKIFreeText is a type, and its SEQUENCE tag is what
// says it is present.
F.define('PKIFreeText', { kind: 'sequence_of', of: 'utf8_string', min: 1 });

F.define('PKIStatusInfo', [
  { name: 'status',       type: 'unsigned' },
  { name: 'statusString', type: 'PKIFreeText', optional: true },
  { name: 'failInfo',     type: 'bit_string', optional: true }
]);

// ---------------------------------------------------------------------------
// The registries
// ---------------------------------------------------------------------------

// RFC 4210 appendix F. The 27 arms of PKIBody, by context tag.
//
// ⚠ NAMED RATHER THAN NUMBERED, because `body: 2` tells a reader nothing and
// `certification-request` tells them what the message is for.
var BODY_TYPES = {
  0:  { name: 'ir',        detail: 'initialization request' },
  1:  { name: 'ip',        detail: 'initialization response' },
  2:  { name: 'cr',        detail: 'certification request' },
  3:  { name: 'cp',        detail: 'certification response' },
  4:  { name: 'p10cr',     detail: 'a PKCS#10 CSR carried in CMP' },
  5:  { name: 'popdecc',   detail: 'proof-of-possession challenge' },
  6:  { name: 'popdecr',   detail: 'proof-of-possession response' },
  7:  { name: 'kur',       detail: 'key update request' },
  8:  { name: 'kup',       detail: 'key update response' },
  9:  { name: 'krr',       detail: 'key recovery request' },
  10: { name: 'krp',       detail: 'key recovery response' },
  11: { name: 'rr',        detail: 'revocation request' },
  12: { name: 'rp',        detail: 'revocation response' },
  13: { name: 'ccr',       detail: 'cross-certification request' },
  14: { name: 'ccp',       detail: 'cross-certification response' },
  15: { name: 'ckuann',    detail: 'CA key update announcement' },
  16: { name: 'cann',      detail: 'certificate announcement' },
  17: { name: 'rann',      detail: 'revocation announcement' },
  18: { name: 'crlann',    detail: 'CRL announcement' },
  19: { name: 'pkiconf',   detail: 'confirmation' },
  20: { name: 'nested',    detail: 'a message containing other messages' },
  21: { name: 'genm',      detail: 'general message' },
  22: { name: 'genp',      detail: 'general response' },
  23: { name: 'error',     detail: 'error' },
  24: { name: 'certConf',  detail: 'certificate confirmation' },
  25: { name: 'pollReq',   detail: 'poll request' },
  26: { name: 'pollRep',   detail: 'poll response' }
};

// Which arms carry a CertReqMessages, so this module can hand it to crmf.js.
var CARRIES_REQUESTS = { 0: true, 2: true, 7: true, 9: true, 13: true };

// And which carry a CertRepMessage: ip, cp, kup, ccp - RFC 4210 5.3.4.
var CARRIES_CERTIFICATES = { 1: true, 3: true, 8: true, 14: true };

// RFC 4210 section 3.2.3.
var STATUS = {
  0: 'accepted',
  1: 'grantedWithMods',
  2: 'rejection',
  3: 'waiting',
  4: 'revocationWarning',
  5: 'revocationNotification',
  6: 'keyUpdateWarning'
};

// The bits of PKIFailureInfo, RFC 4210 appendix F.
var FAILURE_BITS = [
  'badAlg', 'badMessageCheck', 'badRequest', 'badTime', 'badCertId',
  'badDataFormat', 'wrongAuthority', 'incorrectData', 'missingTimeStamp',
  'badPOP', 'certRevoked', 'certConfirmed', 'wrongIntegrity', 'badRecipientNonce',
  'timeNotAvailable', 'unacceptedPolicy', 'unacceptedExtension',
  'addInfoNotAvailable', 'badSenderNonce', 'badCertTemplate',
  'signerNotTrusted', 'transactionIdInUse', 'unsupportedVersion',
  'notAuthorized', 'systemUnavail', 'systemFailure', 'duplicateCertReq'
];

var PBM_OID = '1.2.840.113533.7.66.13';

// ⚠ BELOW THIS, THE ITERATION COUNT IS NOT PROTECTING ANYTHING.
//
// RFC 4210 gives no minimum, which was reasonable in 1999 and is not now.
// A count in the hundreds is a shared secret a laptop brute-forces in
// minutes, and the sender chooses it.
var MIN_ITERATIONS = 1000;

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

function from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var msg = r.read_sequence();
    var problems = [];

    // ⚠ THE TWO SLICES THE PROTECTION COVERS.
    //
    // Taken before reading, because the protected structure is a SEQUENCE
    // holding both - and that SEQUENCE does not exist in the file.
    var header_start = msg.pos;
    var header = F.read_type(msg, 'PKIHeader');
    var header_bytes = bytes.subarray(header_start, msg.pos);

    var body_start = msg.pos;
    var body = read_body(msg, problems);
    var body_bytes = bytes.subarray(body_start, msg.pos);

    var protection = null;

    if (msg.peek_tag() === 0xA0) {
      var w = msg.read_explicit(0);
      var bits = w.read_bit_string();
      w.expect_end();

      if (bits.unused !== 0) {
        fail('bad-protection-bits',
          'the protection BIT STRING has unused bits');
      }
      protection = bits.bytes;
    }

    var extra_certs = null;

    if (msg.peek_tag() === 0xA1) {
      extra_certs = read_extra_certs(msg.read_explicit(1));
    }

    msg.expect_end();

    var alg = read_protection_algorithm(header, problems);

    if (protection === null && header.protectionAlg !== undefined) {
      problems.push({
        code: 'algorithm-without-protection',
        detail: 'the header names a protection algorithm and the message ' +
                'carries no protection value'
      });
    }

    if (protection !== null && header.protectionAlg === undefined) {
      problems.push({
        code: 'protection-without-algorithm',
        detail: 'the message carries a protection value and the header ' +
                'names no algorithm to check it with'
      });
    }

    // ⚠ AN UNPROTECTED MESSAGE IS NOT AN ERROR AND IS NOT SAFE.
    //
    // RFC 4210 permits it - some announcements are public - but a receiver
    // that acted on an unprotected `ir` would be enrolling whoever asked.
    if (protection === null) {
      problems.push({
        code: 'unprotected',
        detail: 'this message carries no protection. Nothing here says who ' +
                'sent it, and a ' + body.name + ' from an unknown sender is ' +
                'a request from anybody.'
      });
    }

    check_nonces(header, body, problems);

    var general_info = header.generalInfo === undefined
      ? null : header.generalInfo.map(info_entry);

    return {
      version:     int_value(header.pvno, 'pvno'),
      sender:      general_name_of(header.sender),
      recipient:   general_name_of(header.recipient),
      message_time: header.messageTime === undefined
        ? null : header.messageTime,
      transaction_id: header.transactionID === undefined
        ? null : header.transactionID,
      sender_nonce: header.senderNonce === undefined
        ? null : header.senderNonce,
      recip_nonce:  header.recipNonce === undefined
        ? null : header.recipNonce,
      sender_kid:   header.senderKID === undefined
        ? null : header.senderKID,

      // ⚠ generalInfo: what a server needs from the header besides the
      // nonces - read whole, and the three RFC 9483 uses picked out. It was
      // parsed and dropped. implicit_confirm is the CLIENT ASKING; whether
      // to grant it is the server's (and it says so by echoing it).
      general_info: general_info,
      implicit_confirm: info_named(general_info, 'implicitConfirm') !== null,
      confirm_wait_time: parsed_info(general_info, 'confirmWaitTime'),
      cert_profile: parsed_info(general_info, 'certProfile'),

      body:        body,
      protection:  protection,
      protection_algorithm: alg,
      extra_certs: extra_certs,

      // ⚠ THE PIECES, NOT THE WHOLE. See protected_bytes().
      header_bytes: header_bytes,
      body_bytes:   body_bytes,

      problems: problems,
      der:      bytes
    };
  });
}

//   PKIBody ::= CHOICE { ... 27 arms ... }
function read_body(r, problems) {
  var tag = r.peek_tag();

  if (tag === null) {
    fail('no-body', 'the message has no PKIBody');
  }

  // ⚠ CLASS_CONTEXT IS 0x80, NOT 0xA0.
  //
  // 0xA0 is 0x80 | 0x20 - context class WITH the constructed bit - so
  // masking with 0xC0 gives 0x80 and the first version of this check
  // compared it against 0xA0 and refused every legal message.
  //
  // The eye reads 0xA0 as "context 0" because that is how it appears in
  // every field table, and the class bits alone are 0x80.
  if ((tag & 0xC0) !== 0x80) {
    fail('bad-body-tag',
      'the PKIBody is a context-tagged CHOICE, got ' +
      '0x' + tag.toString(16));
  }

  var n = tag & 0x1F;
  var spec = BODY_TYPES[n];

  if (spec === undefined) {
    fail('unknown-body-type',
      'PKIBody arm [' + n + '] is not one of the 27 RFC 4210 defines');
  }

  var content = r.read_explicit(n);
  var out = {
    tag:    n,
    name:   spec.name,
    detail: spec.detail,
    requests: null,
    status:   null,
    certificates: null
  };

  if (CARRIES_REQUESTS[n] === true) {
    // ⚠ HANDED TO crmf.js RATHER THAN RE-READ.
    //
    // The body of an `ir` or `cr` IS a CertReqMessages, and a second reader
    // for it here would drift from the first exactly as the EC helpers did
    // between spki.js and pkcs8.js.
    //
    // The [0] wrapper has already been opened by read_explicit, so what
    // remains is the CertReqMessages SEQUENCE itself - INCLUDING its header,
    // which crmf.from_der expects. Passing the contents instead handed it
    // the first CertReqMsg and it failed on the second.
    var start = content.pos;
    var span = capture_span(content);
    out.requests = CRMF.from_der(span);
  } else if (n === 4) {
    // p10cr carries a PKCS#10 CSR, which csr.js already reads. Kept as
    // bytes so the caller decides - importing csr.js here would make this
    // module depend on it for one arm.
    out.csr_der = content.buf.subarray(content.pos, content.end);
    content.pos = content.end;
  } else if (n === 19) {
    // pkiconf is an explicit NULL - the confirmation carries nothing.
    content.pos = content.end;
  } else if (n === 23) {
    read_error(content, out);
  } else if (CARRIES_CERTIFICATES[n] === true) {
    read_cert_rep(content, out);
  } else if (n === 24) {
    out.confirmations = read_cert_conf(content);
  } else if (n === 11) {
    out.revocations = read_rev_req(content);
  } else if (n === 12) {
    read_rev_rep(content, out);
  } else if (n === 21 || n === 22) {
    // genm and genp: InfoTypeAndValues, the request and the answer.
    out.infos = F.read_type(content, 'InfoTypeAndValues').map(info_entry);
  } else if (n === 25) {
    out.poll_requests = read_poll_req(content);
  } else if (n === 26) {
    out.poll_responses = read_poll_rep(content);
  } else {
    out.raw = content.buf.subarray(content.pos, content.end);
    content.pos = content.end;
  }

  return out;
}

//   ErrorMsgContent ::= SEQUENCE {
//        pKIStatusInfo  PKIStatusInfo,
//        errorCode      INTEGER OPTIONAL,
//        errorDetails   PKIFreeText OPTIONAL }
//
// ⚠ A SEQUENCE AROUND THE STATUS, NOT THE STATUS ITSELF. This read the body
// as a bare PKIStatusInfo - and so refused every error message OpenSSL's
// CMP server sends, with "expected INTEGER, got SEQUENCE". The test that
// covered it built its error body the same wrong way, so the two agreed.
function read_error(r, out) {
  var seq = r.read_sequence();
  out.status = read_status(seq);
  out.error_code = null;
  out.error_details = null;

  if (seq.peek_tag() === 0x02) {
    // errorCode is implementation-specific - OpenSSL puts its own error
    // number here - so it is reported as the bytes' value and not named.
    out.error_code = signed_int_value(seq.read_integer(), 'errorCode');
  }
  if (seq.peek_tag() === 0x30) {
    out.error_details = read_free_text(seq);
  }
  seq.expect_end();
}

//   CertRepMessage ::= SEQUENCE {
//        caPubs    [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
//        response      SEQUENCE OF CertResponse }
//
//   CertResponse ::= SEQUENCE {
//        certReqId         INTEGER,
//        status            PKIStatusInfo,
//        certifiedKeyPair  CertifiedKeyPair OPTIONAL,
//        rspInfo           OCTET STRING OPTIONAL }
//
//   CertifiedKeyPair ::= SEQUENCE {
//        certOrEncCert     CertOrEncCert,
//        privateKey    [0] EncryptedValue OPTIONAL,
//        publicationInfo [1] PKIPublicationInfo OPTIONAL }
//
//   CertOrEncCert ::= CHOICE {
//        certificate    [0] CMPCertificate,
//        encryptedCert  [1] EncryptedValue }
//
// The PKIXCMP module is EXPLICIT TAGS, so [0] wraps a whole Certificate.
//
// ⚠ caPubs ARE NOT TRUST ANCHORS BECAUSE THEY ARRIVED. RFC 4210 5.3.4:
// a CA may send them, and a client that installs them on the strength of
// a MAC keyed by a one-time enrolment password has let whoever knew the
// password choose its roots. Reported as `ca_pubs`, and nothing more.
function read_cert_rep(r, out) {
  var seq = r.read_sequence();
  out.ca_pubs = null;

  if (seq.peek_tag() === 0xA1) {
    var pubs = seq.read_explicit(1).read_sequence();
    out.ca_pubs = [];
    while (pubs.remaining() > 0) {
      out.ca_pubs.push(capture_span(pubs));
    }
    if (out.ca_pubs.length === 0) {
      fail('bad-ca-pubs', 'caPubs is SIZE (1..MAX) - present and empty');
    }
  }

  var list = seq.read_sequence();
  out.responses = [];

  while (list.remaining() > 0) {
    out.responses.push(read_cert_response(list));
  }
  seq.expect_end();

  // The certificates themselves, for the common case of one each.
  out.certificates = out.responses.map(function (x) {
    return x.certificate;
  }).filter(function (c) { return c !== null; });
}

function read_cert_response(r) {
  var cr = r.read_sequence();
  var out = {
    cert_req_id: signed_int_value(cr.read_integer(), 'certReqId'),
    status: read_status(cr),
    certificate: null,
    encrypted_certificate: null,
    private_key: null,
    rsp_info: null
  };

  if (cr.peek_tag() === 0x30) {
    var kp = cr.read_sequence();
    var t = kp.peek_tag();

    if (t === 0xA0) {
      var c = kp.read_explicit(0);
      out.certificate = capture_span(c);
      c.expect_end();
    } else if (t === 0xA1) {
      // Encrypted to the requester's key: indirect proof of possession,
      // RFC 4210 5.2.8.3. Kept whole - decrypting it is the caller's.
      var e = kp.read_explicit(1);
      out.encrypted_certificate = capture_span(e);
      e.expect_end();
    } else {
      fail('bad-cert-or-enc-cert',
        'CertOrEncCert is [0] a certificate or [1] an encrypted one');
    }

    if (kp.peek_tag() === 0xA0) {
      var k = kp.read_explicit(0);
      out.private_key = capture_span(k);
      k.expect_end();
    }
    if (kp.peek_tag() === 0xA1) {
      kp.read_explicit(1);
    }
    kp.expect_end();
  }

  if (cr.peek_tag() === 0x04) {
    out.rsp_info = cr.read_octet_string();
  }
  cr.expect_end();

  // RFC 4210 5.3.4: a certificate comes with accepted or grantedWithMods,
  // and with nothing else. One beside a rejection is a contradiction a
  // client should not get to resolve by picking the half it likes.
  var granted = out.status.value === 0 || out.status.value === 1;
  var has_cert = out.certificate !== null || out.encrypted_certificate !== null;

  if (has_cert && !granted) {
    fail('certificate-without-grant',
      'response ' + out.cert_req_id + ' carries a certificate with status ' +
      (out.status.name || out.status.value));
  }

  return out;
}

//   CertConfirmContent ::= SEQUENCE OF CertStatus
//   CertStatus ::= SEQUENCE {
//        certHash    OCTET STRING,
//        certReqId   INTEGER,
//        statusInfo  PKIStatusInfo OPTIONAL }
//
// certHash is over the certificate DER, with the hash of the certificate's
// own signature algorithm (RFC 4210 5.3.18) - the CA computes the same and
// compares, which is how it learns the client got the certificate it sent.
function read_cert_conf(r) {
  var seq = r.read_sequence();
  var out = [];

  while (seq.remaining() > 0) {
    var cs = seq.read_sequence();
    var item = {
      cert_hash: cs.read_octet_string(),
      cert_req_id: signed_int_value(cs.read_integer(), 'certReqId'),
      status: null
    };
    if (cs.peek_tag() === 0x30) {
      item.status = read_status(cs);
    }
    cs.expect_end();
    out.push(item);
  }

  return out;
}

// ---------------------------------------------------------------------------
// What a server reads besides enrolment: revocation, polling, general
// messages - RFC 4210 5.3.9 to 5.3.22, as RFC 9483 profiles them
// ---------------------------------------------------------------------------

// { id, name, value } - name without the table's it_ prefix, value the
// infoValue's DER or null - and `parsed` for the types decoded here.
function info_entry(itav) {
  var name = OID.name_of(itav.infoType);
  var out = {
    id: OID.to_string(itav.infoType),
    name: name !== null && name.indexOf('it_') === 0 ? name.slice(3) : null,
    value: itav.infoValue === undefined ? null : itav.infoValue
  };
  var parse = INFO_READERS[out.name];
  if (parse !== undefined && out.value !== null) {
    out.parsed = DER.read(out.value, parse);
  }
  return out;
}

// The infoValues RFC 9483 has a server read or a client receive.
var INFO_READERS = {
  // GeneralizedTime: how long the server waits for certConf.
  confirmWaitTime: function (r) { return r.read_generalized_time(); },
  // RFC 9480 2.4: SEQUENCE SIZE (1..MAX) OF UTF8String - the profile the
  // client asks to be enrolled under.
  certProfile: function (r) { return read_free_text(r); },
  // RFC 9480 2.3.1: SEQUENCE SIZE (1..MAX) OF CMPCertificate - DER each.
  caCerts: function (r) {
    var seq = r.read_sequence();
    var out = [];
    while (seq.remaining() > 0) { out.push(capture_span(seq)); }
    if (out.length === 0) {
      fail('bad-ca-certs', 'caCerts is SIZE (1..MAX); with none, the value is absent');
    }
    return out;
  },
  // RFC 9483 4.3.2: the request's root CA certificate - CMPCertificate.
  rootCaCert: function (r) { return capture_span(r); },
  // RFC 9480 2.3.2: RootCaKeyUpdateContent ::= SEQUENCE {
  //   newWithNew CMPCertificate, newWithOld [0] CMPCertificate OPTIONAL,
  //   oldWithNew [1] CMPCertificate OPTIONAL } - EXPLICIT, as the module.
  rootCaKeyUpdate: function (r) {
    var seq = r.read_sequence();
    var out = { new_with_new: capture_span(seq), new_with_old: null, old_with_new: null };
    if (seq.peek_tag() === 0xA0) {
      var a = seq.read_explicit(0); out.new_with_old = capture_span(a); a.expect_end();
    }
    if (seq.peek_tag() === 0xA1) {
      var b = seq.read_explicit(1); out.old_with_new = capture_span(b); b.expect_end();
    }
    seq.expect_end();
    return out;
  }
};

function info_named(list, name) {
  if (list === null) { return null; }
  var found = list.filter(function (i) { return i.name === name; });
  if (found.length > 1) {
    fail('duplicate-info', 'generalInfo carries ' + name + ' twice');
  }
  return found.length === 0 ? null : found[0];
}

function parsed_info(list, name) {
  var i = info_named(list, name);
  return i === null || i.parsed === undefined ? null : i.parsed;
}

//   RevReqContent ::= SEQUENCE OF RevDetails
//   RevDetails ::= SEQUENCE {
//        certDetails      CertTemplate,
//        crlEntryDetails  Extensions OPTIONAL }
//
// The template is crmf.js's - issuer and serial are what name the
// certificate - and the entry extensions are x509.js's, which decodes the
// reason and invalidity date as it does for a CRL entry.
function read_rev_req(r) {
  var seq = r.read_sequence();
  var out = [];

  while (seq.remaining() > 0) {
    var d = seq.read_sequence();
    var template = CRMF.read_template(F.read_type(d, 'CertTemplate'));
    var extensions = d.remaining() > 0
      ? F.read_type(d, 'Extensions').map(function (e) { return X509.read_extension(e); }) : [];
    d.expect_end();
    out.push({
      template: template,
      issuer: template.issuer,
      serial: template.serial,
      serial_hex: template.serial === null ? null : hex(template.serial),
      reason: entry_parsed(extensions, 'crlReason'),
      invalidity_date: entry_parsed(extensions, 'invalidityDate'),
      extensions: extensions
    });
  }
  if (out.length === 0) {
    fail('empty-revocation-request', 'a revocation request names no certificate');
  }
  return out;
}

// x509.extension's lookup, which takes any { extensions }.
function entry_parsed(extensions, name) {
  var e = X509.extension({ extensions: extensions }, name);
  return e === null ? null : e.parsed;
}

//   RevRepContent ::= SEQUENCE {
//        status    SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
//        revCerts  [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
//        crls      [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL }
//   CertId ::= SEQUENCE { issuer GeneralName, serialNumber INTEGER }
function read_rev_rep(r, out) {
  var seq = r.read_sequence();
  var st = seq.read_sequence();
  out.revocation_statuses = [];
  while (st.remaining() > 0) { out.revocation_statuses.push(read_status(st)); }
  out.rev_certs = null;
  out.crls = null;

  if (seq.peek_tag() === 0xA0) {
    var rc = seq.read_explicit(0).read_sequence();
    out.rev_certs = [];
    while (rc.remaining() > 0) {
      var id = rc.read_sequence();
      var issuer = X509.read_general_name(id);
      var serial = id.read_integer();
      id.expect_end();
      out.rev_certs.push({ issuer: issuer, serial: serial, serial_hex: hex(serial) });
    }
  }
  if (seq.peek_tag() === 0xA1) {
    var cl = seq.read_explicit(1).read_sequence();
    out.crls = [];
    while (cl.remaining() > 0) { out.crls.push(capture_span(cl)); }
  }
  seq.expect_end();
}

//   PollReqContent ::= SEQUENCE OF SEQUENCE { certReqId INTEGER }
//
// certReqId -1: polling for an rr or genm answered "waiting" (RFC 9483
// 4.4), where there is no request number. Read as the signed number it is.
function read_poll_req(r) {
  var seq = r.read_sequence();
  var out = [];
  while (seq.remaining() > 0) {
    var p = seq.read_sequence();
    out.push({ cert_req_id: signed_int_value(p.read_integer(), 'certReqId') });
    p.expect_end();
  }
  return out;
}

//   PollRepContent ::= SEQUENCE OF SEQUENCE {
//        certReqId   INTEGER,
//        checkAfter  INTEGER,      -- seconds
//        reason      PKIFreeText OPTIONAL }
function read_poll_rep(r) {
  var seq = r.read_sequence();
  var out = [];
  while (seq.remaining() > 0) {
    var p = seq.read_sequence();
    var item = {
      cert_req_id: signed_int_value(p.read_integer(), 'certReqId'),
      check_after: int_value(p.read_integer(), 'checkAfter'),
      reason: null
    };
    if (p.peek_tag() === 0x30) { item.reason = read_free_text(p); }
    p.expect_end();
    out.push(item);
  }
  return out;
}

// PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
function read_free_text(r) {
  var seq = r.read_sequence();
  var out = [];

  while (seq.remaining() > 0) {
    out.push(seq.read_utf8_string());
  }
  if (out.length === 0) {
    fail('bad-free-text', 'PKIFreeText is SIZE (1..MAX) - present and empty');
  }
  return out;
}

// The complete encoding of the next value, header included - for handing to
// another module's from_der, which expects to open a structure rather than
// find one already open.
function capture_span(r) {
  var start = r.pos;
  r.capture();
  return r.buf.subarray(start, r.pos);
}

function read_status(r) {
  var info = F.read_type(r, 'PKIStatusInfo');
  var value = int_value(info.status, 'PKIStatus');
  var failures = [];

  if (info.failInfo !== undefined) {
    var bytes = info.failInfo.bytes;
    var total = bytes.length * 8 - info.failInfo.unused;
    var i;

    for (i = 0; i < total; i++) {
      if (((bytes[Math.floor(i / 8)] >> (7 - (i % 8))) & 1) === 1) {
        failures.push(FAILURE_BITS[i] === undefined
          ? 'bit-' + i : FAILURE_BITS[i]);
      }
    }
  }

  return {
    value:   value,
    name:    STATUS[value] === undefined ? null : STATUS[value],
    text:    info.statusString === undefined ? null : info.statusString,
    failures: failures
  };
}

function read_extra_certs(r) {
  var seq = r.read_sequence();
  var out = [];

  while (seq.remaining() > 0) {
    var start = seq.pos;
    seq.capture();
    out.push(X509.from_der(seq.buf.subarray(start, seq.pos)));
  }

  return out;
}

function general_name_of(bytes) {
  return DER.read(bytes, function (r) {
    return X509.read_general_name(r);
  });
}

// ---------------------------------------------------------------------------
// The protection algorithm
// ---------------------------------------------------------------------------

function read_protection_algorithm(header, problems) {
  if (header.protectionAlg === undefined) {
    return null;
  }

  var dotted = OID.to_string(header.protectionAlg.algorithm);
  var name = OID.name_of(header.protectionAlg.algorithm) || dotted;

  if (dotted !== PBM_OID) {
    // A signature-based protection: the algorithm is an ordinary signature
    // identifier and the key is the sender's.
    return {
      kind:      'signature',
      algorithm: name,
      note: 'the protection is a signature by the sender. The key comes ' +
            'from extraCerts or from a certificate you already hold - ' +
            'senderKID says which.'
    };
  }

  // ⚠ PASSWORD-BASED MAC: THE PARAMETERS ARE CHOSEN BY THE SENDER.
  //
  // Most CMP enrolment starts with a shared secret, and a receiver that runs
  // the KDF without looking is running it with an attacker-chosen iteration
  // count.
  if (header.protectionAlg.parameters === undefined) {
    problems.push({
      code: 'pbm-without-parameters',
      detail: 'password-based MAC with no parameters - there is no salt, ' +
              'no iteration count and nothing to derive a key with'
    });
    return { kind: 'password-mac', algorithm: name, parameters: null };
  }

  var p = DER.read(header.protectionAlg.parameters, function (r) {
    return F.read_type(r, 'PBMParameter');
  });

  var iterations = int_value(p.iterationCount, 'iterationCount');
  var owf = OID.name_of(p.owf.algorithm) || OID.to_string(p.owf.algorithm);
  var mac = OID.name_of(p.mac.algorithm) || OID.to_string(p.mac.algorithm);

  if (iterations < MIN_ITERATIONS) {
    problems.push({
      code: 'weak-iteration-count',
      detail: 'the password-based MAC uses ' + iterations + ' iterations. ' +
              'The SENDER chose that number, and a count this low leaves ' +
              'the shared secret open to a laptop.'
    });
  }

  if (p.salt.length < 8) {
    problems.push({
      code: 'short-salt',
      detail: 'the MAC salt is ' + p.salt.length + ' bytes. A short salt ' +
              'lets one precomputation cover many enrolments.'
    });
  }

  return {
    kind:       'password-mac',
    algorithm:  name,
    salt:       p.salt,
    iterations: iterations,
    // ⚠ THE ONE-WAY FUNCTION IS APPLIED iterationCount TIMES IN ALL, first
    // to secret||salt, and then the MAC uses the result as its key. RFC
    // 4211 4.4 - it is not PBKDF2, and PBKDF2 would derive a different key.
    owf:        owf,
    mac:        mac,
    // ⚠ THIS NOTE HAD THE ORDER AND THE COUNT BOTH WRONG - "salt||secret,
    // then N more times" - and a caller following it derived a key that
    // verified nothing. RFC 4211 4.4: K = secret||salt, hashed, and the
    // hash repeated until iterationCount hashes in all. Checked against a
    // response from OpenSSL's CMP server, cmp-mock-ip.der.
    note: 'RFC 4211 4.4: hash secret||salt with ' + owf + ', and keep ' +
          'hashing the result until ' + owf + ' has run ' + iterations +
          ' times in all; that is the ' + mac + ' key. This is NOT PBKDF2.'
  };
}

// ---------------------------------------------------------------------------
// The protected bytes
// ---------------------------------------------------------------------------

// ⚠ THE ONE PLACE IN THIS LIBRARY WHERE THE SIGNED RANGE IS ASSEMBLED.
//
//   ProtectedPart ::= SEQUENCE { header PKIHeader, body PKIBody }
//
// The message holds header and body as separate fields; the protection
// covers a SEQUENCE containing both, and that SEQUENCE is nowhere in the
// file. So it has to be built.
//
// What makes that safe here, where re-encoding is refused everywhere else:
// the two CONTENTS are exact slices, and only the SEQUENCE header is
// computed - a tag byte and a length. There is no re-serialization of any
// field, so there is nothing that could come out differently.
function protected_bytes(message) {
  var length = message.header_bytes.length + message.body_bytes.length;
  var header = der_header(0x30, length);

  var out = new Uint8Array(header.length + length);
  out.set(header, 0);
  out.set(message.header_bytes, header.length);
  out.set(message.body_bytes, header.length + message.header_bytes.length);

  return out;
}

// What has to be checked, and with what.
function verification_plan(message) {
  if (message.protection === null) {
    return {
      verifiable: false,
      reason: 'this message carries no protection'
    };
  }

  var alg = message.protection_algorithm;

  if (alg === null) {
    return {
      verifiable: false,
      reason: 'the message is protected and the header names no algorithm'
    };
  }

  var plan = {
    verifiable: true,
    kind:       alg.kind,
    bytes:      protected_bytes(message),
    // `signature` in every verification_plan here; for a password-based
    // MAC it is the MAC, and `algorithm` names the MAC.
    signature:  message.protection,
    // ⚠ NAMED, because "the message" is ambiguous and this is not it.
    covers:     'ProtectedPart - a SEQUENCE of the header and body, ' +
                'assembled rather than sliced because it does not appear in ' +
                'the file'
  };

  if (alg.kind === 'signature') {
    plan.algorithm = alg.algorithm;
    plan.key_from = message.extra_certs !== null && message.extra_certs.length
      ? 'extraCerts'
      : 'a certificate you already hold - senderKID says which';
  } else {
    plan.algorithm = alg.mac;
    plan.owf = alg.owf;
    plan.salt = alg.salt;
    plan.iterations = alg.iterations;
    plan.derivation = alg.note;
  }

  return plan;
}

// ---------------------------------------------------------------------------
// Nonces
// ---------------------------------------------------------------------------

// ⚠ THE REPLAY DEFENCE, AND THE COMMONEST THING TO GET WRONG.
//
// RFC 4210 5.1.1: a response must carry the request's senderNonce as its
// recipNonce. A receiver that does not check it will accept a replayed
// response - which for a `cp` means accepting an old certificate as the
// answer to a new request.
function check_nonces(header, body, problems) {
  var is_response = /^(ip|cp|kup|krp|rp|ccp|genp|pollRep)$/.test(body.name);

  if (is_response && header.recipNonce === undefined) {
    problems.push({
      code: 'response-without-recipient-nonce',
      detail: 'a ' + body.name + ' carries no recipNonce, so nothing ties ' +
              'it to a request. RFC 4210 5.1.1 requires it, and without it ' +
              'a replayed response is indistinguishable from a fresh one.'
    });
  }

  if (header.transactionID === undefined) {
    problems.push({
      code: 'no-transaction-id',
      detail: 'no transactionID: nothing groups this message with the rest ' +
              'of its exchange'
    });
  }
}

// Whether a response answers a given request.
//
// ⚠ NOT DONE AUTOMATICALLY, because a caller who did not keep the request
// cannot check it - and a function that silently returned true when it had
// nothing to compare would be worse than no function.
function answers(response, request) {
  if (response.recip_nonce === null) {
    return {
      matches: false,
      reason: 'the response carries no recipNonce'
    };
  }

  if (request.sender_nonce === null) {
    return {
      matches: false,
      reason: 'the request carried no senderNonce, so there is nothing for ' +
              'the response to echo'
    };
  }

  var nonce_ok = hex(response.recip_nonce) === hex(request.sender_nonce);
  var txn_ok = request.transaction_id !== null &&
               response.transaction_id !== null &&
               hex(response.transaction_id) === hex(request.transaction_id);

  return {
    matches: nonce_ok && txn_ok,
    nonce_matches: nonce_ok,
    transaction_matches: txn_ok,
    reason: nonce_ok && txn_ok
      ? null
      : (!nonce_ok
          ? 'the recipNonce does not echo the request senderNonce'
          : 'the transactionID differs')
  };
}

export {
  from_der,
  protected_bytes,
  verification_plan,
  answers,
  BODY_TYPES,
  STATUS,
  FAILURE_BITS
};

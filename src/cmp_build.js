// Building CMP messages - RFC 4210.
//
// Two halves. The ENVELOPE - header, protection, the ProtectedPart bytes:
//
//   var msg = cmp_build.prepare({ body: 'ir', content: crmf_der, ... });
//   var der = cmp_build.assemble(msg, mac_or_signature);
//
// And the BODIES a CA writes: prepare() takes
// any PKIBody arm as `content` bytes, and these produce those bytes for the
// arms a server answers with -
//
//   cert_rep(parts)     ip, cp, kup, ccp: certificates, with a status each
//   error(parts)        error: a status, failure bits, and why
//   pkiconf()           pkiconf: the NULL that ends an exchange
//   cert_conf(list)     certConf: the client's "I got it", by hash
//
//   var body = cmp_build.cert_rep({ responses: [{ cert_req_id: 0,
//                 certificate: issued_der }] });
//   var msg = cmp_build.prepare({ body: 'ip', content: body,
//                 transaction_id: req.transaction_id,
//                 recip_nonce: req.sender_nonce, sender_nonce: random(16),
//                 sender: ca_name, recipient: req.sender, protection });
//
// ⚠ THE RESPONSE ANSWERS ONE REQUEST, AND THE HEADER IS WHAT SAYS WHICH.
// transaction_id copied from the request, recip_nonce = the request's
// sender_nonce (RFC 4210 5.1.1). A client checks both - OpenSSL's refuses
// the response otherwise - and cmp.answers() is the same check.

import * as W from './der_writer.js';

import * as OID from './oid.js';
import * as CMP from './cmp.js';
import { status_info_to_der, algorithm_to_der, general_name_to_der,
  number_bytes as pkix_number_bytes } from './pkix.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, int_bytes } from './commons/bytes.js';
import { encode_utf8 } from './commons/encode_text.js';

var fail = make_fail_here('cmp');
var fail_cmp = fail;

// RFC 4210 5.2.3 - PKIStatus. DELIBERATELY the writer's own table rather
// than cmp.js's turned round: see commons/README.
var STATUS = {
  accepted: 0, grantedWithMods: 1, rejection: 2, waiting: 3,
  revocationWarning: 4, revocationNotification: 5, keyUpdateWarning: 6
};

// RFC 4210 appendix F, PKIFailureInfo - the bit positions.
var FAILURE_BITS = {
  badAlg: 0, badMessageCheck: 1, badRequest: 2, badTime: 3, badCertId: 4,
  badDataFormat: 5, wrongAuthority: 6, incorrectData: 7,
  missingTimeStamp: 8, badPOP: 9, certRevoked: 10, certConfirmed: 11,
  wrongIntegrity: 12, badRecipientNonce: 13, timeNotAvailable: 14,
  unacceptedPolicy: 15, unacceptedExtension: 16, addInfoNotAvailable: 17,
  badSenderNonce: 18, badCertTemplate: 19, signerNotTrusted: 20,
  transactionIdInUse: 21, unsupportedVersion: 22, notAuthorized: 23,
  systemUnavail: 24, systemFailure: 25, duplicateCertReq: 26
};

// { status, text, failure } -> PKIStatusInfo. status defaults to `deflt`.
function status_info(p, deflt) {
  var name = p.status === undefined ? deflt : p.status;

  if (STATUS[name] === undefined) {
    fail('bad-status', 'status is one of ' + Object.keys(STATUS).join(', '));
  }

  var bits = (p.failure || []).map(function (f) {
    if (FAILURE_BITS[f] === undefined) {
      fail('unknown-failure', 'unknown failInfo "' + f + '"');
    }
    return FAILURE_BITS[f];
  });

  return { name: name, der: status_info_to_der(STATUS[name], p.text, bits) };
}

// certReqId: the request's own number, echoed. -1 is what a response to a
// p10cr uses (RFC 4210 5.3.4) - there is no CertReqMsg to number.
function cert_req_id(n) {
  var id = n === undefined ? 0 : n;

  if (id === -1) {
    return W.integer([0xFF]);
  }
  if (typeof id !== 'number' || id % 1 !== 0 || id < 0 || id > 0x7FFFFFFF) {
    fail('bad-cert-req-id', 'certReqId is the request\'s number, or -1 ' +
      'answering a p10cr');
  }
  return W.unsigned(int_bytes(id));
}

// ---------------------------------------------------------------------------

//   CertRepMessage ::= SEQUENCE {
//      caPubs    [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
//      response      SEQUENCE OF CertResponse }
//
// parts.responses: [{ cert_req_id, status, text, failure, certificate,
// rsp_info }]. A certificate goes with accepted or grantedWithMods and
// must be there for them; anything else carries none (RFC 4210 5.3.4).
//
// parts.ca_pubs: CA certificates for the client to - perhaps - trust. A
// client should not install them because they arrived; see cmp.js.
function cert_rep(parts) {
  if (!parts || !Array.isArray(parts.responses) ||
      parts.responses.length === 0) {
    fail('bad-input', 'cert_rep needs { responses: [...] }');
  }

  var fields = [];

  if (parts.ca_pubs !== undefined && parts.ca_pubs !== null) {
    if (!Array.isArray(parts.ca_pubs) || parts.ca_pubs.length === 0) {
      fail('bad-ca-pubs', 'caPubs is SIZE (1..MAX) - omit it, or give one');
    }
    fields.push(W.explicit(1, W.sequence(parts.ca_pubs.map(to_bytes))));
  }

  fields.push(W.sequence(parts.responses.map(cert_response)));

  return W.to_bytes(W.sequence(fields));
}

//   CertResponse ::= SEQUENCE {
//      certReqId         INTEGER,
//      status            PKIStatusInfo,
//      certifiedKeyPair  CertifiedKeyPair OPTIONAL,  -- { [0] Certificate }
//      rspInfo           OCTET STRING OPTIONAL }
function cert_response(r, i) {
  if (!r || typeof r !== 'object') {
    fail('bad-input', 'response ' + i + ' is an object');
  }

  var has_cert = r.certificate !== undefined && r.certificate !== null;
  var st = status_info(r, has_cert ? 'accepted' : 'rejection');
  var granted = st.name === 'accepted' || st.name === 'grantedWithMods';

  if (granted && !has_cert) {
    fail('missing-certificate', 'response ' + i + ' is ' + st.name +
      ' and carries no certificate');
  }
  if (!granted && has_cert) {
    fail('certificate-without-grant', 'response ' + i + ' is ' + st.name +
      ' - a certificate goes only with accepted or grantedWithMods');
  }

  var fields = [cert_req_id(r.cert_req_id), st.der];

  if (has_cert) {
    fields.push(W.sequence([W.explicit(0, to_bytes(r.certificate))]));
  }
  if (r.rsp_info !== undefined && r.rsp_info !== null) {
    fields.push(W.octet_string(to_bytes(r.rsp_info)));
  }

  return W.sequence(fields);
}

//   ErrorMsgContent ::= SEQUENCE {
//      pKIStatusInfo  PKIStatusInfo,
//      errorCode      INTEGER OPTIONAL,
//      errorDetails   PKIFreeText OPTIONAL }
//
// status defaults to rejection, and accepted is refused - an error that
// says it succeeded is two answers.
function error(parts) {
  var p = parts || {};
  var st = status_info(p, 'rejection');

  if (st.name === 'accepted' || st.name === 'grantedWithMods') {
    fail('bad-status', 'an error message does not say ' + st.name);
  }

  var fields = [st.der];

  if (p.error_code !== undefined && p.error_code !== null) {
    if (typeof p.error_code !== 'number' || p.error_code % 1 !== 0 ||
        p.error_code < 0) {
      fail('bad-input', 'error_code is a non-negative integer');
    }
    fields.push(W.unsigned(int_bytes(p.error_code)));
  }

  if (p.error_details !== undefined && p.error_details !== null) {
    if (!Array.isArray(p.error_details) || p.error_details.length === 0) {
      fail('bad-input', 'error_details is a non-empty list of strings');
    }
    fields.push(W.sequence(p.error_details.map(function (t) {
      return W.utf8_string(String(t));
    })));
  }

  return W.to_bytes(W.sequence(fields));
}

// PKIConfirmContent ::= NULL
function pkiconf() {
  return W.to_bytes(W.null());
}

//   CertConfirmContent ::= SEQUENCE OF CertStatus
//   CertStatus ::= SEQUENCE {
//      certHash    OCTET STRING,
//      certReqId   INTEGER,
//      statusInfo  PKIStatusInfo OPTIONAL }
//
// cert_hash: the certificate's DER hashed with the hash of ITS OWN
// signature algorithm - SHA-256 for ecdsa-with-SHA256 (RFC 4210 5.3.18).
// statusInfo absent means accepted; give { status: 'rejection', ... } to
// refuse a certificate the CA sent.
function cert_conf(list) {
  if (!Array.isArray(list) || list.length === 0) {
    fail('bad-input', 'cert_conf takes a list of { cert_hash, cert_req_id }');
  }

  return W.to_bytes(W.sequence(list.map(function (c, i) {
    if (!c || !c.cert_hash || to_bytes(c.cert_hash).length < 20) {
      fail('bad-input', 'confirmation ' + i + ' needs cert_hash, the ' +
        'certificate\'s hash');
    }
    var fields = [W.octet_string(to_bytes(c.cert_hash)),
                  cert_req_id(c.cert_req_id)];
    if (c.status !== undefined || c.failure !== undefined) {
      fields.push(status_info(c, 'accepted').der);
    }
    return W.sequence(fields);
  })));
}

// ---------------------------------------------------------------------------
// Revocation, polling, general messages - the rest of what a server writes
// ---------------------------------------------------------------------------

//   InfoTypeAndValue ::= SEQUENCE { infoType OID, infoValue ANY OPTIONAL }
//
// { type, value }: type by name ('implicitConfirm', as cmp.js names it) or
// dotted OID; value as the type takes it -
//
//   implicitConfirm    nothing - NULL is written, as OpenSSL writes it
//   confirmWaitTime    a Date
//   certProfile        a list of strings
//   caCerts            a list of certificates (DER or read), or none: absent
//   rootCaCert         a certificate (the root to update), or none: absent
//   rootCaKeyUpdate    { new_with_new, new_with_old, old_with_new? }, or
//                      none: absent - "no update available"
//   anything else      the infoValue's DER, or nothing
function info_der(info, i) {
  if (!info || typeof info.type !== 'string') {
    fail_cmp('bad-info', 'info ' + i + ' is { type, value }');
  }
  var dotted = /^\d+(\.\d+)+$/.test(info.type);
  var oid;
  try {
    oid = dotted ? OID.from_string(info.type) : OID.by_name('it_' + info.type);
  } catch (e) {
    fail_cmp('unknown-info-type', '"' + info.type + '" is not an InfoType this library names; ' +
      'pass its dotted OID and the value\'s DER');
  }
  var name = dotted ? null : info.type;
  var v = info.value;
  var value = null;

  if (name === 'implicitConfirm') {
    value = W.null();
  } else if (name === 'confirmWaitTime') {
    value = W.generalized_time(v);
  } else if (name === 'certProfile') {
    if (!Array.isArray(v) || v.length === 0) {
      fail_cmp('bad-info', 'certProfile is a non-empty list of profile names');
    }
    value = W.sequence(v.map(function (t) { return W.utf8_string(String(t)); }));
  } else if (name === 'caCerts') {
    value = v === undefined || v === null || v.length === 0 ? null : W.sequence(v.map(cert_der));
  } else if (name === 'rootCaCert') {
    // RFC 9483 4.3.2's request: the root to be updated, or nothing.
    value = v === undefined || v === null ? null : cert_der(v);
  } else if (name === 'rootCaKeyUpdate') {
    // RFC 9483 4.3.2's answer: absent when there is no update; when there
    // is, newWithNew and newWithOld are both REQUIRED - the second is how a
    // client trusting the old root comes to trust the new one.
    if (v !== undefined && v !== null) {
      if (!v.new_with_new || !v.new_with_old) {
        fail_cmp('bad-info', 'an update carries new_with_new and new_with_old ' +
          '(RFC 9483 4.3.2); with no update, leave the value out');
      }
      var f = [cert_der(v.new_with_new), W.explicit(0, cert_der(v.new_with_old))];
      if (v.old_with_new) { f.push(W.explicit(1, cert_der(v.old_with_new))); }
      value = W.sequence(f);
    }
  } else if (v !== undefined && v !== null) {
    value = to_bytes(v);
  }

  return W.sequence(value === null ? [W.oid(oid)] : [W.oid(oid), value]);
}

function infos_der(list) {
  return W.sequence(list.map(info_der));
}

function cert_der(c) {
  return c instanceof Uint8Array ? c : to_bytes(c.der);
}

// genm and genp bodies: GenMsgContent / GenRepContent ::= SEQUENCE OF
// InfoTypeAndValue. A genp answers each type asked for - with the value, or
// without one when the server has nothing (RFC 9483 4.3).
// One structure, two names: GenMsgContent and GenRepContent are both
// SEQUENCE OF InfoTypeAndValue. Exported as genm and genp.
function genm(infos) {
  if (!Array.isArray(infos)) {
    fail_cmp('bad-input', 'genm and genp take a list of { type, value }');
  }
  return W.to_bytes(infos_der(infos));
}

// RFC 9483 4.3.1: the CA certificates - absent when there are none.
function genp_ca_certs(certs) {
  return genm([{ type: 'caCerts', value: certs }]);
}

// RFC 9483 4.3.2: a root CA's key update - the new root, and the
// certificates linking it to the old one in both directions; called with
// nothing, the answer that there is no update.
function genp_root_ca_key_update(parts) {
  return genm([{ type: 'rootCaKeyUpdate', value: parts }]);
}

//   RevRepContent ::= SEQUENCE {
//      status    SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
//      revCerts  [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
//      crls      [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL }
//
// responses: one { status, failure, text } per RevDetails, in order;
// status defaults to accepted. rev_certs: [{ issuer, serial }] - the issuer
// a Name or a GeneralName, either form. crls: DER.
function rev_rep(parts) {
  if (!parts || !Array.isArray(parts.responses) || parts.responses.length === 0) {
    fail_cmp('bad-input', 'rev_rep needs { responses: [...] } - one per revocation asked for');
  }
  var fields = [W.sequence(parts.responses.map(function (r) {
    return status_info(r || {}, 'accepted').der;
  }))];

  if (parts.rev_certs !== undefined && parts.rev_certs !== null) {
    if (!Array.isArray(parts.rev_certs) || parts.rev_certs.length === 0) {
      fail_cmp('bad-input', 'rev_certs is SIZE (1..MAX) - omit it, or give one');
    }
    fields.push(W.explicit(0, W.sequence(parts.rev_certs.map(function (c, i) {
      if (!c || c.issuer === undefined || c.serial === undefined) {
        fail_cmp('bad-input', 'rev_certs[' + i + '] is { issuer, serial }');
      }
      return W.sequence([general_name(c.issuer, 'issuer'), W.integer(to_bytes(c.serial))]);
    }))));
  }
  if (parts.crls !== undefined && parts.crls !== null) {
    if (!Array.isArray(parts.crls) || parts.crls.length === 0) {
      fail_cmp('bad-input', 'crls is SIZE (1..MAX) - omit it, or give one');
    }
    fields.push(W.explicit(1, W.sequence(parts.crls.map(cert_der))));
  }
  return W.to_bytes(W.sequence(fields));
}

//   PollRepContent ::= SEQUENCE OF SEQUENCE {
//      certReqId INTEGER, checkAfter INTEGER, reason PKIFreeText OPTIONAL }
//
// check_after in seconds. cert_req_id -1 answers polling for an rr or genm
// (RFC 9483 4.4).
function poll_rep(list) {
  if (!Array.isArray(list) || list.length === 0) {
    fail_cmp('bad-input', 'poll_rep takes a list of { cert_req_id, check_after }');
  }
  return W.to_bytes(W.sequence(list.map(function (p, i) {
    if (!p || typeof p.check_after !== 'number' || p.check_after % 1 !== 0 || p.check_after < 0) {
      fail_cmp('bad-input', 'poll response ' + i + ' needs check_after, whole seconds');
    }
    var f = [cert_req_id(p.cert_req_id), W.unsigned(int_bytes(p.check_after))];
    if (p.reason !== undefined && p.reason !== null) {
      f.push(W.sequence([].concat(p.reason).map(function (t) { return W.utf8_string(String(t)); })));
    }
    return W.sequence(f);
  })));
}

// PollReqContent ::= SEQUENCE OF SEQUENCE { certReqId INTEGER } - the
// client's, for symmetry and tests.
function poll_req(ids) {
  if (!Array.isArray(ids) || ids.length === 0) {
    fail_cmp('bad-input', 'poll_req takes a list of certReqIds');
  }
  return W.to_bytes(W.sequence(ids.map(function (id) { return W.sequence([cert_req_id(id)]); })));
}

// ---------------------------------------------------------------------------
// CMP
// ---------------------------------------------------------------------------

var BODY_TAGS = {};
var tag;

for (tag in CMP.BODY_TYPES) {
  if (Object.prototype.hasOwnProperty.call(CMP.BODY_TYPES, tag)) {
    BODY_TAGS[CMP.BODY_TYPES[tag].name] = parseInt(tag, 10);
  }
}

// Builds a PKIMessage and returns the bytes the protection covers.
//
// ⚠ THE PROTECTED BYTES ARE ASSEMBLED, NOT SLICED.
//
//   ProtectedPart ::= SEQUENCE { header PKIHeader, body PKIBody }
//
// A CMP message holds header and body as separate fields, and the
// protection covers a SEQUENCE containing both - which does not appear
// anywhere in the message. cmp.js says so on the reading side; here the
// same structure is produced, and returned as `bytes`.
function prepare(parts) {
  if (parts === null || typeof parts !== 'object') {
    fail_cmp('bad-input', 'prepare takes an object');
  }

  var body_name = parts.body;
  var body_tag = BODY_TAGS[body_name];

  if (body_tag === undefined) {
    fail_cmp('unknown-body',
      '"' + body_name + '" is not one of the 27 PKIBody arms');
  }

  if (parts.content === undefined || parts.content === null) {
    fail_cmp('no-body-content',
      'a ' + body_name + ' needs { content } - the encoded body');
  }

  // --- header -------------------------------------------------------------

  var header_fields = [
    // ⚠ pvno 2 IS CMP VERSION 2, which is what RFC 4210 defines. Version 1
    // is RFC 2510 and has a different header.
    W.unsigned(new Uint8Array([2])),
    general_name(parts.sender, 'sender'),
    general_name(parts.recipient, 'recipient')
  ];

  if (parts.message_time !== undefined && parts.message_time !== null) {
    header_fields.push(W.explicit(0,
      W.generalized_time(parts.message_time)));
  }

  var protection_alg = protection_algorithm(parts);

  if (protection_alg !== null) {
    header_fields.push(W.explicit(1, protection_alg));
  }

  // senderKID: for a password MAC, the reference number the secret was
  // issued under - text to everyone who types it (openssl cmp -ref), so
  // text is taken as its UTF-8.
  if (parts.sender_kid !== undefined && parts.sender_kid !== null) {
    header_fields.push(W.explicit(2, W.octet_string(text_or_bytes(parts.sender_kid))));
  }

  // ⚠ THE TRANSACTION ID GROUPS AN EXCHANGE, and without one nothing ties a
  // response to its request. RFC 4210 5.1.1 - required here rather than
  // optional, because a message that cannot be correlated is a message a
  // replay is indistinguishable from.
  if (parts.transaction_id === undefined || parts.transaction_id === null) {
    fail_cmp('no-transaction-id',
      'a PKIMessage needs { transaction_id } - without one nothing groups ' +
      'this message with the rest of its exchange, and a replayed response ' +
      'is indistinguishable from a fresh one');
  }

  header_fields.push(W.explicit(4,
    W.octet_string(to_bytes(parts.transaction_id))));

  if (parts.sender_nonce !== undefined && parts.sender_nonce !== null) {
    header_fields.push(W.explicit(5,
      W.octet_string(to_bytes(parts.sender_nonce))));
  }

  if (parts.recip_nonce !== undefined && parts.recip_nonce !== null) {
    header_fields.push(W.explicit(6,
      W.octet_string(to_bytes(parts.recip_nonce))));
  }

  // generalInfo [8]: implicitConfirm echoed when the server grants it,
  // confirmWaitTime when it does not, certProfile from a client.
  if (parts.general_info !== undefined && parts.general_info !== null) {
    if (!Array.isArray(parts.general_info) || parts.general_info.length === 0) {
      fail_cmp('bad-general-info', 'general_info is a non-empty list of { type, value }');
    }
    header_fields.push(W.explicit(8, infos_der(parts.general_info)));
  }

  var header = W.to_bytes(W.sequence(header_fields));

  // --- body ---------------------------------------------------------------

  var body = W.to_bytes(W.explicit(body_tag, to_bytes(parts.content)));

  // ⚠ THE PROTECTED STRUCTURE, ASSEMBLED.
  //
  //   ProtectedPart ::= SEQUENCE { header PKIHeader, body PKIBody }
  //
  // It appears nowhere in the message - the two fields travel separately -
  // so the bytes have to be built. The CONTENTS are exact and only the
  // SEQUENCE header is computed, which is the same position cmp.js takes on
  // the reading side.
  var protected_bytes = W.to_bytes(W.sequence([header, body]));

  return {
    bytes:  protected_bytes,
    header: header,
    body:   body,
    parts:  parts
  };
}

function assemble(msg, protection, options) {
  if (msg === null || typeof msg !== 'object' ||
      !(msg.header instanceof Uint8Array)) {
    fail_cmp('bad-message',
      'assemble takes what prepare() returned');
  }

  var opts = options || {};
  var fields = [msg.header, msg.body];

  if (protection !== null && protection !== undefined) {
    if (!(protection instanceof Uint8Array)) {
      fail_cmp('bad-protection', 'the protection is bytes');
    }
    fields.push(W.explicit(0, W.bit_string(protection, 0)));
  } else if (opts.unprotected !== true) {
    // ⚠ AN UNPROTECTED MESSAGE IS LEGAL AND IS NOT SAFE.
    //
    // RFC 4210 permits it for some announcements. A receiver acting on an
    // unprotected `ir` would be enrolling whoever asked, so omitting the
    // protection has to be a decision rather than a forgotten argument.
    fail_cmp('no-protection',
      'this message carries no protection, so nothing says who sent it. ' +
      'Pass { unprotected: true } if that is deliberate.');
  }

  if (opts.extra_certs !== undefined && opts.extra_certs !== null) {
    fields.push(W.explicit(1, W.sequence(
      opts.extra_certs.map(function (c) {
        return c instanceof Uint8Array ? c : c.der;
      }))));
  }

  return W.to_bytes(W.sequence(fields));
}

// ---------------------------------------------------------------------------

function protection_algorithm(parts) {
  if (parts.protection === undefined || parts.protection === null) {
    return null;
  }

  var p = parts.protection;

  if (p.kind === 'signature') {
    return algorithm_to_der(p.algorithm);
  }

  if (p.kind !== 'password-mac') {
    fail_cmp('unknown-protection',
      'protection is { kind: "signature" } or { kind: "password-mac" }');
  }

  // ⚠ THE ITERATION COUNT IS CHOSEN BY THE SENDER, so a receiver runs the
  // KDF with whatever number arrives. RFC 4210 gives no minimum, which was
  // reasonable in 1999 - a count in the hundreds leaves a shared secret open
  // to a laptop, and openssl's own default is 500.
  var iterations = p.iterations === undefined ? 100000 : p.iterations;

  if (iterations < 1000) {
    fail_cmp('weak-iteration-count',
      iterations + ' iterations leaves the shared secret open to a laptop. ' +
      'The RFC sets no minimum and openssl defaults to 500; this module ' +
      'refuses below 1000.');
  }

  var salt = p.salt === undefined ? null : to_bytes(p.salt);

  if (salt === null || salt.length < 8) {
    fail_cmp('short-salt',
      'the MAC salt is at least eight bytes - a short one lets one ' +
      'precomputation cover many enrolments');
  }

  return W.sequence([
    W.oid(OID.by_name('passwordBasedMac')),
    W.sequence([
      W.octet_string(salt),
      algorithm_to_der(p.owf || 'sha256'),
      W.unsigned(pkix_number_bytes(iterations, 'bad-iterations', 'iterations', fail_cmp)),
      // The MAC identifier, which is NOT an algorithm_to_der case - these
      // carry no parameters and are not signature algorithms.
      W.sequence([W.oid(OID.by_name(p.mac || 'hmacSHA'))])
    ])
  ]);
}

function text_or_bytes(v) {
  return typeof v === 'string' ? new Uint8Array(encode_utf8(v, fail)) : to_bytes(v);
}

function general_name(value, what) {
  if (value === undefined || value === null) {
    fail_cmp('missing-' + what,
      'a PKIMessage names both sender and recipient');
  }

  // A bare Name is the directoryName a sender almost always is; every other
  // GeneralName form - { email }, { uri }, { dns }, ... - is the shared
  // writer's. This had its own, which knew only directory and DNS, so a
  // sender named by email was refused.
  return general_name_to_der(Array.isArray(value)
    ? { directory: value } : value);
}

export {
  prepare,
  assemble,
  cert_rep,
  error,
  pkiconf,
  cert_conf,
  rev_rep,
  poll_rep,
  poll_req,
  genm,
  genm as genp,
  genp_ca_certs,
  genp_root_ca_key_update,
  STATUS,
  FAILURE_BITS
};

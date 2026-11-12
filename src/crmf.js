// CRMF - Certificate Request Message Format, RFC 4211.
//
// ⚠ WHAT THIS IS, AND WHY A PKCS#10 CSR IS NOT ENOUGH.
//
// A CSR says "here is a key, please sign it". CRMF says considerably more,
// and every addition exists because somebody automated certificate issuance
// and found the CSR could not express what they needed:
//
//   a TEMPLATE rather than a subject   the request may name a serial, a
//                                      validity window, extensions, an
//                                      issuer - and leave any of them for
//                                      the CA to fill in
//   PROOF OF POSSESSION as a field     a CSR proves possession by being
//                                      self-signed, which only works for
//                                      SIGNING keys. CRMF has four forms,
//                                      because an encryption-only key
//                                      cannot sign anything
//   ARCHIVAL                           the requester may enclose the private
//                                      key, encrypted, for escrow
//   CONTROLS                           registration tokens, the old
//                                      certificate being replaced, who may
//                                      publish the result
//
// This is what 3GPP uses: every cellular base station enrols this way, and
// EJBCA and industrial PKI speak it too.
//
// ⚠ PROOF OF POSSESSION IS THE PART THAT MATTERS, AND IT IS REPORTED RATHER
//    THAN CHECKED.
//
// Without it, anybody can request a certificate for a public key they do not
// hold - and then a signature made by the real key-holder verifies against a
// certificate naming the attacker. The four forms differ in what they prove
// and in what the CA must do about each, so this module names WHICH form is
// present and refuses to let it be absent silently.

import * as DER from './der_reader.js';
import * as F from './fields.js';
import * as OID from './oid.js';
import * as X509 from './x509.js';
import * as SPKI from './spki.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, int_value, signed_int_value, der_wrap }
  from './commons/bytes.js';

import './pkix.js';
import './x509.js';

var fail = make_fail_here('crmf');

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

//   OptionalValidity ::= SEQUENCE {
//        notBefore  [0] Time OPTIONAL,
//        notAfter   [1] Time OPTIONAL }
//
// ⚠ BOTH OPTIONAL, unlike a certificate's Validity where both are required -
// a request may ask for a start and leave the end to the CA, or neither.
//
// ⚠ AND [0] AND [1] ARE EXPLICIT, though the module says IMPLICIT TAGS:
// Time is a CHOICE, and a tag on a CHOICE is explicit (X.680 31.2.7). This
// read and crmf_build wrote them implicit - so the two agreed, and the first
// request from `openssl cmp -days` was refused with "trailing bytes"
// (cmp-mock-ir-validity.der).
F.define('OptionalValidity', [
  { name: 'notBefore', tag: 0xA0, mode: 'explicit', type: 'time',
    optional: true },
  { name: 'notAfter',  tag: 0xA1, mode: 'explicit', type: 'time',
    optional: true }
]);

//   CertTemplate ::= SEQUENCE {
//        version      [0] Version OPTIONAL,
//        serialNumber [1] INTEGER OPTIONAL,
//        signingAlg   [2] AlgorithmIdentifier OPTIONAL,
//        issuer       [3] Name OPTIONAL,
//        validity     [4] OptionalValidity OPTIONAL,
//        subject      [5] Name OPTIONAL,
//        publicKey    [6] SubjectPublicKeyInfo OPTIONAL,
//        issuerUID    [7] UniqueIdentifier OPTIONAL,
//        subjectUID   [8] UniqueIdentifier OPTIONAL,
//        extensions   [9] Extensions OPTIONAL }
//
// ⚠ EVERY FIELD IS OPTIONAL, AND THAT IS THE DESIGN.
//
// A template is a request for a certificate with SOME fields specified; the
// CA supplies the rest. So an empty template is a legal encoding and a
// meaningless request, and a caller has to look at what is actually there
// rather than assume a subject exists.
//
// ⚠ version AND serialNumber ARE PRIMITIVE - INTEGERs, implicitly tagged, so
// 0x80 and 0x81. They were declared 0xA0 and 0xA1, the constructed forms,
// and so every template naming a serial failed to read: OpenSSL's rr and
// kur, and crmf_build's own templates, which wrote 0x81 correctly. No ir
// names a serial, so nothing noticed until a revocation request did.
F.define('CertTemplate', [
  { name: 'version',      tag: 0x80, mode: 'implicit', type: 'unsigned',
    optional: true },
  { name: 'serialNumber', tag: 0x81, mode: 'implicit', type: 'integer',
    optional: true },
  { name: 'signingAlg',   tag: 0xA2, mode: 'implicit',
    type: 'AlgorithmIdentifier', optional: true },
  { name: 'issuer',       tag: 0xA3, mode: 'explicit', type: 'RDNSequence',
    optional: true },
  { name: 'validity',     tag: 0xA4, mode: 'implicit',
    type: 'OptionalValidity', optional: true },
  { name: 'subject',      tag: 0xA5, mode: 'explicit', type: 'RDNSequence',
    optional: true },
  { name: 'publicKey',    tag: 0xA6, mode: 'implicit', type: 'raw',
    optional: true },
  { name: 'issuerUID',    tag: 0x87, mode: 'implicit', type: 'bit_string',
    optional: true },
  { name: 'subjectUID',   tag: 0x88, mode: 'implicit', type: 'bit_string',
    optional: true },
  { name: 'extensions',   tag: 0xA9, mode: 'implicit', type: 'Extensions',
    optional: true }
]);

//   AttributeTypeAndValue is already in pkix.js.
F.define('Controls',
  { kind: 'sequence_of', of: 'AttributeTypeAndValue', min: 1 });

//   CertRequest ::= SEQUENCE {
//        certReqId      INTEGER,
//        certTemplate   CertTemplate,
//        controls       Controls OPTIONAL }
F.define('CertRequest', [
  { name: 'certReqId',    type: 'integer' },
  { name: 'certTemplate', type: 'CertTemplate' },
  { name: 'controls',     type: 'Controls', optional: true }
]);

//   POPOSigningKeyInput ::= SEQUENCE {
//        authInfo  CHOICE { sender [0] GeneralName, publicKeyMAC PKMACValue },
//        publicKey SubjectPublicKeyInfo }
F.define('POPOSigningKey', [
  { name: 'poposkInput',      tag: 0xA0, mode: 'implicit', type: 'raw',
    optional: true },
  { name: 'algorithmIdentifier', type: 'AlgorithmIdentifier' },
  { name: 'signature',        type: 'bit_string' }
]);

// The controls RFC 4211 section 6 defines.
var CONTROLS = {
  '1.3.6.1.5.5.7.5.1.1': { name: 'regToken',
    detail: 'a one-time token issued out of band, proving the requester was ' +
            'authorised to enrol at all' },
  '1.3.6.1.5.5.7.5.1.2': { name: 'authenticator',
    detail: 'a shared secret for later authentication' },
  '1.3.6.1.5.5.7.5.1.3': { name: 'pkiPublicationInfo',
    detail: 'where the issued certificate should be published' },
  '1.3.6.1.5.5.7.5.1.4': { name: 'pkiArchiveOptions',
    detail: 'the private key, enclosed for escrow' },
  '1.3.6.1.5.5.7.5.1.5': { name: 'oldCertID',
    detail: 'the certificate this one replaces' },
  '1.3.6.1.5.5.7.5.1.6': { name: 'protocolEncrKey',
    detail: 'a key the CA may use to encrypt its reply' }
};

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

//   CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
function from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var seq = r.read_sequence();
    var messages = [];

    while (seq.remaining() > 0) {
      messages.push(read_message(seq));
    }

    if (messages.length === 0) {
      fail('no-requests', 'a CertReqMessages with no requests');
    }

    return { messages: messages, der: bytes };
  });
}

//   CertReqMsg ::= SEQUENCE {
//        certReq  CertRequest,
//        popo     [0] ProofOfPossession OPTIONAL,
//        regInfo  SEQUENCE OF AttributeTypeAndValue OPTIONAL }
function read_message(r) {
  var msg = r.read_sequence();

  // ⚠ THE SIGNED PORTION, TAKEN BEFORE READING.
  //
  // A signature-based proof of possession covers the CertRequest as it
  // appears - so the bytes are a slice, the same rule as tbs_bytes.
  var start = msg.pos;
  var request = F.read_type(msg, 'CertRequest');
  var request_bytes = msg.buf.subarray(start, msg.pos);

  var popo = null;
  var popo_encoding = null;
  var tag = msg.peek_tag();

  // ⚠ TWO ENCODERS PRODUCE TWO DIFFERENT ENCODINGS OF THIS FIELD, AND BOTH
  //    ARE IN THE WORLD.
  //
  //   CertReqMsg ::= SEQUENCE { certReq CertRequest,
  //                             popo [0] ProofOfPossession OPTIONAL, ... }
  //
  // The RFC 4211 module is IMPLICIT TAGS, and X.680 31.2.7 says an implicit
  // tag on a CHOICE becomes EXPLICIT automatically - the tag cannot replace
  // the arm's own tag, because then nothing would say which arm it is. So
  // the encoding should be A0 wrapping A1.
  //
  //   asn1crypto writes  A0 { A1 ... }   following the language rule
  //   OpenSSL writes     A1 ...          collapsing the two into one
  //
  // OpenSSL is the one that talks to real CAs, so refusing its output would
  // make this module useless for the protocol it exists to read. Both are
  // accepted, and `popo_encoding` says which arrived - because a caller
  // re-encoding a message has to reproduce what came in, not what the
  // specification says should have.
  //
  // Same class of question as TSTInfo.tsa: the parsed RFC and the language
  // rule disagree, and the bytes in circulation decide.
  if (tag === 0xA0) {
    var wrapper = msg.read_explicit(0);
    popo = read_popo(wrapper);
    wrapper.expect_end();
    popo_encoding = 'wrapped';
  } else if (tag !== null && (tag & 0xC0) === 0x80 &&
             (tag & 0x1F) >= 0 && (tag & 0x1F) <= 3 &&
             msg.remaining() > 0) {
    popo = read_popo(msg);
    popo_encoding = 'collapsed';
  }

  var reg_info = null;

  if (msg.remaining() > 0) {
    reg_info = read_attributes(msg.read_sequence());
  }

  msg.expect_end();

  return {
    // Signed: RFC 4210 5.3.4 uses -1 for "no certReqId".
    id:       signed_int_value(request.certReqId, 'certReqId'),
    template: read_template(request.certTemplate),
    controls: read_controls(request.controls),
    // ⚠ NULL MEANS THE REQUEST PROVES NOTHING.
    //
    // Without a proof of possession, anybody can request a certificate for a
    // public key they do not hold - and then a signature made by the real
    // key-holder verifies against a certificate naming the attacker.
    //
    // Reported as null rather than defaulted, so a CA that does not check
    // has to have decided not to.
    proof_of_possession: popo,
    // ⚠ 'wrapped' is A0 { A1 }, 'collapsed' is A1 alone. See read_message.
    popo_encoding: popo_encoding,
    reg_info: reg_info,
    // The bytes a signature-based proof covers.
    request_bytes: request_bytes
  };
}

//   ProofOfPossession ::= CHOICE {
//        raVerified        [0] NULL,
//        signature         [1] POPOSigningKey,
//        keyEncipherment   [2] POPOPrivKey,
//        keyAgreement      [3] POPOPrivKey }
//
// ⚠ FOUR FORMS, AND THEY PROVE DIFFERENT THINGS.
//
// A CSR proves possession by being SELF-SIGNED, which only works for a key
// that can sign. An encryption-only key cannot, so RFC 4211 gives it two
// indirect forms - the CA encrypts a challenge to the key and the requester
// proves it decrypted - and one form that proves nothing at all.
function read_popo(r) {
  var tag = r.peek_tag();

  // ⚠ raVerified IS [0] NULL, so the implicit tag is PRIMITIVE - 0x80, not
  // 0xA0. The other three arms hold constructed values and carry 0xA1
  // upwards.
  //
  // The first version looked for 0xA0 and refused a legal raVerified, which
  // a test caught by building one. Worth noting because the mistake is easy:
  // every other context tag in this file is constructed, and the eye reads
  // 0xA0 as "context 0".
  if (tag === 0x80) {
    // ⚠ raVerified PROVES NOTHING ABOUT THE KEY.
    //
    // It says a Registration Authority checked possession by some means
    // outside this message. That may be entirely sound - or it may be a
    // request that walked past the check. The structure cannot tell, and
    // saying so is more use than a name a caller might read as a proof.
    var n = r.read_implicit(0, 0x05);
    return {
      form: 'ra-verified',
      proves: null,
      note: 'raVerified: a Registration Authority asserts it checked ' +
            'possession by some means outside this message. Nothing here ' +
            'demonstrates the requester holds the private key, and whether ' +
            'that is acceptable depends on trusting the RA.'
    };
  }

  if (tag === 0xA1) {
    var sk = r.read_implicit(1, 0x30);
    var parsed = F.read_type_from(sk, 'POPOSigningKey');

    if (parsed.signature.unused !== 0) {
      fail('bad-signature-bits',
        'the POP signature BIT STRING has unused bits');
    }

    return {
      form: 'signature',
      proves: 'the requester can SIGN with the private key',
      algorithm: OID.name_of(parsed.algorithmIdentifier.algorithm) ||
                 OID.to_string(parsed.algorithmIdentifier.algorithm),
      signature: parsed.signature.bytes,
      // ⚠ WHEN poposkInput IS PRESENT, THE SIGNATURE COVERS IT AND NOT THE
      // CertRequest.
      //
      // RFC 4211 4.1. Getting this wrong means verifying a real signature
      // over the wrong bytes, which fails in a way that looks like a bad
      // key - so the plan below says which.
      input: parsed.poposkInput === undefined ? null : parsed.poposkInput,
      note: parsed.poposkInput === undefined
        ? 'the signature covers the CertRequest as encoded'
        : 'the signature covers the POPOSigningKeyInput, NOT the ' +
          'CertRequest - RFC 4211 section 4.1'
    };
  }

  if (tag === 0xA2 || tag === 0xA3) {
    var which = tag === 0xA2 ? 'key-encipherment' : 'key-agreement';
    var body = r.capture_tagged(tag & 0x1F);

    return {
      form: which,
      proves: 'the requester can DECRYPT with the private key',
      // ⚠ AN ENCRYPTION-ONLY KEY CANNOT SIGN, which is the whole reason
      // these two forms exist - a CSR's self-signature is not available.
      note: 'the CA encrypts a challenge to this key and the requester ' +
            'proves it decrypted. Two round trips, or the value is enclosed ' +
            'directly - see the subsequentMessage field.',
      value: body
    };
  }

  fail('bad-popo',
    'unrecognised ProofOfPossession tag 0x' +
    (tag === null ? '(end)' : tag.toString(16)));
}

function read_template(t) {
  var out = {
    version:      t.version === undefined ? null : int_value(t.version),
    serial:       t.serialNumber === undefined ? null : t.serialNumber,
    signing_algorithm: t.signingAlg === undefined
      ? null
      : (OID.name_of(t.signingAlg.algorithm) ||
         OID.to_string(t.signingAlg.algorithm)),
    issuer:       t.issuer === undefined ? null : t.issuer,
    subject:      t.subject === undefined ? null : t.subject,
    validity:     null,
    public_key:   null,
    extensions:   [],
    // ⚠ WHAT THE REQUEST LEAVES TO THE CA.
    //
    // A template names some fields and omits others, and the omissions are
    // the interesting part: a request that omits the subject is asking the
    // CA to choose one.
    supplied:     [],
    left_to_ca:   []
  };

  if (t.validity !== undefined) {
    out.validity = {
      not_before: t.validity.notBefore === undefined
        ? null : t.validity.notBefore,
      not_after:  t.validity.notAfter === undefined
        ? null : t.validity.notAfter
    };
  }

  if (t.publicKey !== undefined) {
    // ⚠ A CertTemplate's publicKey is a SubjectPublicKeyInfo with an
    // IMPLICIT tag, so the SEQUENCE header has to be restored before spki.js
    // will read it. Reading the field raw and re-heading it is exact; asking
    // the field engine for an spki type would have needed the tag rewritten
    // anyway.
    out.public_key = SPKI.from_der(der_wrap(0x30, t.publicKey));
  }

  if (t.extensions !== undefined) {
    var i;
    for (i = 0; i < t.extensions.length; i++) {
      out.extensions.push(X509.read_extension(t.extensions[i]));
    }
  }

  var fields = ['version', 'serial', 'issuer', 'subject', 'validity',
                'public_key'];
  var j;

  for (j = 0; j < fields.length; j++) {
    if (out[fields[j]] !== null) {
      out.supplied.push(fields[j]);
    } else {
      out.left_to_ca.push(fields[j]);
    }
  }

  return out;
}

function read_controls(list) {
  if (list === undefined || list === null) {
    return [];
  }

  var out = [];
  var i;

  for (i = 0; i < list.length; i++) {
    var dotted = OID.to_string(list[i].type);
    var known = CONTROLS[dotted];

    out.push({
      id:     dotted,
      name:   known === undefined ? OID.name_of(list[i].type) : known.name,
      detail: known === undefined ? null : known.detail,
      // ⚠ THE VALUE IS KEPT WHOLE. Each control has its own structure, and
      // pkiArchiveOptions in particular holds an ENCRYPTED PRIVATE KEY -
      // interpreting it here would mean deciding how to handle escrowed key
      // material, which is the caller's decision entirely.
      value:  list[i].value
    });
  }

  return out;
}

function read_attributes(r) {
  var out = [];

  while (r.remaining() > 0) {
    var a = F.read_type(r, 'AttributeTypeAndValue');
    out.push({
      id:    OID.to_string(a.type),
      name:  OID.name_of(a.type),
      value: a.value
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// Using
// ---------------------------------------------------------------------------

// What a CA has to verify, for a request whose proof is a signature.
//
// ⚠ AND WHICH BYTES, WHICH IS THE PART THAT GOES WRONG.
//
// RFC 4211 4.1: when POPOSigningKeyInput is present the signature covers
// THAT, and when it is absent the signature covers the CertRequest as
// encoded. Verifying over the wrong one fails in a way that looks like a bad
// key.
function verification_plan(message) {
  var popo = message.proof_of_possession;

  if (popo === null) {
    return {
      verifiable: false,
      reason: 'this request carries no proof of possession. Issuing from it ' +
              'means certifying a public key the requester may not hold.'
    };
  }

  if (popo.form === 'ra-verified') {
    return {
      verifiable: false,
      reason: 'raVerified: possession was asserted by a Registration ' +
              'Authority out of band. There is nothing here to verify, and ' +
              'accepting it is a decision about trusting that RA.'
    };
  }

  if (popo.form !== 'signature') {
    return {
      verifiable: false,
      reason: popo.form + ': possession is proved by DECRYPTING a challenge ' +
              'the CA sends, which takes another round trip. Nothing in ' +
              'this message can be checked on its own.'
    };
  }

  return {
    verifiable: true,
    algorithm:  popo.algorithm,
    // ⚠ WHICHEVER ONE THE STRUCTURE SAYS.
    bytes:      popo.input === null ? message.request_bytes : popo.input,
    covers:     popo.input === null ? 'CertRequest' : 'POPOSigningKeyInput',
    signature:  popo.signature,
    key:        message.template.public_key,
    note: popo.input === null
      ? 'the signature covers the CertRequest as encoded'
      : 'the signature covers the POPOSigningKeyInput, not the CertRequest'
  };
}

export {
  from_der,
  verification_plan,
  // A CertTemplate's fields, read - for a CMP revocation request, whose
  // RevDetails name the certificate with one.
  read_template,
  CONTROLS
};

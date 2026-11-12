// Building CRMF certificate requests - RFC 4211. crmf.js reads them.
//
// A CertReqMessages usually travels inside a CMP message: write it here,
// then hand the bytes to cmp_build.prepare as the body of an `ir`/`cr`/`kur`:
//
//   var p   = crmf_build.prepare({ subject, public_key,
//               signature_algorithm: 'ecdsaWithSHA256' });
//   var req = crmf_build.assemble(p, sign(p.bytes));   // proof of possession
//   var m   = cmp_build.prepare({ body: 'ir', content: req, ... });

import * as W from './der_writer.js';
import * as OID from './oid.js';
import * as CMP from './cmp.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, int_bytes } from './commons/bytes.js';

import './pkix.js';
import { algorithm_to_der, name_to_der, attribute_to_der,
  raw_extensions_to_der, number_bytes as pkix_number_bytes, time_to_der }
  from './pkix.js';

var fail = make_fail_here('crmf');
var fail_cmp = make_fail_here('cmp');

// ---------------------------------------------------------------------------
// CRMF
// ---------------------------------------------------------------------------

var CONTROLS = {
  regToken:           '1.3.6.1.5.5.7.5.1.1',
  authenticator:      '1.3.6.1.5.5.7.5.1.2',
  pkiPublicationInfo: '1.3.6.1.5.5.7.5.1.3',
  pkiArchiveOptions:  '1.3.6.1.5.5.7.5.1.4',
  oldCertID:          '1.3.6.1.5.5.7.5.1.5',
  protocolEncrKey:    '1.3.6.1.5.5.7.5.1.6'
};

// Builds a CertReqMessages and returns the bytes a signature proof covers
// - the key being certified signs them.
function prepare(parts) {
  if (parts === null || typeof parts !== 'object') {
    fail('bad-input', 'prepare takes an object');
  }

  if (parts.public_key === undefined || parts.public_key === null) {
    fail('missing-public-key',
      'a certificate request needs the key it is asking to have certified');
  }

  var template = template_to_der(parts);
  var request_fields = [
    W.unsigned(number_bytes(parts.id === undefined ? 0 : parts.id, 'id')),
    template
  ];

  var controls = controls_to_der(parts.controls);

  if (controls !== null) {
    request_fields.push(controls);
  }

  // ⚠ THE SIGNED SPAN IS THE CertRequest AS ENCODED.
  //
  // RFC 4211 4.1: when POPOSigningKeyInput is absent - which it is here,
  // because this module does not produce the indirect forms - the signature
  // covers the CertRequest exactly as it appears. So the bytes are built
  // once and handed back, never re-encoded.
  var cert_request = W.to_bytes(W.sequence(request_fields));

  return {
    bytes:        cert_request,
    signature_algorithm: parts.signature_algorithm || null,
    parts:        parts,
    // ⚠ NULL until a proof is supplied. A request with none is legal and
    // means the CA is trusting something outside this message - see
    // assemble.
    proof:        null
  };
}

function assemble(req, signature, options) {
  if (req === null || typeof req !== 'object' ||
      !(req.bytes instanceof Uint8Array)) {
    fail('bad-request',
      'assemble takes what prepare() returned');
  }

  var opts = options || {};
  var message_fields = [req.bytes];

  // ⚠ raVerified IS CHECKED FIRST, because it arrives WITH a null signature
  // - there is nothing to sign. The first version tested for the null
  // before looking at the option and refused a legal request with a message
  // telling the caller to pass the option they had already passed.
  if (opts.ra_verified === true) {
    if (signature !== null && signature !== undefined) {
      fail('both-proof-forms',
        'raVerified means an RA checked possession out of band, so there ' +
        'is no signature to carry');
    }

    // [0] NULL - a PRIMITIVE context tag, 0x80, not 0xA0.
    message_fields.push(W.explicit(0, W.implicit(0, W.null())));
  } else if (signature === null || signature === undefined) {
    // ⚠ NO PROOF OF POSSESSION AT ALL.
    //
    // Anybody can then request a certificate for a public key they do not
    // hold, and a signature made by the real key-holder verifies against a
    // certificate naming the requester. Legal, and a decision - so it has
    // to be made explicitly rather than by omitting an argument.
    if (opts.no_proof !== true) {
      fail('no-proof-of-possession',
        'a request with no proof of possession lets anybody ask for a ' +
        'certificate over a key they do not hold. Pass { no_proof: true } ' +
        'if the CA verifies possession some other way, or ' +
        '{ ra_verified: true } to say a Registration Authority did.');
    }
  } else {
    if (!(signature instanceof Uint8Array)) {
      fail('bad-signature', 'the signature is bytes');
    }

    if (signature.length > 0 && signature[0] !== 0x30 &&
        /ecdsa/i.test(req.signature_algorithm || '')) {
      fail('raw-signature',
        'this looks like a raw r||s signature - convert it with ' +
        'signature.raw_to_der({ raw: sig, curve: ... })');
    }

    if (typeof req.signature_algorithm !== 'string') {
      fail('missing-algorithm',
        'a signature proof needs { signature_algorithm } on the request');
    }

    // ⚠ [0] EXPLICIT, because ProofOfPossession is a CHOICE.
    //
    // X.680 31.2.7 - and OpenSSL writes the collapsed form instead, which
    // crmf.js accepts on reading. This writes the form the language rule
    // gives, because that is the one every implementation reads.
    message_fields.push(W.explicit(0, W.implicit(1, W.sequence([
      algorithm_to_der(req.signature_algorithm),
      W.bit_string(signature, 0)
    ]))));
  }

  return W.to_bytes(W.sequence([W.sequence(message_fields)]));
}

// ---------------------------------------------------------------------------

function template_to_der(parts) {
  var fields = [];

  if (parts.serial !== undefined && parts.serial !== null) {
    fields.push(W.implicit(1, W.unsigned(to_bytes(parts.serial))));
  }

  if (parts.issuer !== undefined && parts.issuer !== null) {
    fields.push(W.explicit(3, name_to_der(parts.issuer, attribute_to_der)));
  }

  if (parts.validity !== undefined && parts.validity !== null) {
    var validity = [];

    // ⚠ BOTH OPTIONAL, unlike a certificate's Validity. A request may ask
    // for a start and leave the end to the CA.
    if (parts.validity.not_before) {
      validity.push(W.explicit(0, time_to_der(parts.validity.not_before)));
    }
    if (parts.validity.not_after) {
      validity.push(W.explicit(1, time_to_der(parts.validity.not_after)));
    }

    if (validity.length > 0) {
      fields.push(W.implicit(4, W.sequence(validity)));
    }
  }

  if (parts.subject !== undefined && parts.subject !== null) {
    fields.push(W.explicit(5, name_to_der(parts.subject, attribute_to_der)));
  }

  // ⚠ [6] IMPLICIT SubjectPublicKeyInfo, so the SEQUENCE header is REPLACED
  // by the context tag rather than wrapped. Writing the whole SPKI inside
  // gives a template with an extra layer nothing reads.
  var spki = parts.public_key instanceof Uint8Array
    ? parts.public_key
    : parts.public_key.der;

  if (!(spki instanceof Uint8Array)) {
    fail('bad-public-key',
      'the public key is a SubjectPublicKeyInfo: the DER, or the object ' +
      'spki.from_der returned');
  }

  // ⚠ W.implicit REPLACES THE FIRST BYTE of what it is given, which is
  // exactly what IMPLICIT tagging does - so it takes the WHOLE SPKI and
  // rewrites its 0x30 into 0xA6.
  //
  // The first version stripped the header first and handed over the
  // contents, and implicit rewrote the OID tag inside instead. The result
  // parsed as far as the algorithm and then failed on a tag that had been
  // silently changed.
  fields.push(W.implicit(6, spki));

  if (parts.extensions !== undefined && parts.extensions !== null) {
    var out = raw_extensions_to_der(parts.extensions, fail, 'template');

    if (out.length > 0) {
      fields.push(W.implicit(9, W.sequence(out)));
    }
  }

  return W.sequence(fields);
}



function controls_to_der(controls) {
  if (controls === undefined || controls === null) {
    return null;
  }

  var out = [];
  var name;

  for (name in controls) {
    if (!Object.prototype.hasOwnProperty.call(controls, name)) {
      continue;
    }

    var dotted = CONTROLS[name];

    if (dotted === undefined) {
      if (/^\d+(\.\d+)+$/.test(name)) {
        dotted = name;
      } else {
        fail('unknown-control',
          '"' + name + '" is not an RFC 4211 control. The six are: ' +
          Object.keys(CONTROLS).join(', '));
      }
    }

    var value = controls[name];

    // ⚠ pkiArchiveOptions CARRIES AN ENCRYPTED PRIVATE KEY, and how to
    // encrypt it is the caller's decision entirely. Every control goes in
    // as bytes for the same reason: their structures differ and guessing
    // would produce something the CA does not read.
    if (typeof value === 'string') {
      value = W.to_bytes(W.utf8_string(value));
    }

    if (!(value instanceof Uint8Array)) {
      fail('bad-control-value',
        'control "' + name + '" takes encoded bytes, or a string for the ' +
        'text ones');
    }

    out.push(W.sequence([W.oid(OID.from_string(dotted)), value]));
  }

  return out.length === 0 ? null : W.sequence(out);
}

function number_bytes(n, what) {
  return pkix_number_bytes(n,
    what === 'iterations' ? 'bad-iterations' : 'bad-' + what, what, fail);
}

export {
  prepare,
  assemble,
  CONTROLS
};

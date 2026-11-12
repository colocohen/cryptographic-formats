// SubjectPublicKeyInfo, RFC 5280 section 4.1.
//
//   SubjectPublicKeyInfo  ::=  SEQUENCE  {
//        algorithm            AlgorithmIdentifier,
//        subjectPublicKey     BIT STRING  }
//
//   AlgorithmIdentifier  ::=  SEQUENCE  {
//        algorithm            OBJECT IDENTIFIER,
//        parameters           ANY DEFINED BY algorithm OPTIONAL  }
//
// What sits INSIDE the BIT STRING is not decoded here. The SEC 1 point
// encoding - 0x04 uncompressed, 0x02/0x03 compressed - already exists in
// cryptographic-primitives as encode_point / decode_point, verified to reject a y that does
// not satisfy the curve equation, an x at or above p, an unknown prefix, a
// wrong length, and an x with no square root.
//
// So this module unwraps to the point bytes and hands them over. Two point
// decoders that disagree about which encodings are acceptable is the same
// class of bug as an encoder checked only against its own decoder.
//
// The algorithm identifier is load-bearing and is never discarded.
// brainpoolP256t1 and brainpoolP256r1 share points, so a key labelled t1
// whose point lies on r1 must be refused on the strength of the LABEL - the
// point alone cannot say. Throwing away the identifier makes those cases
// unanswerable, so `curve` here is what the wrapper CLAIMS, and verifying the
// claim against the point is the caller's step with cryptographic-primitives.

import * as DER from './der_reader.js';
import * as W from './der_writer.js';
import * as F from './fields.js';

// Imported for its side effect: pkix.js defines AlgorithmIdentifier,
// RDNSequence, Extension and the other structures PKIX shares.
import './pkix.js';
import * as OID from './oid.js';
import { check_point_length, CURVE_SIZE, OKP_SIZE, KEY_PARAMS, is_curve,
  raw_public_size, identify_key_algorithm, read_key_parameters } from './ec_domain.js';

import { to_bytes } from './commons/bytes.js';
import { read_pss_params } from './algorithm.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('spki');


// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------


F.define('SubjectPublicKeyInfo', [
  { name: 'algorithm', type: 'AlgorithmIdentifier' },
  { name: 'key',       type: 'bit_string' }
]);

// ---------------------------------------------------------------------------
// Algorithm families
// ---------------------------------------------------------------------------


// Field sizes, for checking that a point is the right LENGTH for the curve
// its wrapper names.
//
// Wycheproof found this missing. Two vectors got through: an SPKI whose BIT
// STRING was EMPTY, and an X448 key of 57 bytes where the curve takes 56.
// Both parsed cleanly and returned a "point" that is not a point.
//
// Checking the length is format work and belongs here - it follows from the
// curve identifier, which is the field this module exists to preserve.
// Checking that the point is ON the curve does not: that is cryptographic-primitives's
// decode_point, and two point decoders that disagree about which encodings
// are acceptable is the same class of bug as an encoder checked only against
// its own decoder.

// The named curves - the keys of ec_domain's size table, rather than a second
// list that could name a curve the size check does not know.
var CURVES = Object.keys(CURVE_SIZE);


// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

// Returns the uniform key shape that every source of a key produces, so
// conversion between formats is free and a caller learns one object:
//
//   { algorithm, curve, point, parameters, der }
//
// `point` is the raw BIT STRING content, ready for cryptographic-primitives's decode_point.
// `curve` is what the wrapper claims, or null for algorithms that carry no
// curve parameter.
function from_der(input) {
  var parsed = DER.read(input, function (r) {
    return F.read_type(r, 'SubjectPublicKeyInfo');
  });

  var alg_name = identify_key_algorithm(parsed.algorithm.algorithm, fail,
    'key');
  var params = parsed.algorithm.parameters;

  // The BIT STRING holding a public key is a whole number of octets. A
  // non-zero unused-bits count would mean the key has a fractional last byte,
  // which no key algorithm defines - and it is a second encoding of the same
  // key material.
  if (parsed.key.unused !== 0) {
    fail('bad-key-bit-string',
      'public key BIT STRING has ' + parsed.key.unused + ' unused bits');
  }

  var curve = read_key_parameters(alg_name, params, fail);

  if (curve !== null) {
    check_point_length(curve, parsed.key.bytes, fail);
  } else if (KEY_PARAMS[alg_name] === 'absent') {
    // An X448 key of 57 bytes is not an X448 key. Wycheproof has one, and it
    // parsed cleanly before this check existed.
    // Its own code, bad-point-length, kept: codes are what callers assert on.
    // The post-quantum public keys are raw bytes of a fixed length too
    // (RFC 9881 4, RFC 9909 4, RFC 9935 4).
    var size = raw_public_size(alg_name);
    if (parsed.key.bytes.length !== size) {
      fail('bad-point-length',
        alg_name + ' keys are ' + size + ' bytes, got ' +
        parsed.key.bytes.length);
    }
  }

  var out = {
    algorithm:  alg_name,
    curve:      curve,
    point:      parsed.key.bytes,
    parameters: params === undefined ? null : params,
    der:        to_bytes(input)
  };

  // ⚠ RSA: THE MODULUS AND EXPONENT, AS jwk AND ssh RETURN THEM.
  //
  // `point` holds the RSAPublicKey DER, which is what the BIT STRING is. But
  // jwk.to_key and ssh.key_from_text return an RSA key as rsa: { n, e },
  // and their writers take that - so a key read here could not be written
  // as a JWK or an SSH line, and one read there could not be written here.
  // The same key, three shapes; type-checking the examples is what showed
  // it. Now every reader returns rsa, and every writer takes it.
  if (alg_name === 'rsaEncryption' || alg_name === 'rsassaPss') {
    out.rsa = DER.read(parsed.key.bytes, function (r) {
      var seq = r.read_sequence();
      var n = seq.read_unsigned();
      var e = seq.read_unsigned();
      seq.expect_end();
      return { n: n, e: e };
    });
  }

  // An RSA-PSS key's limits - hash, MGF, minimum salt - or null when it
  // allows any PSS signature. A verifier must hold the signature to them
  // (RFC 4055 3.3): the same hash and MGF, a salt no shorter.
  if (alg_name === 'rsassaPss') {
    out.pss = params === undefined ? null : read_pss_params(params);
  }

  return out;
}



// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

// The AlgorithmIdentifier of a key - shared with pkcs8.to_der, which writes
// the same identifier in front of a private key. Writer side only: the
// readers check the same rules through ec_domain.read_key_parameters, a
// separate function, so a mistake here is caught on the way back in.
function key_algorithm_to_der(key, fail_) {
  var rule = KEY_PARAMS[key.algorithm];

  if (rule === undefined) {
    fail_('unsupported-algorithm', 'cannot encode algorithm ' + key.algorithm);
  }

  var parts = [W.oid(OID.by_name(key.algorithm))];

  if (rule === 'curve') {
    if (!key.curve) {
      fail_('missing-curve', key.algorithm + ' requires a named curve');
    }
    if (!is_curve(key.curve)) {
      fail_('unknown-curve', 'unrecognised curve ' + key.curve);
    }
    parts.push(W.oid(OID.by_name(key.curve)));
  } else if (rule === 'null') {
    parts.push(W.null());
  } else if (rule === 'absent') {
    if (key.curve) {
      fail_('unexpected-parameters', key.algorithm + ' must not carry a curve');
    }
  } else if (rule === 'required') {
    if (!key.parameters) {
      fail_('missing-parameters', key.algorithm + ' requires parameters');
    }
    parts.push(Array.prototype.slice.call(key.parameters));
  } else if (rule === 'pss' && key.parameters) {
    // As read: absent for an unrestricted key, the RSASSA-PSS-params bytes
    // otherwise.
    parts.push(Array.prototype.slice.call(key.parameters));
  }

  return W.sequence(parts);
}

// A magnitude without its leading zero bytes - W.unsigned adds back the one
// a set top bit needs.
function strip_zeros(b) {
  var i = 0;
  while (i < b.length - 1 && b[i] === 0) { i++; }
  return b.subarray(i);
}

function to_der(key) {
  if (!key || typeof key.algorithm !== 'string') {
    fail('bad-key', 'expected a key object with an algorithm');
  }

  // ⚠ AN RSA KEY FROM A JWK OR AN SSH LINE HAS NO `point`. Those readers
  // return the modulus and exponent as `rsa: { n, e }` - the shape that
  // is useful there - and this took only `point`, so the key every other
  // module returned could not be written back as SPKI. Found by
  // type-checking the examples: jwk.to_key's `point` is null for RSA.
  var point = key.point;

  if ((!point || point.length === 0) &&
      (key.algorithm === 'rsaEncryption' || key.algorithm === 'rsassaPss') &&
      key.rsa && key.rsa.n && key.rsa.e) {
    point = W.to_bytes(W.sequence([
      W.unsigned(strip_zeros(to_bytes(key.rsa.n))),
      W.unsigned(strip_zeros(to_bytes(key.rsa.e)))
    ]));
  }

  if (!point || point.length === 0) {
    fail('bad-key', 'key has no point bytes');
  }

  var out = W.sequence([
    key_algorithm_to_der(key, fail),
    W.bit_string(point, 0)
  ]);

  return W.to_bytes(out);
}

// ---------------------------------------------------------------------------


export {
  from_der,
  to_der,
  key_algorithm_to_der,
  CURVES
};

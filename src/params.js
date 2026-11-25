// DH and EC domain parameters, the `openssl dhparam` and `openssl ecparam`
// files.
//
// Small, and here for interoperability rather than for cryptography: these
// are what an older configuration hands a server, and a library that reads
// every key format but not the parameters beside them sends the operator to
// a permissive parser for the last file in the directory.
//
//   DHParameter ::= SEQUENCE {
//        prime               INTEGER,   -- p
//        base                INTEGER,   -- g
//        privateValueLength  INTEGER OPTIONAL }
//
//   ECParameters ::= CHOICE {
//        namedCurve  OBJECT IDENTIFIER,
//        ... }
//
// ⚠ DH PARAMETERS CANNOT BE VALIDATED BY READING THEM.
//
// Whether p is prime, whether g generates a large enough subgroup, whether
// the group is one of the well-known weak ones - none of that is in the
// encoding. Logjam was parameters that parsed perfectly.
//
// So this module reports the BIT LENGTH, which is the one thing that can be
// judged from the bytes and the thing most often wrong, and says plainly that
// the rest is not checked. Reporting a weak size is not the same as refusing
// it: a caller reading an existing file needs to see what is there.

import * as DER from './der_reader.js';
import * as W from './der_writer.js';
import * as PEM from './pem.js';
import * as OID from './oid.js';
import { curve_from_parameters, mark_explicit } from './ec_domain.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, int_value, bit_length } from './commons/bytes.js';

var fail = make_fail_here('params');

// ---------------------------------------------------------------------------
// DH
// ---------------------------------------------------------------------------

function dh_from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var seq = r.read_sequence();
    var prime = seq.read_unsigned();
    var base = seq.read_unsigned();
    var length = null;

    if (seq.remaining() > 0) {
      length = int_value(seq.read_unsigned(), 'privateValueLength');
    }

    seq.expect_end();

    var bits = bit_length(prime);

    if (prime.length === 0) {
      fail('bad-prime', 'the prime has no content octets');
    }
    if ((prime[prime.length - 1] & 1) === 0) {
      // An even p is not prime, and it is the one primality fact available
      // without arithmetic this library does not do.
      fail('bad-prime',
        'the prime is even, so it is not prime');
    }
    if (base.length === 0) {
      fail('bad-base', 'the generator has no content octets');
    }

    var g = base.length <= 4 ? int_value(base, 'base') : null;

    if (g !== null && g < 2) {
      fail('bad-base',
        'the generator is ' + g + ', and a generator is at least 2');
    }

    return {
      prime:      prime,
      base:       base,
      bits:       bits,
      // g is almost always 2 or 5, and reporting it as a number when it is
      // small saves every caller the conversion.
      base_value: g,
      private_length: length,
      // ⚠ THE ONLY JUDGEMENT AVAILABLE FROM THE BYTES.
      //
      // Reported rather than refused: a caller reading an existing file
      // needs to see what is there. Writing one is the other way round - see
      // dh_to_der.
      weak:       bits < 2048,
      note:       bits < 2048
        ? bits + '-bit DH parameters. Logjam broke 512-bit groups in 1024 ' +
          'and made 1024-bit groups plausible for a state actor; 2048 is ' +
          'the current floor.'
        : null,
      // Everything this module CANNOT tell you, said out loud rather than
      // left to be assumed from a successful parse.
      unchecked:  'whether p is prime, whether (p-1)/2 is prime, whether g ' +
                  'generates a large enough subgroup, and whether this is a ' +
                  'known-weak group - none of that is in the encoding',
      der:        bytes
    };
  });
}

// The group of a PKCS#3 DH key (SPKI or PKCS#8), as pkcs8.js reports a DSA
// key's: domain, and the bit length of p with its weak judgement. The same
// reader as a `openssl dhparam` file, because it is the same DHParameter.
function dh_key_group(params) {
  var d = dh_from_der(params);
  return {
    domain: { p: d.prime, g: d.base, private_length: d.private_length },
    bits:   d.bits,
    weak:   d.weak
  };
}

function dh_from_pem(text) {
  return dh_from_der(PEM.decode_one(text, 'DH PARAMETERS').der);
}

// Writing is stricter than reading, the same asymmetry pbes2.js has: a caller
// reading an old file needs to see it, and a caller producing a new one has
// no reason to produce a weak group.
function dh_to_der(parts) {
  if (!parts || !parts.prime || !parts.base) {
    fail('bad-input', 'a prime and a base are required');
  }

  var prime = to_bytes(parts.prime);
  var bits = bit_length(prime);

  if (bits < 2048 && parts.allow_weak !== true) {
    fail('weak-parameters',
      'refusing to write ' + bits + '-bit DH parameters. Pass ' +
      '{ allow_weak: true } if you are deliberately reproducing an old ' +
      'file, and say so in the code that does it.');
  }

  var fields = [W.unsigned(prime), W.unsigned(to_bytes(parts.base))];

  if (parts.private_length) {
    fields.push(W.unsigned([parts.private_length]));
  }

  return W.to_bytes(W.sequence(fields));
}

// ---------------------------------------------------------------------------
// EC
// ---------------------------------------------------------------------------

// An `openssl ecparam` file is normally just the curve's OID - the CHOICE's
// namedCurve arm. The explicit arm carries the curve's equation, and is read
// only when every value is a named curve's - ec_domain.js's rule, the same
// as for a key (DECISIONS 46) - as that curve, with `explicit_parameters`
// and a warning. Any other equation is refused: accepting it would mean
// trusting whatever the file says the curve is. The refusal keeps this
// module's code, `explicit-parameters`.
function ec_from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var tag = r.peek_tag();

    if (tag === 0x30) {
      var params = r.capture();
      var out = {
        curve: curve_from_parameters(params, function (code, detail) {
          fail(code === 'explicit-curve-parameters' ? 'explicit-parameters'
            : code, detail);
        }),
        oid: null,
        der: bytes
      };
      out.oid = OID.by_name(out.curve);
      mark_explicit(out, out.curve);
      return out;
    }
    if (tag === 0x05) {
      // implicitlyCA: the curve is whatever the CA used, stated nowhere.
      fail('implicit-parameters',
        'implicitlyCA parameters name no curve at all');
    }

    var oid = r.read_oid();
    var name = OID.name_of(oid);

    if (name === null) {
      fail('unknown-curve',
        'unrecognised curve ' + OID.to_string(oid));
    }

    return { curve: name, oid: oid, der: bytes };
  });
}

function ec_from_pem(text) {
  return ec_from_der(PEM.decode_one(text, 'EC PARAMETERS').der);
}

function ec_to_der(curve) {
  if (typeof curve !== 'string') {
    fail('bad-input', 'a curve name is required');
  }
  return W.to_bytes(W.oid(OID.by_name(curve)));
}

function ec_to_pem(curve) {
  return PEM.encode(ec_to_der(curve), 'EC PARAMETERS');
}

// ---------------------------------------------------------------------------


export {
  dh_from_der,
  dh_key_group,
  dh_from_pem,
  dh_to_der,
  ec_from_der,
  ec_from_pem,
  ec_to_der,
  ec_to_pem,
  bit_length
};

// Building PKCS#12 / PFX - RFC 7292. A key and its certificates in one file,
// the format every browser, Windows and keytool import.
//
// pkcs12.js reads; this writes. The library encrypts nothing and computes no
// MAC, so a PFX is built in layers, the caller doing the cryptography
// between them - and each layer hands over exactly the bytes the next
// operation applies to:
//
//   // 1. the key, shrouded: PBES2, as pkcs8.encrypted_to_der writes it
//   var epki = pkcs8.encrypted_to_der({ prf, salt, iterations, cipher, iv,
//                           data: aes(pbkdf2(password), pkcs8_der) });
//   var id = sha1(cert_der);                       // ties key to cert
//   var keys = p12.safe_contents([p12.shrouded_key_bag(epki,
//                { friendly_name: 'me', local_key_id: id })]);
//
//   // 2. the certificates, in a safe the caller encrypts as a whole
//   var certs = p12.safe_contents([p12.cert_bag(cert_der,
//                { local_key_id: id })]);
//   var enc = p12.encrypted_safe({ prf, salt, iterations, cipher, iv,
//                data: aes(pbkdf2(password), certs) });
//
//   // 3. the authenticated safe, then the MAC over it
//   var auth = p12.prepare([p12.data_safe(keys), enc]);
//   var mac = hmac(hash, pkcs12_kdf(hash, password, salt, it, 3, len),
//                  prepared.bytes);
//   var pfx = p12.assemble(auth, { hash, salt, iterations: it, digest: mac });
//
// ⚠ THE MAC KEY IS NOT PBKDF2. RFC 7292 appendix B: the PKCS#12 KDF with ID
// byte 3, over the password as BMPString with a trailing NUL. Every mistake
// there produces a file that every importer reports as "wrong password".
// pkcs12.open() takes the same primitives and checks it.
//
// UNLESS THE MAC IS PBMAC1 (RFC 9579): PBKDF2 then HMAC, the password as
// UTF-8 bytes - what the RFC's test vectors use - and FIPS-approved, which
// the PKCS#12 KDF is not. assemble(auth, { scheme: 'pbmac1', ... }):
//
//   var key = pbkdf2('hmacWithSHA256', password, salt, it, 32);
//   var pfx = p12.assemble(auth, { scheme: 'pbmac1', hash: 'sha256',
//               prf: 'hmacWithSHA256', salt, iterations: it,
//               digest: hmac('sha256', key, prepared.bytes) });
//
// Importers older than OpenSSL 3.4 cannot verify a PBMAC1 file; the
// PKCS#12 KDF remains the default for that reason.
//
// ⚠ EVERY CERTIFICATE IN AN UNENCRYPTED SAFE IS READABLE, AND THE MAC IS
// THE ONLY THING PROTECTING IT. A PFX with no MAC has no integrity at all;
// assemble() requires one.

import * as W from './der_writer.js';
import * as OID from './oid.js';
import * as PBES2 from './pbes2.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, int_bytes } from './commons/bytes.js';
import { check_iterations } from './commons/limits.js';
import { pbkdf2_to_der } from './pbes2.js';
import { canonical_name } from './algorithm.js';

var fail = make_fail_here('pkcs12');

var DATA = '1.2.840.113549.1.7.1';
var ENCRYPTED_DATA = '1.2.840.113549.1.7.6';

var BAG = {
  keyBag:              '1.2.840.113549.1.12.10.1.1',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  certBag:             '1.2.840.113549.1.12.10.1.3'
};

var X509_CERTIFICATE = '1.2.840.113549.1.9.22.1';
var FRIENDLY_NAME = '1.2.840.113549.1.9.20';
var LOCAL_KEY_ID = '1.2.840.113549.1.9.21';

var MAC_HASHES = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512'];

// ---------------------------------------------------------------------------
// Bags
// ---------------------------------------------------------------------------

//   SafeBag ::= SEQUENCE {
//      bagId          OBJECT IDENTIFIER,
//      bagValue       [0] EXPLICIT ANY DEFINED BY bagId,
//      bagAttributes  SET OF PKCS12Attribute OPTIONAL }
function bag(oid, value, attrs) {
  var fields = [W.oid(OID.from_string(oid)), W.explicit(0, value)];
  var a = attributes(attrs);
  if (a !== null) {
    fields.push(a);
  }
  return W.sequence(fields);
}

// friendlyName (BMPString - UTF-16BE, not UTF-8) and localKeyId (the bytes
// that tie a key bag to its certificate bag; conventionally the SHA-1 of
// the certificate, which is what OpenSSL and Windows write).
function attributes(attrs) {
  if (!attrs) {
    return null;
  }

  var list = [];

  if (attrs.friendly_name !== undefined) {
    list.push(W.sequence([W.oid(OID.from_string(FRIENDLY_NAME)),
      W.set_of([W.bmp_string(String(attrs.friendly_name))])]));
  }
  if (attrs.local_key_id !== undefined) {
    list.push(W.sequence([W.oid(OID.from_string(LOCAL_KEY_ID)),
      W.set_of([W.octet_string(to_bytes(attrs.local_key_id))])]));
  }

  return list.length === 0 ? null : W.set_of(list);
}

// A key encrypted with PBES2 - pkcs8.encrypted_to_der's output.
function shrouded_key_bag(encrypted_private_key_info, attrs) {
  return bag(BAG.pkcs8ShroudedKeyBag, to_bytes(encrypted_private_key_info),
    attrs);
}

// ⚠ AN UNENCRYPTED KEY. Legal, and readable by anyone holding the file -
// the outer safe may be encrypted, but if it is a data safe this key is in
// the clear. Named so that nobody reaches for it by accident.
function plaintext_key_bag(pkcs8_der, attrs) {
  return bag(BAG.keyBag, to_bytes(pkcs8_der), attrs);
}

//   CertBag ::= SEQUENCE {
//      certId     BAG-TYPE.&id,             -- x509Certificate
//      certValue  [0] EXPLICIT BAG-TYPE.&Type }  -- OCTET STRING of the DER
function cert_bag(cert_der, attrs) {
  return bag(BAG.certBag, W.sequence([
    W.oid(OID.from_string(X509_CERTIFICATE)),
    W.explicit(0, W.octet_string(to_bytes(cert_der)))
  ]), attrs);
}

// SafeContents ::= SEQUENCE OF SafeBag. Returned as BYTES, because the next
// step - encrypting it, or wrapping it as data - takes the bytes.
function safe_contents(bags) {
  if (!Array.isArray(bags) || bags.length === 0) {
    fail('bad-input', 'a SafeContents holds at least one bag');
  }
  return W.to_bytes(W.sequence(bags));
}

// ---------------------------------------------------------------------------
// Safes
// ---------------------------------------------------------------------------

// A safe in the clear: ContentInfo { data, OCTET STRING SafeContents }.
function data_safe(contents) {
  return W.sequence([W.oid(OID.from_string(DATA)),
    W.explicit(0, W.octet_string(to_bytes(contents)))]);
}

// A safe encrypted as a whole: ContentInfo { encryptedData, EncryptedData }.
//
//   EncryptedData ::= SEQUENCE {
//      version               0,
//      encryptedContentInfo  SEQUENCE {
//         contentType                 data,
//         contentEncryptionAlgorithm  PBES2 AlgorithmIdentifier,
//         encryptedContent        [0] IMPLICIT OCTET STRING } }
//
// parts: the PBES2 parameters the caller encrypted with - as
// pkcs8.encrypted_to_der
// takes them - and `data`, the encrypted SafeContents.
function encrypted_safe(parts) {
  if (!parts || !parts.data) {
    fail('bad-input', 'the encrypted SafeContents is required as data');
  }

  return W.sequence([
    W.oid(OID.from_string(ENCRYPTED_DATA)),
    W.explicit(0, W.sequence([
      W.integer([0]),
      W.sequence([
        W.oid(OID.from_string(DATA)),
        PBES2.scheme_to_der(parts),
        W.implicit(0, W.octet_string(to_bytes(parts.data)))
      ])
    ]))
  ]);
}

// AuthenticatedSafe ::= SEQUENCE OF ContentInfo
//
// prepare() as in every builder here: returns { bytes } - THE BYTES THE MAC
// COVERS. Not the PFX, not the
// ContentInfo around them: this SEQUENCE, which becomes the content of the
// authSafe's OCTET STRING. Computing the MAC over anything else is the
// commonest way to write a PFX no importer opens.
function prepare(safes) {
  if (!Array.isArray(safes) || safes.length === 0) {
    fail('bad-input', 'an AuthenticatedSafe holds at least one safe');
  }
  return { bytes: W.to_bytes(W.sequence(safes)) };
}

// ---------------------------------------------------------------------------
// The PFX
// ---------------------------------------------------------------------------

//   PFX ::= SEQUENCE {
//      version     3,
//      authSafe    ContentInfo,                   -- data, AuthenticatedSafe
//      macData     MacData OPTIONAL }
//
//   MacData ::= SEQUENCE {
//      mac         DigestInfo,
//      macSalt     OCTET STRING,
//      iterations  INTEGER DEFAULT 1 }
//
// mac: { hash, salt, iterations, digest } - digest is the HMAC the caller
// computed over prepared.bytes with the PKCS#12-KDF key (ID 3).
function assemble(prepared, mac) {
  if (!prepared || !(prepared.bytes instanceof Uint8Array)) {
    fail('bad-input', 'assemble takes what prepare() returned');
  }
  if (!mac || typeof mac !== 'object') {
    fail('no-mac',
      'a PFX without a MAC has no integrity check at all - its ' +
      'certificates could be swapped freely. Compute the MAC over ' +
      'prepared.bytes and pass { hash, salt, iterations, digest }');
  }
  if (MAC_HASHES.indexOf(mac.hash) === -1) {
    fail('unsupported-digest', 'the MAC hash is one of ' +
      MAC_HASHES.join(', '));
  }

  var digest = to_bytes(mac.digest || new Uint8Array(0));

  if (digest.length !== OID.digest_size(mac.hash)) {
    fail('bad-digest-length', mac.hash + ' produces ' +
      OID.digest_size(mac.hash) + ' bytes');
  }

  var salt = to_bytes(mac.salt || new Uint8Array(0));

  if (salt.length < 8) {
    fail('bad-salt', 'the MAC salt is at least 8 bytes');
  }

  check_iterations(mac.iterations, undefined, fail, 'the MAC iteration count');

  var mac_data;

  if (mac.scheme === 'pbmac1') {
    mac_data = pbmac1_mac_data(mac, digest);
  } else if (mac.scheme === undefined || mac.scheme === 'pkcs12-kdf') {
    mac_data = [
      W.sequence([
        W.sequence([W.oid(OID.by_name(mac.hash)), W.null()]),
        W.octet_string(digest)
      ]),
      W.octet_string(salt)
    ];

    // DEFAULT 1 is omitted, as DER requires.
    if (mac.iterations !== 1) {
      mac_data.push(W.unsigned(int_bytes(mac.iterations)));
    }
  } else {
    fail('bad-input', 'the MAC scheme is pkcs12-kdf (default) or pbmac1');
  }

  return W.to_bytes(W.sequence([
    W.integer([3]),
    W.sequence([W.oid(OID.from_string(DATA)),
      W.explicit(0, W.octet_string(prepared.bytes))]),
    W.sequence(mac_data)
  ]));
}

//   DigestInfo { AlgorithmIdentifier { id-PBMAC1, PBMAC1-params }, digest }
//   PBMAC1-params ::= SEQUENCE { keyDerivationFunc, messageAuthScheme }
//
// RFC 9579. keyLength is ALWAYS written - section 5 makes a reader refuse
// a file without it - and defaults to the HMAC's output size, as section 5
// recommends. macSalt and iterations are ignored by a PBMAC1 reader (4 c,
// d) and SHOULD be present for older ones; the PBKDF2 salt is repeated in
// macSalt, and iterations is left at its DEFAULT of 1, so an old importer
// that misreads the MAC as the PKCS#12 KDF fails at once instead of
// spending the real iteration count to reach the same "wrong password".
function pbmac1_mac_data(mac, digest) {
  // The PRF in either spelling; by default the HMAC of the MAC's own hash.
  var prf = canonical_name(mac.prf === undefined ? hmac_oid_name(mac.hash)
    : mac.prf);
  var size = OID.digest_size(mac.hash);
  var key_length = mac.key_length === undefined ? size : mac.key_length;

  if (typeof key_length !== 'number' || key_length % 1 !== 0 ||
      key_length < 20) {
    fail('weak-key-length', 'the PBMAC1 key is at least 20 bytes, RFC 9579 9');
  }
  if (mac.hash === 'sha1' || prf === 'hmacWithSHA1') {
    fail('weak-mac', 'RFC 9579 7: PBMAC1 SHOULD NOT use SHA-1, and a new ' +
      'file has no reason to');
  }

  return [
    W.sequence([
      W.sequence([
        W.oid(OID.by_name('pbmac1')),
        W.sequence([
          pbkdf2_to_der({ prf: prf, salt: mac.salt,
                          iterations: mac.iterations }, key_length),
          W.sequence([W.oid(OID.by_name(hmac_oid_name(mac.hash))), W.null()])
        ])
      ]),
      W.octet_string(digest)
    ]),
    W.octet_string(to_bytes(mac.salt))
  ];
}

function hmac_oid_name(hash) {
  return 'hmacWith' + hash.toUpperCase();
}

export {
  shrouded_key_bag,
  plaintext_key_bag,
  cert_bag,
  safe_contents,
  data_safe,
  encrypted_safe,
  prepare,
  assemble
};

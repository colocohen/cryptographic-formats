// Signed Certificate Timestamps, RFC 6962.
//
// ⚠ WHAT THIS IS FOR, IN ONE SENTENCE: any CA can issue a certificate for
// any domain, and Certificate Transparency is how the domain's owner finds
// out.
//
// DigiNotar issued working certificates for Google in 2011 and it was
// discovered months later, after they had been used against people in Iran.
// The certificate itself carried nothing that would have exposed it - it was
// signed by a CA every browser trusted, and it looked exactly like a real
// one.
//
// So: every certificate is submitted to public append-only logs before it is
// issued. The log returns a Signed Certificate Timestamp - a signature over
// "I saw this certificate at this time" - and the CA embeds the SCTs in the
// certificate. Anybody can then scan the logs, and a monitor watching for
// certificates naming google.com sees a forgery within minutes.
//
// Chrome has required this since 2018: a public TLS certificate with no SCTs
// is rejected.
//
// ⚠ AND THE ENCODING IS NOT ASN.1.
//
// This is the only extension in X.509 whose body is a TLS structure. RFC
// 6962 was written by the TLS working group and reuses TLS's presentation
// language - length-prefixed, big-endian, no tags:
//
//   opaque SerializedSCT<1..2^16-1>;
//   struct { SerializedSCT sct_list<1..2^16-1>; } SignedCertificateTimestampList;
//
// wrapped in an OCTET STRING so that X.509 can carry it. Two encodings, one
// inside the other, and reading the inner one with a DER reader produces
// nonsense that sometimes parses.

import * as DER from './der_reader.js';
import * as OID from './oid.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, der_wrap } from './commons/bytes.js';

var fail = make_fail_here('sct');

// ---------------------------------------------------------------------------
// The TLS registries RFC 6962 uses
// ---------------------------------------------------------------------------

// RFC 5246 section 7.4.1.4.1. These are TLS's numbers, not X.509's - a
// SignatureAndHashAlgorithm, which is where an SCT's signature algorithm
// comes from.
var HASH_ALGORITHMS = {
  0: 'none', 1: 'md5', 2: 'sha1', 3: 'sha224',
  4: 'sha256', 5: 'sha384', 6: 'sha512'
};

var SIGNATURE_ALGORITHMS = {
  0: 'anonymous', 1: 'rsa', 2: 'dsa', 3: 'ecdsa'
};

// ⚠ THE SIGNATURE IS DER INSIDE A TLS STRUCTURE.
//
// The hash and signature come as two TLS bytes, and the signature VALUE that
// follows is an ordinary DER-encoded ECDSA or RSA signature. So the caller
// gets a name they already know - `ecdsaWithSHA256` - rather than a pair of
// numbers they would have to look up.
function algorithm_name(hash, signature) {
  var h = HASH_ALGORITHMS[hash];
  var s = SIGNATURE_ALGORITHMS[signature];

  if (h === undefined || s === undefined) {
    return null;
  }

  if (s === 'ecdsa') {
    return h === 'sha256' ? 'ecdsaWithSHA256'
      : h === 'sha384' ? 'ecdsaWithSHA384'
      : h === 'sha512' ? 'ecdsaWithSHA512'
      : h === 'sha1' ? 'ecdsaWithSHA1' : null;
  }

  if (s === 'rsa') {
    return h === 'sha256' ? 'sha256WithRSA'
      : h === 'sha384' ? 'sha384WithRSA'
      : h === 'sha512' ? 'sha512WithRSA'
      : h === 'sha1' ? 'sha1WithRSA' : null;
  }

  return s + '-with-' + h;
}

// ---------------------------------------------------------------------------
// A TLS cursor
// ---------------------------------------------------------------------------

// ⚠ A SEPARATE READER, DELIBERATELY.
//
// TLS's presentation language and DER share nothing: no tags, no
// self-describing values, lengths in a fixed number of big-endian bytes
// decided by the field's declared maximum. Reading one with the other
// produces values that are wrong in ways that sometimes parse.
//
// It lives here rather than in commons because this is the only format in
// the library that uses it - and a TLS reader in commons would invite
// somebody to reach for it from a DER path.
function tls_reader(bytes, base) {
  var pos = 0;

  function need(n, what) {
    if (pos + n > bytes.length) {
      fail('truncated',
        'expected ' + n + ' bytes for ' + what + ' at offset ' +
        (base + pos) + ', ' + (bytes.length - pos) + ' remain');
    }
  }

  return {
    u8: function (what) {
      need(1, what);
      return bytes[pos++];
    },

    u16: function (what) {
      need(2, what);
      var v = (bytes[pos] << 8) | bytes[pos + 1];
      pos += 2;
      return v;
    },

    // ⚠ 64 BITS, AND JAVASCRIPT NUMBERS HOLD 53.
    //
    // The timestamp is milliseconds since the epoch, so the top 11 bits stay
    // zero until the year 287396 - but reading it with a shift would silently
    // wrap. Multiplication keeps every bit that matters and the high half is
    // checked rather than assumed.
    u64: function (what) {
      need(8, what);

      var high = (bytes[pos] * 0x1000000) + (bytes[pos + 1] << 16) +
                 (bytes[pos + 2] << 8) + bytes[pos + 3];
      var low  = (bytes[pos + 4] * 0x1000000) + (bytes[pos + 5] << 16) +
                 (bytes[pos + 6] << 8) + bytes[pos + 7];
      pos += 8;

      if (high > 0x1FFFFF) {
        fail('timestamp-too-large',
          'the timestamp exceeds what a JavaScript number holds exactly');
      }

      return high * 0x100000000 + low;
    },

    bytes: function (n, what) {
      need(n, what);
      var out = bytes.subarray(pos, pos + n);
      pos += n;
      return out;
    },

    // A vector with a two-byte length prefix, which is every variable-length
    // field in RFC 6962.
    vector16: function (what) {
      var length = this.u16(what + ' length');
      return this.bytes(length, what);
    },

    remaining: function () {
      return bytes.length - pos;
    },

    at: function () {
      return base + pos;
    }
  };
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// The extension value, as it arrives from x509.js: an OCTET STRING whose
// content is the TLS structure.
function from_extension(input) {
  var bytes = to_bytes(input);

  // ⚠ AN OCTET STRING INSIDE THE OCTET STRING THAT EVERY EXTENSION HAS.
  //
  // extnValue is already an OCTET STRING and x509.js unwraps it. RFC 6962
  // puts ANOTHER one inside, so the TLS structure is two layers down - and a
  // reader that unwrapped once would take the DER header of the inner one as
  // the first two bytes of a TLS length.
  var inner = DER.read(bytes, function (r) {
    return r.read_octet_string();
  });

  return from_tls(inner);
}

// The TLS SignedCertificateTimestampList, without the DER wrapper.
function from_tls(input) {
  var bytes = to_bytes(input);
  var r = tls_reader(bytes, 0);

  var list = r.vector16('sct_list');

  if (r.remaining() !== 0) {
    fail('trailing-bytes',
      r.remaining() + ' bytes follow the SCT list');
  }

  if (list.length === 0) {
    fail('empty-list',
      'an SCT list with no timestamps says nothing, and a certificate ' +
      'carrying one has an extension that does no work');
  }

  var items = tls_reader(list, 2);
  var out = [];

  while (items.remaining() > 0) {
    var one = items.vector16('SerializedSCT');
    out.push(read_sct(one));
  }

  return out;
}

//   struct {
//       Version sct_version;
//       LogID id;                       -- 32 bytes, SHA-256 of the log key
//       uint64 timestamp;
//       CtExtensions extensions;
//       digitally-signed struct { ... } signature;
//   } SignedCertificateTimestamp;
function read_sct(bytes) {
  var r = tls_reader(bytes, 0);

  var version = r.u8('sct_version');

  // RFC 6962 defines v1 as 0 and nothing else. A later version would have a
  // different structure, so guessing at it would misread every field.
  if (version !== 0) {
    fail('bad-version',
      'SCT version ' + version + '; RFC 6962 defines only v1, encoded as 0');
  }

  // ⚠ THE LOG ID IS THE SHA-256 OF THE LOG'S PUBLIC KEY.
  //
  // Not a name and not a URL - so identifying WHICH log requires a list of
  // known logs, which changes as logs are added and retired. This module
  // reports the hash and does not carry the list: a list baked into a
  // library is a list that is wrong within months.
  var log_id = r.bytes(32, 'LogID');

  var timestamp = r.u64('timestamp');
  var extensions = r.vector16('CtExtensions');

  var hash = r.u8('hash algorithm');
  var signature_alg = r.u8('signature algorithm');
  var signature = r.vector16('signature');

  if (r.remaining() !== 0) {
    fail('trailing-bytes',
      r.remaining() + ' bytes follow the SCT');
  }

  var name = algorithm_name(hash, signature_alg);

  return {
    version:   1,
    log_id:    log_id,
    log_id_hex: hex(log_id),
    // ⚠ MILLISECONDS, unlike almost every other timestamp in this library.
    // Passing it to a Date constructor expecting seconds gives a date in
    // 1970.
    timestamp: timestamp,
    date:      new Date(timestamp),
    extensions: extensions.length > 0 ? extensions : null,
    hash_algorithm: HASH_ALGORITHMS[hash] === undefined
      ? hash : HASH_ALGORITHMS[hash],
    signature_algorithm: SIGNATURE_ALGORITHMS[signature_alg] === undefined
      ? signature_alg : SIGNATURE_ALGORITHMS[signature_alg],
    // The name this library uses everywhere else, so a caller does not have
    // to translate a pair of TLS numbers.
    algorithm: name,
    signature: signature
  };
}

// ---------------------------------------------------------------------------
// Verifying
// ---------------------------------------------------------------------------

// ⚠ WHAT AN SCT SIGNATURE COVERS IS NOT THE CERTIFICATE.
//
// It covers a TLS structure built from the certificate WITH THE SCT
// EXTENSION REMOVED - because the log signed the precertificate, before the
// SCTs existed to be embedded.
//
//   digitally-signed struct {
//       Version sct_version;
//       SignatureType signature_type;   -- 0, certificate_timestamp
//       uint64 timestamp;
//       LogEntryType entry_type;        -- 1, precert_entry
//       PreCert signed_entry;           -- issuer key hash + TBS
//       CtExtensions extensions;
//   }
//
// Building that needs the issuer's public key hash and a re-encoded TBS with
// one extension deleted - which is a re-encoding, and this library does not
// re-encode signed structures.
//
// So the plan says what is needed and hands over the pieces it can. That is
// the same position pbes2.js takes: report the parameters, hand over the
// bytes, let the caller do the work this module refuses to guess at.
function verification_plan(sct) {
  return {
    algorithm: sct.algorithm,
    signature: sct.signature,
    log_id:    sct.log_id,

    // ⚠ NULL, ALWAYS, AND FOR A REASON.
    bytes: null,

    needs: 'the signed structure is built from the PRECERTIFICATE - this ' +
           'certificate with the SCT extension removed - prefixed by the ' +
           'SHA-256 of the issuer public key, and wrapped in the TLS ' +
           'structure of RFC 6962 section 3.2. Building it means ' +
           're-encoding a TBSCertificate with one extension deleted, which ' +
           'this library does not do: a re-encode that differs by one byte ' +
           'hashes differently and the signature fails for reasons that ' +
           'look like a bad key.',

    also: 'and the log public key, which is not in the certificate. The ' +
          'log_id is the SHA-256 of that key, so finding it means a list of ' +
          'known logs - which this library does not carry, because a list ' +
          'baked into a library is wrong within months.'
  };
}

// ---------------------------------------------------------------------------

// Whether a certificate carries SCTs at all - the check Chrome makes.
//
// ⚠ THE FIRST VERSION LOOKED AT `.name` AND RETURNED false FOR EVERY
//    CERTIFICATE.
//
// x509.js names the field `id`. Reading a property that does not exist gives
// `undefined`, which is not equal to anything, so the function reported
// "no SCTs" for a certificate that had two - silently, with no error
// anywhere.
//
// That is the failure mode a boolean helper invites: there is no wrong
// answer it can give that looks wrong. It goes through extension(), which
// knows the field names, rather than walking the array here.
function present_in(cert) {
  return extension_of(cert, 'sct_list') !== null;
}

function extension_of(cert, name) {
  var i;

  for (i = 0; i < cert.extensions.length; i++) {
    if (cert.extensions[i].name === name) {
      return cert.extensions[i];
    }
  }

  return null;
}

// The SCTs in a certificate, or an empty array. Saves a caller reaching into
// `extension(...).parsed` and handling the null.
function in_certificate(cert) {
  var ext = extension_of(cert, 'sct_list');

  return ext === null || ext.parsed === null || ext.parsed === undefined
    ? [] : ext.parsed;
}

export {
  from_extension,
  to_tls,
  to_extension,
  from_tls,
  verification_plan,
  present_in,
  in_certificate,
  HASH_ALGORITHMS,
  SIGNATURE_ALGORITHMS
};

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------
//
// ⚠ A CA DOES PRODUCE THIS, EVEN THOUGH IT CANNOT PRODUCE AN SCT.
//
// The SCTs themselves come from logs - a CA submits a precertificate and
// each log returns a signed timestamp. But the LIST is assembled by the CA,
// and embedding it means building the TLS structure and wrapping it twice in
// OCTET STRINGs.
//
// So `to_tls` takes SCTs a caller received and produces the extension value.
// It does not mint one, and there is no function that pretends to.

// The SignedCertificateTimestampList, ready for an extension value.
//
//   var value = sct.to_extension(sctsFromLogs);
//   x509_build.prepare({ extensions: { sct_list: value } });
function to_tls(list) {
  if (!Array.isArray(list) || list.length === 0) {
    fail('empty-list',
      'an SCT list with no timestamps says nothing, and a certificate ' +
      'carrying one has an extension that does no work');
  }

  var items = [];
  var total = 0;
  var i;

  for (i = 0; i < list.length; i++) {
    var one = one_to_tls(list[i]);

    if (one.length > 0xFFFF) {
      fail('sct-too-large',
        'an SCT is length-prefixed with two bytes, so it cannot exceed ' +
        '65535');
    }

    items.push(new Uint8Array([(one.length >> 8) & 0xFF, one.length & 0xFF]));
    items.push(one);
    total += 2 + one.length;
  }

  if (total > 0xFFFF) {
    fail('list-too-large',
      'the SCT list is length-prefixed with two bytes');
  }

  var out = new Uint8Array(2 + total);
  out[0] = (total >> 8) & 0xFF;
  out[1] = total & 0xFF;

  var at = 2;

  for (i = 0; i < items.length; i++) {
    out.set(items[i], at);
    at += items[i].length;
  }

  return out;
}

// The extension VALUE: the TLS list inside an OCTET STRING.
//
// ⚠ AND THAT OCTET STRING SITS INSIDE THE ONE EVERY EXTENSION VALUE ALREADY
// HAS. Two layers, and a writer that produced one gives a certificate whose
// SCT extension every CT-aware client refuses.
function to_extension(list) {
  return der_wrap(0x04, to_tls(list));
}

function one_to_tls(sct) {
  if (sct === null || typeof sct !== 'object') {
    fail('bad-sct',
      'an SCT is the object from_tls produced, or { log_id, timestamp, ' +
      'algorithm, signature }');
  }

  var log_id = to_bytes(sct.log_id);

  if (log_id.length !== 32) {
    fail('bad-log-id',
      'a LogID is the SHA-256 of the log public key: 32 bytes, got ' +
      log_id.length);
  }

  if (typeof sct.timestamp !== 'number' || sct.timestamp < 0) {
    fail('bad-timestamp',
      'the timestamp is MILLISECONDS since the epoch - a value in seconds ' +
      'dates the SCT to 1970 and nothing says so');
  }

  var pair = algorithm_pair(sct);
  var signature = to_bytes(sct.signature);
  var extensions = sct.extensions === null || sct.extensions === undefined
    ? new Uint8Array(0) : to_bytes(sct.extensions);

  var out = [];

  // version v1
  out.push(0);

  var i;

  for (i = 0; i < 32; i++) {
    out.push(log_id[i]);
  }

  // ⚠ uint64, AND A SHIFT WOULD WRAP AT 32 BITS. Milliseconds since the
  // epoch passed 2^32 in 1970 plus seven weeks, so this is not theoretical.
  var high = Math.floor(sct.timestamp / 0x100000000);
  var low = sct.timestamp % 0x100000000;

  out.push((high >> 24) & 0xFF, (high >> 16) & 0xFF,
           (high >> 8) & 0xFF, high & 0xFF);
  out.push((low >> 24) & 0xFF, (low >> 16) & 0xFF,
           (low >> 8) & 0xFF, low & 0xFF);

  out.push((extensions.length >> 8) & 0xFF, extensions.length & 0xFF);

  for (i = 0; i < extensions.length; i++) {
    out.push(extensions[i]);
  }

  out.push(pair.hash, pair.signature);
  out.push((signature.length >> 8) & 0xFF, signature.length & 0xFF);

  for (i = 0; i < signature.length; i++) {
    out.push(signature[i]);
  }

  return new Uint8Array(out);
}

// ⚠ THE TLS NUMBERS, NOT X.509'S.
//
// A caller holding `ecdsaWithSHA256` has a name from this library's own
// table, and the wire wants a pair of bytes from RFC 5246's registry. Taking
// the name and producing the pair is the conversion this module exists to
// make in the other direction too.
function algorithm_pair(sct) {
  if (typeof sct.hash_algorithm === 'number' &&
      typeof sct.signature_algorithm === 'number') {
    return { hash: sct.hash_algorithm, signature: sct.signature_algorithm };
  }

  var name = sct.algorithm ||
    (typeof sct.signature_algorithm === 'string' &&
     typeof sct.hash_algorithm === 'string'
       ? sct.signature_algorithm + '-' + sct.hash_algorithm : null);

  if (name === null) {
    fail('no-algorithm',
      'an SCT needs { algorithm } - the name, as from_tls reports it');
  }

  var hashes = { sha1: 2, sha224: 3, sha256: 4, sha384: 5, sha512: 6 };
  var sigs = { rsa: 1, dsa: 2, ecdsa: 3 };

  var hash = /sha512|SHA512/.test(name) ? hashes.sha512
    : /sha384|SHA384/.test(name) ? hashes.sha384
    : /sha256|SHA256/.test(name) ? hashes.sha256
    : /sha1|SHA1/.test(name) ? hashes.sha1 : null;

  var sig = /ecdsa/i.test(name) ? sigs.ecdsa
    : /rsa/i.test(name) ? sigs.rsa
    : /dsa/i.test(name) ? sigs.dsa : null;

  if (hash === null || sig === null) {
    fail('unknown-algorithm',
      'no TLS SignatureAndHashAlgorithm for "' + name + '"');
  }

  return { hash: hash, signature: sig };
}

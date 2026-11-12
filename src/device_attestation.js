// Certificate extensions that attest a device: what Apple and Android put
// in the leaf certificate an attestation hands over. Read as x509.js reads
// any extension - x509.js's handlers call these - and nothing here judges
// them: whether a challenge matches, a bootloader is locked, or a model is
// acceptable is the verifier's.
//
// Each layout is from its source, checked against real certificates
// (test/vectors/README.md):
//
// APPLE
//   1.2.840.113635.100.8.2   WebAuthn "apple" attestation (W3C 8.8) and App
//                            Attest: SEQUENCE { [1] EXPLICIT OCTET STRING }
//                            - the nonce, SHA-256(authData || clientDataHash).
//   1.2.840.113635.100.8.9.1   serial number       \
//   1.2.840.113635.100.8.9.2   UDID                 |  Managed Device
//   1.2.840.113635.100.8.10.1  OS version           |  Attestation (Apple
//   1.2.840.113635.100.8.10.2  sepOS version        |  Platform Security,
//   1.2.840.113635.100.8.10.3  LLB version          |  "Managed device
//   1.2.840.113635.100.8.11.1  freshness code      /   attestation")
//
// ⚠ THE MDA VALUES ARE NOT ASN.1. extnValue's OCTET STRING holds the text
// itself - "DMH9ZK607VP8", not a UTF8String around it - and the freshness
// code holds the raw bytes: for ACME, SHA-256 of the device-attest-01
// token; for a DeviceInformation query, the DeviceAttestationNonce. That is
// how step-ca reads them (acme/challenge.go: `string(ext.Value)`), and what
// a published iPad certificate shows.
//
// ANDROID
//   1.3.6.1.4.1.11129.2.1.17 KeyDescription - the Android Keystore / KeyMint
//                            key attestation (KeyMint's KeyCreationResult.aidl;
//                            source.android.com, "Key and ID attestation").

import * as DER from './der_reader.js';
import * as T from './tags.js';
import * as OID from './oid.js';
import { make_fail_here } from './commons/fail.js';
import { decode_utf8 } from './commons/decode_text.js';

var fail = make_fail_here('device_attestation');

// ---------------------------------------------------------------------------
// Apple
// ---------------------------------------------------------------------------

function apple_nonce(value) {
  return DER.read(value, function (r) {
    var seq = r.read_sequence();
    var nonce = seq.read_explicit(1).read_octet_string();
    seq.expect_end();
    return { nonce: nonce };
  });
}

// A Managed Device Attestation text value: the extension's bytes, as text.
function apple_text(value) {
  return decode_utf8(value, function (pos, code, detail) { fail(code, detail); }, 0);
}

function apple_bytes(value) {
  return value;
}

// ---------------------------------------------------------------------------
// Android: KeyDescription
// ---------------------------------------------------------------------------
//
//   KeyDescription ::= SEQUENCE {
//     attestationVersion INTEGER, attestationSecurityLevel SecurityLevel,
//     keyMintVersion INTEGER, keyMintSecurityLevel SecurityLevel,
//     attestationChallenge OCTET STRING, uniqueId OCTET STRING,
//     softwareEnforced AuthorizationList, hardwareEnforced AuthorizationList }
//
// The same shape since Keymaster 2 (attestationVersion 1); the version
// numbers are Keymaster's (1-4) and KeyMint's (100-400).

var SECURITY_LEVELS = ['Software', 'TrustedEnvironment', 'StrongBox'];
var BOOT_STATES = ['Verified', 'SelfSigned', 'Unverified', 'Failed'];

function key_description(value, warn) {
  return DER.read(value, function (r) {
    var seq = r.read_sequence();
    var out = {
      attestation_version: small(seq.read_unsigned(), 'attestationVersion'),
      attestation_security_level: level(seq.read_enumerated()),
      keymint_version: small(seq.read_unsigned(), 'keyMintVersion'),
      keymint_security_level: level(seq.read_enumerated()),
      attestation_challenge: seq.read_octet_string(),
      unique_id: seq.read_octet_string(),
      software_enforced: authorization_list(seq.read_sequence(), warn, 'softwareEnforced'),
      hardware_enforced: authorization_list(seq.read_sequence(), warn, 'hardwareEnforced')
    };
    seq.expect_end();
    return out;
  });
}

function level(bytes) {
  var n = small(bytes, 'SecurityLevel');
  return { code: n, name: SECURITY_LEVELS[n] === undefined ? null : SECURITY_LEVELS[n] };
}

// AuthorizationList ::= SEQUENCE { each field [tag] EXPLICIT ... OPTIONAL },
// the tag the KeyMint tag number. KeyMint 4's list, as KeyCreationResult.aidl
// gives it; a tag not in it - a Keymaster-era field, or one newer than this -
// is kept as { tag, value } under `unknown`, its content's DER.
var AUTH = {
  1: ['purpose', 'set'], 2: ['algorithm', 'int'], 3: ['key_size', 'int'],
  4: ['block_mode', 'set'], 5: ['digest', 'set'], 6: ['padding', 'set'],
  7: ['caller_nonce', 'null'], 8: ['min_mac_length', 'int'], 10: ['ec_curve', 'int'],
  200: ['rsa_public_exponent', 'int'], 203: ['mgf_digest', 'set'],
  303: ['rollback_resistance', 'null'], 305: ['early_boot_only', 'null'],
  400: ['active_date_time', 'int'], 401: ['origination_expire_date_time', 'int'],
  402: ['usage_expire_date_time', 'int'], 405: ['usage_count_limit', 'int'],
  502: ['user_secure_id', 'int'], 503: ['no_auth_required', 'null'],
  504: ['user_auth_type', 'int'], 505: ['auth_timeout', 'int'],
  506: ['allow_while_on_body', 'null'], 507: ['trusted_user_presence_required', 'null'],
  508: ['trusted_confirmation_required', 'null'], 509: ['unlocked_device_required', 'null'],
  701: ['creation_date_time', 'int'], 702: ['origin', 'int'],
  704: ['root_of_trust', 'root_of_trust'], 705: ['os_version', 'int'],
  706: ['os_patch_level', 'int'], 709: ['attestation_application_id', 'application_id'],
  710: ['attestation_id_brand', 'octets'], 711: ['attestation_id_device', 'octets'],
  712: ['attestation_id_product', 'octets'], 713: ['attestation_id_serial', 'octets'],
  714: ['attestation_id_imei', 'octets'], 715: ['attestation_id_meid', 'octets'],
  716: ['attestation_id_manufacturer', 'octets'], 717: ['attestation_id_model', 'octets'],
  718: ['vendor_patch_level', 'int'], 719: ['boot_patch_level', 'int'],
  720: ['device_unique_attestation', 'null'], 723: ['attestation_id_second_imei', 'octets'],
  724: ['module_hash', 'octets']
};

function authorization_list(seq, warn, what) {
  var out = { unknown: [] };
  var last = -1;
  while (seq.remaining() > 0) {
    var field = explicit_field(seq);
    if (field.tag <= last) {
      // X.690: SEQUENCE components in definition order, each at most once.
      if (field.tag === last) {
        fail('duplicate-tag', what + ' has tag [' + field.tag + '] twice');
      }
      warn('unordered-authorization-list', what + ': tag [' + field.tag +
        '] after [' + last + ']');
    }
    last = Math.max(last, field.tag);
    var spec = AUTH[field.tag];
    if (spec === undefined) {
      out.unknown.push({ tag: field.tag, value: field.content.capture() });
      continue;
    }
    out[spec[0]] = typed(field.content, spec[1], spec[0], warn);
    field.content.expect_end();
  }
  return out;
}

// One [n] EXPLICIT field, low tag number or high: { tag, content }.
function explicit_field(seq) {
  if (seq.is_high_tag()) {
    var h = seq.read_high_tag();
    if (h.class_ !== T.CLASS_CONTEXT || !h.constructed) {
      fail('bad-authorization-list', 'a field is [n] EXPLICIT, context class');
    }
    return { tag: h.number, content: h.content };
  }
  var t = seq.peek_tag();
  if ((t & T.CLASS_MASK) !== T.CLASS_CONTEXT || (t & T.CONSTRUCTED) === 0) {
    fail('bad-authorization-list', 'a field is [n] EXPLICIT, context class');
  }
  var n = t & T.NUMBER_MASK;
  return { tag: n, content: seq.read_explicit(n) };
}

function typed(r, type, name, warn) {
  switch (type) {
  case 'int': return safe(r.read_unsigned(), name);
  case 'null': r.read_null(); return true;
  case 'octets': return r.read_octet_string();
  case 'set':
    return set_of(r, function (m) { return small(m.read_unsigned(), name); });
  case 'root_of_trust': return root_of_trust(r);
  case 'application_id': return application_id(r.read_octet_string(), warn);
  }
  return null;
}

// RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked
//   BOOLEAN, verifiedBootState VerifiedBootState, verifiedBootHash OCTET
//   STRING } - the hash from attestation version 3 on; null before.
function root_of_trust(r) {
  var seq = r.read_sequence();
  var key = seq.read_octet_string();
  var locked = seq.read_boolean();
  var state = small(seq.read_enumerated(), 'verifiedBootState');
  var hash = seq.remaining() > 0 ? seq.read_octet_string() : null;
  seq.expect_end();
  return {
    verified_boot_key: key,
    device_locked: locked,
    verified_boot_state: { code: state, name: BOOT_STATES[state] === undefined ? null : BOOT_STATES[state] },
    verified_boot_hash: hash
  };
}

// attestationApplicationId is an OCTET STRING holding the DER of
//   AttestationApplicationId ::= SEQUENCE {
//     package_infos SET OF AttestationPackageInfo,
//     signature_digests SET OF OCTET_STRING }
//   AttestationPackageInfo ::= SEQUENCE { package_name OCTET_STRING, version INTEGER }
// Kept as bytes (`der`) beside what it says.
function application_id(der, warn) {
  var out = { der: der, packages: null, signature_digests: null };
  try {
    DER.read(der, function (r) {
      var seq = r.read_sequence();
      out.packages = set_of(seq, function (p) {
        var s = p.read_sequence();
        var name = s.read_octet_string();
        var version = safe(s.read_unsigned(), 'version');
        s.expect_end();
        return { name: apple_text(name), version: version };
      });
      out.signature_digests = set_of(seq, function (d) { return d.read_octet_string(); });
      seq.expect_end();
    });
  } catch (e) {
    out.packages = null;
    out.signature_digests = null;
    warn('malformed-application-id', e.message);
  }
  return out;
}

// Each member read by `fn` from the SET's reader; DER order checked by
// read_set_of.
function set_of(r, fn) {
  var set = r.read_set_of();
  var out = [];
  while (set.remaining() > 0) { out.push(fn(set)); }
  return out;
}

function small(bytes, what) {
  if (bytes.length > 4) {
    fail('integer-too-large', what + ' is ' + bytes.length + ' bytes');
  }
  return safe(bytes, what);
}

// Times are milliseconds since the epoch, so six bytes; anything past 2^53
// would not survive as a number and is refused rather than rounded.
function safe(bytes, what) {
  if (bytes.length > 7 || (bytes.length === 7 && bytes[0] > 0x1F)) {
    fail('integer-too-large', what + ' does not fit a number exactly');
  }
  var v = 0;
  for (var i = 0; i < bytes.length; i++) { v = v * 256 + bytes[i]; }
  return v;
}

export {
  apple_nonce,
  apple_text,
  apple_bytes,
  key_description,
  SECURITY_LEVELS,
  BOOT_STATES
};

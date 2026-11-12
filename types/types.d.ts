// Types shared by the declarations of several modules. Declarations only:
// there is no types.js, and nothing here exists at run time.
//
// ⚠ THESE ARE CHECKED AGAINST WHAT THE CODE RETURNS.
// test/types.test.js runs tsc over the examples, and over a file generated
// from the values the whole test suite passed to and got back from every
// exported function - so a declaration narrower than real use fails there.

/** Bytes as the readers accept them: copied or viewed into a Uint8Array. */
export type BytesInput = Uint8Array | ArrayBuffer | readonly number[];

/**
 * A DER writer's output before `der_writer.to_bytes`: plain byte values, so
 * nested writers concatenate cheaply. Every writer that takes content also
 * takes a Uint8Array.
 */
export type DerNode = number[];

/** An OID name from the table (`'sha256WithRSA'`) or dotted (`'1.2.3'`). */
export type OidName = string;

/** An AlgorithmIdentifier as the field tables read it. */
export interface AlgorithmIdentifier {
  /** The OID's content bytes. */
  algorithm: Uint8Array;
  /** The parameters' complete DER, or undefined when absent. */
  parameters?: Uint8Array;
}

/** A UTCTime or GeneralizedTime, read. */
export interface Time {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  date: Date;
  /** The fractional seconds digit for digit (GeneralizedTime only). */
  fraction?: string | null;
  /** Set when a GeneralizedTime holds a date before 2050. */
  profile_violation?: 'generalized-time-before-2050';
}

/** A time a builder accepts: a Date, or a Time as a reader returned it. */
export type TimeInput = Date | Time;

/** One attribute of a distinguished name, both parts as DER content. */
export interface NameAttribute {
  /** The attribute type's OID content bytes. */
  type: Uint8Array;
  /** The value's complete DER (a string type, usually). */
  value: Uint8Array;
}

/** A distinguished name: RDNs in encoding order, each a SET of attributes. */
export type Name = NameAttribute[][];

/**
 * A name as builders take it: RDNs in order, each `{ attribute: value }` -
 * `[{ countryName: 'US' }, { commonName: 'Example' }]` - or an array of those
 * for a multi-valued RDN. A Name a reader returned is accepted as it is.
 * An attribute may be named as this library names it (`stateOrProvince`),
 * as X.520 does (`stateOrProvinceName`), by RFC 4514's short name (`ST`), or
 * by a dotted OID; readers return this library's names.
 */
export type NameInput = Array<RdnInput | RdnInput[]>;

export type RdnInput = Record<string, string> | NameAttribute;

/** The GeneralName CHOICE, read (RFC 5280 4.2.1.6). */
export type GeneralName =
  | { type: 'email' | 'dns' | 'uri'; value: string }
  | { type: 'ip'; value: Uint8Array }
  | { type: 'directory'; value: Name }
  | { type: 'registered-id'; value: string; name: string | null; oid: Uint8Array }
  | { type: 'other'; id: string; name: string | null; value: Uint8Array;
      /** 1.3.6.1.4.1.311.20.2.3; null when malformed. */
      upn?: string | null;
      /** RFC 4043 (1.3.6.1.5.5.7.8.3). null in either field means absent - see RFC 4043 2 for what each absence means. */
      permanent_identifier?: PermanentIdentifier | null;
      /** RFC 4108 5 (1.3.6.1.5.5.7.8.4). */
      hardware_module_name?: HardwareModuleName | null }
  | { type: 'other-tag'; tag: number; value: Uint8Array };

export interface PermanentIdentifier {
  value: string | null;
  /** Dotted; null: the issuer assigned it. */
  assigner: string | null;
  assigner_name: string | null;
}

export interface HardwareModuleName {
  /** hwType, dotted. */
  type: string;
  type_name: string | null;
  /** hwSerialNum: bytes, no structure. */
  serial: Uint8Array;
  serial_hex: string;
}

/**
 * A GeneralName as builders take it: exactly one key.
 * `{ dns: 'example.com' }`, `{ ip: '10.0.0.1' }`, `{ directory: [...] }`.
 * In nameConstraints an `ip` is a range: `'10.0.0.0/8'`, `'2001:db8::/32'`,
 * or the address-and-mask bytes.
 */
export type GeneralNameInput =
  | { dns: string }
  | { email: string }
  | { uri: string }
  | { ip: string | Uint8Array }
  | { directory: NameInput }
  | { registered_id: string }
  | { other: { id: string; value: BytesInput } }
  /** An otherName, RFC 4043. Either may be left out. */
  | { permanent_identifier: { value?: string | null; assigner?: string | null } }
  /** An otherName, RFC 4108 5: hwType (dotted or a name), hwSerialNum. */
  | { hardware_module_name: { type: string; serial: BytesInput } }
  /** What x509.read_general_name returned - a name read is a name written back. */
  | GeneralName;

/** A public key read from a SubjectPublicKeyInfo. */
export interface PublicKey {
  /** The key algorithm's OID name: 'rsaEncryption', 'ecPublicKey', 'Ed25519'... */
  algorithm: string;
  /** For EC keys, the named curve; otherwise null. */
  curve: string | null;
  /** The subjectPublicKey bits: an EC point, an RSAPublicKey, raw OKP bytes. */
  point: Uint8Array;
  /** The algorithm parameters' DER, when present. */
  parameters: Uint8Array | null;
  /** The whole SubjectPublicKeyInfo. */
  der: Uint8Array;
  /** RSA keys: the modulus and exponent - the shape jwk and ssh return too. */
  rsa?: { n: Uint8Array; e: Uint8Array };
  /** RSA-PSS keys ('rsassaPss'): the limits a signature must keep to, or null for none (RFC 4055 3.1). */
  pss?: PssLimits | null;
}

/** RSASSA-PSS-params as an RSA-PSS key restricts them. */
export interface PssLimits {
  hash: string;
  mgf: 'mgf1';
  mgf_hash: string;
  /** The minimum salt length. */
  salt_length: number;
  trailer: number;
}

/** A public key as builders take it: a PublicKey, or SPKI DER. */
export type PublicKeyInput = PublicKey | { der: Uint8Array } | Uint8Array;

/** What algorithm.describe reports about an AlgorithmIdentifier. */
export interface AlgorithmDescription {
  /** The OID-table name, or the dotted OID when the table has none. */
  name: string;
  scheme: 'pkcs1' | 'pss' | 'ecdsa' | 'dsa' | 'eddsa' | 'ml-dsa' | 'hash-ml-dsa' | 'slh-dsa' | 'oaep' | 'rsa' | null;
  /** The hash the algorithm implies, by OID-table name; null when none. */
  hash: string | null;
  /** True for MD2, MD4, MD5 and SHA-1 - see DECISIONS 14.2. */
  weak: boolean;
  pss?: PssParams;
  oaep?: OaepParams;
  /** ML-DSA and SLH-DSA: the one length a signature of the set has. */
  signature_length?: number;
}

export interface PssParams {
  hash: string;
  mgf: 'mgf1';
  mgf_hash: string;
  salt_length: number;
  trailer: number;
}

export interface OaepParams {
  hash: string;
  mgf: 'mgf1';
  mgf_hash: string;
  label: Uint8Array;
}

/** An extension as every reader returns it (x509.extension_entry). */
export interface ExtensionEntry {
  /** The dotted OID. */
  id: string;
  /** The name builders take ('subjectAltName'), or null when unknown. */
  name: string | null;
  oid: Uint8Array;
  critical: boolean;
  /** The extnValue OCTET STRING's content. */
  value: Uint8Array;
}

/** A certificate's extension: the entry, and the value decoded. */
export interface Extension<P = unknown> extends ExtensionEntry {
  /** The decoded value, for the extensions x509 reads; else null. */
  parsed: P | null;
  /** Present when the value was read despite a violation OpenSSL accepts. */
  warnings?: Array<{ code: string; detail: string }>;
}

/** The two steps of every signed structure: what prepare() returns. */
export interface Prepared {
  /** The exact bytes to sign. */
  bytes: Uint8Array;
}

/** What every verification_plan returns, at least. */
export interface VerificationPlanBase {
  /** The exact bytes the signature (or MAC) covers. */
  bytes: Uint8Array;
  /** The signature or MAC value. */
  signature: Uint8Array;
  /** The algorithm, by OID-table name. */
  algorithm: string;
}

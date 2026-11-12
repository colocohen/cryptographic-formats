// Building certificates, in two steps around the caller's signature:
//
//   const tbs = x509_build.prepare(parts);         // the bytes to sign
//   const sig = sign(tbs.bytes);                    // not this library
//   const der = x509_build.assemble(tbs, sig);      // the certificate

import type {
  BytesInput, GeneralNameInput, NameInput, PublicKeyInput, TimeInput
} from './types.js';

export type KeyUsageName =
  | 'digitalSignature' | 'nonRepudiation' | 'keyEncipherment'
  | 'dataEncipherment' | 'keyAgreement' | 'keyCertSign' | 'cRLSign'
  | 'encipherOnly' | 'decipherOnly';

/** An algorithm name ('ecdsaWithSHA256'), or PSS with its parameters. */
export type SignatureAlgorithmInput = string | { name: string; hash?: string; mgf_hash?: string; salt_length?: number };

/**
 * Extensions by name. Each value may also be `{ value, critical }` to set
 * criticality yourself; an unknown name takes the extnValue as bytes.
 */
export interface ExtensionsInput {
  basicConstraints?: ExtensionValue<{ ca?: boolean; path_length?: number | null }>;
  keyUsage?: ExtensionValue<KeyUsageName[]>;
  /** EKU_NAMES keys or dotted OIDs - or { id, name } as x509.from_der returns them. */
  extKeyUsage?: ExtensionValue<Array<string | { id: string; name?: string | null }>>;
  subjectAltName?: ExtensionValue<GeneralNameInput[]>;
  issuerAltName?: ExtensionValue<GeneralNameInput[]>;
  subjectKeyId?: ExtensionValue<BytesInput>;
  authorityKeyId?: ExtensionValue<{ key_id?: BytesInput | null; issuer?: GeneralNameInput[] | null; serial?: BytesInput | null }>;
  nameConstraints?: ExtensionValue<{ permitted?: GeneralNameInput[]; excluded?: GeneralNameInput[] }>;
  /** method 'ocsp', 'caIssuers' or a dotted OID. */
  authorityInfoAccess?: ExtensionValue<Array<{ method: string; location: GeneralNameInput }>>;
  /** Each point: its names, or { names }. */
  crlDistribution?: ExtensionValue<Array<GeneralNameInput[] | { names: GeneralNameInput[] }>>;
  /** A policy OID (name or dotted), or { id, cps }. */
  certificatePolicy?: ExtensionValue<Array<string | { id: string; cps?: string }>>;
  inhibitAnyPolicy?: ExtensionValue<number>;
  [other: string]: ExtensionValue<unknown> | undefined;
}

export type ExtensionValue<T> = T | { value: T; critical: boolean };

export interface CertificateParts {
  /** Positive, at least one byte; 16 random bytes is the CA/B Forum's minimum. */
  serial: BytesInput;
  issuer: NameInput;
  subject: NameInput;
  validity: { not_before: TimeInput; not_after: TimeInput };
  public_key: PublicKeyInput;
  signature_algorithm: SignatureAlgorithmInput;
  extensions?: ExtensionsInput;
}

export interface PreparedCertificate {
  /** The TBSCertificate: sign exactly these bytes. */
  bytes: Uint8Array;
  signature_algorithm: SignatureAlgorithmInput;
  parts: CertificateParts;
}

export const KEY_USAGE_ORDER: readonly KeyUsageName[];
export const EKU_NAMES: Readonly<Record<string, string>>;

export function prepare(parts: CertificateParts): PreparedCertificate;
/** The certificate's DER, with the caller's signature (DER for ECDSA). */
export function assemble(tbs: PreparedCertificate, signature: BytesInput): Uint8Array;

/** Problems with the parts that are legal but unwise; empty when none. */
export function check(parts: Partial<CertificateParts>): Array<{ code: string; detail: string }>;

/** The subjectPublicKey bits - what a key identifier hashes (RFC 5280 4.2.1.2). */
export function key_id_input(public_key: PublicKeyInput): Uint8Array;

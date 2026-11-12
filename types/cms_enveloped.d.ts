// CMS EnvelopedData, AuthEnvelopedData, DigestedData and EncryptedData
// (RFC 5652, 5083, 5084), read: every recipient kind, and the parameters a
// caller needs to decrypt. Building is cms_enveloped_build.

import type { AlgorithmDescription, BytesInput, Name } from './types.js';
import type { Pbkdf2Params } from './pbes2.js';
import type { Certificate } from './x509.js';
import type { CmsAttribute } from './cms.js';

export type RecipientId =
  | { by: 'issuer-and-serial'; issuer: Name; serial: Uint8Array; serial_hex: string }
  | { by: 'key-id'; key_id: Uint8Array };

export interface KeyTransportRecipient {
  kind: 'key-transport';
  version: number;
  recipient: RecipientId;
  /** 'rsaEncryption' or 'rsaOAEP'. */
  algorithm: string;
  /** null when the AlgorithmIdentifier has none; the declaration said undefined (DECISIONS 30). */
  parameters: Uint8Array | null;
  key_params: AlgorithmDescription;
  encrypted_key: Uint8Array;
  note: string;
}

export interface KeyAgreementRecipient {
  kind: 'key-agreement';
  /** The X9.63 KDF's SharedInfo (RFC 5753 7.2), built from the message. */
  shared_info: Uint8Array | null;
  kdf_hash: string | null;
  version: number;
  originator:
    | { by: 'ephemeral-key'; algorithm: string; point: Uint8Array }
    | RecipientId;
  ukm: Uint8Array | null;
  kdf: string;
  wrap: string;
  keys: Array<{ recipient: RecipientId; encrypted_key: Uint8Array }>;
  note: string;
}

export interface KekRecipient {
  kind: 'kek';
  identifier: Uint8Array;
  algorithm: string;
  encrypted_key: Uint8Array;
  note: string;
}

export interface PasswordRecipient {
  kind: 'password';
  version: 0;
  kdf: (Pbkdf2Params & { algorithm: 'pbkdf2' }) | null;
  /** 'pwri_kek', or the key-wrap algorithm's name. */
  algorithm: string;
  /** For PWRI-KEK: the inner cipher. */
  kek: { cipher: string; key_length: number; iv: Uint8Array } | null;
  encrypted_key: Uint8Array;
  note: string;
}

/** RFC 9629 KEMRecipientInfo - an ori [4] of type id-ori-kem. */
export interface KemRecipient {
  kind: 'kem';
  version: 0;
  recipient: RecipientId;
  /** 'mlKem512'... or the dotted OID. */
  kem: string;
  kem_parameters: Uint8Array | null;
  kem_ciphertext: Uint8Array;
  /** 'hkdfWithSha256'... */
  kdf: string;
  kdf_parameters: Uint8Array | null;
  /** The HKDF's hash; null for another KDF. */
  kdf_hash: string | null;
  /** The KEK's length in bytes - the KDF's L. */
  kek_length: number;
  ukm: Uint8Array | null;
  /** CMSORIforKEMOtherInfo, the KDF's info, built from the message. */
  kdf_info: Uint8Array;
  wrap: string;
  encrypted_key: Uint8Array;
  note: string;
}

export interface OtherRecipient {
  kind: 'other';
  /** The oriType, dotted. */
  ori_type: string;
  value: Uint8Array;
  note: string;
}

export type Recipient =
  | KeyTransportRecipient
  | KeyAgreementRecipient
  | KekRecipient
  | PasswordRecipient
  | KemRecipient
  | OtherRecipient;

/** RFC 5652 9: content in the clear, a MAC, and the MAC key per recipient. */
export interface AuthenticatedData {
  version: number;
  recipients: Recipient[];
  originator: Uint8Array | null;
  /** 'hmacWithSHA256'... or the dotted OID. */
  mac_algorithm: string;
  mac_parameters: Uint8Array | null;
  /** Present with authAttrs - the hash of message_digest. */
  digest: string | null;
  /** 'data', or the dotted OID. */
  content_type: string;
  content: Uint8Array | null;
  detached: boolean;
  auth_attrs: CmsAttribute[] | null;
  /** As it travels, [2] IMPLICIT; mac_plan gives the MACed form. */
  auth_attrs_raw: Uint8Array | null;
  message_digest: Uint8Array | null;
  mac: Uint8Array;
  unauth_attrs_unauthenticated: CmsAttribute[] | null;
  der: Uint8Array;
  note: string;
}

export type MacPlan =
  | { kind: 'direct'; bytes: Uint8Array; mac: Uint8Array; algorithm: string; note: string }
  | { kind: 'auth-attrs'; bytes: Uint8Array; mac: Uint8Array; algorithm: string;
      digest: string | null; content_bytes: Uint8Array; expected_digest: Uint8Array | null; note: string };

/** RFC 3274. The content comes back compressed: inflate it, with a limit. */
export interface CompressedData {
  version: 0;
  /** 'zlibCompress', or the dotted OID. */
  algorithm: string;
  content_type: string;
  compressed: Uint8Array | null;
  detached: boolean;
  der: Uint8Array;
  note: string;
}

export interface EncryptedContent {
  /** Dotted. */
  content_type: string;
  /** By OID-table name. */
  cipher: string;
  /** Whether CONTENT_CIPHERS knows it. */
  known: boolean;
  key_length: number | null;
  mode: 'cbc' | 'gcm' | null;
  /** Single DES: readable, and broken. */
  weak: boolean;
  /** 'constructed-encrypted-content': the BER segmented form, read as one. */
  warnings: Array<{ code: string; detail: string }>;
  detached: boolean;
  data: Uint8Array | null;
  iv: Uint8Array | null;
  /** GCM. */
  nonce?: Uint8Array;
  tag_length?: number;
}

export interface EnvelopedData {
  version: number;
  recipients: Recipient[];
  /** OriginatorInfo, whole. */
  originator: Uint8Array | null;
  content: EncryptedContent;
  /** Named for what they are: nothing protects them. */
  unprotected_attrs_unauthenticated: Uint8Array | null;
  /** The content's warnings. */
  warnings: Array<{ code: string; detail: string }>;
  authenticated: boolean;
  note: string;
  der: Uint8Array;
}

export interface AuthEnvelopedData {
  version: number;
  recipients: Recipient[];
  originator: Uint8Array | null;
  content: EncryptedContent;
  auth_attrs: Array<{ type: string; oid: string; values: Uint8Array[] }> | null;
  /** The AAD: authAttrs with the SET tag - or empty. */
  aad: Uint8Array;
  /** The GCM tag. */
  mac: Uint8Array;
  unauth_attrs_unauthenticated: Uint8Array | null;
  authenticated: true;
  note: string;
  der: Uint8Array;
}

export interface DigestedData {
  version: number;
  digest_algorithm: string;
  content_type: string;
  content: Uint8Array | null;
  detached: boolean;
  digest: Uint8Array;
  der: Uint8Array;
  note: string;
}

export interface EncryptedData {
  version: number;
  content: EncryptedContent;
  unprotected_attrs_unauthenticated: Uint8Array | null;
  authenticated: false;
  der: Uint8Array;
  note: string;
}

export const CONTENT_CIPHERS: Readonly<Record<string, { key: number | null; iv: number; mode: 'cbc' | 'gcm'; tag?: number }>>;

/** `max_iterations` raises the PBKDF2 ceiling for password recipients. */
export function from_der(input: BytesInput, options?: { max_iterations?: number }): EnvelopedData;
export function auth_from_der(input: BytesInput, options?: { max_iterations?: number }): AuthEnvelopedData;
export function digested_from_der(input: BytesInput): DigestedData;
export function encrypted_from_der(input: BytesInput): EncryptedData;

/**
 * The content-encryption key from a PWRI block the caller decrypted (both
 * CBC layers removed); the check bytes are verified. block_size defaults 16.
 */
export function pwri_key_from_block(block: Uint8Array, block_size?: number): Uint8Array;

/**
 * The recipient this certificate can decrypt for - a key-agreement entry
 * flattened to the matching key - or null.
 */
export function authenticated_from_der(input: BytesInput, options?: { max_iterations?: number }): AuthenticatedData;

/** What the MAC is over - and, with authAttrs, the digest to check first. */
export function mac_plan(ad: Pick<AuthenticatedData, 'content' | 'auth_attrs_raw' | 'mac' | 'mac_algorithm' | 'digest' | 'message_digest'>, detached_content?: BytesInput | null): MacPlan;

export function compressed_from_der(input: BytesInput): CompressedData;

export function recipient_for(
  enveloped: { recipients: Recipient[] },
  cert: Pick<Certificate, 'serial' | 'issuer' | 'extensions'>
): KeyTransportRecipient | KemRecipient | (Omit<KeyAgreementRecipient, 'keys' | 'shared_info' | 'kdf_hash' | 'version'> & { encrypted_key: Uint8Array; recipient: RecipientId }) | null;

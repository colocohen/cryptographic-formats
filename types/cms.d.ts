// CMS SignedData (RFC 5652), read: signers, the bytes each signature
// covers, and the certificate each names. Building is cms_build;
// EnvelopedData and the other content types are cms_enveloped.

import type { AlgorithmDescription, BytesInput, Name, Time, VerificationPlanBase } from './types.js';
import type { Certificate } from './x509.js';

/** A CMS Attribute: `value` is the SET OF values, as content bytes. */
export interface CmsAttribute {
  id: string;
  oid: Uint8Array;
  /** The ATTRIBUTE table's name ('messageDigest'), or null. */
  name: string | null;
  value: Uint8Array;
}

export type SignerIdentifier =
  | { by: 'issuer-and-serial'; issuer: Name; serial: Uint8Array; serial_hex: string }
  | { by: 'key-id'; key_id: Uint8Array };

export interface SignerInfo {
  version: number;
  sid: SignerIdentifier;
  /** The digestAlgorithm, by OID-table name. */
  digest: string;
  signature_algorithm: string;
  /** With rsaEncryption / ecPublicKey as the "signature algorithm", the hash is the digest's. */
  signature_params: AlgorithmDescription;
  signature: Uint8Array;
  /** Null when the signer has no signedAttrs. */
  signed_attrs: CmsAttribute[] | null;
  /** The signedAttrs [0] as it arrived; see signed_attrs_der. */
  signed_attrs_raw: Uint8Array | null;
  /** Named for what they are: NOT covered by the signature. */
  unsigned_attrs_unsigned: CmsAttribute[] | null;
  /** The message-digest attribute, when there are signedAttrs. */
  message_digest?: Uint8Array;
  /** The content-type attribute, by name. */
  signed_content_type?: string;
  /** The signing-time attribute: what the signer CLAIMS, unverified. */
  signing_time_claimed?: Time;
}

export interface SignedData {
  version: number;
  /** No signers: a certificate bundle (.p7b). */
  degenerate: boolean;
  digests: string[];
  /** The CONTENT table's name ('data', 'tstInfo'), or dotted. */
  content_type: string;
  /** Null when detached. */
  content: Uint8Array | null;
  detached: boolean;
  /** DER certificates the message carries. */
  certificates: Uint8Array[];
  /** DER revocation entries, captured whole. */
  crls: Uint8Array[];
  signers: SignerInfo[];
  der: Uint8Array;
}

export type CmsVerificationPlan =
  | (VerificationPlanBase & {
      kind: 'direct';
      digest: string;
      note: string;
    })
  | (VerificationPlanBase & {
      kind: 'signed-attrs';
      digest: string;
      /** Step one: hash these and compare with expected_digest. */
      content_bytes: Uint8Array;
      expected_digest: Uint8Array | undefined;
      note: string;
    });

/** Content type OIDs by name. */
export const CONTENT: Readonly<Record<string, string>>;
/** Attribute OIDs by name. */
export const ATTRIBUTE: Readonly<Record<string, string>>;

export function from_der(input: BytesInput): SignedData;

/** signedAttrs with the [0] tag replaced by SET (RFC 5652 5.4) - what is signed. */
export function signed_attrs_der(signer: SignerInfo): Uint8Array;

/** The content octets - the message's, or `detached_content` when it has none. */
export function content_signing_input(cms: { content: Uint8Array | null }, detached_content?: BytesInput | null): Uint8Array;

/** What to hash and verify for a signer, in order. */
export function verification_plan(cms: { content: Uint8Array | null }, signer: SignerInfo, detached_content?: BytesInput | null): CmsVerificationPlan;

/** A digest the caller computed, against the message-digest attribute. */
export function digest_matches(signer: SignerInfo, computed: BytesInput): boolean;

/** The certificate the signer names, among those carried; null when absent. */
export function certificate_for(cms: { certificates: Uint8Array[] }, signer: SignerInfo): Certificate | null;

// Building CMS SignedData: prepare -> the caller signs -> assemble. And the
// degenerate SignedData that is a certificate bundle (.p7b).

import type { BytesInput, DerNode, TimeInput } from './types.js';
import type { Certificate } from './x509.js';

/** A certificate: its DER, or what x509.from_der returned (its original bytes are used). */
export type CertificateInput = Uint8Array | Pick<Certificate, 'der'> | Certificate;

/** An extra signed attribute: a name from ATTR or a dotted OID, and its value's DER. */
export interface AttributeInput {
  type: string;
  value: BytesInput;
}

export interface SignedDataParts {
  /** The signer's certificate - its issuer and serial become the sid. */
  certificate: CertificateInput;
  /** 'sha256'... */
  digest: string;
  signature_algorithm: string;
  /** The content; leave out with detached for a detached signature. */
  content?: BytesInput | null;
  detached?: boolean;
  /** A CONTENT name or dotted OID; default 'data'. */
  content_type?: string;
  /** The content's digest, computed by the caller - required with signedAttrs. */
  content_digest?: BytesInput;
  /** Default true. Without them the signature is over the content itself. */
  signed_attrs?: boolean;
  signing_time?: TimeInput | null;
  attributes?: AttributeInput[];
}

/** What prepare returns: the bytes to sign, and the rest assemble needs. */
export interface PreparedSigner {
  /** The signedAttrs in their SET form - or, without them, the content. */
  bytes: Uint8Array;
  content: Uint8Array | null;
  content_type: string;
  content_oid: string;
  detached: boolean;
  certificate: CertificateInput;
  digest: string;
  signature_algorithm: string;
  use_attrs: boolean;
  signing_time: TimeInput | null;
  extra_attrs: AttributeInput[];
  signed_attrs_set: unknown;
}

/** Attribute OIDs the builder names. */
export const ATTR: Readonly<Record<string, string>>;

export function prepare(parts: SignedDataParts): PreparedSigner;
/** The ContentInfo. `certificates` replaces the default of the signer's alone. */
export function assemble(si: PreparedSigner, signature: BytesInput, options?: { certificates?: CertificateInput[] }): Uint8Array;
/** A degenerate SignedData: certificates, no signers - a .p7b. */
export function bundle(certificates: CertificateInput[]): Uint8Array;

/** One Attribute: a dotted OID and its values' DER. */
export function attribute(oid: string, values: Array<Uint8Array | DerNode>): DerNode;
/** An AttributeInput as an Attribute. */
export function extra_attribute(extra: AttributeInput): DerNode;

/**
 * contentType, messageDigest, signingTime when given and the caller's, as
 * the SET OF DER that is signed (signedAttrs) or MACed (AuthenticatedData's
 * authAttrs). The digest's length is checked against `digest`.
 */
export function content_attributes(opts: {
  content_oid: string;
  digest: string;
  content_digest: Uint8Array;
  signing_time?: Date | null;
  attributes?: AttributeInput[];
}): Uint8Array;

// XMLDSig as SAML uses it: the structural checks that stop signature
// wrapping, the canonical SignedInfo a signature covers, and the pieces to
// write one. Not a full XMLDSig implementation - see the README.

import type { BytesInput } from './types.js';
import type { Certificate } from './x509.js';

export interface SamlVerificationPlan {
  /** Structural problems: wrapping, unsafe transforms, a DOCTYPE... Refuse on any. */
  problems: Array<{ code: string; detail: string }>;
  /** The ID the Reference points at, or null for the whole document. */
  element_id: string | null;
  reference_uri: string;
  whole_document: boolean;
  /** The enveloped-signature transform is present. */
  remove_signature: boolean;
  canonicalization: string | null;
  with_comments: boolean | null;
  inclusive_prefixes: string[];
  transforms: Array<{ uri: string; name: string | null; safe: boolean; inclusive_prefixes?: string[] }>;
  /** The Reference's digest, by name. */
  digest: string | null;
  digest_value: Uint8Array;
  /** The signature algorithm, by name ('sha256WithRSA'). */
  algorithm: string | null;
  algorithm_uri: string;
  signature: Uint8Array | null;
  /** The canonical SignedInfo - what the signature covers. Null when it cannot be computed. */
  bytes: Uint8Array | null;
  signed_info_text: string | null;
  signed_info_raw: string;
  /** From KeyInfo: reported, not trusted. */
  certificates: Certificate[];
  /** Every ID attribute in the document. */
  ids: string[];
  doctype: boolean;
}

export interface SamlSigningPlan {
  element_id: string;
  reference_uri: string;
  algorithm: string;
  algorithm_uri: string;
  digest: string;
  digest_uri: string;
  canonicalization: string;
  c14n_uri: string;
  transforms: string[];
  certificate: Uint8Array | null;
  prefix: string;
}

export const SIGNATURE_ALGORITHMS: Readonly<Record<string, { name: string; digest: string; weak: string | null }>>;
export const DIGEST_ALGORITHMS: Readonly<Record<string, { name: string; weak: string | null }>>;
export const CANONICALIZATION: Readonly<Record<string, { name: string; comments: boolean }>>;
export const SAFE_TRANSFORMS: Readonly<Record<string, string>>;
/** By URI: why each is refused. */
export const UNSAFE_TRANSFORMS: Readonly<Record<string, string>>;

/** The document as text, or bytes in its declared encoding. */
export function verification_plan(input: string | BytesInput): SamlVerificationPlan;

/** How the signature will be written; defaults are rsa-sha256, sha256, exclusive C14N, 'ds'. */
export function signing_plan(options: {
  element_id: string;
  algorithm?: string;
  digest?: string;
  canonicalization?: string;
  certificate?: Uint8Array | null;
  prefix?: string;
}): SamlSigningPlan;

/** The SignedInfo for a digest the caller computed - `bytes` is what to sign. */
export function signed_info(plan: SamlSigningPlan, digest_value: BytesInput): { xml: string; bytes: Uint8Array; canonical: true };

/** The ds:Signature element to insert, with the caller's signature. */
export function signature_element(plan: SamlSigningPlan, info: { xml: string }, signature: Uint8Array): string;

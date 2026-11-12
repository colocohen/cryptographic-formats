// S/MIME (RFC 8551): multipart/signed and application/pkcs7-mime messages,
// MIME canonical form, and the bytes a signature covers.

import type { BytesInput } from './types.js';
import type { SignedData, SignerInfo, CmsVerificationPlan } from './cms.js';
import type { EnvelopedData } from './cms_enveloped.js';

export interface MimeHeader {
  /** Lower-cased. */
  name: string;
  value: string;
}

export type SmimeMessage =
  | {
      kind: 'multipart/signed';
      headers: MimeHeader[];
      /** The micalg parameter as written ('sha-256'); see micalg_digest. */
      micalg: string | null;
      /** The first part as transmitted - what the signature covers. */
      signed_bytes: Uint8Array;
      /** That part's body alone. */
      content_only: Uint8Array;
      cms: SignedData;
      signature_der: Uint8Array;
      raw: Uint8Array;
    }
  | {
      kind: 'application/pkcs7-mime';
      headers: MimeHeader[];
      smime_type: string | null;
      signed_bytes: Uint8Array | null;
      content_only: Uint8Array | null;
      cms: SignedData;
      signature_der: Uint8Array;
      raw: Uint8Array;
    }
  | {
      kind: 'application/pkcs7-mime';
      headers: MimeHeader[];
      smime_type: string;
      encrypted: true;
      enveloped: EnvelopedData;
      signature_der: Uint8Array;
      raw: Uint8Array;
    };

export function from_bytes(input: BytesInput): SmimeMessage;

/** The CMS plan for a signer (default the first), with the S/MIME content filled in. */
export function verification_plan(
  message: { cms: SignedData; signed_bytes: Uint8Array | null },
  signer_index?: number
): CmsVerificationPlan & { signer: SignerInfo; canonical: boolean };

/** The micalg parameter as a hash name ('sha256'), or null. */
export function micalg_digest(message: { micalg?: string | null }): string | null;

/** Every line ending made CRLF. */
export function canonicalize(input: BytesInput): Uint8Array;
export function is_canonical(input: BytesInput): boolean;

/** The bytes to sign: the part's headers, a blank line and the body, canonical. */
export function signed_part(content: BytesInput, headers?: Record<string, string>): Uint8Array;

/** A multipart/signed message around signed_part's bytes and the CMS signature. */
export function wrap(parts: { part: Uint8Array; signature: Uint8Array; digest?: string; boundary?: string }): Uint8Array;
/** An application/pkcs7-mime message around CMS bytes. */
export function wrap_opaque(signature: Uint8Array, options?: { smime_type?: string }): Uint8Array;

export function parse_headers(text: string): MimeHeader[];
/** A Content-Type value: the type (lower-cased) and its unquoted parameters. */
export function content_type(value: string): { type: string | null; params: Record<string, string> };
/** The byte ranges of a multipart body's parts, delimiter CRLFs excluded. */
export function split_parts(bytes: Uint8Array, boundary: string, from: number): Array<{ start: number; end: number }>;

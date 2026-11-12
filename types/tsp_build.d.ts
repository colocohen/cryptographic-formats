// Building time-stamp requests, TSTInfo, and responses. The token itself is
// cms_build with content_type 'tstInfo'.

import type { BytesInput, GeneralNameInput } from './types.js';

export interface TstInfoParts {
  /** Dotted policy OID. */
  policy: string;
  /** { algorithm, hash } - tsp.request_from_der returns this shape. */
  imprint: { algorithm: string; hash: BytesInput };
  /** Unique per TSA, up to 160 bits. */
  serial: BytesInput;
  gen_time: Date;
  /** Write genTime with milliseconds. */
  millis?: boolean;
  accuracy?: { seconds?: number; millis?: number; micros?: number } | null;
  ordering?: boolean;
  /** Required when the request had one. */
  nonce?: BytesInput | null;
  tsa?: GeneralNameInput | null;
}

export const STATUS: Readonly<Record<string, number>>;
export const FAILURE_BITS: Readonly<Record<string, number>>;

/** A TimeStampReq over a hash the caller computed. */
export function request(parts: {
  algorithm: string;
  hash: BytesInput;
  policy?: string | null;
  nonce?: BytesInput | null;
  cert_req?: boolean;
}): Uint8Array;

/** The TSTInfo DER - the content cms_build signs. */
export function tst_info(parts: TstInfoParts): Uint8Array;

/** A signingCertificateV2 attribute, ready for cms_build's `attributes`. */
export function signing_certificate_v2(cert_hash: BytesInput, hash?: string): { type: 'signingCertificateV2'; value: Uint8Array };

/** response(token) grants; response(null, { status, failure, text }) refuses. */
export function response(token: BytesInput | null, options?: { status?: string; failure?: string[]; text?: string }): Uint8Array;

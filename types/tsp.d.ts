// Time-stamp protocol (RFC 3161): requests and responses, read. A token is
// a CMS SignedData; building is tsp_build.

import type { BytesInput, Time } from './types.js';
import type { SignedData, CmsVerificationPlan } from './cms.js';
import type { Certificate } from './x509.js';

export interface TimeStampRequest {
  version: number;
  /** The imprint's hash algorithm, by name. */
  algorithm: string;
  hash: Uint8Array;
  policy: string | null;
  nonce: Uint8Array | null;
  cert_req: boolean;
  der: Uint8Array;
}

export interface TstInfo {
  version: number;
  policy: string;
  algorithm: string;
  hash: Uint8Array;
  serial: Uint8Array;
  serial_hex: string;
  time: Time;
  accuracy: { seconds: number; millis: number; micros: number } | null;
  ordering: boolean;
  nonce: Uint8Array | null;
}

export type TimeStampResponse =
  | {
      status: 'granted' | 'grantedWithMods';
      status_text: string | null;
      failure: string[] | null;
      /** The token's DER - a CMS ContentInfo. */
      token: Uint8Array;
      tst: TstInfo;
      cms: SignedData;
      der: Uint8Array;
    }
  | {
      status: string;
      status_text: string | null;
      failure: string[] | null;
      token: null;
      tst: null;
      der: Uint8Array;
    };

/** Status names by number. */
export const STATUS: readonly string[];
/** failInfo bit names by bit number. */
export const FAILURE: Readonly<Record<number, string>>;

export function request_from_der(input: BytesInput): TimeStampRequest;
export function response_from_der(input: BytesInput): TimeStampResponse;

/**
 * The response against the request: hash algorithm, imprint, nonce, an ESS
 * certificate id, and `policy` when one is required.
 */
export function check(
  response: { token: Uint8Array | null; tst: Pick<TstInfo, 'algorithm' | 'hash' | 'nonce' | 'policy'> | null; cms?: SignedData; status?: string; failure?: string[] | null },
  request: { algorithm: string; hash: Uint8Array; nonce: Uint8Array | null } | null,
  options?: { policy?: string }
): { ok: boolean; problems: string[] };

/** The signer's plan (cms.verification_plan for the token's first signer). */
export function verification_plan(response: { cms: SignedData }): CmsVerificationPlan;

/**
 * The ESS certificate ids among the signed attributes: hash the TSA
 * certificate's DER with `hash` and compare with cert_hash. Null when absent.
 */
export function ess_cert_ids(response: { cms: SignedData }): Array<{ hash: string; cert_hash: Uint8Array; version: 1 | 2 }> | null;

/** The TSA certificate the token carries (critical timeStamping EKU required); null when absent. */
export function tsa_certificate(response: { cms: SignedData }): Certificate | null;

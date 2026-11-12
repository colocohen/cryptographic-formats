// CBOR Web Token, RFC 8392: JWT's claims under integer labels, over a COSE
// message. Decode, check the signature or MAC with cose.js's input, then
// claims().

import type { BytesInput } from './types.js';
import type { ClaimsOptions } from './jwt.js';
import type { Sign1, Sign, Mac0, Mac, Encrypt0, Encrypt, DecodeOptions } from './cose.js';

export type CoseType = 'sign1' | 'sign' | 'mac0' | 'mac' | 'encrypt0' | 'encrypt';

export type DecodedCwt =
  | { cwt_tagged: boolean; type: 'sign1'; message: Sign1; alg: string | null; nested: boolean }
  | { cwt_tagged: boolean; type: 'sign'; message: Sign; alg: string | null; nested: boolean }
  | { cwt_tagged: boolean; type: 'mac0'; message: Mac0; alg: string | null; nested: boolean }
  | { cwt_tagged: boolean; type: 'mac'; message: Mac; alg: string | null; nested: boolean }
  | { cwt_tagged: boolean; type: 'encrypt0'; message: Encrypt0; alg: string | null; nested: boolean }
  | { cwt_tagged: boolean; type: 'encrypt'; message: Encrypt; alg: string | null; nested: boolean };

export interface CwtClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  /** NumericDate: seconds, an integer or a float. */
  exp?: number;
  nbf?: number;
  iat?: number;
  cti?: Uint8Array;
  /** Every other [label, value] pair, as read. */
  extra: Array<[unknown, unknown]>;
}

export interface CwtClaimsOptions extends Omit<ClaimsOptions, 'typ'> {
  /** encrypt0 / encrypt: the decrypted payload. */
  plaintext?: BytesInput;
  /** A detached sign1 / mac0 payload. */
  payload?: BytesInput;
  /** sign: which signature `verified` is about. Default 0. */
  signer?: number;
}

export interface CwtClaimsInput {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  cti?: Uint8Array;
  /** Other claims: [label, the value's CBOR]. */
  extra?: Array<[number | string, BytesInput]>;
}

export const LABELS: Readonly<Record<string, number>>;
export const TAG_CWT: 61;

/** An untagged COSE message needs options.type. */
export function decode(input: BytesInput, options?: DecodeOptions & { type?: CoseType }): DecodedCwt;

/** The claims - only when verified is true and the algorithm is accepted, and they pass. */
export function claims(decoded: DecodedCwt, accepted: string[], verified: boolean, options?: CwtClaimsOptions): CwtClaims;

/** The claims as the CBOR map a COSE message carries as its payload. */
export function claims_to_cbor(claims: CwtClaimsInput): Uint8Array;

/** A COSE message inside the CWT tag, 61. */
export function tagged(cose_message: BytesInput): Uint8Array;

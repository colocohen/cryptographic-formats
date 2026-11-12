// JSON Web Keys (RFC 7517, 7518, 8037) and key sets.

import type { JsonObject } from './json.js';

/** A key as to_key returns it - the same shape spki and pkcs8 produce. */
export interface JwkKey {
  /** 'ecPublicKey', 'rsaEncryption', or the OKP curve ('Ed25519', 'X25519'...). */
  algorithm: string;
  /** The OID-table curve name for EC keys ('secp256r1'); otherwise null. */
  curve: string | null;
  /** The JWK name ('P-256', 'Ed25519'); null for RSA. */
  jwk_curve: string | null;
  /** EC: the uncompressed point (04 || x || y). OKP: x. RSA: null. */
  point: Uint8Array | null;
  /** The private value (d), when the JWK has one. */
  scalar: Uint8Array | null;
  private: boolean;
  rsa?: {
    n: Uint8Array;
    e: Uint8Array;
    d?: Uint8Array;
    p?: Uint8Array;
    q?: Uint8Array;
    dp?: Uint8Array;
    dq?: Uint8Array;
    qi?: Uint8Array;
  };
  kid: string | null;
  use: string | null;
  alg: string | null;
  key_ops: string[] | null;
}

/** What from_key takes: any key shape this library returns. */
export interface KeyInput {
  algorithm: string;
  curve?: string | null;
  point?: Uint8Array | null;
  scalar?: Uint8Array | null;
  rsa?: { n: Uint8Array; e: Uint8Array; d?: Uint8Array };
  kid?: string | null;
}

/** A JWK as JSON members. */
export type Jwk = {
  kty: 'EC' | 'OKP' | 'RSA';
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
  n?: string;
  e?: string;
  kid?: string;
};

/** A JWK - parsed, or its JSON text or bytes - to a key. */
export function to_key(input: JsonObject | string | Uint8Array): JwkKey;
/** A key to a JWK; from_key(to_key(j)) is j. */
export function from_key(key: KeyInput): Jwk;

/** The `keys` of a JWKS; refuses duplicate kids. */
export function set_from_json(input: JsonObject | string | Uint8Array): JsonObject[];
/** The raw JWK with this kid, or null. */
export function set_find(input: JsonObject | string | Uint8Array, kid: string): JsonObject | null;

export const EC_CURVES: Readonly<Record<string, { oid: string; size: number }>>;
export const OKP_CURVES: Readonly<Record<string, { oid: string; size: number }>>;

/** RFC 7638: the required members, sorted, no whitespace, UTF-8 - hash it (SHA-256 for ACME) and base64url the digest. */
export function thumbprint_input(jwk: JsonObject | string): Uint8Array;

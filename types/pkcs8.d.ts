// PKCS#8 private keys (RFC 5958), the SEC 1 and PKCS#1 forms inside them,
// and EncryptedPrivateKeyInfo with PBES2.

import type { BytesInput, PssLimits } from './types.js';

export interface RsaPrivateComponents {
  n: Uint8Array;
  e: Uint8Array;
  d: Uint8Array;
  p: Uint8Array;
  q: Uint8Array;
  dp: Uint8Array;
  dq: Uint8Array;
  qinv: Uint8Array;
}

export interface PrivateKey {
  /** 'ecPublicKey', 'rsaEncryption', 'Ed25519', 'X25519', 'dsa', 'mlDsa65', 'mlKem768', 'slhDsaSha2_128s'... */
  algorithm: string;
  /** EC keys: the named curve. Otherwise null. */
  curve: string | null;
  /**
   * The private value: an EC/OKP scalar, the RSA d, the DSA x; for ML-DSA
   * and ML-KEM the seed when present, else the expanded key; SLH-DSA's key.
   */
  scalar: Uint8Array;
  /** The public point, when the key carries one. */
  point: Uint8Array | null;
  /** The whole input. */
  der: Uint8Array;
  /** RSA only. */
  rsa?: RsaPrivateComponents;
  /** RSA-PSS keys: the limits (null for none), and the parameters' DER they came from. */
  pss?: PssLimits | null;
  parameters?: Uint8Array | null;
  /** DSA only (read, never written). */
  domain?: { p: Uint8Array; q: Uint8Array; g: Uint8Array };
  bits?: number;
  subgroup_bits?: number;
  /** ML-DSA / ML-KEM: which arm of the CHOICE (RFC 9881 6, RFC 9935 6). */
  private_format?: 'seed' | 'expanded' | 'both';
  /** ML-DSA's xi (32 bytes) or ML-KEM's d || z (64); null in the expanded form. */
  seed?: Uint8Array | null;
  /** The FIPS 204 / 203 expanded private key; null in the seed form. */
  expanded_key?: Uint8Array | null;
  /** What could not be checked without the arithmetic - set for non-seed forms. */
  unchecked?: string;
}

/** What to_der takes: EC needs curve and scalar (point optional), RSA rsa, OKP scalar. */
export interface PrivateKeyInput {
  algorithm: string;
  curve?: string | null;
  scalar?: Uint8Array;
  point?: Uint8Array | null;
  rsa?: RsaPrivateComponents;
  /** ML-DSA / ML-KEM: written as the seed form, or `both` with expanded_key. */
  seed?: Uint8Array | null;
  expanded_key?: Uint8Array | null;
}

export interface EncryptedPrivateKey {
  kdf: 'pbkdf2';
  /** The PRF by OID-table name: 'hmacWithSHA256'. */
  prf: string;
  salt: Uint8Array;
  iterations: number;
  key_length: number;
  /** The cipher by OID-table name: 'aes256CBC'. See algorithm.node_name. */
  cipher: string;
  iv: Uint8Array;
  /** The ciphertext: decrypted, it is a PrivateKeyInfo for from_der. */
  data: Uint8Array;
  /** Fewer than 1,000 iterations, or the SHA-1 PRF. */
  weak: boolean;
}

export interface EncryptedPrivateKeyInput {
  /** OID-table name or node/OpenSSL spelling: 'aes256CBC' or 'aes-256-cbc'. */
  cipher: string;
  iv: Uint8Array;
  salt: Uint8Array;
  iterations: number;
  /** Default hmacWithSHA1; either spelling, as for cipher. */
  prf?: string;
  key_length?: number | null;
  /** The ciphertext the caller produced. */
  data: Uint8Array;
}

export const CURVE_SIZE: Readonly<Record<string, number>>;

export function from_der(input: BytesInput): PrivateKey;
export function to_der(key: PrivateKeyInput): Uint8Array;
/** A bare SEC 1 ECPrivateKey ('EC PRIVATE KEY'). */
export function sec1_from_der(input: BytesInput): PrivateKey & { format: 'sec1' };
/** A bare PKCS#1 RSAPrivateKey ('RSA PRIVATE KEY'). */
export function pkcs1_from_der(input: BytesInput): {
  format: 'pkcs1';
  algorithm: 'rsaEncryption';
  curve: null;
  scalar: Uint8Array;
  rsa: RsaPrivateComponents;
  der: Uint8Array;
};

export function encrypted_from_der(input: BytesInput, options?: { max_iterations?: number }): EncryptedPrivateKey;
export function encrypted_to_der(parts: EncryptedPrivateKeyInput): Uint8Array;

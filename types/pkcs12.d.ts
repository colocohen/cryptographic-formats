// PKCS#12 / PFX (RFC 7292, RFC 9579), read. Decrypts nothing unless the
// caller hands open() the primitives. Building is pkcs12_build.

import type { BytesInput } from './types.js';

/** How a safe or shrouded key is encrypted. */
export type PbeParams =
  | {
      kdf: 'pbkdf2';
      prf: string;
      salt: Uint8Array;
      iterations: number;
      key_length: number;
      cipher: string;
      iv: Uint8Array;
      data: Uint8Array | null;
    }
  | {
      /** RFC 7292 appendix B - NOT PBKDF2. */
      kdf: 'pkcs12';
      kdf_note: string;
      hash: string;
      salt: Uint8Array;
      iterations: number;
      key_length: number;
      iv_length: number;
      cipher: string;
      scheme: string;
      id: { key: number; iv: number; mac: number };
      data: Uint8Array | null;
    };

export type MacParams =
  | { scheme: 'pkcs12-kdf'; hash: string; digest: Uint8Array; salt: Uint8Array; iterations: number; id: number }
  | {
      scheme: 'pbmac1';
      hash: string;
      digest: Uint8Array;
      kdf: 'pbkdf2';
      prf: string;
      salt: Uint8Array;
      iterations: number;
      key_length: number;
      weak: boolean;
      id: null;
    };

export type Safe =
  | { type: 'data'; content: Uint8Array }
  | { type: 'encryptedData'; encrypted: PbeParams }
  | { type: string; content?: Uint8Array; encrypted?: PbeParams };

export interface Pfx {
  version: number;
  /** The authSafe content the MAC covers. */
  mac_data: Uint8Array;
  safes: Safe[];
  mac: MacParams | null;
  /** 'ber' when the file needed the BER reader (Windows writes BER). */
  encoding: 'der' | 'ber';
  der: Uint8Array;
}

export interface Bag {
  /** BAG name ('certBag'), or the dotted OID. */
  kind: string;
  /** keyBag: the PrivateKeyInfo. After open(), also on shrouded bags. */
  key?: Uint8Array;
  /** pkcs8ShroudedKeyBag: the EncryptedPrivateKeyInfo. */
  encrypted?: Uint8Array;
  /** certBag: the certificate DER. */
  certificate?: Uint8Array;
  /** Other bags: the value, whole. */
  value?: Uint8Array;
  friendly_name: string | null;
  /** Hex. */
  local_key_id: string | null;
}

/** The primitives open() calls - this library performs no cryptography. */
export interface Pkcs12Primitives {
  /** RFC 7292 appendix B. Needed for legacy safes and the traditional MAC. */
  pkcs12_kdf?: (hash: string, password: string, salt: Uint8Array, iterations: number, id: number, length: number) => Uint8Array;
  pbkdf2: (prf: string, password: string, salt: Uint8Array, iterations: number, length: number) => Uint8Array;
  decrypt: (cipher: string, key: Uint8Array, iv: Uint8Array, data: Uint8Array) => Uint8Array;
  hmac: (hash: string, key: Uint8Array, data: Uint8Array) => Uint8Array;
}

export const BAG: Readonly<Record<string, string>>;
export const CONTENT: Readonly<Record<string, string>>;
export const KDF_ID: Readonly<{ key: 1; iv: 2; mac: 3 }>;

export function from_der(input: BytesInput, options?: { max_iterations?: number }): Pfx;
/** A SafeContents - a data safe's content, or what decrypting a safe gave. */
export function bags_from_der(input: BytesInput, encoding?: 'der' | 'ber'): Bag[];

/** The whole container: MAC verified (unless verify_mac: false), everything decrypted. */
export function open(input: BytesInput, password: string, primitives: Pkcs12Primitives, options?: { verify_mac?: boolean; max_iterations?: number }): {
  encoding: 'der' | 'ber';
  /** Null when the container has no MAC, or verify_mac was false. */
  mac_verified: boolean | null;
  bags: Bag[];
  keys: Bag[];
  certificates: Bag[];
};

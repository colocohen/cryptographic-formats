// Building PKCS#12: bags -> safes -> prepare (the bytes the MAC covers) ->
// the caller computes the MAC -> assemble.

import type { BytesInput, DerNode } from './types.js';
import type { EncryptedPrivateKeyInput } from './pkcs8.js';

/** friendlyName and localKeyId - what ties a key to its certificate. */
export interface BagAttributes {
  friendly_name?: string;
  local_key_id?: BytesInput;
}

export interface MacInput {
  /** 'pkcs12-kdf' (default, the traditional MAC) or 'pbmac1' (RFC 9579). */
  scheme?: 'pkcs12-kdf' | 'pbmac1';
  /** 'sha256'... */
  hash: string;
  /** The HMAC over prepared.bytes, computed by the caller. */
  digest: BytesInput;
  /** At least 8 bytes. */
  salt: BytesInput;
  iterations: number;
  /** pbmac1: the PBKDF2 PRF; default the HMAC of `hash`. */
  prf?: string;
  key_length?: number;
}

/** A pkcs8ShroudedKeyBag around pkcs8.encrypted_to_der's output. */
export function shrouded_key_bag(encrypted_private_key_info: BytesInput, attrs?: BagAttributes): DerNode;
/** An UNENCRYPTED keyBag - readable by anyone with the file. */
export function plaintext_key_bag(pkcs8_der: BytesInput, attrs?: BagAttributes): DerNode;
export function cert_bag(cert_der: BytesInput, attrs?: BagAttributes): DerNode;
/** SafeContents, as bytes - to encrypt, or to wrap with data_safe. */
export function safe_contents(bags: DerNode[]): Uint8Array;

export function data_safe(contents: BytesInput): DerNode;
/** The PBES2 parameters the caller encrypted with, and `data`, the encrypted SafeContents. */
export function encrypted_safe(parts: EncryptedPrivateKeyInput): DerNode;

/** The AuthenticatedSafe - `bytes` is what the MAC covers. */
export function prepare(safes: DerNode[]): { bytes: Uint8Array };
export function assemble(prepared: { bytes: Uint8Array }, mac: MacInput): Uint8Array;

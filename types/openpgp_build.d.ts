// OpenPGP (RFC 9580), written: armour, cleartext, packets, keys,
// signatures, and the containers of an encrypted message. The hashing,
// signing and encrypting are the caller's.

import type { BytesInput, PublicKey } from './types.js';

export type ArmorType = 'MESSAGE' | 'PUBLIC KEY BLOCK' | 'PRIVATE KEY BLOCK' | 'SIGNATURE';

export interface BuiltKey {
  packet: Uint8Array;
  body: Uint8Array;
  public_body: Uint8Array;
  version: 4 | 6;
  fingerprint_input: Uint8Array;
  fingerprint_hash: 'sha1' | 'sha256';
}

export interface SubpacketInput {
  /** A registry name ('created', 'key_flags'...) or a number. */
  type: string | number;
  critical?: boolean;
  value?: unknown;
  /** Octets as they are, instead of value. */
  raw?: BytesInput;
}

export interface PreparedSignature {
  version: 4 | 6;
  alg_id: number;
  hash: string;
  salt: number[];
  hashed_portion: number[];
  unhashed: number[];
  /** Hash these, and sign the digest. */
  bytes: Uint8Array;
}

export interface S2KInput {
  type: 'iterated' | 'salted' | 'argon2';
  hash?: string;
  salt: BytesInput;
  coded_count?: number;
  passes?: number;
  parallelism?: number;
  encoded_memory?: number;
}

export function armor_encode(type: ArmorType, data: BytesInput, options?: { headers?: Array<[string, string]>; checksum?: boolean }): string;
export function cleartext_signed_bytes(text: string): Uint8Array;
export function cleartext_encode(text: string, signature_packets: BytesInput, options?: { hashes?: string[]; checksum?: boolean }): string;
export function packet(type: string | number, body: BytesInput | number[]): Uint8Array;
export function packets(list: Array<BytesInput>): Uint8Array;
export function key_packet(parts: {
  version: 4 | 6;
  created: number | Date;
  algorithm: string | number;
  material?: Record<string, unknown>;
  public_key?: PublicKey | { algorithm: string; point?: BytesInput; curve?: string | null; rsa?: { n: BytesInput; e: BytesInput } };
  subkey?: boolean;
  secret?: { material: Record<string, BytesInput> } | { usage: 253 | 254; cipher: string | number; aead?: string | number; s2k: S2KInput | Record<string, unknown>; iv: BytesInput; encrypted: BytesInput };
}): BuiltKey;
export function s2k(spec: S2KInput | Record<string, unknown>): Uint8Array;
export function user_id_packet(text: string | BytesInput): Uint8Array;
export function subpacket(sp: SubpacketInput): number[];
export function signature_prepare(parts: {
  version: 4 | 6;
  type: string | number;
  algorithm: string | number;
  hash: string | number;
  salt?: BytesInput;
  hashed: SubpacketInput[];
  unhashed?: SubpacketInput[];
  target: {
    document?: BytesInput | string;
    key?: { public_body: Uint8Array };
    subkey?: { public_body: Uint8Array };
    user_id?: string | BytesInput | { user_id: Uint8Array };
    user_attribute?: BytesInput | { body: Uint8Array };
  };
}): PreparedSignature;
/** The packet: the digest of prepared.bytes, and the signature (native, r || s, or RSA's octets). */
export function signature_assemble(prepared: PreparedSignature, digest: BytesInput, signature: BytesInput): Uint8Array;
export function literal_packet(parts: { format?: 'b' | 'u'; filename?: string; date?: number | Date; data: BytesInput }): Uint8Array;
export function compressed_packet(algorithm: 'uncompressed' | 'zip' | 'zlib' | 'bzip2' | number, compressed: BytesInput): Uint8Array;
export function one_pass_signature(parts: {
  version: 3 | 6; type: string | number; hash: string | number; algorithm: string | number;
  salt?: BytesInput; issuer_fingerprint?: string | BytesInput; issuer_key_id?: string | BytesInput; last?: boolean;
}): Uint8Array;
export function padding_packet(random: BytesInput): Uint8Array;
export function session_key_block(parts: { version: 3 | 6; cipher?: string | number; session_key: BytesInput; algorithm?: string }): Uint8Array;
export function pkesk(parts: {
  version: 3 | 6; key_id?: string | BytesInput; fingerprint?: string | BytesInput; key_version?: number;
  algorithm: string | number; fields: Record<string, BytesInput | string | number>;
}): Uint8Array;
export function skesk(parts: {
  version: 4 | 6; cipher: string | number; s2k: S2KInput | Record<string, unknown>;
  aead?: string | number; iv?: BytesInput; encrypted_key?: BytesInput | null; auth_tag?: BytesInput;
}): Uint8Array;
export function skesk_v6_info(cipher: string | number, aead: string | number): Uint8Array;
/** What to SHA-1 for the MDC; the plaintext to encrypt is these bytes and the digest. */
export function seipd_v1_mdc_input(random: BytesInput, packets_bytes: BytesInput): Uint8Array;
export function seipd_v1(ciphertext: BytesInput): Uint8Array;
export function seipd_v2_prepare(parts: { cipher: string | number; aead: string | number; chunk_size_octet?: number; salt: BytesInput; plaintext_length?: number }): {
  cipher_id: number; aead_id: number; chunk_size_octet: number; salt: Uint8Array; chunk_size: number;
  hkdf_info: Uint8Array; aad: Uint8Array; key_length: number; iv_length: number; final_aad: Uint8Array;
  chunk_nonce_suffix: (index: number) => Uint8Array;
};
export function seipd_v2_assemble(prepared: { cipher_id: number; aead_id: number; chunk_size_octet: number; salt: BytesInput },
  chunks: BytesInput[], final_tag: BytesInput): Uint8Array;

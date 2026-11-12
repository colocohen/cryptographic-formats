// OpenPGP (RFC 9580), read: armour, the cleartext framework, packets,
// transferable keys, and the bytes each signature and encryption layer is
// computed over. The cryptography is the caller's.

import type { BytesInput } from './types.js';

/** A key in the shape spki.to_der, jwk and ssh take - without the DER, which OpenPGP never had. */
export interface PgpPublicKey {
  algorithm: 'rsaEncryption' | 'ecPublicKey' | 'Ed25519' | 'Ed448' | 'X25519' | 'X448';
  curve: string | null;
  point: Uint8Array | null;
  rsa?: { n: Uint8Array; e: Uint8Array };
}

export interface Armor {
  type: 'MESSAGE' | 'PUBLIC KEY BLOCK' | 'PRIVATE KEY BLOCK' | 'SIGNATURE';
  headers: Array<[string, string]>;
  data: Uint8Array;
  /** RFC 9580 6.1: never a reason to refuse. */
  checksum: 'ok' | 'absent' | 'mismatch';
}

export interface Cleartext {
  /** Dash-unescaped, with \n line endings. */
  text: string;
  /** What a text signature over it covers. */
  signed_bytes: Uint8Array;
  /** The legacy Hash header's values. */
  hashes: string[];
  signature: Armor;
}

export interface S2K {
  type: 'simple' | 'salted' | 'iterated' | 'argon2' | 'gnu' | 'md5-legacy';
  hash?: string | null;
  hash_id?: number;
  salt?: Uint8Array;
  /** iterated: the coded octet, and the number of OCTETS hashed. */
  coded_count?: number;
  count?: number;
  passes?: number;
  parallelism?: number;
  encoded_memory?: number;
  memory_kib?: number;
  mode?: string | number;
  serial?: Uint8Array;
}

export interface Subpacket {
  id: number;
  name: string | null;
  critical: boolean;
  hashed: boolean;
  data: Uint8Array;
  value?: unknown;
}

interface PacketBase {
  tag: number;
  legacy: boolean;
  partial: boolean;
  body: Uint8Array;
  /** The packet as it was in the stream, header included. */
  raw: Uint8Array;
}

export interface KeyMaterial {
  n?: Uint8Array; e?: Uint8Array; p?: Uint8Array; q?: Uint8Array; g?: Uint8Array; y?: Uint8Array;
  /** Dotted, for the curve algorithms. */
  oid?: string;
  curve?: string | null;
  point?: Uint8Array;
  kdf?: { hash_id: number; hash: string | null; cipher_id: number; cipher: string | null };
}

export interface KeyPacket extends PacketBase {
  type: 'public-key' | 'public-subkey' | 'secret-key' | 'secret-subkey';
  version: 3 | 4 | 6;
  subkey: boolean;
  secret: boolean;
  /** Seconds since the epoch. */
  created: number;
  expires_days?: number;
  algorithm_id: number;
  /** 'rsa', 'ecdsa', 'eddsa-legacy', 'ecdh', 'ed25519', 'x25519'... */
  algorithm: string | null;
  material: KeyMaterial | Uint8Array;
  /** What a signature over this key hashes it from. */
  public_body: Uint8Array;
  /** In spki.js's shape, where there is one. */
  public_key: PgpPublicKey | null;
  fingerprint_input: Uint8Array;
  fingerprint_hash: 'sha1' | 'sha256' | 'md5';
  /** v3 only; for v4 and v6 see key_id(). */
  key_id?: string;
  protection?: {
    usage: number; cipher_id?: number; cipher?: string | null; aead_id?: number; aead?: string;
    s2k?: S2K; iv?: Uint8Array; encrypted?: Uint8Array; hkdf_info?: Uint8Array; aad?: Uint8Array; note?: string;
  };
  secret_material?: Record<string, Uint8Array>;
}

export interface SignaturePacket extends PacketBase {
  type: 'signature';
  version: 3 | 4 | 6;
  signature_type_id: number;
  signature_type: string | null;
  public_key_algorithm_id: number;
  public_key_algorithm: string | null;
  hash_id: number;
  hash: string | null;
  weak: boolean;
  hashed_subpackets: Subpacket[];
  unhashed_subpackets: Subpacket[];
  hashed_portion: Uint8Array;
  left16: Uint8Array;
  salt?: Uint8Array;
  value: { s?: Uint8Array; r?: Uint8Array; raw?: Uint8Array;
    /** EdDSALegacy: R or S came with its leading zero octets counted, as GnuPG writes them. */
    padded?: boolean };
  unknown_critical: number[];
  created?: number;
  issuer_key_id?: string;
  issuer_key_id_unhashed?: boolean;
  issuer_fingerprint?: { version: number; fingerprint: string };
  issuer_fingerprint_unhashed?: boolean;
  key_flags?: string[];
  features?: { seipd_v1: boolean; seipd_v2: boolean };
  notations: Array<{ name: string; human_readable: boolean; value: string | Uint8Array }>;
  embedded_signatures: SignaturePacket[];
  [subpacket: string]: unknown;
}

export interface LiteralPacket extends PacketBase {
  type: 'literal';
  format: string;
  filename: string | null;
  filename_bytes: Uint8Array;
  date: number;
  data: Uint8Array;
  note: string;
}

export interface Seipd2Chunk { index: number; ciphertext: Uint8Array; tag: Uint8Array; aad: Uint8Array }

export type Packet =
  | KeyPacket
  | SignaturePacket
  | LiteralPacket
  | (PacketBase & { type: 'user-id'; user_id: Uint8Array; text: string | null })
  | (PacketBase & { type: 'user-attribute'; subpackets: Array<{ id: number; data: Uint8Array; image?: { encoding: string | number; data: Uint8Array } }> })
  | (PacketBase & { type: 'compressed'; algorithm: 'uncompressed' | 'zip' | 'zlib' | 'bzip2'; compressed: Uint8Array; note: string })
  | (PacketBase & { type: 'one-pass-signature'; version: 3 | 6; signature_type_id: number; signature_type: string | null;
      hash_id: number; hash: string | null; public_key_algorithm_id: number; salt?: Uint8Array;
      issuer_fingerprint?: string; issuer_key_id?: string; last: boolean })
  | (PacketBase & { type: 'pkesk'; version: 3 | 6; key_id?: string; key_version?: number; fingerprint?: string;
      anonymous?: boolean; algorithm_id: number; algorithm: string | null; fields: Record<string, Uint8Array | number>;
      kdf?: { hash: string; info: string; key_length: number; wrap: string } })
  | (PacketBase & { type: 'skesk'; version: 4 | 6; cipher_id: number; cipher: string | null; s2k: S2K;
      encrypted_key: Uint8Array | null; aead_id?: number; aead?: string; iv?: Uint8Array; auth_tag?: Uint8Array;
      hkdf_info?: Uint8Array; aad?: Uint8Array })
  | (PacketBase & { type: 'seipd'; version: 1 | 2; ciphertext?: Uint8Array; cipher_id?: number; aead_id?: number;
      cipher?: string; aead?: string; chunk_size_octet?: number; chunk_size?: number; salt?: Uint8Array;
      hkdf_info?: Uint8Array; key_length?: number; iv_length?: number; chunks?: Seipd2Chunk[];
      final?: { index: number; tag: Uint8Array; aad: Uint8Array }; note: string })
  | (PacketBase & { type: 'sed'; ciphertext: Uint8Array; warning: string })
  | (PacketBase & { type: 'mdc'; mdc: Uint8Array })
  | (PacketBase & { type: 'marker' | 'trust' | 'padding' | 'unknown' });

export interface TransferableKey {
  primary: KeyPacket;
  secret: boolean;
  direct_signatures: SignaturePacket[];
  users: Array<{ packet: Packet; signatures: SignaturePacket[]; user_id?: Uint8Array; text?: string | null; user_attribute?: Packet }>;
  subkeys: Array<{ key: KeyPacket; signatures: SignaturePacket[] }>;
}

export interface SignatureTarget {
  document?: BytesInput | string;
  key?: { public_body: Uint8Array };
  subkey?: { public_body: Uint8Array };
  user_id?: BytesInput | string | { user_id: Uint8Array };
  user_attribute?: BytesInput | { body: Uint8Array };
  signature?: SignaturePacket;
}

export interface PgpVerificationPlan {
  hash: string;
  bytes: Uint8Array;
  left16: Uint8Array;
  algorithm: string | null;
  signature: { s?: Uint8Array; r?: Uint8Array; raw?: Uint8Array };
  note: string;
  warning?: string;
}

export function armor_decode(text: string): Armor;
export function cleartext_decode(text: string): Cleartext;
/** Bytes, or armour text. */
export function packets_from_bytes(input: BytesInput | string, options?: { max_packets?: number }): Packet[];
export function keys_from_packets(packets: Packet[]): TransferableKey[];
export function verification_plan(sig: SignaturePacket, target?: SignatureTarget): PgpVerificationPlan;
/** From the fingerprint the caller computed over fingerprint_input. */
export function key_id(key: Pick<KeyPacket, 'version'> & { key_id?: string }, fingerprint: BytesInput): string;
/** Line endings to CRLF - what a text signature covers. */
export function canonical_text(doc: BytesInput | string): Uint8Array;
export function seipd_v1_open(plaintext: BytesInput, block_size: 8 | 16): {
  quick_check: boolean; mdc_input: Uint8Array; mdc: Uint8Array; packets: Uint8Array; note: string;
};
export function seipd_v2_nonce(iv: BytesInput, index: number): Uint8Array;
/** The session key from the decrypted block - RSA/Elgamal after EME-PKCS1 decoding, ECDH after unwrapping. */
export function session_key_from(decrypted: BytesInput, version: 3 | 6, algorithm?: string):
  { session_key: Uint8Array; cipher_id?: number; cipher?: string | null };
export function ecdh_kdf_param(key: KeyPacket, fingerprint: BytesInput): Uint8Array;

// Building CMS EnvelopedData and AuthEnvelopedData. The caller encrypts the
// content and wraps the key; this writes the structures around them.

import type { BytesInput } from './types.js';
import type { CertificateInput, AttributeInput } from './cms_build.js';

/** RSA key transport: the CEK encrypted to the recipient's key. */
export interface KtriInput {
  type: 'ktri';
  /** Default 'rsaEncryption'; or 'rsaOAEP', or { name: 'rsaOAEP', hash... }. */
  algorithm?: string | { name: string; hash?: string; mgf_hash?: string; label?: Uint8Array };
  /** Identifies the recipient by issuer and serial - or key_id instead. */
  certificate?: CertificateInput;
  key_id?: BytesInput;
  encrypted_key: BytesInput;
}

/** ECDH key agreement (RFC 5753), ephemeral-static. */
export interface KariInput {
  type: 'kari';
  certificate: CertificateInput;
  /** The ephemeral public point. */
  ephemeral_point: BytesInput;
  /** The KDF's hash: default 'sha256'. */
  kdf?: string;
  /** 'aes256Wrap' or 'id-aes256-wrap'... */
  wrap: string;
  ukm?: BytesInput | null;
  encrypted_key: BytesInput;
}

/** A previously distributed key-encryption key. */
export interface KekriInput {
  type: 'kekri';
  kek_id: BytesInput;
  wrap: string;
  encrypted_key: BytesInput;
}

/** A password (RFC 3211): PBKDF2, and PWRI-KEK over a CBC cipher. */
export interface PwriInput {
  type: 'pwri';
  kdf?: { salt: Uint8Array; iterations: number; prf?: string } | null;
  cipher: string;
  iv: BytesInput;
  /** The doubly encrypted pwri_key_block. */
  encrypted_key: BytesInput;
}

/** A KEM recipient - ML-KEM (RFC 9936) in RFC 9629's KEMRecipientInfo. */
export interface KemriInput {
  type: 'kemri';
  /** Identifies the recipient by issuer and serial - or key_id instead. */
  certificate?: CertificateInput;
  key_id?: BytesInput;
  kem: 'mlKem512' | 'mlKem768' | 'mlKem1024';
  /** What Encapsulate() returned beside the shared secret. */
  kem_ciphertext: BytesInput;
  /** Default 'hkdfWithSha256'; or hkdfWithSha384, hkdfWithSha512. */
  kdf?: string;
  /** 'aes128Wrap', 'aes256Wrap'... (either spelling). */
  wrap: string;
  /** Default, and required to be, the wrap's key size in bytes. */
  kek_length?: number;
  ukm?: BytesInput | null;
  encrypted_key: BytesInput;
}

export type RecipientInput = KtriInput | KariInput | KekriInput | PwriInput | KemriInput;

export interface EnvelopedParts {
  /** 'aes128CBC' | 'aes192CBC' | 'aes256CBC' (either spelling), or 'des_ede3_cbc' with allow_weak. */
  cipher: string;
  iv: BytesInput;
  /** Required for 3DES: for clients that have nothing better (old SCEP clients). */
  allow_weak?: boolean;
  /** The ciphertext; omit with detached. */
  encrypted_content?: BytesInput;
  detached?: boolean;
  recipients: RecipientInput[];
  /** Dotted OID or 'data' (default). */
  content_type?: string;
}

export interface AuthEnvelopedParts {
  /** 'aes128GCM' | 'aes192GCM' | 'aes256GCM'. */
  cipher: string;
  /** 12 bytes. */
  nonce: BytesInput;
  /** 12 to 16; default 16. */
  tag_length?: number;
  /** Without the tag. */
  encrypted_content?: BytesInput;
  detached?: boolean;
  mac: BytesInput;
  content_type?: string;
  /** As given to auth_aad - the same values. */
  auth_attrs?: AttributeInput[];
  recipients: RecipientInput[];
}

export const CIPHERS: Readonly<Record<string, unknown>>;
export const GCM: Readonly<Record<string, unknown>>;
/** The KDF OID name for each hash. */
export const KDFS: Readonly<Record<string, string>>;

export interface AuthenticatedParts {
  /** 'hmacWithSHA256' (or 'hmac-sha256')... */
  mac_algorithm: string;
  /** With content_digest: authAttrs are written and the MAC covers them. */
  digest?: string;
  content_digest?: Uint8Array;
  signing_time?: Date;
  auth_attrs?: AttributeInput[];
  /** The content, in the clear; omit with detached. */
  content?: BytesInput;
  detached?: boolean;
  content_type?: string;
  /** Computed over authenticated_mac_input(parts). */
  mac: BytesInput;
  recipients: RecipientInput[];
}

/** ContentInfo DER. */
export function enveloped_data(parts: EnvelopedParts): Uint8Array;
export function auth_enveloped_data(parts: AuthEnvelopedParts): Uint8Array;

/** An AuthenticatedData (RFC 5652 9), ContentInfo DER. */
export function authenticated_data(parts: AuthenticatedParts): Uint8Array;
/** The bytes to MAC: the SET-tagged authAttrs, or the content without a digest. */
export function authenticated_mac_input(parts: Omit<AuthenticatedParts, 'mac' | 'recipients'> & { recipients?: RecipientInput[]; mac?: BytesInput }): Uint8Array;

/** A CompressedData (RFC 3274): `compressed` is the zlib stream deflateSync writes. */
export function compressed_data(parts: { compressed?: BytesInput; detached?: boolean; content_type?: string }): Uint8Array;

/** The AAD to encrypt with: the authAttrs' DER with the SET tag, or empty. */
export function auth_aad(parts: { content_type?: string; auth_attrs?: AttributeInput[] }): Uint8Array;

/** RFC 3211 2.3.1: LEN || check || CEK || padding - what the caller encrypts twice. */
export function pwri_key_block(cek: BytesInput, padding: BytesInput, block_size?: number): Uint8Array;
/** How many padding bytes pwri_key_block needs. */
export function pwri_padding_length(cek_length: number, block_size?: number): number;

/** The KDF's info for a kemri recipient: CMSORIforKEMOtherInfo (RFC 9629 5). */
export function kem_kdf_info(options: { wrap: string; kek_length?: number; ukm?: BytesInput | null }): Uint8Array;

/** The X9.63 KDF's SharedInfo for a kari recipient (RFC 5753 7.2). */
export function kari_shared_info(options: { wrap: string; ukm?: BytesInput | null }): Uint8Array;

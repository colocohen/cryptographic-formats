// OpenSSH keys: RFC 4253 public keys (wire and .pub text), the
// openssh-key-v1 private key container, and fingerprints.

import type { BytesInput } from './types.js';
import type { AuthenticatorData } from './webauthn.js';
import type { CoseKey } from './cose.js';

/** A public key read from SSH. */
export interface SshPublicKey {
  /** 'Ed25519', 'ecPublicKey' or 'rsaEncryption' - the shape spki returns. */
  algorithm: string;
  curve: string | null;
  /** Ed25519 / EC: the key bytes. RSA: null (see rsa). */
  point: Uint8Array | null;
  rsa?: { e: Uint8Array; n: Uint8Array };
  /** 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa', 'sk-ssh-ed25519@openssh.com'... */
  ssh_type: string;
  /** Security keys (FIDO, PROTOCOL.u2f) only: what the authenticator was enrolled for - 'ssh:'. */
  application?: string;
  /** The RFC 4253 encoding - what a fingerprint hashes. */
  wire: Uint8Array;
  /** The .pub line's comment, or null. */
  comment: string | null;
}

/** A private key as the container holds it (and as the writers take it). */
export interface SshPrivateKey {
  algorithm: string;
  /** null for a security key's Ed25519, which carries its public fields as read. */
  curve?: string | null;
  point?: Uint8Array;
  scalar?: Uint8Array;
  rsa?: { n: Uint8Array; e: Uint8Array; d: Uint8Array; p: Uint8Array; q: Uint8Array; qinv: Uint8Array };
  /** Security keys: no scalar - the key stays in the authenticator; these are what it needs. */
  application?: string;
  flags?: number;
  key_handle?: Uint8Array;
  reserved?: Uint8Array;
  comment?: string;
}

/** An openssh-key-v1 container as read. */
export interface SshPrivateContainer {
  format: 'openssh-key-v1';
  /** 'none' or 'aes256-ctr'... */
  cipher: string;
  /** 'none' or 'bcrypt'. */
  kdf: string;
  encrypted: boolean;
  public: SshPublicKey;
  /** The private section - ciphertext when encrypted. */
  data: Uint8Array;
  /** Unencrypted only. */
  private?: SshPrivateKey;
  comment?: string;
  /** bcrypt-pbkdf parameters, when encrypted. */
  salt?: Uint8Array;
  rounds?: number;
  kdf_note?: string;
}

/** What private_prepare returns: the plaintext to encrypt, and how. */
export interface SshPrepared {
  key: SshPrivateKey;
  cipher: string;
  kdf: string;
  salt: Uint8Array;
  rounds: number;
  /** bcrypt-pbkdf output: key_length + iv_length bytes. */
  key_length: number;
  iv_length: number;
  plaintext: Uint8Array;
}

/** A public key in any shape this library returns. */
export type SshKeyInput = {
  algorithm: string;
  curve?: string | null;
  point?: Uint8Array | null;
  rsa?: { e: Uint8Array; n: Uint8Array };
  /** Present: a security key ('sk-...@openssh.com'), Ed25519 or P-256 only. */
  application?: string | null;
  comment?: string | null;
};

export const EC_CURVES: Readonly<Record<string, { oid: string; size: number }>>;

export function key_from_wire(input: BytesInput): SshPublicKey;
/** One .pub line: 'ssh-ed25519 AAAA... comment'. */
export function key_from_text(text: string): SshPublicKey;
export function key_to_wire(key: SshKeyInput): Uint8Array;
export function key_to_text(key: SshKeyInput, comment?: string): string;

export function private_from_pem(text: string): SshPrivateContainer;
export function private_from_bytes(input: BytesInput): SshPrivateContainer;
/** Reads the section the caller decrypted, into the container. */
export function private_from_decrypted(container: SshPrivateContainer, plaintext: Uint8Array):
  Omit<SshPrivateContainer, 'data' | 'salt' | 'rounds' | 'kdf_note'> & { private: SshPrivateKey; comment: string };

/** An UNENCRYPTED container. `check` is the 4-byte check value (default 0). */
export function private_to_pem(key: SshPrivateKey, options?: { check?: BytesInput; comment?: string }): string;
/** Encrypted, step one: aes256-ctr with bcrypt-pbkdf. */
export function private_prepare(key: SshPrivateKey, options: { salt: BytesInput; rounds: number; check: BytesInput; comment?: string }): SshPrepared;
/** Step two: the ciphertext the caller produced, as the file's text. */
export function private_assemble(prepared: SshPrepared, ciphertext: Uint8Array): string;

/** The bytes a fingerprint hashes: the wire encoding. */
export function fingerprint_input(key: SshKeyInput & { wire?: Uint8Array }): Uint8Array;
/** 'SHA256:<base64, unpadded>' from a SHA-256 the caller computed. */
export function fingerprint_sha256(digest: Uint8Array): string;
/** 'MD5:aa:bb:...' */
export function fingerprint_md5(digest: Uint8Array): string;

/** An SSH signature blob: format, the hash it signs with, and the bytes. */
export interface SshSignatureValue {
  /** 'ssh-ed25519', 'rsa-sha2-512', 'ecdsa-sha2-nistp256'... */
  format: string;
  /** null for Ed25519. */
  hash: string | null;
  /** ssh-rsa: SHA-1. */
  weak: boolean;
  bytes: Uint8Array;
  /** ECDSA: r || s at the curve's width (dsaEncoding 'ieee-p1363'). */
  raw?: Uint8Array;
  /** A security key's signature: what the authenticator reported. */
  sk?: SshSkFields;
}

/** A security key signature's extra fields (PROTOCOL.u2f). */
export interface SshSkFields {
  flags: number;
  counter: number;
  /** flags 0x01: touched. OpenSSH requires it unless no-touch-required. */
  user_present: boolean;
  /** flags 0x04: PIN or biometric. What verify-required requires. */
  user_verified: boolean;
  /** webauthn- only. */
  origin?: string;
  client_data?: Uint8Array;
  extensions?: Uint8Array;
}

/** A signature as the writers take it: bytes, or for a security key the value and its fields. */
export type SshSignatureInput = BytesInput | {
  signature: BytesInput; flags: number; counter: number;
  origin?: string; client_data?: BytesInput; extensions?: BytesInput;
};

/**
 * The bytes a security key signed: SHA-256(application) || flags || counter
 * || extensions || SHA-256(message), the digests the caller's.
 */
export function sk_signed_data(signature: SshSignatureValue, application_digest: BytesInput, message_digest: BytesInput): Uint8Array;
/** What the message digest is of: `data`, or webauthn's clientData once checked to carry it. */
export function sk_message(signature: SshSignatureValue, data: BytesInput): Uint8Array;

/** An SSHSIG (PROTOCOL.sshsig). */
export interface SshSignature {
  version: 1;
  public_key: SshPublicKey;
  /** What the signature is for - compare it with yours. */
  namespace: string;
  reserved: Uint8Array;
  hash: 'sha256' | 'sha512';
  signature: SshSignatureValue;
  wire: Uint8Array;
  note: string;
}

/** An OpenSSH certificate (PROTOCOL.certkeys). */
export interface SshCertificate {
  ssh_type: string;
  nonce: Uint8Array;
  public_key: SshPublicKey;
  serial: Uint8Array;
  serial_hex: string;
  type: 'user' | 'host';
  key_id: string;
  /** Empty means any principal. */
  principals: string[];
  /** Seconds since the epoch. */
  valid_after: number;
  /** null: forever. */
  valid_before: number | null;
  critical_options: Record<string, string>;
  /** Critical options OpenSSH does not define - refuse the certificate if you do not either. */
  unknown_critical: string[];
  extensions: Record<string, string>;
  reserved: Uint8Array;
  /** The CA's key. */
  signature_key: SshPublicKey;
  signature: SshSignatureValue;
  /** What the signature covers. */
  tbs_bytes: Uint8Array;
  wire: Uint8Array;
  comment: string | null;
}

export function sshsig_from_text(text: string): SshSignature;
export function sshsig_from_wire(input: BytesInput): SshSignature;
/** What an SSHSIG signature is over, given H(message). */
export function sshsig_signed_data(sig: { namespace: string; hash: string; reserved?: BytesInput }, digest: BytesInput): Uint8Array;
export function sshsig_prepare(parts: { public_key: SshKeyInput; namespace: string; hash: 'sha256' | 'sha512'; digest: BytesInput; reserved?: BytesInput; format?: string }):
  { bytes: Uint8Array; key: Uint8Array; namespace: string; reserved: number[]; hash: string; format: string };
/** The armoured signature. ECDSA takes r || s; Ed25519 and RSA their bytes. */
export function sshsig_assemble(prepared: ReturnType<typeof sshsig_prepare>, signature: SshSignatureInput): string;

export function certificate_from_text(text: string): SshCertificate;
export function certificate_from_wire(input: BytesInput): SshCertificate;
export function certificate_prepare(parts: {
  public_key: SshKeyInput;
  /** At least 16 random bytes; OpenSSH writes 32. */
  nonce: BytesInput;
  /** 8 bytes. */
  serial?: BytesInput;
  type: 'user' | 'host';
  key_id?: string;
  principals?: string[];
  valid_after?: number;
  /** null: forever (the default). */
  valid_before?: number | null;
  critical_options?: Record<string, string>;
  extensions?: Record<string, string>;
  signature_key: SshKeyInput;
  format?: string;
}): { bytes: Uint8Array; format: string; ssh_type: string };
/** The certificate's wire form; the .pub line is ssh_type, base64, comment. */
export function certificate_assemble(prepared: { bytes: BytesInput; format: string }, signature: SshSignatureInput): Uint8Array;
/** valid_after <= when < valid_before. Default: now. */
export function certificate_valid_at(cert: Pick<SshCertificate, 'valid_after' | 'valid_before'>, when?: Date | number): boolean;

/** A serial as KRL writers take it: 16 hex digits (as serial_hex), 8 bytes, or a whole number. Never 0. */
export type KrlSerialInput = string | Uint8Array | number;

/** A certificates section's entry. Serials come back as 16 hex digits. */
export type KrlCertEntry =
  | { type: 'serial_list'; serials: string[] }
  | { type: 'serial_range'; min: string; max: string }
  | { type: 'serial_bitmap'; offset: string; serials: string[] }
  | { type: 'key_ids'; key_ids: string[] }
  | { type: 'extension'; name: string; critical: false; contents: Uint8Array };

export type KrlSection =
  /** ca_key null: the entries apply to certificates from any CA. */
  | { type: 'certificates'; ca_key: SshPublicKey | null; reserved: Uint8Array; entries: KrlCertEntry[] }
  | { type: 'explicit_keys'; keys: SshPublicKey[] }
  | { type: 'fingerprint_sha1' | 'fingerprint_sha256'; hashes: Uint8Array[] }
  | { type: 'extension'; name: string; critical: false; contents: Uint8Array }
  /** Reported, never written: OpenSSH 9.4+ refuses a KRL with one. */
  | { type: 'signature'; signature_key: SshPublicKey; signature: SshSignatureValue; signed_bytes: Uint8Array; note: string };

/** An OpenSSH KRL (PROTOCOL.krl). */
export interface Krl {
  format_version: 1;
  krl_version: number;
  /** Seconds since the epoch. */
  generated_date: number;
  flags: number;
  reserved: Uint8Array;
  comment: string;
  sections: KrlSection[];
  /** true when there is a signature section - which sshd 9.4+ refuses to load. */
  signed: boolean;
}

export function krl_from_bytes(input: BytesInput): Krl;

/** One step: a KRL has nothing to sign. Sections and entries in the order given. */
export function krl_to_bytes(parts: {
  krl_version: number;
  generated_date: number;
  comment?: string;
  /** None are defined: anything but 0 is refused. */
  flags?: number;
  reserved?: BytesInput;
  /** What krl_from_bytes returned is accepted as it is - a signature section is refused. */
  sections?: Array<
    | KrlSection
    | { type: 'certificates'; ca_key: SshKeyInput | null; reserved?: BytesInput; entries: Array<
        | { type: 'serial_list'; serials: KrlSerialInput[] }
        | { type: 'serial_range'; min: KrlSerialInput; max: KrlSerialInput }
        | { type: 'serial_bitmap'; offset: KrlSerialInput; serials: KrlSerialInput[] }
        | { type: 'key_ids'; key_ids: string[] }
        | { type: 'extension'; name: string; critical?: false; contents?: BytesInput }> }
    | { type: 'explicit_keys'; keys: SshKeyInput[] }
    | { type: 'fingerprint_sha1' | 'fingerprint_sha256'; hashes: BytesInput[] }
    | { type: 'extension'; name: string; critical?: false; contents?: BytesInput }>;
}): Uint8Array;

/** `ssh-keygen -O write-attestation=FILE` (PROTOCOL.u2f): ssh-sk-attest-v01, or v00. */
export interface SkAttestation {
  version: 'v00' | 'v01';
  /** The attestation certificate, DER; null when the authenticator gave none. */
  certificate: Uint8Array | null;
  signature: Uint8Array | null;
  /** As stored: a CBOR byte string (libfido2's fido_cred_authdata_ptr). null in v00. */
  auth_data_cbor: Uint8Array | null;
  auth_data_bytes: Uint8Array | null;
  auth_data: AuthenticatorData | null;
  note: string;
}

export interface SkAttestationPlan {
  /** One verifies - the format the authenticator used, which the file does not record. */
  inputs: Array<{ format: 'packed' | 'fido-u2f'; bytes: Uint8Array }>;
  signature: Uint8Array;
  certificate: Uint8Array | null;
  /** No certificate: the credential key signed. */
  self_attested: boolean;
  credential_key: CoseKey;
  credential_id: Uint8Array;
  aaguid: string;
  /** null when no application_digest was given. */
  rp_id_matches: boolean | null;
  /** null when no public_key was given. */
  key_matches: boolean | null;
  note: string;
}

export function sk_attestation_from_bytes(input: BytesInput): SkAttestation;
export function sk_attestation_plan(att: SkAttestation, options: {
  /** SHA-256 of the enrollment challenge. */
  client_data_hash: BytesInput;
  /** SHA-256 of the key's application ("ssh:" by default). */
  application_digest?: BytesInput;
  public_key?: SshPublicKey;
}): SkAttestationPlan;

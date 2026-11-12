// JSON Web Encryption (RFC 7516): compact and JSON serializations, the AAD
// and the steps of decryption. The caller decrypts.

import type { BytesInput } from './types.js';
import type { JsonObject } from './json.js';

export interface JweKeyParams {
  /** e.g. 'RSA1_5: PKCS#1 v1.5, Bleichenbacher'. */
  warnings: string[];
  /** ECDH-ES: the sender's ephemeral key, and PartyUInfo / PartyVInfo. */
  epk?: JsonObject;
  apu?: Uint8Array | null;
  apv?: Uint8Array | null;
  /** AxxxGCMKW: the key wrap's IV and tag, from the header. */
  iv?: Uint8Array;
  tag?: Uint8Array;
  /** PBES2: p2s, p2c, and the PBKDF2 salt and PRF they make. */
  p2s?: Uint8Array;
  p2c?: number;
  salt?: Uint8Array;
  prf?: string;
}

export interface Jwe {
  serialization: 'compact' | 'flattened' | 'general';
  alg: string;
  enc: string;
  key_length: number;
  kind: 'gcm' | 'cbc-hmac';
  /** The protected header, parsed. */
  header: JsonObject;
  /** Named for what they are: neither is authenticated. */
  unprotected_unauthenticated: JsonObject | null;
  per_recipient_unauthenticated: JsonObject | null;
  zip: string | null;
  key_params: JweKeyParams;
  protected_b64: string;
  aad_b64: string | null;
  encrypted_key: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
  /** The recipient's position, in the general form. */
  index: number;
}

export interface DecryptionPlan {
  key_step: {
    alg: string;
    /** Whether encrypted_key is to be unwrapped (false for dir and ECDH-ES). */
    wrapped: boolean;
    encrypted_key: Uint8Array;
    needs_password: boolean;
    key_length: number;
    params: JweKeyParams;
    warnings: string[];
    note: string;
  };
  content_step: {
    enc: string;
    kind: 'gcm' | 'cbc-hmac';
    key_length: number;
    iv: Uint8Array;
    ciphertext: Uint8Array;
    tag: Uint8Array;
    aad: Uint8Array;
    note: string;
  };
}

export interface PreparedJwe {
  protected_b64: string;
  header: JsonObject;
  alg: string | null;
  enc: string;
  key_length: number;
  iv_length: number;
  tag_length: number;
  aad_b64: string | null;
  /** The AAD to encrypt with. */
  aad: Uint8Array;
}

export const KEY_ALG: Readonly<Record<string, { wraps: boolean; note?: string; ecdh?: boolean; iv_in_header?: boolean; password?: boolean }>>;
export const ENC_ALG: Readonly<Record<string, { key: number; iv: number; tag: number; kind: 'gcm' | 'cbc-hmac' }>>;

/** The general JSON form: one entry per recipient, each with the shared fields. */
export interface JweGeneral {
  serialization: 'general';
  recipients: Jwe[];
}

/** `max_iterations` caps PBES2 p2c; `understood` lists implemented crit extensions. */
export function decode(input: string | JsonObject, options?: { max_iterations?: number; understood?: string[] }): Jwe | JweGeneral;
/** The AAD: ASCII of the protected header as it appears (with '.' aad when present). */
export function aad(jwe: Pick<Jwe, 'protected_b64' | 'aad_b64'>): Uint8Array;
export function decryption_plan(jwe: Jwe): DecryptionPlan;
/** Refuses a content key of the wrong length for enc; returns it. */
export function check_key(jwe: Pick<Jwe, 'enc' | 'key_length' | 'kind'>, cek: BytesInput): Uint8Array;

/** The header serialized once; `aad` (JSON only) is extra authenticated data. */
export function prepare(header: JsonObject, options?: { aad?: BytesInput | null }): PreparedJwe;

export interface JweParts {
  encrypted_key?: BytesInput;
  iv: BytesInput;
  ciphertext: BytesInput;
  tag: BytesInput;
  /** JSON: the shared unprotected header. */
  unprotected?: JsonObject;
  /** JSON, one recipient: its header. */
  header?: JsonObject;
  /** JSON, several recipients. */
  recipients?: Array<{ header?: JsonObject; encrypted_key?: BytesInput }>;
}

export function assemble(prepared: PreparedJwe, parts: JweParts, options?: { serialization?: 'compact' }): string;
export function assemble(prepared: PreparedJwe, parts: JweParts, options: { serialization: 'json' }): JsonObject;
export function assemble(prepared: PreparedJwe, parts: JweParts, options?: { serialization?: 'compact' | 'json' }): string | JsonObject;

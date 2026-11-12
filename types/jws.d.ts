// JSON Web Signature (RFC 7515, RFC 7797) in all three serializations. The
// payload is reached only through payload() / read_verified(), which make
// the caller name the algorithms they accept.

import type { BytesInput } from './types.js';
import type { JsonObject, JsonValue } from './json.js';

/** One signature, as decode returns it (the general form has several). */
export interface JwsSignature {
  serialization: 'compact' | 'flattened' | 'general';
  alg: string;
  /** The protected header, parsed. */
  header: JsonObject;
  /** The unprotected header - named for what it is. */
  unprotected_unsigned: JsonObject | null;
  /** Exactly as received: the signing input is built from these. */
  protected_b64: string;
  /** Null when the payload is detached. With b64 false, the raw text. */
  payload_b64: string | null;
  signature: Uint8Array;
  crit: string[] | null;
  /** RFC 7797: false means the payload is NOT base64url-encoded. */
  b64: boolean;
  /** Reported, not trusted: a chain the signer chose. */
  x5c: JsonValue | null;
  /** The signature's position, in the general form. */
  index: number;
}

export type Jws =
  | JwsSignature
  | { serialization: 'general'; signatures: JwsSignature[]; payload_b64: string | null };

export interface PreparedJws {
  protected_b64: string;
  payload_b64: string;
  header: JsonObject;
  alg: string;
  b64: boolean;
  /** The signing input: sign exactly these bytes. */
  bytes: Uint8Array;
}

/** A flattened or general JSON serialization, as an object. */
export interface JwsJson {
  payload?: string;
  protected?: string;
  header?: JsonObject;
  signature?: string;
  signatures?: Array<{ protected: string; header?: JsonObject; signature: string }>;
}

export const ALGORITHMS: Readonly<Record<string, { kind: 'mac' | 'rsa' | 'ecdsa' | 'eddsa' | 'none'; size: number | null; curve?: string }>>;

/**
 * Any serialization: compact text, or JSON text / object. `understood`
 * lists the crit extensions the caller implements.
 */
export function decode(input: string | JsonObject, options?: { understood?: string[] }): Jws;

/** The exact bytes the signature covers. A detached payload is supplied here. */
/** detached_payload: for b64 (the default), its base64url text or the payload's bytes; for b64:false, the payload as text or bytes. */
export function signing_input(jws: JwsSignature, detached_payload?: string | BytesInput): Uint8Array;

/**
 * `i_understand_embedded_key`: a token carrying its own key (a protected
 * `jwk`) is not refused - it proves only that the sender holds that key, as
 * ACME's newAccount and revokeCert need (RFC 8555 6.2). Verify it with
 * embedded_key(). jku, x5u and an unprotected jwk stay refused.
 */
export interface PayloadOptions {
  i_understand_embedded_key?: true;
}

/** The payload - once the caller has said which algorithms they accept. Not a verification. */
export function payload(jws: JwsSignature, accepted: string[], options?: PayloadOptions): Uint8Array;
/** The payload only if `verified` - the caller's own signature check - is true. */
export function read_verified(jws: JwsSignature, accepted: string[], verified: boolean, options?: PayloadOptions): Uint8Array;

/**
 * The protected header's `jwk`, checked: public, not a MAC key, suited to
 * alg. The key a self-signed token is verified with.
 */
export function embedded_key(jws: JwsSignature): JsonObject;

/**
 * The key a token's kid names, in the caller's JWKS - never the token's
 * own jwk / jku. Null when absent.
 */
export function select_key(jws: JwsSignature, jwks: JsonObject | string | Uint8Array): JsonObject | null;

/** The signing input for a token being created. */
/** A string payload is its UTF-8. */
export function prepare(header: JsonObject, payload_bytes: string | BytesInput): PreparedJws;

/** Compact text by default; flattened JSON with an unprotected `header`; `detached` leaves the payload out. */
export function assemble(prepared: PreparedJws, signature: BytesInput, options?: { serialization?: 'compact'; detached?: boolean }): string;
export function assemble(prepared: PreparedJws, signature: BytesInput, options: { serialization: 'flattened'; header?: JsonObject; detached?: boolean }): JwsJson;
export function assemble(prepared: PreparedJws, signature: BytesInput, options?: { serialization?: 'compact' | 'flattened'; header?: JsonObject; detached?: boolean }): string | JwsJson;

/** The general JSON serialization: several signers, each prepared over the same payload. */
export function general_assemble(
  signers: Array<{ prepared: PreparedJws; signature: BytesInput; header?: JsonObject }>,
  options?: { detached?: boolean }
): JwsJson;

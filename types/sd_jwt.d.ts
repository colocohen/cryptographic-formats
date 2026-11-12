// SD-JWT (RFC 9901): a JWT whose claims are revealed one Disclosure at a
// time, and the Key Binding JWT that ties a presentation to its holder.
// The digests are the caller's to compute - over each disclosure's
// digest_input, and over sd_hash_input.

import type { BytesInput } from './types.js';
import type { JsonObject, JsonValue } from './json.js';
import type { PreparedJws } from './jws.js';
import type { DecodedJwt, ClaimsOptions } from './jwt.js';

export interface Disclosure {
  /** The base64url string as it travels. */
  encoded: string;
  salt: string;
  /** The claim name; null for an array element. */
  name: string | null;
  value: JsonValue;
  /** The US-ASCII of `encoded` - what its digest is over. */
  digest_input: Uint8Array;
}

export interface DecodedSdJwt {
  jwt: DecodedJwt;
  disclosures: Disclosure[];
  kb: DecodedJwt | null;
  /** _sd_alg, or the default 'sha-256' - the hash to compute. */
  sd_alg: string;
  /** The presentation up to its last ~: what a KB-JWT's sd_hash is over. */
  sd_hash_input: Uint8Array;
}

export interface SdJwtClaimsOptions extends ClaimsOptions {
  /** One digest per decoded.disclosures entry, in order: bytes or base64url. */
  digests: Array<Uint8Array | string>;
  /** false - none expected, and one present is refused - or key_binding()'s result. */
  key_binding: false | JsonObject;
  /** Acceptable _sd_alg values. Default ['sha-256']. */
  sd_algs?: string[];
}

export interface KeyBindingOptions {
  /** The digest of decoded.sd_hash_input: bytes or base64url. */
  sd_hash: Uint8Array | string;
  /** Who you are: aud must equal it. */
  audience: string;
  nonce: string;
  /** Seconds the KB-JWT may be old. */
  max_age: number;
  now?: number | Date;
  leeway?: number;
}

export function decode(text: string): DecodedSdJwt;

/** The Processed SD-JWT Payload (RFC 9901 7.1), after every check. */
export function claims(decoded: DecodedSdJwt, accepted: string[], verified: boolean, options: SdJwtClaimsOptions): JsonObject;

/** The KB-JWT's claims, once its signature (with the cnf key) and contents check. */
export function key_binding(decoded: DecodedSdJwt, accepted: string[], verified: boolean, options: KeyBindingOptions): JsonObject;

/** [salt, name, value] or [salt, value] -> the Disclosure, and what to hash for its digest. */
/** parts: [salt, name, value] for an object property, [salt, value] for an array element. */
export function disclosure(parts: unknown[]): { encoded: string; digest_input: Uint8Array };

/** <JWT>~<D1>~...~<DN>~ and the KB-JWT when given. */
export function serialize(issuer_jwt: string, disclosures?: Array<string | { encoded: string }>, kb_jwt?: string | null): string;

/** A KB-JWT's signing input: typ kb+jwt, with iat, aud, nonce and sd_hash. */
export function kb_prepare(header: JsonObject, payload: { iat: number; aud: string; nonce: string; sd_hash: Uint8Array | string; [k: string]: unknown }): PreparedJws;

/** The KB-JWT, compact. */
export function kb_assemble(prepared: PreparedJws, signature: BytesInput): string;

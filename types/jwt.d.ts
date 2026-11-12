// JSON Web Tokens (RFC 7519): compact JWS, claims checked with the
// caller's policy stated explicitly.

import type { BytesInput } from './types.js';
import type { JsonObject, JsonValue } from './json.js';
import type { JwsSignature, PreparedJws } from './jws.js';

export interface DecodedJwt {
  jws: JwsSignature;
  alg: string;
  header: JsonObject;
  typ: JsonValue | null;
  /** What the signature covers. */
  signing_input: Uint8Array;
  signature: Uint8Array;
}

export interface ClaimsOptions {
  /** Seconds since the epoch, or a Date. Default: the system clock. */
  now?: number | Date;
  /** Seconds of skew on exp and nbf. Default 0. */
  leeway?: number;
  /** iss must be present and one of these. */
  issuer?: string | string[];
  /** The audiences YOU are - required when the token carries aud. */
  audience?: string | string[];
  subject?: string;
  /** Matched ignoring case and an 'application/' prefix. */
  typ?: string;
  /** Seconds: iat required, and no older than this. */
  max_age?: number;
  /** Claims that must be present; default ['exp']. */
  require?: string[];
}

/** The claim types RFC 7519 registers: 'string', 'date', 'audience'. */
export const REGISTERED: Readonly<Record<string, string>>;

/** A compact JWS token. A five-part (encrypted) token is refused: jwe.decode it first. */
export function decode(token: string, options?: { understood?: string[] }): DecodedJwt;

/**
 * The claims - after the caller names the algorithms they accept and says
 * whether the signature verified - checked against `options`.
 */
export function claims(decoded: DecodedJwt, accepted: string[], verified: boolean, options?: ClaimsOptions): JsonObject;

/** typ defaults to 'JWT'. Claims are type-checked on the way out too. */
export function prepare(header: JsonObject, payload: JsonObject): PreparedJws;
/** The compact token. */
export function assemble(prepared: PreparedJws, signature: BytesInput): string;

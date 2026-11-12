// A strict JSON scanner: duplicate members, trailing content, non-canonical
// numbers, lone surrogates and raw control characters are refused.

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [member: string]: JsonValue };

export type JsonObject = { [member: string]: JsonValue };

/** One value; text, or UTF-8 bytes. */
export function parse(text: string | Uint8Array): JsonValue;

/** An own member, or undefined - never one inherited from Object.prototype. */
export function member(obj: unknown, name: string): JsonValue | undefined;
export function has(obj: unknown, name: string): boolean;
/** Sets an own member - defineProperty, so __proto__ is an ordinary key. */
export function put(obj: object, name: string, value: unknown): void;

/** Strict UTF-8 decoding: overlongs, surrogates and truncation refused. */
export function utf8_to_string(bytes: Uint8Array): string;

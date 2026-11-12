/** Every refusal this library makes. Assert on `code`, never on `message`. */
export class FormatError extends Error {
  constructor(family: string, offset: number | null | undefined, code: string, detail: string);
  name: 'FormatError';
  /** The module or encoding family that refused: 'der', 'x509', 'jws'... */
  family: string;
  /** Byte offset into the input, or null for text formats. */
  offset: number | null;
  /** A stable identifier: 'non-minimal-length', 'bad-signature-algorithm'... */
  code: string;
}

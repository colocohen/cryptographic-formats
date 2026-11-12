// Building PKCS#10 requests: prepare -> the caller signs -> assemble.

import type { BytesInput, NameInput, PublicKeyInput } from './types.js';
import type { ExtensionsInput } from './x509_build.js';

export interface RequestParts {
  subject: NameInput;
  public_key: PublicKeyInput;
  /** Requested in an extensionRequest attribute; as x509_build takes them. */
  extensions?: ExtensionsInput;
  /** An algorithm name: 'ecdsaWithSHA256'. */
  signature_algorithm: string;
}

export interface PreparedRequest {
  /** The CertificationRequestInfo: sign exactly these bytes. */
  bytes: Uint8Array;
  signature_algorithm: string;
}

export function prepare(parts: RequestParts): PreparedRequest;
export function assemble(prepared: PreparedRequest, signature: BytesInput): Uint8Array;

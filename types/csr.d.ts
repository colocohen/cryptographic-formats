// PKCS#10 certificate requests (RFC 2986), read. Building is csr_build.

import type { AlgorithmDescription, BytesInput, Extension, Name, PublicKey } from './types.js';

export interface CertificationRequest {
  subject: Name;
  public_key: PublicKey;
  /** Every attribute, raw: `value` is the SET OF values' content. */
  attributes: Array<{ id: string; oid: Uint8Array; name: string | null; value: Uint8Array }>;
  /**
   * The extensions an extensionRequest attribute asks for, decoded as a
   * certificate's are: `x509.extension({ extensions: csr.requested },
   * 'subjectAltName').parsed`. Asked for - a CA may grant or ignore them.
   */
  requested: Extension[];
  /** challengePassword (RFC 2985 5.4.1) as text - SCEP's shared secret - or null. Checking it is the caller's. */
  challenge_password: string | null;
  signature: Uint8Array;
  signature_algorithm: string;
  signature_params: AlgorithmDescription;
  /** The CertificationRequestInfo as it arrived - what the signature covers. */
  tbs_bytes: Uint8Array;
  der: Uint8Array;
}

export function from_der(input: BytesInput): CertificationRequest;

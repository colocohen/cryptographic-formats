// cryptographic-formats - container and encoding formats around cryptography.
// Each module's declarations are beside it in src/; this re-exports them as
// index.js does.

import type { BytesInput } from './src/types.js';

export type * from './src/types.js';

// level 0: the encodings
export * as der from './src/der_reader.js';
export * as der_writer from './src/der_writer.js';
export * as ber from './src/ber_reader.js';
export * as fields from './src/fields.js';
export * as tags from './src/tags.js';
export * as oid from './src/oid.js';
export * as real from './src/real.js';
export * as xml from './src/xml_reader.js';
export * as cbor from './src/cbor_reader.js';
export * as cbor_writer from './src/cbor_writer.js';
export * as json from './src/json.js';
export * as base from './src/base.js';
export * as bech32 from './src/bech32.js';
export * as multiformats from './src/multiformats.js';

// level 1: the formats
export * as pem from './src/pem.js';
export * as spki from './src/spki.js';
export * as pkcs8 from './src/pkcs8.js';
export * as pkcs12 from './src/pkcs12.js';
export * as pbes2 from './src/pbes2.js';
export * as x509 from './src/x509.js';
export * as csr from './src/csr.js';
export * as crl from './src/crl.js';
export * as ocsp from './src/ocsp.js';
export * as cms from './src/cms.js';
export * as cms_enveloped from './src/cms_enveloped.js';
export * as tsp from './src/tsp.js';
export * as smime from './src/smime.js';
export * as saml from './src/saml.js';
export * as attrcert from './src/attrcert.js';
export * as crmf from './src/crmf.js';
export * as cmp from './src/cmp.js';
export * as scep from './src/scep.js';
export * as sct from './src/sct.js';
export * as signature from './src/signature.js';
export * as algorithm from './src/algorithm.js';

export * as x509_build from './src/x509_build.js';
export * as csr_build from './src/csr_build.js';
export * as cms_build from './src/cms_build.js';
export * as cms_enveloped_build from './src/cms_enveloped_build.js';
export * as crl_build from './src/crl_build.js';
export * as ocsp_build from './src/ocsp_build.js';
export * as tsp_build from './src/tsp_build.js';
export * as pkcs12_build from './src/pkcs12_build.js';
export * as attrcert_build from './src/attrcert_build.js';
export * as crmf_build from './src/crmf_build.js';
export * as cmp_build from './src/cmp_build.js';
export * as scep_build from './src/scep_build.js';

export * as jwk from './src/jwk.js';
export * as jws from './src/jws.js';
export * as jwe from './src/jwe.js';
export * as jwt from './src/jwt.js';
export * as cose from './src/cose.js';
export * as cwt from './src/cwt.js';
export * as sd_jwt from './src/sd_jwt.js';
export * as openpgp from './src/openpgp.js';
export * as openpgp_build from './src/openpgp_build.js';
export * as webauthn from './src/webauthn.js';
export * as fido_mds from './src/fido_mds.js';
export * as ssh from './src/ssh.js';
export * as params from './src/params.js';

export { FormatError } from './src/error.js';

import type { Certificate } from './src/x509.js';
import type { AttributeCertificate } from './src/attrcert.js';
import type { CertificationRequest } from './src/csr.js';
import type { CertificateList } from './src/crl.js';
import type { PrivateKey, EncryptedPrivateKey } from './src/pkcs8.js';
import type { Pfx } from './src/pkcs12.js';
import type { SignedData } from './src/cms.js';
import type { EnvelopedData, AuthEnvelopedData, AuthenticatedData, CompressedData, DigestedData, EncryptedData } from './src/cms_enveloped.js';
import type { SmimeMessage } from './src/smime.js';
import type { OcspRequest, OcspResponse } from './src/ocsp.js';
import type { TimeStampRequest, TimeStampResponse } from './src/tsp.js';
import type { PkiMessage } from './src/cmp.js';
import type { CertReqMessage } from './src/crmf.js';
import type { DhParams } from './src/params.js';
import type { SshPublicKey, SshPrivateContainer, SshSignature, SshCertificate } from './src/ssh.js';
import type { JwkKey } from './src/jwk.js';
import type { JsonObject } from './src/json.js';
import type { Jws } from './src/jws.js';
import type { Jwe, JweGeneral } from './src/jwe.js';
import type { CoseKey } from './src/cose.js';
import type { DecodedCwt } from './src/cwt.js';
import type { DecodedSdJwt } from './src/sd_jwt.js';
import type { Armor, Packet, Cleartext } from './src/openpgp.js';
import type { AttestationObject } from './src/webauthn.js';
import type { PemBlock } from './src/pem.js';
import type { PublicKey } from './src/types.js';

/** What sniff found - narrow on `format` to get `value`'s type. */
export type SniffResult = { label?: string } & (
  | { format: 'x509'; value: Certificate }
  | { format: 'trusted-certificate'; value: Certificate; trust_settings: Uint8Array | null; note: string | null }
  | { format: 'attribute-certificate'; value: AttributeCertificate }
  | { format: 'csr'; value: CertificationRequest }
  | { format: 'crl'; value: CertificateList }
  | { format: 'spki'; value: PublicKey }
  | { format: 'pkcs8' | 'sec1'; value: PrivateKey }
  | { format: 'pkcs1'; value: ReturnType<typeof import('./src/pkcs8.js').pkcs1_from_der> }
  | { format: 'pkcs1-public'; value: Uint8Array; note: string }
  | { format: 'pkcs8-encrypted'; value: EncryptedPrivateKey }
  | { format: 'pkcs12'; value: Pfx }
  | { format: 'cms'; value: SignedData }
  | { format: 'cms-enveloped'; value: EnvelopedData }
  | { format: 'cms-auth-enveloped'; value: AuthEnvelopedData }
  | { format: 'cms-authenticated'; value: AuthenticatedData }
  | { format: 'cms-compressed'; value: CompressedData }
  | { format: 'cms-digested'; value: DigestedData }
  | { format: 'cms-encrypted'; value: EncryptedData }
  | { format: 'smime'; value: SmimeMessage }
  | { format: 'ocsp-request'; value: OcspRequest }
  | { format: 'ocsp-response'; value: OcspResponse }
  | { format: 'tsp-request'; value: TimeStampRequest }
  | { format: 'tsp-response'; value: TimeStampResponse }
  | { format: 'cmp'; value: PkiMessage }
  | { format: 'crmf'; value: { messages: CertReqMessage[]; der: Uint8Array } }
  | { format: 'dhparam'; value: DhParams }
  | { format: 'ecparam'; value: { curve: string; oid: Uint8Array; der: Uint8Array } }
  | { format: 'ssh-public'; value: SshPublicKey }
  | { format: 'openssh-private'; value: SshPrivateContainer }
  | { format: 'ssh-signature'; value: SshSignature }
  | { format: 'openpgp'; armor: Armor; value: Packet[] }
  | { format: 'openpgp-cleartext'; value: Cleartext }
  | { format: 'ssh-certificate'; value: SshCertificate }
  | { format: 'jwk'; value: JwkKey }
  | { format: 'jwks'; value: JsonObject[] }
  | { format: 'jws'; value: Jws }
  | { format: 'jwe'; value: Jwe | JweGeneral }
  | { format: 'cose-key'; value: CoseKey }
  | { format: 'cwt'; value: DecodedCwt }
  | { format: 'sd-jwt'; value: DecodedSdJwt }
  | { format: 'webauthn'; value: AttestationObject }
  | { format: 'pem-bundle'; value: PemBlock[]; labels: string[]; note: string }
  | { format: 'legacy-encrypted-pem'; value: PemBlock; note: string }
);

export type SniffFormat = SniffResult['format'];

/**
 * Level 2: the only function that guesses - and the result says what it
 * guessed. Narrow on `format` before using `value`. `expect` limits a DER
 * guess to one format.
 */
export function sniff(input: string | BytesInput, options?: { expect?: SniffFormat }): SniffResult;

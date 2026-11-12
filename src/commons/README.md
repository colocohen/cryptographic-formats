# commons — and what deliberately is not here

Shared helpers, plus the rule that decides what is allowed to be shared.

## The rule

**A helper may be shared by any number of modules that face the same
direction. It may NOT be shared between a reader and its writer.**

The reason is the failure this whole library exists to prevent, applied to
itself. From the brief:

> `sig_to_der` wrote a short-form length of 135 for P-521, which is not DER
> at all. It went unnoticed because the decoder was equally wrong in the
> other direction and the pair round-tripped with each other. **An encoder
> checked only against its own decoder can be wrong in both and look right.**

A shared helper produces exactly that by construction. One mistake, both
directions, and the only test that ever exercises the pair is a round trip
between them — which passes.

## What is here

| file | shared by | why it is safe |
|---|---|---|
| `bytes.js` | everything | coercion, comparison and joining - `append` grows a writer's octet array in place, the linear way (`out = out.concat(part)` in a loop is quadratic); not part of any encode/decode pair |
| `fail.js` | everything | builds an error. A mistake makes every refusal report the wrong thing, which is loud |
| `decode_text.js` | **readers only** | two decoders cannot cancel each other out |
| `encode_text.js` | **writers only** | two encoders cannot either. Holds `code_points`, the surrogate-pairing walk UTF-8 and UCS-4 share |
| `limits.js` | everything | validation only: ceilings on values an attacker chooses and the caller pays for (iteration counts). Produces nothing, so it cannot cancel out |
| `crc24.js` | everything | OpenPGP's armour checksum - a checksum over bytes, not one half of an encode/decode pair. The armour from gpg and from RFC 9580's appendix A checks it independently |
| `rfc4514.js` | everything | RFC 4514's short attribute names (CN, ST, OU...) to OIDs - a name table, not an encode/decode pair. x509.js prints and looks up names with it and pkix.js accepts it in a builder's Name; OpenSSL checks the DER it leads to |
| `ip.js` | everything | text a person typed (an IP address) to octets - neither half of a DER encode/decode pair. x509.js matches hosts with it and pkix.js writes GeneralNames with it, so the same text is the same address in both |

`der_reader` and `cbor_reader` both import `decode_text`. `der_writer` and
`cbor_writer` both import `encode_text`. Nothing imports both.

## What is deliberately NOT here

Two things jscpd will flag forever, and both must stay duplicated.

### Length encoding

`der_reader._read_length` and `der_writer.encode_length` implement the same
rule — shortest form, no leading zero — in opposite directions. They are the
literal case the brief describes.

### Bytewise comparison for SET OF ordering

`der_writer.compare` sorts SET OF members; `fields.read_set_of` validates that
order; `cbor_writer.compare` sorts map keys; `cbor_reader.read_map` validates
that order.

These look like four copies of a ten-line function, and sharing them would be
the same trap in a smaller package: a `compare` that ordered by length before
content would make the writer emit a "sorted" set the reader accepts and every
external tool rejects. The round trip would pass.

So each direction keeps its own, and each carries a comment saying so.

## Shared outside commons, by the same rule

Not every shared helper lives here. These are shared between modules that
face the SAME direction, and each says so where it is defined:

| where | what | shared by |
|---|---|---|
| `pkix.js` | `extension_to_der`, `raw_extensions_to_der`, `validity_to_der`, `number_bytes` | the four PKIX builders |
| `ec_domain.js` | `KEY_PARAMS`, `identify_key_algorithm`, `read_key_parameters` | `spki.js` and `pkcs8.js` readers |
| `spki.js` | `key_algorithm_to_der` | `spki.to_der` and `pkcs8.to_der` |
| `der_writer.js` | `base128` | `der_writer.relative_oid` and `oid.from_string`, both encoders |
| `jose.js` | `split_serialization`, `check_crit`, `union_headers` | `jws.js` and `jwe.js` |
| `oid.js` | `checked_digest_size(name, fail)` | `pkcs12.js` and `tsp.js` |
| `algorithm.js` | `describe` (reader) and `to_der` (writer) | every signed format; the two halves are separate functions, each checked against OpenSSL |
| `pkix.js` | `status_info_to_der` - PKIStatusInfo | `tsp_build` and `cmp_build`; RFC 3161 imports the type from CMP. Each keeps its own name-to-bit table |
| `pbes2.js` | `scheme_to_der`, `pbkdf2_to_der`, `cipher_to_der` (writers) | `pkcs8.encrypted_to_der`, `pkcs12_build`, CMS pwri, PBMAC1 |
| `pbes2.js` | `read_pbkdf2`, `read_cipher` (readers) | `pkcs8.encrypted_from_der`, CMS pwri in `cms_enveloped`, PBMAC1 in `pkcs12` |
| `pkix.js` | `x509_name_to_der`, `general_name_to_der`, `public_key_to_der`, `certificate_extensions_to_der`, `issuer_and_serial_to_der`, `REASONS` | every builder that writes a Name, GeneralName, key, extension, IssuerAndSerialNumber or revocation reason. They lived in `x509_build` and `crl_build`, and four builders imported them from there; no builder imports another now (`test/naming.test.js`) |
| `crl.js` | `REASONS` (reader) | `ocsp.js` - one reader table for the reason codes both formats carry |
| `pkix.js` | `as_date`, `validity_days`, `time_to_der` | every builder taking a validity or time: a Date or the time a reader returned (`crmf_build` had its own copy of the time rule) |
| `algorithm.js` | `canonical_name`, `node_name` | every writer that takes an algorithm name; tests and examples at the node:crypto boundary |
| `cms_build.js` | `extra_attribute` | signedAttrs, and AuthEnvelopedData's authAttrs in `cms_enveloped_build` |
| `cose.js` | `enc_structure`, `mac_structure`, `encrypted_body`, `mac_body` | the 0 and non-0 forms of Encrypt and Mac, in one module, one direction each |

## Adding to commons

Before moving a helper here, ask one question:

> If this were wrong, would a round trip through this library still pass?

If yes, it stays duplicated.

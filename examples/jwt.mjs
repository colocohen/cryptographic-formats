// Issue an ES256 JWT and verify it. The token's signature is the raw r||s
// pair (64 bytes), not DER - node:crypto is told so with dsaEncoding.
import crypto from 'node:crypto';
import { jwt } from 'cryptographic-formats';

const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const now = Math.floor(Date.now() / 1000);

// Issuing: the library gives the bytes to sign, the caller signs.
const prepared = jwt.prepare({ alg: 'ES256', kid: 'k1' },
  { iss: 'https://issuer.example', aud: 'my-api', sub: 'user-42',
    iat: now, exp: now + 300 });
const sig = crypto.sign('sha256', prepared.bytes,
  { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
const token = jwt.assemble(prepared, sig);

// Verifying: structure, then signature, then claims - in that order.
const t = jwt.decode(token);
const ok = crypto.verify('sha256', t.signing_input,
  { key: key.publicKey, dsaEncoding: 'ieee-p1363' }, t.signature);

// claims() hands nothing over unless the signature verified, the algorithm
// is one you accept, and iss / aud / exp all pass.
const claims = jwt.claims(t, ['ES256'], ok,
  { issuer: 'https://issuer.example', audience: 'my-api' });
console.log(claims.sub);                                 // user-42

// The named curves' domain parameters, for recognising a key that spells its
// curve out instead of naming it (DECISIONS 46) - what node writes with
// paramEncoding: 'explicit' and `openssl ecparam -param_enc explicit` does.
//
// ⚠ GENERATED, NOT WRITTEN: each is the ECParameters node:crypto (Node
// 22.23.4 / OpenSSL 3.5.9) exports for the curve with explicit encoding,
// and every value was checked against `openssl ecparam -param_enc explicit`
// from the OpenSSL 3.0.13 CLI. test/ec_explicit.test.js asks node again for
// every curve here and fails if a value differs.
//
// Hex, field elements without leading zeros; g is the uncompressed base
// point. seed is the X9.62 seed where the curve has one (Brainpool's do not).
// Data only: ec_domain.js compares a file's parameters against these, value
// for value, and nothing here is computed with.

export var EXPLICIT_CURVES = {
  secp192r1: {
    p: 'fffffffffffffffffffffffffffffffeffffffffffffffff',
    a: 'fffffffffffffffffffffffffffffffefffffffffffffffc',
    b: '64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1',
    g: '04188da80eb03090f67cbf20eb43a18800f4ff0afd82ff101207192b95ffc8da78631011ed6b24cdd573f977a11e794811',
    n: 'ffffffffffffffffffffffff99def836146bc9b1b4d22831',
    h: '01',
    seed: '3045ae6fc8422f64ed579528d38120eae12196d5'
  },
  secp224r1: {
    p: 'ffffffffffffffffffffffffffffffff000000000000000000000001',
    a: 'fffffffffffffffffffffffffffffffefffffffffffffffffffffffe',
    b: 'b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4',
    g: '04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34',
    n: 'ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d',
    h: '01',
    seed: 'bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5'
  },
  secp256r1: {
    p: 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
    a: 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
    b: '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
    g: '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
    n: 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    h: '01',
    seed: 'c49d360886e704936a6678e1139d26b7819f7e90'
  },
  secp384r1: {
    p: 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
    a: 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
    b: 'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
    g: '04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
    n: 'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
    h: '01',
    seed: 'a335926aa319a27a1d00896a6773a4827acdac73'
  },
  secp521r1: {
    p: '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    a: '01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc',
    b: '51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00',
    g: '0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
    n: '01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
    h: '01',
    seed: 'd09e8800291cb85396cc6717393284aaa0da64ba'
  },
  secp256k1: {
    p: 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
    a: '00',
    b: '07',
    g: '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
    n: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    h: '01'
  },
  brainpoolP256r1: {
    p: 'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
    a: '7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9',
    b: '26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6',
    g: '048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997',
    n: 'a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
    h: '01'
  },
  brainpoolP256t1: {
    p: 'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
    a: 'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374',
    b: '662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04',
    g: '04a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f42d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be',
    n: 'a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
    h: '01'
  },
  brainpoolP320r1: {
    p: 'd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27',
    a: '3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4',
    b: '520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6',
    g: '0443bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e2061114fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1',
    n: 'd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311',
    h: '01'
  },
  brainpoolP320t1: {
    p: 'd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27',
    a: 'd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e24',
    b: 'a7f561e038eb1ed560b3d147db782013064c19f27ed27c6780aaf77fb8a547ceb5b4fef422340353',
    g: '04925be9fb01afc6fb4d3e7d4990010f813408ab106c4f09cb7ee07868cc136fff3357f624a21bed5263ba3a7a27483ebf6671dbef7abb30ebee084e58a0b077ad42a5a0989d1ee71b1b9bc0455fb0d2c3',
    n: 'd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311',
    h: '01'
  },
  brainpoolP384r1: {
    p: '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53',
    a: '7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826',
    b: '04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11',
    g: '041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315',
    n: '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565',
    h: '01'
  },
  brainpoolP384t1: {
    p: '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53',
    a: '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec50',
    b: '7f519eada7bda81bd826dba647910f8c4b9346ed8ccdc64e4b1abd11756dce1d2074aa263b88805ced70355a33b471ee',
    g: '0418de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928',
    n: '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565',
    h: '01'
  },
  brainpoolP512r1: {
    p: 'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3',
    a: '7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca',
    b: '3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723',
    g: '0481aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f8227dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892',
    n: 'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069',
    h: '01'
  },
  brainpoolP512t1: {
    p: 'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3',
    a: 'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f0',
    b: '7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423e',
    g: '04640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332',
    n: 'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069',
    h: '01'
  }

};

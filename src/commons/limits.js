// Ceilings on values an attacker controls and the CALLER pays for.
//
// This library performs no cryptography, so a large iteration count costs it
// nothing - it reads a number and hands it over. The cost lands on the
// caller, who runs PBKDF2 that many times because a file said to. A PKCS#12
// or a JWE with p2c = 2^31 is a denial of service delivered as a parameter,
// and it has been one in practice (CVE-2022-36083 in jose, and the same
// class in jose4j and python-jose).
//
// So the number is checked here, where it is read, against a ceiling the
// caller can raise. The default is high enough for every real file this
// library has seen - OpenSSL writes 2048, keytool 10000, OWASP's 2023
// guidance for PBKDF2-SHA256 is 600,000 - and low enough that the worst case
// is under a second rather than a day.
//
// Validation only: produces nothing, so it cannot be half of a pair that
// cancels out, and may be shared by readers and writers alike.

var DEFAULT_MAX_ITERATIONS = 1000000;

// `options.max_iterations` raises (or lowers) the ceiling. A caller who has a
// file with more, and trusts where it came from, says so explicitly.
function check_iterations(n, options, fail, what) {
  var max = DEFAULT_MAX_ITERATIONS;

  if (options && options.max_iterations !== undefined) {
    max = options.max_iterations;
    if (typeof max !== 'number' || !(max >= 1) || max % 1 !== 0) {
      fail('bad-options', 'max_iterations must be a positive integer');
    }
  }

  if (typeof n !== 'number' || n % 1 !== 0 || n < 1) {
    fail('bad-iterations', (what || 'the iteration count') +
      ' must be a positive integer');
  }

  if (n > max) {
    fail('too-many-iterations',
      (what || 'the iteration count') + ' is ' + n + ', above the ceiling of ' +
      max + '. Running it is the caller\'s cost, and an attacker chooses it - ' +
      'pass options.max_iterations to accept more from a source you trust');
  }

  return n;
}

export {
  DEFAULT_MAX_ITERATIONS,
  check_iterations
};

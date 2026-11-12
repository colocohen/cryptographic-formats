// T.61 / TeletexString decoding.
//
// ⚠ WHY THIS IS NOT JUST latin1().
//
// RFC 5280 deprecates TeletexString and certificates issued before that carry
// it, so this library reads one rather than refusing. For a long time it read
// it as Latin-1 with a comment saying the true encoding is "a shifting
// multi-byte set almost nobody implemented correctly".
//
// That comment was true and the conclusion was wrong. The shifting part is
// real, but the part that appears in certificates is small and fixed: a
// diacritic escape in 0xC1..0xCF followed by a base letter, plus two ranges
// of standalone symbols. Lapo Luchini's decoder - the one behind lapo.it/asn1js
// and the one most people look at a certificate with - handles exactly that,
// and comparing against it is what showed the difference matters.
//
// It matters because of LENGTH. `C1 41` is ONE character, À. Read as Latin-1
// it becomes TWO, Á followed by A. And x509.name_matches compares strings -
// so a subject name with a single accented letter compares unequal to itself
// across two encodings of the same name, and a chain fails to build for a
// reason nothing reports.
//
// ⚠ WHAT IS STILL NOT HANDLED, and is refused rather than guessed:
//
// The ISO 2022 escape sequences that switch character sets mid-string. Those
// are the part almost nobody implemented, they do not appear in certificates,
// and a decoder that silently ignored an escape would produce a string that
// is not what the bytes say.

// The diacritic table, T.61 clause 4.3. Index by the escape byte minus 0xC0;
// each entry pairs the base letters with the composed characters.
//
// Taken from Lapo Luchini's decoder, which is the reference implementation
// most people compare a certificate against.
var DIACRITICS = [
  ['', ''],
  ['AEIOUaeiou', '\u00C0\u00C8\u00CC\u00D2\u00D9' +
                 '\u00E0\u00E8\u00EC\u00F2\u00F9'],           // grave
  ['ACEILNORSUYZacegilnorsuyz',
   '\u00C1\u0106\u00C9\u00CD\u0139\u0143\u00D3\u0154\u015A\u00DA\u00DD' +
   '\u0179\u00E1\u0107\u00E9\u0123\u00ED\u013A\u0144\u00F3\u0155\u015B' +
   '\u00FA\u00FD\u017A'],                                     // acute
  ['ACEGHIJOSUWYaceghijosuwy',
   '\u00C2\u0108\u00CA\u011C\u0124\u00CE\u0134\u00D4\u015C\u00DB\u0174' +
   '\u0176\u00E2\u0109\u00EA\u011D\u0125\u00EE\u0135\u00F4\u015D\u00FB' +
   '\u0175\u0177'],                                           // circumflex
  ['AINOUainou', '\u00C3\u0128\u00D1\u00D5\u0168' +
                 '\u00E3\u0129\u00F1\u00F5\u0169'],           // tilde
  ['AEIOUaeiou', '\u0100\u0112\u012A\u014C\u016A' +
                 '\u0101\u0113\u012B\u014D\u016B'],           // macron
  ['AGUagu', '\u0102\u011E\u016C\u0103\u011F\u016D'],         // breve
  ['CEGIZcegz', '\u010A\u0116\u0120\u0130\u017B' +
                '\u010B\u0117\u0121\u017C'],                  // dot above
  ['AEIOUYaeiouy', '\u00C4\u00CB\u00CF\u00D6\u00DC\u0178' +
                   '\u00E4\u00EB\u00EF\u00F6\u00FC\u00FF'],   // diaeresis
  ['', ''],
  ['AUau', '\u00C5\u016E\u00E5\u016F'],                       // ring
  ['CGKLNRSTcklnrst', '\u00C7\u0122\u0136\u013B\u0145\u0156\u015E\u0162' +
                      '\u00E7\u0137\u013C\u0146\u0157\u015F\u0163'], // cedilla
  ['', ''],
  ['OUou', '\u0150\u0170\u0151\u0171'],                       // double acute
  ['AEIUaeiu', '\u0104\u0118\u012E\u0172\u0105\u0119\u012F\u0173'], // ogonek
  ['CDELNRSTZcdelnrstz',
   '\u010C\u010E\u011A\u013D\u0147\u0158\u0160\u0164\u017D' +
   '\u010D\u010F\u011B\u013E\u0148\u0159\u0161\u0165\u017E']  // caron
];

// The two ranges of standalone characters. A \u0000 marks an unassigned
// position, which is refused rather than emitted.
var SYMBOLS_A4 =
  '\u0024\u00A5\u0023\u00A7\u00A4\u0000\u0000\u00AB\u0000\u0000\u0000' +
  '\u0000\u00B0\u00B1\u00B2\u00B3\u00D7\u00B5\u00B6\u00B7\u00F7\u0000' +
  '\u0000\u00BB\u00BC\u00BD\u00BE\u00BF';

var SYMBOLS_E0 =
  '\u03A9\u00C6\u00D0\u00AA\u0126\u0000\u0132\u013F\u0141\u00D8\u0152' +
  '\u00BA\u00DE\u0166\u014A\u0149\u0138\u00E6\u0111\u00F0\u0127\u0131' +
  '\u0133\u0140\u0142\u00F8\u0153\u00DF\u00FE\u0167\u014B\u0000';

// Decodes a T.61 byte string.
//
// `fail` is passed in so the error carries the calling module's family and
// offset - a bad T61 string in a certificate should say `der`, and the same
// bytes inside a PKCS#12 should say `ber`.
function decode_t61(bytes, fail, pos) {
  var s = '';
  var i = 0;

  while (i < bytes.length) {
    var c = bytes[i];

    // ⚠ THE ISO 2022 ESCAPE. Refused rather than skipped: a decoder that
    // ignored it would produce a string in a character set other than the
    // one the bytes name, which is worse than not reading the value at all.
    if (c === 0x1B) {
      fail(pos, 't61-escape-sequence',
        'this TeletexString contains an ISO 2022 escape sequence at offset ' +
        i + ', which switches character set mid-string. That part of T.61 ' +
        'is not decoded here, and guessing would give a string the bytes ' +
        'do not say.');
    }

    // A diacritic escape: the accent comes FIRST, then the base letter.
    if (c >= 0xC0 && c <= 0xCF) {
      if (i + 1 >= bytes.length) {
        fail(pos, 'bad-t61-string',
          'a T.61 diacritic at offset ' + i + ' with no letter after it');
      }

      var table = DIACRITICS[c - 0xC0];
      var base = String.fromCharCode(bytes[i + 1]);
      var at = table[0].indexOf(base);

      if (at === -1) {
        fail(pos, 'bad-t61-string',
          'T.61 has no composed form for 0x' + c.toString(16) +
          ' followed by "' + base + '"');
      }

      s += table[1].charAt(at);
      i += 2;
      continue;
    }

    if (c >= 0xA4 && c <= 0xBF) {
      var sym = SYMBOLS_A4.charAt(c - 0xA4);
      if (sym === '\u0000') {
        fail(pos, 'bad-t61-string',
          'byte 0x' + c.toString(16) + ' is unassigned in T.61');
      }
      s += sym;
      i += 1;
      continue;
    }

    if (c >= 0xE0) {
      var sym2 = SYMBOLS_E0.charAt(c - 0xE0);
      if (sym2 === '\u0000') {
        fail(pos, 'bad-t61-string',
          'byte 0x' + c.toString(16) + ' is unassigned in T.61');
      }
      s += sym2;
      i += 1;
      continue;
    }

    // Below 0xA4 and outside the escape ranges, T.61 agrees with ASCII.
    s += String.fromCharCode(c);
    i += 1;
  }

  return s;
}

export { decode_t61 };

// An IP address typed as text, to the octets a certificate carries: IPv4
// dotted-quad, or IPv6 in RFC 4291 2.2's forms - "::" and a dotted IPv4
// tail included - with [brackets] allowed around it. null when it is not one.
//
// Shared by x509.js (matching a host, or a name against a constraint) and
// pkix.js (writing a GeneralName or a name constraint). That is not the pair commons/README.md keeps
// apart: neither side encodes or decodes DER here - both read what a person
// typed - and the same text must mean the same address in both.

// An IPv4 dotted quad or an IPv6 literal (brackets optional) as bytes, or
// null when the text is not an IP literal at all. Strict: no leading zeros
// in IPv4 - "010.0.0.1" is octal in some stacks and decimal in others, and
// a name two parsers read differently is not one to match on.
function parse_ip(text) {
  var t = text.replace(/^\[(.*)\]$/, '$1');

  var v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(t);
  if (v4 !== null) {
    var out4 = [];
    var k;
    for (k = 1; k <= 4; k++) {
      if (v4[k].length > 1 && v4[k].charAt(0) === '0') { return null; }
      var n = parseInt(v4[k], 10);
      if (n > 255) { return null; }
      out4.push(n);
    }
    return new Uint8Array(out4);
  }

  if (t.indexOf(':') === -1 || !/^[0-9A-Fa-f:.]+$/.test(t)) {
    return null;
  }

  var halves = t.split('::');
  if (halves.length > 2) { return null; }

  function groups(part) {
    if (part === '') { return []; }
    var g = part.split(':');
    var out = [];
    var j;
    for (j = 0; j < g.length; j++) {
      if (j === g.length - 1 && g[j].indexOf('.') !== -1) {
        var tail = parse_ip(g[j]);
        if (tail === null || tail.length !== 4) { return null; }
        out.push((tail[0] << 8) | tail[1], (tail[2] << 8) | tail[3]);
      } else {
        if (!/^[0-9A-Fa-f]{1,4}$/.test(g[j])) { return null; }
        out.push(parseInt(g[j], 16));
      }
    }
    return out;
  }

  var head = groups(halves[0]);
  var tail_groups = halves.length === 2 ? groups(halves[1]) : [];
  if (head === null || tail_groups === null) { return null; }

  var missing = 8 - head.length - tail_groups.length;
  if ((halves.length === 1 && missing !== 0) ||
      (halves.length === 2 && missing < 1)) {
    return null;
  }

  var all = head;
  var z;
  for (z = 0; z < (halves.length === 2 ? missing : 0); z++) { all.push(0); }
  all = all.concat(tail_groups);

  var bytes = new Uint8Array(16);
  for (z = 0; z < 8; z++) {
    bytes[z * 2] = all[z] >> 8;
    bytes[z * 2 + 1] = all[z] & 0xFF;
  }
  return bytes;
}

// A range in CIDR notation - "10.0.0.0/8", "2001:db8::/32" - as a name
// constraint carries it (RFC 5280 4.2.1.10): the address, then a mask of
// `prefix` one bits, 8 or 32 bytes. null when the text is not one.
//
// Strict: the prefix is a decimal with no leading zero, within the family's
// width, and the address has no bits set past it. "10.0.0.1/8" is refused
// rather than read as 10.0.0.0/8 - the constraint would mean the same, but
// the text says something its writer probably did not intend.
function parse_cidr(text) {
  var m = /^([^/]+)\/(0|[1-9]\d{0,2})$/.exec(text);
  if (m === null) { return null; }

  var address = parse_ip(m[1]);
  if (address === null) { return null; }

  var prefix = parseInt(m[2], 10);
  var n = address.length;
  if (prefix > n * 8) { return null; }

  var out = new Uint8Array(n * 2);
  var i;
  for (i = 0; i < n; i++) {
    var bits = Math.max(0, Math.min(8, prefix - i * 8));
    var mask = (0xFF << (8 - bits)) & 0xFF;
    if ((address[i] & ~mask & 0xFF) !== 0) { return null; }
    out[i] = address[i];
    out[n + i] = mask;
  }
  return out;
}

export { parse_ip, parse_cidr };

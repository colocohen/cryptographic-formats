// A strict XML reader, for the XML this library has to look inside: XMLDSig
// and the SAML documents that carry it.
//
// ⚠ IT REPLACES A SET OF REGULAR EXPRESSIONS, AND THE REASON IS ATTACKS.
//
// saml.js used to find elements and attributes with patterns, and every
// pattern was a place where this module and the consumer's XML library could
// disagree about what the document says:
//
//   ID='_x'          single quotes are legal XML. The pattern only knew
//                    double quotes, so a duplicate ID written this way was
//                    invisible and the duplicate-id check passed.
//   ID="&#95;x"      a character reference is the same attribute value. The
//                    pattern compared the raw text, so this was invisible too.
//   <!DOCTYPE ...>   an internal subset can define entities that change what
//                    a value says. Nothing noticed one was there.
//   xmlns:x="other"  a <x:Signature> in a foreign namespace was read as an
//                    XMLDSig signature, because matching was on local names.
//
// Those are the published signature-wrapping and parser-differential
// classes. The answer is to READ the document - tokens, a tree, namespaces -
// and to refuse what a strict reader should refuse rather than skipping it.
//
// ⚠ WHAT IT REFUSES, AND WHY EACH ONE.
//
//   unknown entity references   only a DTD defines them, and expanding a DTD
//                               is where XXE and billion-laughs live. The
//                               five predefined ones and character
//                               references are read; anything else throws.
//   malformed markup            an unclosed tag, a mismatched end tag, an
//                               attribute twice, '<' in a value. A document
//                               two parsers read differently is the attack.
//   unbound prefixes            a name whose namespace cannot be resolved
//                               cannot be compared with one that can.
//   nesting beyond 256          no SAML document is that deep, and a reader
//                               that recurses must stop somewhere.
//
// A DOCTYPE is NOT refused here - it is reported, on `doctype`, and saml.js
// turns it into a problem. Its entities are never expanded either way.
//
// ⚠ THIS IS NOT A GENERAL-PURPOSE XML LIBRARY. No DTD validation, no
// external anything, no streaming. It reads well-formed, namespace-
// well-formed documents completely, and refuses the rest.

import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('xml');

var XML_NS = 'http://www.w3.org/XML/1998/namespace';
var XMLNS_NS = 'http://www.w3.org/2000/xmlns/';

var MAX_DEPTH = 256;

var NAME = /^[A-Za-z_:À-￿][A-Za-z0-9_:.\-·À-￿]*/;

var PREDEFINED = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// Returns { root, doctype, elements } where every element is
//
//   { type: 'element', name, prefix, local, ns, attrs: [...], children,
//     parent, scope, start, start_end, end }
//
// `start` and `end` are offsets into the input string covering the whole
// element, start tag to end tag. `scope` maps prefix -> namespace URI, with
// '' for the default namespace.
function parse(text) {
  if (typeof text !== 'string') {
    fail('bad-input', 'xml.parse takes a string');
  }

  var pos = text.charCodeAt(0) === 0xFEFF ? 1 : 0;
  var root = null;
  var doctype = null;
  var stack = [];
  var elements = [];
  var base_scope = { xml: XML_NS };

  function here() {
    return stack.length === 0 ? null : stack[stack.length - 1];
  }

  function add_child(node) {
    var parent = here();
    if (parent !== null) {
      node.parent = parent;
      parent.children.push(node);
    }
  }

  while (pos < text.length) {
    var lt = text.indexOf('<', pos);

    if (lt === -1) { lt = text.length; }

    if (lt > pos) {
      var raw = text.substring(pos, lt);

      if (stack.length === 0) {
        if (/\S/.test(raw)) {
          fail('text-outside-root', 'text outside the document element at ' +
            pos);
        }
      } else {
        if (raw.indexOf(']]>') !== -1) {
          fail('malformed', ']]> may not appear in text, at ' + pos);
        }
        add_child({ type: 'text', value: decode_text(raw, pos), start: pos,
                    end: lt });
      }
      pos = lt;
      continue;
    }

    if (text.substr(pos, 4) === '<!--') {
      var c_end = text.indexOf('-->', pos + 4);
      if (c_end === -1) { fail('malformed', 'unterminated comment at ' + pos); }
      var body = text.substring(pos + 4, c_end);
      if (body.indexOf('--') !== -1 || body.charAt(body.length - 1) === '-') {
        fail('malformed', '"--" inside a comment at ' + pos);
      }
      if (stack.length > 0) {
        add_child({ type: 'comment', value: normalise_newlines(body),
                    start: pos, end: c_end + 3 });
      }
      pos = c_end + 3;
      continue;
    }

    if (text.substr(pos, 9) === '<![CDATA[') {
      var cd_end = text.indexOf(']]>', pos + 9);
      if (cd_end === -1) { fail('malformed', 'unterminated CDATA at ' + pos); }
      if (stack.length === 0) {
        fail('malformed', 'CDATA outside the document element at ' + pos);
      }
      add_child({ type: 'text', cdata: true,
                  value: normalise_newlines(text.substring(pos + 9, cd_end)),
                  start: pos, end: cd_end + 3 });
      pos = cd_end + 3;
      continue;
    }

    if (text.substr(pos, 9) === '<!DOCTYPE') {
      if (root !== null || doctype !== null) {
        fail('malformed', 'a DOCTYPE must come once, before the root');
      }
      var dt_end = doctype_end(text, pos);
      doctype = { start: pos, end: dt_end,
                  internal_subset: text.substring(pos, dt_end).indexOf('[') !==
                                   -1 };
      pos = dt_end;
      continue;
    }

    if (text.substr(pos, 2) === '<?') {
      var pi_end = text.indexOf('?>', pos + 2);
      if (pi_end === -1) {
        fail('malformed', 'unterminated processing instruction at ' + pos);
      }
      var pi = text.substring(pos + 2, pi_end);
      var target = NAME.exec(pi);
      if (target === null) {
        fail('malformed', 'processing instruction without a target at ' +
          pos);
      }
      if (stack.length > 0) {
        add_child({ type: 'pi', target: target[0],
                    data: pi.substring(target[0].length).replace(/^\s+/, ''),
                    start: pos, end: pi_end + 2 });
      }
      pos = pi_end + 2;
      continue;
    }

    if (text.substr(pos, 2) === '</') {
      var m = NAME.exec(text.substring(pos + 2));
      if (m === null) { fail('malformed', 'end tag without a name at ' + pos); }
      var after = pos + 2 + m[0].length;
      while (after < text.length && is_space(text.charCodeAt(after))) {
        after += 1;
      }
      if (text.charAt(after) !== '>') {
        fail('malformed', 'end tag </' + m[0] + ' is not closed at ' + pos);
      }
      var open = here();
      if (open === null || open.name !== m[0]) {
        fail('mismatched-tag',
          'end tag </' + m[0] + '> at ' + pos + ' closes ' +
          (open === null ? 'nothing' : '<' + open.name + '>'));
      }
      open.end = after + 1;
      stack.pop();
      pos = after + 1;
      continue;
    }

    // A start tag.
    var tag = read_start_tag(text, pos);
    var parent_scope = here() === null ? base_scope : here().scope;
    var el = make_element(tag, parent_scope, pos);

    if (here() === null) {
      if (root !== null) {
        fail('malformed', 'a second document element at ' + pos);
      }
      root = el;
    }

    add_child(el);
    elements.push(el);

    if (tag.self_closing) {
      el.end = tag.end;
    } else {
      stack.push(el);
      if (stack.length > MAX_DEPTH) {
        fail('xml-too-deep', 'nesting deeper than ' + MAX_DEPTH + ' levels');
      }
    }
    pos = tag.end;
  }

  if (stack.length > 0) {
    fail('malformed', '<' + here().name + '> is never closed');
  }
  if (root === null) {
    fail('malformed', 'no document element');
  }

  return { root: root, doctype: doctype, elements: elements };
}

function doctype_end(text, pos) {
  var i = pos + 9;
  var depth = 0;
  var quote = null;

  for (; i < text.length; i++) {
    var c = text.charAt(i);

    if (quote !== null) {
      if (c === quote) { quote = null; }
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '[') { depth += 1; continue; }
    if (c === ']') { depth -= 1; continue; }
    if (c === '>' && depth === 0) { return i + 1; }
  }

  fail('malformed', 'unterminated DOCTYPE at ' + pos);
}

function read_start_tag(text, pos) {
  var m = NAME.exec(text.substring(pos + 1));

  if (m === null) {
    fail('malformed', '"<" not followed by a name at ' + pos);
  }

  var name = m[0];
  var i = pos + 1 + name.length;
  var attrs = [];
  var seen = {};

  while (true) {
    var had_space = false;
    while (i < text.length && is_space(text.charCodeAt(i))) {
      i += 1;
      had_space = true;
    }

    if (i >= text.length) {
      fail('malformed', 'start tag <' + name + ' runs off the end');
    }

    if (text.charAt(i) === '>') {
      return { name: name, attrs: attrs, self_closing: false, end: i + 1 };
    }
    if (text.substr(i, 2) === '/>') {
      return { name: name, attrs: attrs, self_closing: true, end: i + 2 };
    }

    if (!had_space) {
      fail('malformed', 'attributes of <' + name + '> need whitespace ' +
        'between them, at ' + i);
    }

    var an = NAME.exec(text.substring(i));
    if (an === null) {
      fail('malformed', 'bad attribute name in <' + name + '> at ' + i);
    }

    var attr_name = an[0];
    i += attr_name.length;
    while (i < text.length && is_space(text.charCodeAt(i))) { i += 1; }
    if (text.charAt(i) !== '=') {
      fail('malformed', 'attribute ' + attr_name + ' has no value at ' + i);
    }
    i += 1;
    while (i < text.length && is_space(text.charCodeAt(i))) { i += 1; }

    var q = text.charAt(i);
    if (q !== '"' && q !== "'") {
      fail('malformed', 'attribute ' + attr_name + ' is not quoted at ' + i);
    }

    var close = text.indexOf(q, i + 1);
    if (close === -1) {
      fail('malformed', 'attribute ' + attr_name + ' is never closed');
    }

    var raw = text.substring(i + 1, close);

    if (raw.indexOf('<') !== -1) {
      fail('malformed', '"<" inside the value of ' + attr_name);
    }
    if (Object.prototype.hasOwnProperty.call(seen, attr_name)) {
      fail('duplicate-attribute',
        '<' + name + '> has ' + attr_name + ' twice');
    }
    seen[attr_name] = true;

    attrs.push({ name: attr_name, value: decode_attribute(raw, i + 1) });
    i = close + 1;
  }
}

function make_element(tag, parent_scope, pos) {
  var scope = {};
  var k;

  for (k in parent_scope) {
    if (Object.prototype.hasOwnProperty.call(parent_scope, k)) {
      scope[k] = parent_scope[k];
    }
  }

  var declared = {};
  var attrs = [];
  var i;

  for (i = 0; i < tag.attrs.length; i++) {
    var a = tag.attrs[i];

    if (a.name === 'xmlns') {
      scope[''] = a.value;
      declared[''] = a.value;
    } else if (a.name.substring(0, 6) === 'xmlns:') {
      var p = a.name.substring(6);
      if (a.value === '') {
        fail('malformed', 'xmlns:' + p + ' may not be undeclared in XML 1.0');
      }
      if (p === 'xml' && a.value !== XML_NS) {
        fail('malformed', 'the xml prefix is reserved');
      }
      scope[p] = a.value;
      declared[p] = a.value;
    } else {
      attrs.push(a);
    }
  }

  var parts = split_name(tag.name);
  var ns = resolve(scope, parts.prefix, true, tag.name);

  var expanded = {};
  for (i = 0; i < attrs.length; i++) {
    var an = split_name(attrs[i].name);
    attrs[i].prefix = an.prefix;
    attrs[i].local = an.local;
    attrs[i].ns = an.prefix === '' ? '' : resolve(scope, an.prefix, false,
      attrs[i].name);

    // Namespaces in XML 6.3: two attributes with the same expanded name
    // are an error even when their qualified names differ.
    var key = attrs[i].ns + ' ' + an.local;
    if (Object.prototype.hasOwnProperty.call(expanded, key)) {
      fail('duplicate-attribute',
        '<' + tag.name + '> has two attributes named {' + attrs[i].ns + '}' +
        an.local);
    }
    expanded[key] = true;
  }

  return {
    type: 'element',
    name: tag.name,
    prefix: parts.prefix,
    local: parts.local,
    ns: ns,
    attrs: attrs,
    declared: declared,
    scope: scope,
    children: [],
    parent: null,
    start: pos,
    start_end: tag.end,
    end: null
  };
}

function split_name(name) {
  var colon = name.indexOf(':');

  if (colon === -1) {
    return { prefix: '', local: name };
  }
  if (colon === 0 || colon === name.length - 1 ||
      name.indexOf(':', colon + 1) !== -1) {
    fail('malformed', '"' + name + '" is not a valid qualified name');
  }
  return { prefix: name.substring(0, colon), local: name.substring(colon + 1) };
}

function resolve(scope, prefix, is_element, name) {
  if (prefix === '') {
    return is_element && scope[''] !== undefined ? scope[''] : '';
  }
  if (!Object.prototype.hasOwnProperty.call(scope, prefix)) {
    fail('unbound-prefix', 'the prefix of "' + name + '" is not declared');
  }
  return scope[prefix];
}

function is_space(c) {
  return c === 0x20 || c === 0x09 || c === 0x0A || c === 0x0D;
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

// XML 2.11: \r\n and a lone \r both become \n before anything else sees the
// text. Canonicalization works on the parsed form, so this is not optional.
function normalise_newlines(s) {
  return s.replace(/\r\n?/g, '\n');
}

function decode_text(raw, pos) {
  return decode_refs(normalise_newlines(raw), pos, false);
}

// XML 3.3.3 attribute-value normalization, for CDATA attributes - which is
// every attribute when there is no DTD: each LITERAL whitespace character
// becomes a space. A character reference is NOT normalized - &#10; stays a
// newline - so the two steps happen in this order and not the other.
function decode_attribute(raw, pos) {
  return decode_refs(normalise_newlines(raw).replace(/[\t\n]/g, ' '), pos,
    true);
}

function decode_refs(s, pos) {
  if (s.indexOf('&') === -1) {
    return s;
  }

  return s.replace(/&([^;&\s]*);?/g, function (all, body) {
    if (all.charAt(all.length - 1) !== ';') {
      fail('malformed', 'a bare "&" near offset ' + pos);
    }
    if (body.charAt(0) === '#') {
      var cp = body.charAt(1) === 'x'
        ? (/^[0-9A-Fa-f]+$/.test(body.substring(2))
            ? parseInt(body.substring(2), 16) : NaN)
        : (/^[0-9]+$/.test(body.substring(1))
            ? parseInt(body.substring(1), 10) : NaN);

      if (!(cp === 0x9 || cp === 0xA || cp === 0xD ||
            (cp >= 0x20 && cp <= 0xD7FF) || (cp >= 0xE000 && cp <= 0xFFFD) ||
            (cp >= 0x10000 && cp <= 0x10FFFF))) {
        fail('bad-character-reference',
          '&' + body + '; is not a legal XML character, near offset ' + pos);
      }
      return String.fromCodePoint(cp);
    }
    if (Object.prototype.hasOwnProperty.call(PREDEFINED, body)) {
      return PREDEFINED[body];
    }
    fail('unknown-entity',
      '&' + body + '; is not one of the five predefined entities. Only a ' +
      'DTD defines others, and expanding a DTD is not something this reader ' +
      'does - near offset ' + pos);
  });
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

function attribute(el, local, ns) {
  var want = ns === undefined ? '' : ns;
  var i;

  for (i = 0; i < el.attrs.length; i++) {
    if (el.attrs[i].local === local && el.attrs[i].ns === want) {
      return el.attrs[i].value;
    }
  }
  return null;
}

function child_elements(el, ns, local) {
  return el.children.filter(function (c) {
    return c.type === 'element' &&
      (ns === undefined || c.ns === ns) &&
      (local === undefined || c.local === local);
  });
}

function descendants(el, ns, local) {
  var out = [];

  function walk(node) {
    var i;
    for (i = 0; i < node.children.length; i++) {
      var c = node.children[i];
      if (c.type !== 'element') { continue; }
      if ((ns === undefined || c.ns === ns) &&
          (local === undefined || c.local === local)) {
        out.push(c);
      }
      walk(c);
    }
  }

  walk(el);
  return out;
}

function text_content(el) {
  var out = '';
  var i;

  for (i = 0; i < el.children.length; i++) {
    var c = el.children[i];
    if (c.type === 'text') {
      out += c.value;
    } else if (c.type === 'element') {
      out += text_content(c);
    }
  }
  return out;
}

function is_inside(el, ancestor) {
  var p = el;
  while (p !== null) {
    if (p === ancestor) { return true; }
    p = p.parent;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Canonicalization, of ONE SUBTREE
// ---------------------------------------------------------------------------

// ⚠ FOR ds:SignedInfo, AND THE REASON IT IS HERE AT ALL.
//
// The signature value covers SignedInfo AFTER canonicalization, and the
// first version of saml.js handed over the raw slice as "the signed bytes".
// For the commonest real shape - signxml, xmlsec, Shibboleth - that slice
// verifies against nothing: SignedInfo inherits xmlns:ds from ds:Signature,
// and exclusive c14n puts the declaration ON SignedInfo; the file writes
// <ds:Foo/> and c14n writes <ds:Foo></ds:Foo>. A field promising the signed
// bytes that never verified is worse than no field.
//
// Canonicalizing a whole document element under an arbitrary transform
// chain is a program the document chooses; canonicalizing one subtree under
// one of the two c14n algorithms is a function. This is the function.
//
//   options.exclusive          Exclusive XML Canonicalization 1.0
//   options.inclusive_prefixes the PrefixList, for exclusive ('#default'
//                              for the default namespace)
//   options.with_comments      keep comments
//
// Without `exclusive` it is Canonical XML 1.0, inclusive: every namespace in
// scope at the apex is rendered there, and inherited xml:* attributes too.
function canonicalize(el, options) {
  var opts = options || {};
  var out = [];

  render(el, opts, true, {}, out);
  return out.join('');
}

function render(el, opts, apex, rendered, out) {
  var ns_out = [];
  var now = {};
  var k;

  for (k in rendered) {
    if (Object.prototype.hasOwnProperty.call(rendered, k)) {
      now[k] = rendered[k];
    }
  }

  var wanted = {};

  if (opts.exclusive) {
    // Visibly utilized: the element's own prefix, and its attributes'.
    wanted[el.prefix] = true;
    var i;
    for (i = 0; i < el.attrs.length; i++) {
      if (el.attrs[i].prefix !== '' && el.attrs[i].prefix !== 'xml') {
        wanted[el.attrs[i].prefix] = true;
      }
    }
    var list = opts.inclusive_prefixes || [];
    for (i = 0; i < list.length; i++) {
      var pfx = list[i] === '#default' ? '' : list[i];
      if (Object.prototype.hasOwnProperty.call(el.scope, pfx)) {
        wanted[pfx] = true;
      }
    }
  } else {
    for (k in el.scope) {
      if (Object.prototype.hasOwnProperty.call(el.scope, k) && k !== 'xml') {
        wanted[k] = true;
      }
    }
  }

  for (k in wanted) {
    if (!Object.prototype.hasOwnProperty.call(wanted, k)) { continue; }

    var uri = el.scope[k] === undefined ? '' : el.scope[k];
    var before = now[k] === undefined ? '' : now[k];

    if (k === '') {
      // The default namespace: emitted when it differs from what the
      // nearest output ancestor rendered, including xmlns="" to undo one.
      if (uri !== before) {
        ns_out.push({ prefix: '', uri: uri });
        now[''] = uri;
      }
    } else if (uri !== '' && now[k] !== uri) {
      ns_out.push({ prefix: k, uri: uri });
      now[k] = uri;
    }
  }

  ns_out.sort(function (a, b) {
    return a.prefix < b.prefix ? -1 : a.prefix > b.prefix ? 1 : 0;
  });

  var attrs = el.attrs.slice();

  // Canonical XML 1.0 2.4: the apex of a subtree carries the xml:* attributes
  // it inherits, because the subtree has lost the ancestors that held them.
  if (apex && !opts.exclusive) {
    var have = {};
    var j;
    for (j = 0; j < attrs.length; j++) {
      if (attrs[j].ns === XML_NS) { have[attrs[j].local] = true; }
    }
    var p = el.parent;
    while (p !== null) {
      for (j = 0; j < p.attrs.length; j++) {
        var a = p.attrs[j];
        if (a.ns === XML_NS && !have[a.local]) {
          have[a.local] = true;
          attrs.push(a);
        }
      }
      p = p.parent;
    }
  }

  attrs.sort(function (a, b) {
    if (a.ns !== b.ns) { return a.ns < b.ns ? -1 : 1; }
    return a.local < b.local ? -1 : a.local > b.local ? 1 : 0;
  });

  var s = '<' + el.name;
  var n;

  for (n = 0; n < ns_out.length; n++) {
    s += ns_out[n].prefix === ''
      ? ' xmlns="' + escape_attr(ns_out[n].uri) + '"'
      : ' xmlns:' + ns_out[n].prefix + '="' + escape_attr(ns_out[n].uri) + '"';
  }
  for (n = 0; n < attrs.length; n++) {
    s += ' ' + attrs[n].name + '="' + escape_attr(attrs[n].value) + '"';
  }
  out.push(s + '>');

  for (n = 0; n < el.children.length; n++) {
    var c = el.children[n];

    if (c.type === 'element') {
      render(c, opts, false, now, out);
    } else if (c.type === 'text') {
      out.push(escape_text(c.value));
    } else if (c.type === 'comment') {
      if (opts.with_comments) {
        out.push('<!--' + c.value + '-->');
      }
    } else if (c.type === 'pi') {
      out.push('<?' + c.target + (c.data === '' ? '' : ' ' + c.data) + '?>');
    }
  }

  out.push('</' + el.name + '>');
}

function escape_text(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
}

function escape_attr(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/"/g, '&quot;').replace(/\t/g, '&#x9;')
    .replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');
}

export {
  parse,
  attribute,
  child_elements,
  descendants,
  text_content,
  is_inside,
  canonicalize,
  XML_NS,
  XMLNS_NS
};

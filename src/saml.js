// SAML and XMLDSig - the parts that are containers, and the one signed range
// that can be computed.
//
// ⚠ WHAT THIS MODULE CANONICALIZES, AND WHAT IT DELIBERATELY DOES NOT.
//
// Every other signed format here answers "what was signed?" by pointing at a
// byte range that exists in the file:
//
//   X.509      tbs_bytes         a slice
//   CMS        signedAttrs       a slice with one tag substituted
//   JWS        header.payload    two base64 strings and a dot
//
// XMLDSig signs two things, and they differ in kind:
//
//   ds:SignedInfo        canonicalized under the method it names - a
//                        FUNCTION of the document. Computed here, by
//                        xml_reader.js, and handed over as
//                        bytes: verify the SignatureValue over
//                        these.
//   the referenced       produced by running the Reference's TRANSFORMS - a
//   element              program the document chooses. NOT computed here:
//                        the caller's XML library does it, and compares the
//                        result with digest_value.
//
// The line is drawn there on purpose. The referenced element is what the
// consumer will READ, and digesting it with a second XML reader beside the
// consumer's is the parser differential that signature-wrapping attacks
// live in. SignedInfo is read only by this module.
//
// (The first version returned the raw SignedInfo slice as the signed bytes.
// For the commonest real shape it verified against nothing - see
// xml_reader.js.)
//
// The parts that ARE containers:
//
//   <ds:X509Certificate>   base64 DER. A certificate, read by x509.js.
//   <ds:SignatureValue>    base64.
//   <ds:DigestValue>       base64.
//   Algorithm="...URI"     mapped to this library's own algorithm names.
//
// ⚠ AND IT CHECKS THE STRUCTURE, WHICH IS WHERE THE ATTACKS ARE.
//
// XML Signature Wrapping works because "what was signed" and "what gets
// read" are two separate resolutions, and a document can make them differ.
// Microsoft, SAP and IBM implementations all fell to it. Every check in
// `problems` is answerable from the structure alone, before any arithmetic -
// which is exactly why they are worth doing here. The document is READ -
// tokens, a tree, namespaces - by xml_reader.js, which refuses what a strict
// reader should refuse rather than skipping it.

import * as X509 from './x509.js';
import * as BASE from './base.js';

import * as XML from './xml_reader.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes } from './commons/bytes.js';
import { latin1, decode_utf8 } from './commons/decode_text.js';
import { encode_utf8 } from './commons/encode_text.js';

var fail = make_fail_here('saml');

// ---------------------------------------------------------------------------
// The URI registries
// ---------------------------------------------------------------------------

// ⚠ MAPPED TO THIS LIBRARY'S OWN NAMES, not left as URIs.
//
// A caller comparing URI strings has to know that
// `...xmldsig#rsa-sha1` and `1.2.840.113549.1.1.5` are the same thing. They
// already have a table for the second - this is the first, pointing at it.
var SIGNATURE_ALGORITHMS = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1':
    { name: 'sha1WithRSA', digest: 'sha1', weak: 'SHA-1' },
  'http://www.w3.org/2000/09/xmldsig#dsa-sha1':
    { name: 'dsaWithSHA1', digest: 'sha1', weak: 'SHA-1' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256':
    { name: 'sha256WithRSA', digest: 'sha256', weak: null },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384':
    { name: 'sha384WithRSA', digest: 'sha384', weak: null },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512':
    { name: 'sha512WithRSA', digest: 'sha512', weak: null },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1':
    { name: 'ecdsaWithSHA1', digest: 'sha1', weak: 'SHA-1' },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256':
    { name: 'ecdsaWithSHA256', digest: 'sha256', weak: null },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384':
    { name: 'ecdsaWithSHA384', digest: 'sha384', weak: null },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512':
    { name: 'ecdsaWithSHA512', digest: 'sha512', weak: null },
  'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1':
    { name: 'rsassaPss', digest: 'sha256', weak: null }
};

var DIGEST_ALGORITHMS = {
  'http://www.w3.org/2000/09/xmldsig#sha1':      { name: 'sha1',   weak: 'SHA-1' },
  'http://www.w3.org/2001/04/xmlenc#sha256':     { name: 'sha256', weak: null },
  'http://www.w3.org/2001/04/xmldsig-more#sha384': { name: 'sha384', weak: null },
  'http://www.w3.org/2001/04/xmlenc#sha512':     { name: 'sha512', weak: null }
};

var CANONICALIZATION = {
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
    { name: 'inclusive-c14n', comments: false },
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
    { name: 'inclusive-c14n', comments: true },
  'http://www.w3.org/2001/10/xml-exc-c14n#':
    { name: 'exclusive-c14n', comments: false },
  'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
    { name: 'exclusive-c14n', comments: true },
  'http://www.w3.org/2006/12/xml-c14n11':
    { name: 'c14n11', comments: false }
};

// ⚠ THE TRANSFORM ALLOWLIST, AND WHY IT IS AN ALLOWLIST.
//
// A Reference may name any transform, and two of the ones the specification
// defines are arbitrary code:
//
//   xslt    runs an XSLT program written in the document
//   xpath   runs an XPath expression that selects what gets signed
//
// Both are chosen by whoever wrote the document, which in a SAML response is
// whoever sent it. A verifier that runs them is running the attacker's code
// to decide what the attacker signed.
//
// So anything outside this list is a `problem`, not an unknown.
var SAFE_TRANSFORMS = {
  'http://www.w3.org/2000/09/xmldsig#enveloped-signature':
    'enveloped-signature',
  'http://www.w3.org/2001/10/xml-exc-c14n#': 'exclusive-c14n',
  'http://www.w3.org/2001/10/xml-exc-c14n#WithComments': 'exclusive-c14n',
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315': 'inclusive-c14n',
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
    'inclusive-c14n',
  'http://www.w3.org/2006/12/xml-c14n11': 'c14n11',
  'http://www.w3.org/2000/09/xmldsig#base64': 'base64'
};

var UNSAFE_TRANSFORMS = {
  'http://www.w3.org/TR/1999/REC-xslt-19991116':
    'runs an arbitrary XSLT program chosen by whoever wrote the document',
  'http://www.w3.org/TR/1999/REC-xpath-19991116':
    'runs an XPath expression that selects what gets signed, chosen by ' +
    'whoever wrote the document',
  'http://www.w3.org/2002/06/xmldsig-filter2':
    'XPath Filter 2.0, which selects what gets signed by expression'
};

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

var DSIG = 'http://www.w3.org/2000/09/xmldsig#';
var EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

// The attribute names that carry an element's ID, across the SAML versions.
//
// ⚠ ID, Id and id are three different names in XML, and SAML 1.1 used
// AssertionID, ResponseID and RequestID instead. A scanner that knew one
// missed duplicates spelled as another. xml:id is the generic one.
var ID_ATTRIBUTES = ['ID', 'Id', 'id', 'AssertionID', 'ResponseID',
                     'RequestID'];

// ⚠ A BAD VALUE IS A PROBLEM, NOT AN EXCEPTION.
//
// Throwing here would stop the scan at the first malformed field and hide
// every structural problem after it - which in a hostile document is exactly
// backwards: the attacker would only have to corrupt one base64 blob to stop
// this module reporting the wrapping.
//
// So a value that will not decode is recorded and the scan continues. The
// caller sees all of it. (Malformed MARKUP is different: a document the
// reader cannot read is refused outright - see xml_reader.js.)
function decode_b64(value, what, problems) {
  if (value === null) {
    return null;
  }

  try {
    return BASE.decode('base64', value.replace(/\s/g, ''));
  } catch (e) {
    problems.push({
      code: 'bad-base64',
      detail: what + ' is not valid base64'
    });
    return null;
  }
}

function dsig_child(el, local) {
  var found = el === null ? [] : XML.child_elements(el, DSIG, local);
  return found.length === 0 ? null : found[0];
}

function dsig_text(el, local) {
  var c = dsig_child(el, local);
  return c === null ? null : XML.text_content(c);
}

function dsig_algorithm(el, local) {
  var c = dsig_child(el, local);
  return c === null ? null : XML.attribute(c, 'Algorithm');
}

// The text, decoded to bytes. Bytes arrive as UTF-8 - XML's default, and the
// only encoding SAML bindings use - and a document declaring anything else
// is refused rather than misread.
function input_text(input) {
  if (typeof input === 'string') {
    return input;
  }

  var bytes = to_bytes(input);
  var head = latin1(bytes.subarray(0, Math.min(bytes.length, 200)));
  var decl = /^﻿?<\?xml[^>]*encoding\s*=\s*["']([^"']+)["']/.exec(
    head.replace(/^\xEF\xBB\xBF/, ''));

  if (decl !== null && !/^utf-?8$/i.test(decl[1])) {
    fail('unsupported-encoding',
      'the document declares encoding "' + decl[1] + '"; only UTF-8 is read');
  }

  return decode_utf8(bytes, function (pos, code, detail) {
    fail(code, detail);
  }, 0);
}

// `options.understood` is not a thing here; `options` is reserved for the
// same reason everywhere else - flags that relax nothing.
function verification_plan(input) {
  var text = input_text(input);
  var doc = XML.parse(text);
  var problems = [];

  // ⚠ A DOCTYPE IS A PROBLEM. SAML 2.0 bindings forbid one (saml-bindings
  // 3.4.4.1 and 3.5.4), and its internal subset can define entities that
  // change what a value says. Entities are never expanded here - an unknown
  // one throws - but the consumer's XML library may expand them, and then
  // the two of us are reading different documents.
  if (doc.doctype !== null) {
    problems.push({
      code: 'doctype',
      detail: 'the document has a DOCTYPE' +
              (doc.doctype.internal_subset ? ' with an internal subset' : '') +
              '. SAML forbids it, and an XML library that honours it may ' +
              'read a different document from the one checked here.'
    });
  }

  // ⚠ BY NAMESPACE, NOT BY NAME. <x:Signature xmlns:x="urn:other"> is not
  // an XMLDSig signature, and the regular-expression version thought it was.
  var signatures = XML.descendants({ children: [doc.root] }, DSIG,
    'Signature');

  if (signatures.length === 0) {
    fail('no-signature',
      'this document carries no ds:Signature element');
  }

  // ⚠ A SECOND SIGNATURE IS NOT A BONUS.
  //
  // A document with two signatures has two answers to "what is protected",
  // and a verifier that checks the first and reads the whole document has
  // checked the wrong one. Reported rather than silently ignored.
  if (signatures.length > 1) {
    problems.push({
      code: 'multiple-signatures',
      detail: 'this document carries ' + signatures.length + ' ds:Signature ' +
              'elements. Each protects a different part, and reading the ' +
              'document as a whole after checking one of them checks ' +
              'nothing about the rest.'
    });
  }

  var sig = signatures[0];
  var signed_info = dsig_child(sig, 'SignedInfo');

  if (signed_info === null) {
    fail('no-signed-info', 'the ds:Signature has no ds:SignedInfo');
  }

  // --- the algorithms -----------------------------------------------------

  var c14n_uri = dsig_algorithm(signed_info, 'CanonicalizationMethod');
  var sig_uri = dsig_algorithm(signed_info, 'SignatureMethod');

  var c14n = c14n_uri === null ? null : CANONICALIZATION[c14n_uri];
  var alg = sig_uri === null ? null : SIGNATURE_ALGORITHMS[sig_uri];

  if (c14n_uri === null) {
    problems.push({ code: 'no-canonicalization',
      detail: 'the ds:SignedInfo names no canonicalization method' });
  } else if (c14n === undefined) {
    problems.push({
      code: 'unknown-canonicalization',
      detail: 'the canonicalization method is "' + c14n_uri +
              '", which this module does not recognise. Producing the ' +
              'signed bytes would be guessing.'
    });
  }

  if (sig_uri === null) {
    problems.push({ code: 'no-signature-method',
      detail: 'the ds:SignedInfo names no signature algorithm' });
  } else if (alg === undefined) {
    problems.push({
      code: 'unknown-signature-algorithm',
      detail: 'the signature algorithm is "' + sig_uri + '"'
    });
  } else if (alg.weak !== null) {
    problems.push({
      code: 'weak-signature-algorithm',
      detail: alg.name + ' uses ' + alg.weak +
              '. Collisions have been public since 2017, and a collision ' +
              'is enough to move a signature onto a different document.'
    });
  }

  // --- the references -----------------------------------------------------

  var references = XML.child_elements(signed_info, DSIG, 'Reference');

  if (references.length === 0) {
    problems.push({
      code: 'no-reference',
      detail: 'the ds:SignedInfo names nothing to protect'
    });
  }

  // ⚠ SEVERAL REFERENCES MEANS SEVERAL PROTECTED PARTS, and a verifier that
  // checks one has checked one.
  if (references.length > 1) {
    problems.push({
      code: 'multiple-references',
      detail: 'the ds:SignedInfo names ' + references.length + ' references. ' +
              'Every one of them has to be checked, and a verifier that ' +
              'checks the first has verified a fraction of the document.'
    });
  }

  var ref = references.length > 0 ? references[0] : null;
  var uri = ref === null ? null : XML.attribute(ref, 'URI');
  var element_id = null;

  if (ref !== null && uri === null) {
    // An absent URI means the application knows what is signed - which in
    // SAML, where the document is the only context, means nothing does.
    problems.push({
      code: 'no-reference-uri',
      detail: 'the ds:Reference has no URI, so the document does not say ' +
              'what it protects'
    });
  } else if (uri === '') {
    // ⚠ An empty URI means "the whole document", which is legal and is the
    // one case where wrapping cannot apply - there is nothing outside it.
    element_id = null;
  } else if (uri !== null && uri.charAt(0) !== '#') {
    problems.push({
      code: 'external-reference',
      detail: 'the Reference URI is "' + uri + '", which points OUTSIDE ' +
              'this document. Verifying it means fetching a resource an ' +
              'attacker named.'
    });
  } else if (uri !== null) {
    element_id = uri.substring(1);
    if (/^xpointer\(/.test(element_id)) {
      problems.push({
        code: 'xpointer-reference',
        detail: 'the Reference URI is an XPointer expression, which selects ' +
                'by program rather than by ID'
      });
    }
  }

  var digest_uri = ref === null ? null : dsig_algorithm(ref, 'DigestMethod');
  var digest = digest_uri === null ? null : DIGEST_ALGORITHMS[digest_uri];

  if (digest_uri !== null && digest === undefined) {
    problems.push({ code: 'unknown-digest-algorithm',
      detail: 'the reference digest is "' + digest_uri + '"' });
  }
  if (digest !== undefined && digest !== null && digest.weak !== null) {
    problems.push({
      code: 'weak-digest-algorithm',
      detail: 'the reference digest is ' + digest.weak
    });
  }

  // --- the transforms -----------------------------------------------------

  var transforms_el = ref === null ? null : dsig_child(ref, 'Transforms');
  var transform_els = transforms_el === null ? []
    : XML.child_elements(transforms_el, DSIG, 'Transform');
  var transforms = [];
  var ref_prefixes = [];
  var i;

  for (i = 0; i < transform_els.length; i++) {
    var t = XML.attribute(transform_els[i], 'Algorithm');

    if (t === null) {
      problems.push({ code: 'unknown-transform',
        detail: 'a ds:Transform has no Algorithm' });
      transforms.push({ uri: null, name: null, safe: false });
      continue;
    }

    if (UNSAFE_TRANSFORMS[t] !== undefined) {
      problems.push({
        code: 'unsafe-transform',
        detail: 'the Reference names transform "' + t + '", which ' +
                UNSAFE_TRANSFORMS[t] + '. A verifier that runs it is ' +
                'running the sender\'s code to decide what the sender signed.'
      });
      transforms.push({ uri: t, name: null, safe: false });
      continue;
    }

    if (SAFE_TRANSFORMS[t] === undefined) {
      problems.push({
        code: 'unknown-transform',
        detail: 'the Reference names transform "' + t + '", which is not ' +
                'on the allowlist. Anything not recognised is refused ' +
                'rather than attempted.'
      });
      transforms.push({ uri: t, name: null, safe: false });
      continue;
    }

    var list = prefix_list(transform_els[i]);
    if (list.length > 0) { ref_prefixes = list; }
    transforms.push({ uri: t, name: SAFE_TRANSFORMS[t], safe: true,
                      inclusive_prefixes: list });
  }

  // --- the structure ------------------------------------------------------

  var ids = scan_ids(doc);
  check_duplicate_ids(ids, problems);
  check_wrapping(doc, sig, element_id, ids, problems);

  // --- the values ---------------------------------------------------------

  var sig_value = decode_b64(dsig_text(sig, 'SignatureValue'),
    'ds:SignatureValue', problems);
  var digest_value = ref === null ? null
    : decode_b64(dsig_text(ref, 'DigestValue'), 'ds:DigestValue', problems);

  if (sig_value === null) {
    problems.push({ code: 'no-signature-value',
      detail: 'the ds:Signature carries no ds:SignatureValue' });
  }

  if (digest_value !== null && digest !== undefined && digest !== null) {
    var expected = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 }[
      digest.name];

    if (expected !== undefined && digest_value.length !== expected) {
      problems.push({
        code: 'bad-digest-length',
        detail: digest.name + ' produces ' + expected + ' bytes and the ' +
                'DigestValue holds ' + digest_value.length
      });
    }
  }

  var certificates = read_certificates(sig, problems);

  // ⚠ THE SIGNED BYTES OF ds:SignedInfo - CANONICALIZED, NOT SLICED.
  //
  // SignedInfo is signed after ITS OWN canonicalization, with no other
  // transforms, so these bytes are a function of the document and the
  // c14n method - which xml_reader.js computes. See the note there for why
  // the raw slice the first version returned did not verify.
  var signed_info_text = null;

  if (c14n !== undefined && c14n !== null && c14n.name !== 'c14n11') {
    signed_info_text = XML.canonicalize(signed_info, {
      exclusive:          c14n.name === 'exclusive-c14n',
      with_comments:      c14n.comments,
      inclusive_prefixes: prefix_list(dsig_child(signed_info,
        'CanonicalizationMethod'))
    });
  } else if (c14n !== undefined && c14n !== null) {
    problems.push({
      code: 'unsupported-canonicalization',
      detail: 'ds:SignedInfo uses Canonical XML 1.1, which this module ' +
              'does not compute; the signed bytes are not available'
    });
  }

  return {
    // ⚠ AN EMPTY `problems` IS NOT A PASS.
    //
    // It means none of the checks this module knows how to make found
    // anything. The signature still has to be verified over
    // bytes, and the referenced element's digest still has to
    // be computed by the caller's XML library and compared.
    problems: problems,

    element_id:       element_id,
    reference_uri:    uri,
    whole_document:   uri === '',
    remove_signature: has_enveloped(transforms),
    canonicalization: c14n === undefined || c14n === null ? null : c14n.name,
    with_comments:    c14n === undefined || c14n === null
      ? null : c14n.comments,
    // The PrefixList of the REFERENCE's exclusive c14n - for the caller's XML
    // library. SignedInfo's own list is applied here and not reported.
    inclusive_prefixes: ref_prefixes,
    transforms:       transforms,

    digest:        digest === undefined || digest === null
      ? null : digest.name,
    digest_value:  digest_value,
    algorithm:     alg === undefined || alg === null ? null : alg.name,
    algorithm_uri: sig_uri,
    signature:     sig_value,

    // What the SignatureValue covers. Verify the signature over THESE.
    bytes: signed_info_text === null
      ? null : new Uint8Array(encode_utf8(signed_info_text, fail)),
    signed_info_text:  signed_info_text,
    // The element as it appears in the file, for display and debugging -
    // NOT the signed bytes.
    signed_info_raw:   text.substring(signed_info.start, signed_info.end),

    certificates: certificates,
    ids:          ids.map(function (e) { return e.id; }),
    doctype:      doc.doctype !== null
  };
}

function prefix_list(el) {
  if (el === null) { return []; }

  var inc = XML.child_elements(el, EXC_C14N, 'InclusiveNamespaces');

  if (inc.length === 0) { return []; }

  var list = XML.attribute(inc[0], 'PrefixList');
  return list === null ? [] : list.split(/\s+/).filter(function (p) {
    return p !== '';
  });
}

function has_enveloped(transforms) {
  var i;
  for (i = 0; i < transforms.length; i++) {
    if (transforms[i].name === 'enveloped-signature') {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// The structural checks
// ---------------------------------------------------------------------------

// Every element carrying an ID, by any of the names IDs go by.
function scan_ids(doc) {
  var out = [];
  var i, j;

  for (i = 0; i < doc.elements.length; i++) {
    var el = doc.elements[i];

    for (j = 0; j < el.attrs.length; j++) {
      var a = el.attrs[j];
      var is_id = (a.ns === '' && ID_ATTRIBUTES.indexOf(a.local) !== -1) ||
                  (a.ns === XML.XML_NS && a.local === 'id');

      if (is_id) {
        out.push({ element: el, id: a.value, at: el.start });
      }
    }
  }

  return out;
}

function check_duplicate_ids(ids, problems) {
  // ⚠ A REFERENCE URI NAMES ONE ELEMENT AND A CONSUMER MAY RESOLVE ANOTHER.
  //
  // Two elements with the same ID make the document ambiguous, and the
  // ambiguity is resolved differently by different XML libraries - which is
  // precisely the gap a wrapping attack lives in.
  //
  // The values compared are DECODED - ID='_a' and ID="&#95;a" are the same
  // ID, and the regular-expression version saw two different strings.
  var counts = {};
  var order = [];
  var i;

  for (i = 0; i < ids.length; i++) {
    var key = '$' + ids[i].id;
    if (counts[key] === undefined) {
      counts[key] = 0;
      order.push(ids[i].id);
    }
    counts[key] += 1;
  }

  for (i = 0; i < order.length; i++) {
    if (counts['$' + order[i]] > 1) {
      problems.push({
        code: 'duplicate-id',
        detail: 'ID "' + order[i] + '" appears on ' + counts['$' + order[i]] +
                ' elements. A Reference URI names one of them, and which ' +
                'one a consumer resolves depends on its XML library.'
      });
    }
  }
}

// ⚠ THE WRAPPING CHECKS.
//
// A ds:Signature that protects element X should sit inside X. When it sits
// inside Y and names X, the thing it protects is not the thing that contains
// it - so a consumer reading Y gets unsigned content next to a valid
// signature.
//
// And the twin: an element of the SAME KIND as the protected one - another
// saml:Assertion, say - that is not inside it. A consumer asking for "the
// assertion" may get the unsigned one. This catches the wrapping variants
// that give the injected element a fresh ID, which the duplicate check
// cannot see.
function check_wrapping(doc, sig, element_id, ids, problems) {
  if (element_id === null) {
    return;
  }

  var target = null;
  var i;

  for (i = 0; i < ids.length; i++) {
    if (ids[i].id === element_id) {
      target = ids[i].element;
      break;
    }
  }

  if (target === null) {
    problems.push({
      code: 'reference-not-found',
      detail: 'the Reference names "#' + element_id + '" and no element in ' +
              'this document carries that ID'
    });
    return;
  }

  if (!XML.is_inside(sig, target)) {
    problems.push({
      code: 'signature-outside-what-it-covers',
      detail: 'this ds:Signature protects the element with ID "' +
              element_id + '" and does not sit inside it. A consumer ' +
              'reading the enclosing element gets content the signature ' +
              'says nothing about. This is XML Signature Wrapping.'
    });
  }

  for (i = 0; i < doc.elements.length; i++) {
    var el = doc.elements[i];

    if (el === target || el.ns !== target.ns || el.local !== target.local) {
      continue;
    }
    // Inside the target is covered by the signature; an ANCESTOR of the
    // same kind (a Response inside a Response) is its own problem below.
    if (XML.is_inside(el, target) || XML.is_inside(target, el)) {
      continue;
    }

    problems.push({
      code: 'unsigned-twin',
      detail: 'another <' + el.name + '> sits outside the signed one. A ' +
              'consumer asking for "the ' + el.local + '" may be handed ' +
              'the unsigned copy.'
    });
    break;
  }
}

// ---------------------------------------------------------------------------
// The certificates
// ---------------------------------------------------------------------------

function read_certificates(sig, problems) {
  var key_info = dsig_child(sig, 'KeyInfo');
  var nodes = key_info === null ? []
    : XML.descendants(key_info, DSIG, 'X509Certificate');
  var out = [];
  var i;

  for (i = 0; i < nodes.length; i++) {
    var der;

    try {
      der = BASE.decode('base64',
        XML.text_content(nodes[i]).replace(/\s/g, ''));
    } catch (e) {
      problems.push({
        code: 'bad-certificate-base64',
        detail: 'a ds:X509Certificate is not valid base64'
      });
      continue;
    }

    try {
      // ⚠ THE SAME CERTIFICATE OBJECT AS FROM A PEM FILE.
      //
      // A certificate inside a SAML assertion is a certificate. Reading it
      // with x509.js rather than reporting bytes is the point of this
      // module living in this library.
      out.push(X509.from_der(der));
    } catch (e) {
      problems.push({
        code: 'bad-certificate',
        detail: 'a ds:X509Certificate did not parse: ' + e.code
      });
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

// What to build, given what the caller wants to sign.
//
// Returns the URIs rather than taking them: a caller who had to write
// `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` by hand would write it
// wrong once and produce signatures nothing verifies.
function signing_plan(options) {
  var opts = options || {};
  var algorithm = opts.algorithm || 'sha256WithRSA';
  var c14n_name = opts.canonicalization || 'exclusive-c14n';

  var alg_uri = null;
  var uri;

  for (uri in SIGNATURE_ALGORITHMS) {
    if (Object.prototype.hasOwnProperty.call(SIGNATURE_ALGORITHMS, uri) &&
        SIGNATURE_ALGORITHMS[uri].name === algorithm) {
      alg_uri = uri;
      break;
    }
  }

  if (alg_uri === null) {
    fail('unsupported-algorithm',
      'no XMLDSig URI for "' + algorithm + '"');
  }

  var spec = SIGNATURE_ALGORITHMS[alg_uri];

  if (spec.weak !== null) {
    fail('weak-algorithm',
      algorithm + ' uses ' + spec.weak + ', and this module will not ' +
      'produce a new signature with it. Reading one is a different ' +
      'question from writing one.');
  }

  var digest_name = opts.digest || spec.digest;
  var digest_uri = null;

  for (uri in DIGEST_ALGORITHMS) {
    if (Object.prototype.hasOwnProperty.call(DIGEST_ALGORITHMS, uri) &&
        DIGEST_ALGORITHMS[uri].name === digest_name) {
      digest_uri = uri;
      break;
    }
  }

  if (digest_uri === null) {
    fail('unsupported-digest', 'no XMLDSig URI for digest "' +
      digest_name + '"');
  }

  var c14n_uri = null;

  for (uri in CANONICALIZATION) {
    if (Object.prototype.hasOwnProperty.call(CANONICALIZATION, uri) &&
        CANONICALIZATION[uri].name === c14n_name &&
        CANONICALIZATION[uri].comments === false) {
      c14n_uri = uri;
      break;
    }
  }

  if (c14n_uri === null) {
    fail('unsupported-canonicalization',
      'no XMLDSig URI for "' + c14n_name + '"');
  }

  // ⚠ EXCLUSIVE ONLY, FOR WRITING.
  //
  // signed_info() emits SignedInfo carrying exactly one namespace
  // declaration. Under INCLUSIVE c14n, SignedInfo's canonical form includes
  // every namespace in scope where the signature is finally inserted -
  // samlp, saml, whatever the document declares - so the bytes signed here
  // would not be the bytes a verifier computes. Exclusive c14n exists for
  // exactly this: a signature that survives being moved.
  if (c14n_name !== 'exclusive-c14n') {
    fail('unsupported-canonicalization',
      'signatures are written with exclusive-c14n only; ' + c14n_name +
      ' makes the signed bytes depend on where the signature is inserted');
  }

  if (opts.element_id === undefined || opts.element_id === null) {
    fail('no-element-id',
      'signing_plan needs the ID of the element to protect');
  }

  return {
    element_id:       opts.element_id,
    reference_uri:    '#' + opts.element_id,
    algorithm:        algorithm,
    algorithm_uri:    alg_uri,
    digest:           digest_name,
    digest_uri:       digest_uri,
    canonicalization: c14n_name,
    c14n_uri:         c14n_uri,
    // The enveloped-signature transform first, then the canonicalization -
    // the order is part of the specification and getting it wrong produces
    // a signature that verifies nowhere.
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      c14n_uri
    ],
    certificate: opts.certificate || null,
    prefix: opts.prefix === undefined ? 'ds' : opts.prefix
  };
}

// The element prefix and the namespace declaration both writers use - the
// default namespace when the plan's prefix is empty.
function dsig_namespace(plan) {
  var p = plan.prefix === null || plan.prefix === '' ? '' : plan.prefix + ':';
  return {
    p: p,
    xmlns: p === ''
      ? ' xmlns="' + DSIG + '"'
      : ' xmlns:' + plan.prefix + '="' + DSIG + '"'
  };
}

// Builds ds:SignedInfo and returns BOTH the text and the bytes.
//
// ⚠ THE BYTES ARE THE POINT.
//
// These are what gets signed. Returning only a string would leave the caller
// to serialize it, and any serializer that differs by one space produces a
// signature that verifies against nothing - the same reason every read path
// in this library returns the original bytes rather than a re-encoding.
function signed_info(plan, digest_value) {
  if (!(digest_value instanceof Uint8Array)) {
    fail('bad-digest-value',
      'signed_info takes the digest of the canonicalized element as bytes');
  }

  var ns = dsig_namespace(plan);
  var p = ns.p;
  var xmlns = ns.xmlns;

  var transforms = plan.transforms.map(function (t) {
    return '<' + p + 'Transform Algorithm="' + t + '"></' + p + 'Transform>';
  }).join('');

  var text =
    '<' + p + 'SignedInfo' + xmlns + '>' +
      '<' + p + 'CanonicalizationMethod Algorithm="' + plan.c14n_uri +
        '"></' + p + 'CanonicalizationMethod>' +
      '<' + p + 'SignatureMethod Algorithm="' + plan.algorithm_uri +
        '"></' + p + 'SignatureMethod>' +
      '<' + p + 'Reference URI="' + plan.reference_uri + '">' +
        '<' + p + 'Transforms>' + transforms + '</' + p + 'Transforms>' +
        '<' + p + 'DigestMethod Algorithm="' + plan.digest_uri +
          '"></' + p + 'DigestMethod>' +
        '<' + p + 'DigestValue>' + BASE.encode('base64', digest_value) +
          '</' + p + 'DigestValue>' +
      '</' + p + 'Reference>' +
    '</' + p + 'SignedInfo>';

  return {
    xml:   text,
    bytes: new Uint8Array(encode_utf8(text, fail)),
    // ⚠ ALREADY CANONICAL. This is emitted in exclusive-c14n form - one
    // namespace declaration, attributes in specification order, no
    // self-closing tags, no whitespace between elements - so the caller
    // signs these bytes directly rather than canonicalizing them again.
    canonical: true
  };
}

// The complete ds:Signature element, as text for the caller to insert.
function signature_element(plan, info, signature) {
  if (!(signature instanceof Uint8Array)) {
    fail('bad-signature', 'signature_element takes the signature as bytes');
  }

  var ns = dsig_namespace(plan);
  var p = ns.p;
  var xmlns = ns.xmlns;

  var key_info = '';

  if (plan.certificate !== null) {
    key_info =
      '<' + p + 'KeyInfo>' +
        '<' + p + 'X509Data>' +
          '<' + p + 'X509Certificate>' +
            BASE.encode('base64', to_bytes(plan.certificate)) +
          '</' + p + 'X509Certificate>' +
        '</' + p + 'X509Data>' +
      '</' + p + 'KeyInfo>';
  }

  return '<' + p + 'Signature' + xmlns + '>' +
    info.xml.replace(xmlns, '') +
    '<' + p + 'SignatureValue>' + BASE.encode('base64', signature) +
      '</' + p + 'SignatureValue>' +
    key_info +
    '</' + p + 'Signature>';
}

// ---------------------------------------------------------------------------

export {
  verification_plan,
  signing_plan,
  signed_info,
  signature_element,
  SIGNATURE_ALGORITHMS,
  DIGEST_ALGORITHMS,
  CANONICALIZATION,
  SAFE_TRANSFORMS,
  UNSAFE_TRANSFORMS
};

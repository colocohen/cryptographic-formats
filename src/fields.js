// The field-table engine. A structure is declared as data rather than walked
// in imperative code.
//
// The cursor reader alone is enough for a flat structure, but X.509's
// TBSCertificate has four optional context-tagged fields and every one of
// them becomes a hand-written peek-and-backtrack block. Four blocks is four
// chances to get the implicit/explicit distinction wrong, and getting it
// wrong reads the right bytes as the wrong type.
//
// A table states the shape once:
//
//   define('AlgorithmIdentifier', [
//     { name: 'algorithm',  type: 'oid' },
//     { name: 'parameters', type: 'any', optional: true }
//   ]);
//
// Four things the table supports from the start, because adding any of them
// later is a rewrite and all four are needed for X.509 regardless:
//
//   named types      AlgorithmIdentifier is referenced, not copied. Recursion
//                    needs names, and so does any future compiler.
//   ANY DEFINED BY   a field whose content depends on an earlier OID.
//   CHOICE           GeneralName is a nine-way choice.
//   structure only   the table describes shape. "this curve label must match
//                    this point" is semantics and lives above.

import * as T from './tags.js';

import { make_fail } from './commons/fail.js';
import { der_wrap, hex } from './commons/bytes.js';

var fail = make_fail('der');


// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

var TYPES = {};

// A definition is either a field list (a SEQUENCE) or a descriptor object for
// SET OF, CHOICE and the like. Registering by name is what makes recursion
// possible: a type can refer to itself, because the lookup happens at read
// time rather than at definition time.
// A definition is either a field list (a SEQUENCE) or a descriptor object.
//
// `options` carries the two things an ASN.1 module declares about a type as
// a whole rather than field by field:
//
//   extensible    the `...` marker. Fields beyond those declared are
//                 CAPTURED rather than refused.
//   automatic     AUTOMATIC TAGS. Context tags are assigned by position,
//                 which is how most modules outside PKIX are written.
function define(name, definition, options) {
  if (Object.prototype.hasOwnProperty.call(TYPES, name)) {
    throw new Error('cryptographic-formats: type "' + name + '" is already defined');
  }

  var opts = options || {};
  var def;

  if (Object.prototype.toString.call(definition) === '[object Array]') {
    def = { kind: 'sequence', fields: definition };
  } else {
    def = definition;
  }

  // ⚠ AUTOMATIC TAGS, X.680 section 12.3.
  //
  // A module declared AUTOMATIC TAGS gives every field of a SEQUENCE a
  // context tag by POSITION - [0], [1], [2] - unless the field already
  // carries an explicit one. Most 3GPP and ITU modules are written this way,
  // and a table transcribed from one without applying the rule reads every
  // field as the wrong type.
  //
  // The tags are IMPLICIT unless the field's type is a CHOICE or an open
  // type, which cannot be implicitly tagged because their own tag is what
  // identifies the alternative.
  if (opts.automatic && def.kind === 'sequence') {
    var i;
    for (i = 0; i < def.fields.length; i++) {
      var field = def.fields[i];
      if (field.tag === undefined) {
        field.tag = T.CLASS_CONTEXT | i;
        field.mode = needs_explicit(field) ? 'explicit' : 'implicit';
      }
    }
  }

  if (opts.extensible) {
    def.extensible = true;
  }

  TYPES[name] = def;
  return name;
}

// A CHOICE cannot be implicitly tagged: replacing its tag would remove the
// only thing that says which alternative is present. X.680 section 31.2.7.
function needs_explicit(field) {
  if (field.type === 'any' || field.type === 'raw') {
    return true;
  }
  if (is_builtin(field.type)) {
    return BUILTIN[field.type].tags !== undefined;
  }
  if (!defined(field.type)) {
    return false;
  }
  return definition_of(field.type).kind === 'choice';
}

function defined(name) {
  return Object.prototype.hasOwnProperty.call(TYPES, name);
}

function definition_of(name) {
  if (!defined(name)) {
    throw new Error('cryptographic-formats: no type named "' + name + '"');
  }
  return TYPES[name];
}

// Only for tests that need a clean registry.
function reset() {
  TYPES = {};
}

// ---------------------------------------------------------------------------
// Built-in readers
// ---------------------------------------------------------------------------

// Each entry takes a reader positioned at the value and returns it. The tag
// each one expects is listed alongside, because OPTIONAL fields have to be
// recognised by their tag before anything is consumed.

var BUILTIN = {
  integer:       { tag: T.INTEGER,      read: function (r) { return r.read_integer(); } },
  unsigned:      { tag: T.INTEGER,      read: function (r) { return r.read_unsigned(); } },
  boolean:       { tag: T.BOOLEAN,      read: function (r) { return r.read_boolean(); } },
  enumerated:    { tag: T.ENUMERATED,   read: function (r) { return r.read_enumerated(); } },
  real:          { tag: T.REAL,         read: function (r) { return r.read_real(); } },
  relative_oid:  { tag: T.RELATIVE_OID, read: function (r) { return r.read_relative_oid(); } },
  external:      { tag: T.EXTERNAL,     read: function (r) { return r.read_external(); } },
  embedded_pdv:  { tag: T.EMBEDDED_PDV, read: function (r) { return r.read_embedded_pdv(); } },
  character_string: { tag: T.CHARACTER_STRING, read: function (r) { return r.read_character_string(); } },
  object_descriptor: { tag: T.OBJECT_DESCRIPTOR, read: function (r) { return r.read_object_descriptor(); } },
  null:          { tag: T.NULL,         read: function (r) { return r.read_null(); } },
  oid:           { tag: T.OID,          read: function (r) { return r.read_oid(); } },
  octet_string:  { tag: T.OCTET_STRING, read: function (r) { return r.read_octet_string(); } },
  bit_string:    { tag: T.BIT_STRING,   read: function (r) { return r.read_bit_string(); } },
  sequence:      { tag: T.SEQUENCE,     read: function (r) { return r.read_sequence(); } },
  set:           { tag: T.SET,          read: function (r) { return r.read_set(); } },

  utf8_string:      { tag: T.UTF8_STRING,      read: function (r) { return r.read_utf8_string(); } },
  printable_string: { tag: T.PRINTABLE_STRING, read: function (r) { return r.read_printable_string(); } },
  ia5_string:       { tag: T.IA5_STRING,       read: function (r) { return r.read_ia5_string(); } },
  bmp_string:       { tag: T.BMP_STRING,       read: function (r) { return r.read_bmp_string(); } },
  t61_string:       { tag: T.T61_STRING,       read: function (r) { return r.read_t61_string(); } },
  visible_string:   { tag: T.VISIBLE_STRING,   read: function (r) { return r.read_visible_string(); } },
  numeric_string:   { tag: T.NUMERIC_STRING,   read: function (r) { return r.read_numeric_string(); } },

  // DirectoryString and friends: any of several string types. Lists the tags
  // it may appear as, so an OPTIONAL one can be tested for presence.
  any_string: {
    tag: null,
    tags: [T.UTF8_STRING, T.PRINTABLE_STRING, T.IA5_STRING, T.BMP_STRING,
           T.T61_STRING, T.VISIBLE_STRING, T.NUMERIC_STRING,
           T.UNIVERSAL_STRING, T.GRAPHIC_STRING, T.GENERAL_STRING,
           T.VIDEOTEX_STRING],
    read: function (r) { return r.read_any_string(); }
  },
  utc_time:         { tag: T.UTC_TIME,         read: function (r) { return r.read_utc_time(); } },
  generalized_time: { tag: T.GENERALIZED_TIME, read: function (r) { return r.read_generalized_time(); } },

  // The X.509 Time CHOICE. It has no single tag, so it lists the two it may
  // appear as - which is what lets an OPTIONAL Time be tested for presence
  // without being mistaken for a registered CHOICE type.
  time: {
    tag: null,
    tags: [T.UTC_TIME, T.GENERALIZED_TIME],
    read: function (r) { return r.read_time(); }
  }
};

function is_builtin(type) {
  return Object.prototype.hasOwnProperty.call(BUILTIN, type);
}

// ---------------------------------------------------------------------------
// Raw capture
// ---------------------------------------------------------------------------

// Reads one complete TLV without interpreting it, and returns its bytes.
//
// Needed in two places, and both matter:
//
//   ANY        the content is decided by an OID elsewhere in the structure,
//              so it cannot be read until that OID has been seen.
//   raw        a signed portion must be returned as the ORIGINAL bytes.
//              A certificate whose DER deviates from canonical form would
//              hash differently after a re-encode and its signature would
//              fail to verify. The bytes that were signed are the bytes that
//              came in.
function capture(r) {
  var start = r.pos;

  if (r.pos >= r.end) {
    fail(r.pos, 'truncated', 'expected a value, input ended');
  }

  // Walk tag and length by hand rather than reusing the reader's private
  // helpers, because nothing here should consume the value.
  var p = r.pos + 1;

  if (p >= r.end) {
    fail(start, 'truncated', 'length octet missing');
  }

  var first = r.buf[p];
  p += 1;
  var length;

  if ((first & 0x80) === 0) {
    length = first;
  } else {
    if (first === 0x80) {
      fail(start, 'indefinite-length', 'indefinite length is BER, not DER');
    }
    if (first === 0xFF) {
      fail(start, 'reserved-length', '0xFF is a reserved length octet');
    }
    var count = first & 0x7F;
    if (count > 4) {
      fail(start, 'length-too-large',
        'length of ' + count + ' octets is beyond what this reader accepts');
    }
    if (p + count > r.end) {
      fail(start, 'truncated', 'length field runs past the end');
    }
    if (r.buf[p] === 0x00) {
      fail(start, 'non-minimal-length',
        'length has a superfluous leading 0x00');
    }
    length = 0;
    var i;
    for (i = 0; i < count; i++) {
      length = (length * 256) + r.buf[p + i];
    }
    p += count;
    if (length < 128) {
      fail(start, 'non-minimal-length',
        'length ' + length + ' must use the short form');
    }
  }

  if (p + length > r.end) {
    fail(start, 'length-exceeds-input',
      'declared length ' + length + ' exceeds ' + (r.end - p) + ' remaining');
  }

  r.pos = p + length;
  return r.buf.subarray(start, r.pos);
}

// ---------------------------------------------------------------------------
// Field reading
// ---------------------------------------------------------------------------

// What tag identifies this field in the input? For a context-tagged field it
// is the context tag; otherwise it is the tag of the underlying type.
//
// Returns null when the field has no fixed tag: ANY and raw match whatever is
// there, and a CHOICE is decided by trying its arms. Presence of an OPTIONAL
// field is then decided by read_fields rather than by a tag comparison.
function expected_tag(field) {
  if (field.tag !== undefined) {
    return field.tag;
  }
  if (field.type === 'any' || field.type === 'raw') {
    return null;
  }
  if (is_builtin(field.type)) {
    return BUILTIN[field.type].tag;
  }
  var def = definition_of(field.type);
  if (def.kind === 'sequence' || def.kind === 'sequence_of') {
    return T.SEQUENCE;
  }
  if (def.kind === 'set_of') {
    return T.SET;
  }
  // A CHOICE has no single tag; presence is decided by trying its arms.
  return null;
}

function read_value(r, field, context) {
  // Context tagging first, because it changes how the value is reached.
  if (field.tag !== undefined) {
    if (field.mode === 'implicit') {
      return read_implicit_field(r, field, context);
    }
    // EXPLICIT: the context tag wraps the value, which keeps its own tag.
    var inner = r.read_explicit(field.tag & T.NUMBER_MASK);
    var value = read_bare(inner, field, context);
    inner.expect_end();
    return value;
  }
  return read_bare(r, field, context);
}

// IMPLICIT replaces the value's tag, so nothing in the bytes says what is
// inside and the type must come from the table. This is why implicit tagging
// cannot be handled generically.
function read_implicit_field(r, field, context) {
  var n = field.tag & T.NUMBER_MASK;

  // ⚠ `raw` HAS NO BASE TAG, so it cannot go through the builtin path.
  //
  // The whole point of `raw` is that the caller will decide what the bytes
  // are later - which means there is no tag to substitute and nothing to
  // validate. What an IMPLICIT raw field wants is the CONTENT of the tagged
  // value, with the context tag consumed and nothing put in its place.
  //
  // Found by CRMF, where CertTemplate's publicKey is [6] IMPLICIT
  // SubjectPublicKeyInfo and the module reads it raw so spki.js can have it.
  // Every earlier use of `raw` happened to be untagged, so the gap had never
  // been reached.
  if (field.type === 'raw') {
    var start = r.pos;
    var tag = r.peek_tag();

    if (tag === null) {
      fail(r.pos, 'truncated',
        'expected [' + n + '] for field "' + field.name + '"');
    }

    // Consume the value whole, then hand back everything after its header.
    var whole = r.capture_tagged(n);
    return whole;
  }

  if (is_builtin(field.type)) {
    var base = BUILTIN[field.type].tag;
    var got  = r.read_implicit(n, base);

    if (base === T.SEQUENCE || base === T.SET) {
      return got;
    }

    // ⚠ EVERY PRIMITIVE IS RE-READ BY ITS OWN READER, NOT TWO OF THEM.
    //
    // Implicit tagging replaces the universal tag, so the type's reader -
    // which checks for that tag - cannot run on the value as it stands. The
    // first version re-applied the checks by hand for INTEGER and BIT
    // STRING only, in copies of the reader's code, and every other type
    // came back as unchecked bytes: an implicit BOOLEAN of 0x01, an
    // implicit `unsigned` that was negative, an implicit OID with a
    // non-minimal arc, all accepted. And policyConstraints in x509.js read
    // its [0] and [1] IMPLICIT INTEGERs past this entirely.
    //
    // So the universal tag is restored over the content and the type's own
    // reader runs on it - the same reader, every rule, one copy. der_wrap
    // restores a header on bytes that already exist; see the structure
    // test for why that is not the direction rule being broken.
    return reread_primitive(r, field.type, base, got);
  }

  var def = definition_of(field.type);
  var tag = def.kind === 'set_of' ? T.SET : T.SEQUENCE;

  // read_implicit consumes the context tag and returns a reader bounded to
  // the content, so the container is already open - read_contents, not
  // read_definition, which would look for a second container inside.
  var sub = r.read_implicit(n, tag);
  return read_contents(sub, def, context);
}

function read_bare(r, field, context) {
  if (field.type === 'any') {
    // ANY DEFINED BY: the content is decided by an OID read EARLIER in the
    // same structure. This is the pattern that makes AlgorithmIdentifier
    // work - the parameters mean one thing after ecPublicKey and another
    // after rsaEncryption - and it is the reason field tables carry a
    // registry rather than being independent.
    //
    // Without a table the value is captured whole and the caller dispatches,
    // which is what every format module here did before this existed. With
    // one, the dispatch happens once, in the place the structure is
    // described.
    if (field.definedBy !== undefined) {
      return read_defined_by(r, field, context);
    }
    return capture(r);
  }
  if (field.type === 'raw') {
    return capture(r);
  }
  if (is_builtin(field.type)) {
    return BUILTIN[field.type].read(r);
  }
  return read_definition(r, definition_of(field.type), context);
}

function read_defined_by(r, field, context) {
  var key = context === null || context === undefined
    ? undefined
    : context[field.definedBy];

  if (key === undefined) {
    fail(r.pos, 'defined-by-missing',
      'field "' + field.name + '" is defined by "' + field.definedBy +
      '", which has not been read');
  }

  var name = lookup_defined(field.table, key);

  if (name === null) {
    // An unrecognised discriminant is NOT an error by itself. X.509 is full
    // of algorithm identifiers a given parser has never seen, and the value
    // is captured so the caller can decide. Refusing here would make an
    // unknown extension fatal.
    if (field.strict) {
      fail(r.pos, 'defined-by-unknown',
        'no entry in the table for the value of "' + field.definedBy + '"');
    }
    return capture(r);
  }

  if (name === 'absent') {
    fail(r.pos, 'unexpected-parameters',
      'this discriminant requires the field to be absent');
  }

  return read_bare(r, { type: name }, context);
}

// The table is keyed by the hex of an OID's encoding, or by a string or
// number for other discriminants. Comparing encodings rather than dotted
// strings keeps the lookup consistent with how OIDs are held everywhere
// else.
function lookup_defined(table, key) {
  if (!table) {
    return null;
  }

  var k;

  if (key instanceof Uint8Array) {
    k = '';
    var i;
    for (i = 0; i < key.length; i++) {
      var h = key[i].toString(16);
      k += (h.length === 1 ? '0' : '') + h;
    }
  } else {
    k = String(key);
  }

  return Object.prototype.hasOwnProperty.call(table, k) ? table[k] : null;
}

function read_definition(r, def, context) {
  // Opens the container - consuming its tag and length - and then reads what
  // is inside. Implicit tagging takes the other entry point, read_contents,
  // because there the tag has already been consumed by read_implicit and
  // reading another one here would look for a container inside the container.
  if (def.kind === 'sequence') {
    var seq = r.read_sequence();
    var out = read_fields(seq, def.fields, context);
    finish(seq, def, out);
    return out;
  }
  if (def.kind === 'sequence_of') {
    return read_contents(r.read_sequence(), def, context);
  }
  if (def.kind === 'set_of') {
    return read_contents(r.read_set_of(), def, context);
  }
  if (def.kind === 'choice') {
    return read_choice(r, def, context);
  }
  throw new Error('cryptographic-formats: unknown definition kind ' + def.kind);
}

// Reads a definition from a reader ALREADY POSITIONED INSIDE the container.
// This is the form implicit tagging needs: [0] IMPLICIT SET OF replaces the
// SET's tag with the context tag, so by the time the members are read the
// container has already been opened.
function read_contents(r, def, context) {
  if (def.kind === 'sequence') {
    var out = read_fields(r, def.fields, context);
    finish(r, def, out);
    return out;
  }
  if (def.kind === 'sequence_of') {
    return read_sequence_of(r, def, context);
  }
  if (def.kind === 'set_of') {
    return read_set_of(r, def, context);
  }
  throw new Error(
    'cryptographic-formats: ' + def.kind + ' cannot be implicitly tagged');
}

// SEQUENCE OF, unlike SET OF, has no ordering requirement - the order is the
// value. So no comparison is kept, and the only checks are the count bounds.
//
// `def.unique` - { field, code, what } - refuses two members whose `field`
// has the same encoding. RFC 5280 4.2's "an extension appears at most once"
// is the case: it was checked by hand in x509, crl and csr and not at all in
// attrcert, ocsp, tsp or crmf. Declared on the TYPE, every reader of it
// gets the rule.
function read_sequence_of(seq, def, context) {
  var out = [];
  var seen = {};

  while (seq.remaining() > 0) {
    var at = seq.pos;
    var member = read_bare(seq, { type: def.of }, context);

    if (def.unique !== undefined) {
      var key = hex(member[def.unique.field]);
      if (Object.prototype.hasOwnProperty.call(seen, key)) {
        fail(at, def.unique.code,
          def.unique.what + ' ' + key + ' appears more than once');
      }
      seen[key] = true;
    }

    out.push(member);
  }

  if (def.min !== undefined && out.length < def.min) {
    fail(seq.pos, 'sequence-of-too-small',
      'SEQUENCE OF has ' + out.length + ' members, minimum is ' + def.min);
  }

  return out;
}


// ---------------------------------------------------------------------------
// Validation reapplied after implicit tagging
// ---------------------------------------------------------------------------

// Runs a builtin type's own reader over content whose universal tag was
// replaced by an implicit one. `r.constructor` is the reader the value came
// from - DER or BER - so the rules are that reader's, not a third set.
function reread_primitive(r, type, base, got) {
  var wrapped = der_wrap(base, got.bytes);
  var sub = new r.constructor(wrapped, 0, wrapped.length);
  var value;

  try {
    value = BUILTIN[type].read(sub);
  } catch (e) {
    if (e && e.code !== undefined) {
      fail(got.start, e.code,
        e.message.replace(/^cryptographic-formats: \w+: (offset \d+: )?/, ''));
    }
    throw e;
  }

  return value;
}

// ---------------------------------------------------------------------------
// SET OF
// ---------------------------------------------------------------------------

// DER requires SET OF members in ascending order of their complete encodings.
// No competing JS parser checks this, and X.509 relative distinguished names
// are SET OF - so an unordered SET OF is a second encoding of one name, which
// matters wherever names are compared.
//
// Verifying it means holding the previous member's encoding to compare
// against the next. That is one member at a time, not the whole set.
function read_set_of(set, def, context) {
  var out = [];
  var previous = null;

  while (set.remaining() > 0) {
    var start = set.pos;
    var value = read_bare(set, { type: def.of }, context);
    var encoding = set.buf.subarray(start, set.pos);

    if (previous !== null && compare(previous, encoding) > 0) {
      fail(start, 'set-of-not-ordered',
        'SET OF members are not in ascending encoding order');
    }
    previous = encoding;
    out.push(value);
  }

  if (def.min !== undefined && out.length < def.min) {
    fail(set.pos, 'set-of-too-small',
      'SET OF has ' + out.length + ' members, minimum is ' + def.min);
  }

  return out;
}

// ⚠ DELIBERATELY NOT SHARED. There are four copies of this comparison in the
// library - two in each direction - and jscpd will flag them forever.
//
// The writer SORTS with it; the reader VALIDATES the order with it. A version
// that compared length before content would make the writer emit a "sorted"
// set that the reader accepts and every external tool rejects, and the round
// trip would pass. That is the sig_to_der failure in a smaller package.
//
// See src/commons/README.md.
function compare(a, b) {
  var n = Math.min(a.length, b.length);
  var i;
  for (i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

// ---------------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------------

// ⚠ THE EXTENSION MARKER, X.680 section 25.5.
//
// A type declared with `...` accepts fields beyond those in its definition,
// and that is the WHOLE POINT of the marker: a message from a newer version
// of a protocol must remain readable by an older implementation.
//
// Without it, every extensible type in existence fails against this library
// with `trailing-bytes` - which is the exact opposite of what the marker was
// added to the language for.
//
// The extra fields are CAPTURED rather than discarded, under a name that
// says what they are. A caller re-encoding the structure has to put them
// back or they will have silently dropped data somebody else depends on.
function finish(r, def, out) {
  if (!def.extensible) {
    r.expect_end();
    return;
  }

  var extra = [];

  while (r.remaining() > 0) {
    extra.push(capture(r));
  }

  if (extra.length > 0) {
    out.extensions = extra;
  }
}

// A CHOICE is decided by the tag that is actually present. Each arm names its
// tag, so no backtracking is needed and no arm is ever half-read.
function read_choice(r, def, context) {
  var tag = r.peek_tag();

  if (tag === null) {
    fail(r.pos, 'truncated', 'expected one of a CHOICE, input ended');
  }

  var i;
  for (i = 0; i < def.arms.length; i++) {
    var arm = def.arms[i];
    if (expected_tag(arm) === tag) {
      return {
        arm: arm.name,
        value: read_value(r, arm, context)
      };
    }
  }

  fail(r.pos, 'no-choice-arm',
    'no arm of this CHOICE has tag ' + T.name_of(tag));
}

// ---------------------------------------------------------------------------
// The entry point
// ---------------------------------------------------------------------------

// Reads a field list from a reader already positioned inside the SEQUENCE.
// Does NOT call expect_end - the caller decides, because a structure may be
// extensible.
//
// `context` is the ENCLOSING structure's values, used only to resolve ANY
// DEFINED BY against a field read earlier. It is deliberately not the object
// being filled: sharing one object between a structure and the structures
// nested inside it makes a child write its fields over its parent's, and the
// result looks plausible - the parent still has every key it expected, just
// with the child's values.
function read_fields(r, fields, context) {
  var out = {};
  var i;

  for (i = 0; i < fields.length; i++) {
    var field = fields[i];
    var want  = expected_tag(field);
    var here  = r.peek_tag();

    if (field.optional) {
      // A field with no fixed tag needs a different presence test. ANY and
      // raw match whatever is there, so presence simply means something
      // remains; a CHOICE is present if one of its arms claims the tag.
      var present;
      if (field.tag !== undefined) {
        // A context-tagged field is identified by its tag, whatever its
        // type. This has to come FIRST: an optional `raw` field carrying a
        // tag would otherwise take the any/raw branch below and be treated
        // as present whenever anything at all remained.
        present = here === want;
      } else if (field.type === 'any' || field.type === 'raw') {
        present = here !== null;
      } else if (is_builtin(field.type) && BUILTIN[field.type].tags) {
        // A builtin that may appear as more than one tag - Time is UTCTime
        // or GeneralizedTime - matches any of them.
        present = here !== null &&
          BUILTIN[field.type].tags.indexOf(here) !== -1;
      } else if (want === null) {
        present = here !== null && choice_matches(field, here);
      } else {
        present = here === want;
      }

      if (!present) {
        if (field.def !== undefined) {
          out[field.name] = field.def;
        }
        continue;
      }
    }

    if (here === null) {
      fail(r.pos, 'missing-field',
        'required field "' + field.name + '" is absent');
    }

    // Fields read so far are visible to those that follow, which is what
    // ANY DEFINED BY needs: the OID that decides a later field's content is
    // always an earlier field of the same structure.
    var value = read_value(r, field, out);

    // ⚠ CONSTRAINTS, X.680 section 51.
    //
    // SIZE(1..64) on a field is not decoration: it is the schema saying what
    // the protocol permits, and a value outside it is one the peer will not
    // accept either. Checking it here means a caller finds out at the parse,
    // where the field name is still in hand, rather than three layers up.
    if (field.size !== undefined) {
      check_size(r, field, value);
    }

    // ⚠ X.690 11.5: DER OMITS a value equal to its DEFAULT.
    //
    // An explicitly encoded default is a SECOND ENCODING of the same
    // structure, and the structure is usually signed. x509.js and pkcs12.js
    // each checked this by hand for one field - `cA FALSE` in
    // basicConstraints, `critical FALSE` in an extension - which meant every
    // other DEFAULT in the library went unchecked.
    //
    // The engine is the one place that knows what the default IS, so the
    // check belongs here and applies to every field that declares one.
    if (field.def !== undefined && same_as_default(value, field.def)) {
      fail(r.pos, 'non-canonical-default',
        'field "' + field.name + '" is encoded with its DEFAULT value, ' +
        'which DER requires to be omitted');
    }

    out[field.name] = value;
  }

  return out;
}

// SIZE applies to whatever a value's length means for its type: octets for a
// string, members for a SEQUENCE OF, characters for a text type.
function check_size(r, field, value) {
  var n;

  if (typeof value === 'string' ||
      Object.prototype.toString.call(value) === '[object Array]') {
    n = value.length;
  } else if (value instanceof Uint8Array) {
    n = value.length;
  } else if (value && value.bytes instanceof Uint8Array) {
    n = value.bytes.length;      // BIT STRING
  } else {
    return;                      // nothing with a length to check
  }

  var min = Object.prototype.toString.call(field.size) === '[object Array]'
    ? field.size[0] : field.size;
  var max = Object.prototype.toString.call(field.size) === '[object Array]'
    ? field.size[1] : field.size;

  if (n < min || (max !== undefined && n > max)) {
    fail(r.pos, 'constraint-violated',
      'field "' + field.name + '" has size ' + n + ', and the schema says ' +
      (min === max ? String(min) : min + '..' + max));
  }
}

// Compares a decoded value against a declared default. Only the shapes a
// DEFAULT can actually take are handled - a boolean, a small number, a
// string - because ASN.1 does not permit a structured DEFAULT that this
// engine would need to walk.
function same_as_default(value, def) {
  if (typeof def === 'boolean' || typeof def === 'string') {
    return value === def;
  }

  if (typeof def === 'number') {
    // An INTEGER comes back as bytes, so the default is compared against the
    // value those bytes encode rather than against the array.
    if (!(value instanceof Uint8Array)) {
      return false;
    }
    if (value.length === 0 || value.length > 4) {
      return false;
    }
    var v = 0;
    var i;
    for (i = 0; i < value.length; i++) {
      v = (v * 256) + value[i];
    }
    return v === def;
  }

  // `def: null` is this library's way of saying "absent", not a DEFAULT in
  // the ASN.1 sense, so nothing to compare.
  return false;
}

function choice_matches(field, tag) {
  var def = definition_of(field.type);
  if (def.kind !== 'choice') {
    return false;
  }
  var i;
  for (i = 0; i < def.arms.length; i++) {
    if (expected_tag(def.arms[i]) === tag) {
      return true;
    }
  }
  return false;
}

// Reads a named type from a reader positioned at its outer tag.
function read_type(r, name) {
  return read_definition(r, definition_of(name), null);
}

// Builds a lookup table for ANY DEFINED BY, keyed by the hex of each OID's
// encoding. Written as a helper so a table can be declared with readable
// names rather than hex literals - a table of hex strings is one nobody
// checks.
//
//   defined_by({ ecPublicKey: 'NamedCurve', rsaEncryption: 'null' })
//
// The value 'absent' means the field must not be present for that
// discriminant, which is how RFC 8410 states the rule for Ed25519.
function defined_by(mapping, oid_module) {
  var out = {};
  var name;

  for (name in mapping) {
    if (Object.prototype.hasOwnProperty.call(mapping, name)) {
      var bytes = oid_module.by_name(name);
      var k = '';
      var i;
      for (i = 0; i < bytes.length; i++) {
        var h = bytes[i].toString(16);
        k += (h.length === 1 ? '0' : '') + h;
      }
      out[k] = mapping[name];
    }
  }

  return out;
}

// Reads a named type from a reader whose cursor is already inside the
// structure - as opposed to read_type, which expects to open one.
//
// Needed by attrcert.js, where a Holder's fields arrive already unwrapped by
// an implicit tag: the SEQUENCE has been consumed and its contents are what
// remains.
function read_type_from(reader, name) {
  var def = definition_of(name);

  if (def.kind !== 'sequence') {
    throw new Error('cryptographic-formats: read_type_from needs a SEQUENCE type');
  }

  return read_fields(reader, def.fields, def.options || {}, name);
}

export {
  read_type_from,
  define,
  defined_by,
  defined,
  definition_of,
  reset,
  read_fields,
  read_type,
  capture
};

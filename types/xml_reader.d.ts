// A strict, small XML reader for signed documents: no DTD processing, no
// entity expansion beyond the five predefined, namespaces resolved - and
// Canonical XML 1.0 / Exclusive C14N, checked against libxml2.

export interface XmlAttribute {
  name: string;
  value: string;
  prefix: string;
  local: string;
  ns: string;
}

export interface XmlText { type: 'text'; value: string; start: number; end: number }
export interface XmlComment { type: 'comment'; value: string; start: number; end: number }
export interface XmlPi { type: 'pi'; target: string; data: string; start: number; end: number }

export interface XmlElement {
  type: 'element';
  /** As written: 'ds:Signature'. */
  name: string;
  prefix: string;
  local: string;
  /** The namespace URI. */
  ns: string;
  attrs: XmlAttribute[];
  /** The namespace declarations made on this element. */
  declared: Record<string, string>;
  /** Every prefix in scope here -> URI; '' is the default namespace. */
  scope: Record<string, string>;
  children: XmlNode[];
  parent: XmlElement | null;
  /** Offsets into the input: the whole element, and the end of its start tag. */
  start: number;
  start_end: number;
  end: number;
}

export type XmlNode = XmlElement | XmlText | XmlComment | XmlPi;

export interface XmlDocument {
  root: XmlElement;
  /** Present when the document has a DOCTYPE - itself a problem for SAML. */
  doctype: { start: number; end: number; internal_subset: boolean } | null;
  /** Every element, in document order. */
  elements: XmlElement[];
}

export const XML_NS: string;
export const XMLNS_NS: string;

export function parse(text: string): XmlDocument;

/** An attribute's value by local name (and namespace, '' by default), or null. */
export function attribute(el: XmlElement, local: string, ns?: string): string | null;
/** Element children, optionally by namespace and local name. */
export function child_elements(el: Pick<XmlElement, 'children'>, ns?: string, local?: string): XmlElement[];
/** Every element below, in document order. `{ children: [doc.root] }` includes the root. */
export function descendants(el: Pick<XmlElement, 'children'>, ns?: string, local?: string): XmlElement[];
export function text_content(el: Pick<XmlElement, 'children'>): string;
export function is_inside(el: XmlElement, ancestor: XmlElement): boolean;

/** C14N 1.0 by default; `exclusive` for Exclusive C14N with its PrefixList. */
export function canonicalize(el: XmlElement, options?: { exclusive?: boolean; inclusive_prefixes?: string[]; with_comments?: boolean }): string;

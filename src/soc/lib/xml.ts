// Minimal XML reader for Windows event exports. DOMParser is unavailable in
// workers, and these documents only need elements, attributes, text, CDATA
// and the predefined entities. Document type declarations are refused, so no
// entity can be defined or expanded.

export interface XmlElement {
  name: string;
  attributes: Record<string, string>;
  children: XmlElement[];
  text: string;
}

export class XmlError extends Error {
  constructor(
    message: string,
    readonly offset: number,
  ) {
    super(message);
  }
}

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

export function decodeEntities(value: string): string {
  return value.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (match, entity: string) => {
    if (entity.startsWith('#')) {
      const code = entity[1] === 'x' || entity[1] === 'X' ? parseInt(entity.slice(2), 16) : parseInt(entity.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    }
    return ENTITIES[entity] ?? match;
  });
}

const localName = (name: string) => name.slice(name.indexOf(':') + 1);

/**
 * Parses a sequence of top-level elements (exports may hold several <Event>
 * roots without a wrapper). Calls onElement for each top-level element.
 */
export function parseXmlElements(source: string, onElement: (element: XmlElement, offset: number) => void, maxDepth = 64): void {
  let index = 0;
  const stack: XmlElement[] = [];
  let rootStart = 0;
  while (index < source.length) {
    const lt = source.indexOf('<', index);
    if (lt < 0) {
      if (stack.length > 0) throw new XmlError('Unexpected end of document', source.length);
      return;
    }
    if (stack.length > 0 && lt > index) {
      (stack[stack.length - 1] as XmlElement).text += decodeEntities(source.slice(index, lt));
    }
    if (source.startsWith('<!--', lt)) {
      const end = source.indexOf('-->', lt + 4);
      if (end < 0) throw new XmlError('Unterminated comment', lt);
      index = end + 3;
    } else if (source.startsWith('<![CDATA[', lt)) {
      const end = source.indexOf(']]>', lt + 9);
      if (end < 0) throw new XmlError('Unterminated CDATA section', lt);
      if (stack.length > 0) (stack[stack.length - 1] as XmlElement).text += source.slice(lt + 9, end);
      index = end + 3;
    } else if (source.startsWith('<?', lt)) {
      const end = source.indexOf('?>', lt + 2);
      if (end < 0) throw new XmlError('Unterminated processing instruction', lt);
      index = end + 2;
    } else if (source.startsWith('<!', lt)) {
      throw new XmlError('Document type and entity declarations are not accepted', lt);
    } else if (source[lt + 1] === '/') {
      const end = source.indexOf('>', lt);
      if (end < 0) throw new XmlError('Unterminated closing tag', lt);
      const name = source.slice(lt + 2, end).trim();
      const open = stack.pop();
      if (!open || localName(open.name) !== localName(name)) throw new XmlError(`Unexpected closing tag </${name}>`, lt);
      if (stack.length === 0) onElement(open, rootStart);
      else (stack[stack.length - 1] as XmlElement).children.push(open);
      index = end + 1;
    } else {
      const tag = /^<([A-Za-z_][\w.:-]*)((?:\s+[A-Za-z_][\w.:-]*\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>/.exec(source.slice(lt, lt + 65536));
      if (!tag) throw new XmlError('Malformed tag', lt);
      const attributes: Record<string, string> = {};
      for (const attribute of (tag[2] ?? '').matchAll(/([A-Za-z_][\w.:-]*)\s*=\s*("([^"]*)"|'([^']*)')/g)) {
        attributes[localName(attribute[1] as string)] = decodeEntities(attribute[3] ?? attribute[4] ?? '');
      }
      const element: XmlElement = { name: localName(tag[1] as string), attributes, children: [], text: '' };
      if (stack.length === 0) rootStart = lt;
      if (tag[3] === '/') {
        if (stack.length === 0) onElement(element, lt);
        else (stack[stack.length - 1] as XmlElement).children.push(element);
      } else {
        if (stack.length >= maxDepth) throw new XmlError('Nesting too deep', lt);
        stack.push(element);
      }
      index = lt + tag[0].length;
    }
  }
  if (stack.length > 0) throw new XmlError('Unexpected end of document', source.length);
}

export const child = (element: XmlElement | undefined, name: string) => element?.children.find((candidate) => candidate.name === name);

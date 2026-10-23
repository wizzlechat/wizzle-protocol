// A UI element an agent sends as a file: an envelope plus a tree of nodes the app draws with its own components.
export const ELEMENT_VERSION = 1;
export const ELEMENT_FILE_SUFFIX = '.wizzle.json';

export const ELEMENT_LIMITS = {
  depth: 8,
  children: 50,
  pages: 200,
  nodes: 2000,
  text: 4000,
  title: 120,
  kind: 40,
  alt: 300,
  url: 2048,
  issues: 50,
} as const;

export const ELEMENT_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const URL_PATTERN = /^https:\/\/[^\s/?#]\S*$/;
const DEFAULT_KIND = 'Other';

export type UiTextRole = 'title' | 'body' | 'caption';
export type UiText = { type: 'text'; text: string; role?: UiTextRole };
export type UiImage = { type: 'image'; url: string; alt: string };
export type UiStack = { type: 'stack'; children: UiNode[] };
export type UiList = { type: 'list'; items: UiNode[]; ordered?: boolean };
export type UiReveal = { type: 'reveal'; front: UiNode; back: UiNode };
export type UiPager = { type: 'pager'; pages: UiNode[] };
export type UiNode = UiText | UiImage | UiStack | UiList | UiReveal | UiPager;
export type UiNodeType = UiNode['type'];

// `id` is unique per agent: the same id again replaces the element on the phone.
export type UiElement = { wizzle: number; id: string; kind: string; title: string; content: UiNode };
export type UiIssue = { path: string; message: string };
export type UiElementResult = { element: UiElement | null; issues: UiIssue[] };

type FieldSpec =
  | { kind: 'string'; required: boolean; max: number; cut: boolean; pattern?: RegExp }
  | { kind: 'enum'; values: readonly string[] }
  | { kind: 'boolean' }
  | { kind: 'node' }
  | { kind: 'nodes'; max: number };

// Every field of a node type has exactly one spec, so the types and the checks cannot drift apart.
type Fields<N extends UiNode> = { [F in Exclude<keyof N, 'type'>]-?: FieldSpec };
type Spec = { [T in UiNodeType]: Fields<Extract<UiNode, { type: T }>> };

const ROLES: readonly UiTextRole[] = ['title', 'body', 'caption'];

const SPEC: Spec = {
  text: {
    text: { kind: 'string', required: true, max: ELEMENT_LIMITS.text, cut: true },
    role: { kind: 'enum', values: ROLES },
  },
  image: {
    url: { kind: 'string', required: true, max: ELEMENT_LIMITS.url, cut: false, pattern: URL_PATTERN },
    alt: { kind: 'string', required: true, max: ELEMENT_LIMITS.alt, cut: true },
  },
  stack: { children: { kind: 'nodes', max: ELEMENT_LIMITS.children } },
  list: { items: { kind: 'nodes', max: ELEMENT_LIMITS.children }, ordered: { kind: 'boolean' } },
  reveal: { front: { kind: 'node' }, back: { kind: 'node' } },
  pager: { pages: { kind: 'nodes', max: ELEMENT_LIMITS.pages } },
};

export const UI_NODE_TYPES = Object.keys(SPEC) as UiNodeType[];

type Context = { issues: UiIssue[]; nodes: number };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOwn(object: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function isNodeType(type: string): type is UiNodeType {
  return hasOwn(SPEC, type);
}

function issue(cx: Context, path: string, message: string): void {
  if (cx.issues.length < ELEMENT_LIMITS.issues) cx.issues.push({ path, message });
}

function fail(cx: Context, path: string, message: string): null {
  issue(cx, path, message);
  return null;
}

// Names taken from the input go into issue messages, so they are kept short.
function quote(name: string): string {
  return `'${name.length > 40 ? `${name.slice(0, 40)}...` : name}'`;
}

// Cuts by UTF-16 units without leaving half of a surrogate pair at the end.
function truncate(text: string, max: number): string {
  const end = /[\uD800-\uDBFF]/.test(text.charAt(max - 1)) ? max - 1 : max;
  return text.slice(0, end);
}

function string(spec: { max: number; cut: boolean; pattern?: RegExp }, raw: unknown, path: string, cx: Context): string | undefined {
  if (typeof raw !== 'string' || raw.length === 0) return void issue(cx, path, 'must be a non-empty string');
  let value = raw;
  if (value.length > spec.max) {
    if (!spec.cut) return void issue(cx, path, `longer than ${spec.max} characters`);
    issue(cx, path, `cut to ${spec.max} characters`);
    value = truncate(value, spec.max);
  }
  if (spec.pattern && !spec.pattern.test(value)) return void issue(cx, path, 'not in the expected form');
  return value;
}

// Returns undefined when the field is unusable; the caller drops the node if the field is required.
function field(spec: FieldSpec, raw: unknown, path: string, depth: number, cx: Context): unknown {
  switch (spec.kind) {
    case 'string':
      return string(spec, raw, path, cx);
    case 'enum':
      if (typeof raw === 'string' && spec.values.includes(raw)) return raw;
      return void issue(cx, path, `ignored, expected one of ${spec.values.join(', ')}`);
    case 'boolean':
      if (typeof raw === 'boolean') return raw;
      return void issue(cx, path, 'ignored, expected true or false');
    case 'node':
      return node(raw, path, depth + 1, cx) ?? undefined;
    case 'nodes': {
      if (!Array.isArray(raw)) return void issue(cx, path, 'must be an array of nodes');
      if (raw.length > spec.max) issue(cx, path, `cut to the first ${spec.max}`);
      const nodes: UiNode[] = [];
      raw.slice(0, spec.max).forEach((child: unknown, index) => {
        const parsed = node(child, `${path}[${index}]`, depth + 1, cx);
        if (parsed) nodes.push(parsed);
      });
      return nodes;
    }
  }
}

function required(spec: FieldSpec): boolean {
  return spec.kind === 'node' || spec.kind === 'nodes' || (spec.kind === 'string' && spec.required);
}

function node(value: unknown, path: string, depth: number, cx: Context): UiNode | null {
  if (!isRecord(value) || typeof value['type'] !== 'string') return fail(cx, path, 'a node is an object with a string type');
  const type = value['type'];
  if (!isNodeType(type)) return fail(cx, path, `dropped, unknown node type ${quote(type)}`);
  if (depth > ELEMENT_LIMITS.depth) return fail(cx, path, `dropped, nested deeper than ${ELEMENT_LIMITS.depth}`);
  if (cx.nodes >= ELEMENT_LIMITS.nodes) return fail(cx, path, `dropped, more than ${ELEMENT_LIMITS.nodes} nodes`);
  cx.nodes += 1;

  const fields: Record<string, FieldSpec> = SPEC[type];
  for (const key of Object.keys(value)) {
    if (key !== 'type' && !hasOwn(fields, key)) issue(cx, `${path}.${key.slice(0, 40)}`, `ignored, ${type} has no field ${quote(key)}`);
  }
  const out: Record<string, unknown> = { type };
  for (const [key, spec] of Object.entries(fields)) {
    const raw = value[key];
    // A model often fills an optional field with null; that means absent.
    const parsed = raw === undefined || raw === null ? undefined : field(spec, raw, `${path}.${key}`, depth, cx);
    if (parsed !== undefined) out[key] = parsed;
    else if (required(spec)) return fail(cx, path, `dropped, ${type} needs a valid ${key}`);
  }
  return out as UiNode;
}

export function isElementFile(name: string): boolean {
  return name.length > ELEMENT_FILE_SUFFIX.length && name.toLowerCase().endsWith(ELEMENT_FILE_SUFFIX);
}

const ENVELOPE = new Set(['wizzle', 'id', 'kind', 'title', 'content']);

// Never throws. Invalid pieces are dropped and reported; without an id, a title and content there is no element.
export function validateElement(value: unknown): UiElementResult {
  const cx: Context = { issues: [], nodes: 0 };
  if (!isRecord(value)) return { element: null, issues: [{ path: 'element', message: 'an element is a JSON object' }] };
  for (const key of Object.keys(value)) if (!ENVELOPE.has(key)) issue(cx, key.slice(0, 40), `ignored, an element has no field ${quote(key)}`);

  const version = value['wizzle'];
  const wizzle = typeof version === 'number' && Number.isInteger(version) && version > 0 ? version : ELEMENT_VERSION;
  if (wizzle !== version) issue(cx, 'wizzle', `missing or not a whole number, read as ${ELEMENT_VERSION}`);
  const id = string({ max: 64, cut: false, pattern: ELEMENT_ID_PATTERN }, value['id'], 'id', cx);
  const title = string({ max: ELEMENT_LIMITS.title, cut: true }, value['title'], 'title', cx);
  const kind = value['kind'] === undefined || value['kind'] === null ? undefined : string({ max: ELEMENT_LIMITS.kind, cut: true }, value['kind'], 'kind', cx);
  const content = node(value['content'], 'content', 1, cx);
  if (!id || !title || !content) return { element: null, issues: cx.issues };
  return { element: { wizzle, id, kind: kind ?? DEFAULT_KIND, title, content }, issues: cx.issues };
}

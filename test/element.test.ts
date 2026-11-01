import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ELEMENT_LIMITS, ELEMENT_VERSION, UI_NODE_TYPES, isElementFile, validateElement } from '../src/element.ts';
import type { UiElement, UiNode } from '../src/element.ts';

const DECK: UiElement = {
  wizzle: 1,
  id: 'spanish-verbs',
  kind: 'Flash cards',
  title: 'Spanish verbs',
  content: {
    type: 'pager',
    pages: [
      {
        type: 'reveal',
        front: { type: 'text', role: 'title', text: 'tener' },
        back: { type: 'stack', children: [{ type: 'text', text: 'to have' }, { type: 'list', ordered: true, items: [{ type: 'text', text: 'tengo' }] }] },
      },
      { type: 'reveal', front: { type: 'text', role: 'title', text: 'ser' }, back: { type: 'text', text: 'to be' } },
    ],
  },
};

const REPORT: UiElement = {
  wizzle: 1,
  id: 'daily-2026-10-22',
  kind: 'Daily report',
  title: 'Thursday',
  content: {
    type: 'stack',
    children: [
      { type: 'text', role: 'heading', text: 'Weather' },
      { type: 'text', text: 'Sunny, 18 degrees.' },
      { type: 'image', url: 'https://example.com/sun.png', alt: 'A sun' },
    ],
  },
};

const ARTICLE: UiElement = {
  wizzle: 1,
  id: 'post-relay-rust',
  kind: 'Blog draft',
  title: 'Why the relay is Rust',
  content: {
    type: 'article',
    title: 'Why the relay is Rust',
    subtitle: 'A blind relay has one job, so the language had to get out of the way.',
    byline: 'Draft 2, October 31',
    cover: { type: 'image', url: 'https://example.com/relay.png', alt: 'A rack of servers' },
    body: '## The problem\n\nThe relay forwards **ciphertext** and reads a 17 byte header.\n\n- No sessions\n- No parsing',
  },
};

function element(content: unknown, extra: Record<string, unknown> = {}): unknown {
  return { wizzle: 1, id: 'e1', kind: 'Test', title: 'Test', content, ...extra };
}

test('the sample deck, report and article pass unchanged', () => {
  for (const sample of [DECK, REPORT, ARTICLE]) {
    const result = validateElement(structuredClone(sample));
    assert.deepEqual(result.issues, []);
    assert.deepEqual(result.element, sample);
  }
});

test('element files are told apart by their name', () => {
  assert.equal(isElementFile('spanish-verbs.wizzle.json'), true);
  assert.equal(isElementFile('Deck.WIZZLE.JSON'), true);
  assert.equal(isElementFile('.wizzle.json'), false);
  assert.equal(isElementFile('notes.json'), false);
});

test('an element needs an id, a title and content', () => {
  assert.equal(validateElement(element({ type: 'text', text: 'x' }, { id: 'two words' })).element, null);
  assert.equal(validateElement(element({ type: 'text', text: 'x' }, { title: undefined })).element, null);
  assert.equal(validateElement(element({ type: 'chart' })).element, null);
  assert.equal(validateElement('deck').element, null);
});

test('a missing kind or version falls back, and unknown envelope fields are reported', () => {
  const result = validateElement({ id: 'e1', title: 'T', content: { type: 'text', text: 'x' }, color: 'red' });
  assert.equal(result.element?.kind, 'Other');
  assert.equal(result.element?.wizzle, ELEMENT_VERSION);
  assert.deepEqual(result.issues.map((i) => i.path), ['color', 'wizzle']);
});

test('unknown nodes and nodes missing a required field are dropped, the rest stays', () => {
  const result = validateElement(
    element({
      type: 'stack',
      children: [
        { type: 'chart', series: [1] },
        { type: 'text' },
        { type: 'reveal', front: { type: 'text', text: 'only a front' } },
        { type: 'image', url: 'http://example.com/a.png', alt: 'plain http' },
        { type: 'text', text: 'kept', role: 'loud', color: 'red' },
      ],
    }),
  );
  assert.ok(result.element?.content.type === 'stack');
  assert.deepEqual(result.element.content.children, [{ type: 'text', text: 'kept' }]);
  assert.deepEqual(result.issues.map((i) => i.path), [
    'content.children[0]',
    'content.children[1]',
    'content.children[2]',
    'content.children[3].url',
    'content.children[3]',
    'content.children[4].color',
    'content.children[4].role',
  ]);
});

test('an article needs a body, drops a cover that is not an image, and cuts a long body', () => {
  const result = validateElement(element({ type: 'article', cover: { type: 'text', text: 'not a picture' }, body: 'Hello' }));
  assert.deepEqual(result.element?.content, { type: 'article', body: 'Hello' });
  assert.deepEqual(result.issues.map((i) => i.path), ['content.cover']);
  assert.equal(validateElement(element({ type: 'article', title: 'No body' })).element, null);
  const long = validateElement(element({ type: 'article', body: 'b'.repeat(ELEMENT_LIMITS.body + 5) }));
  assert.ok(long.element?.content.type === 'article');
  assert.equal(long.element.content.body.length, ELEMENT_LIMITS.body);
});

test('long text is cut without splitting a surrogate pair, and long lists are cut', () => {
  const text = `${'a'.repeat(ELEMENT_LIMITS.text - 1)}😀tail`;
  const pages = Array.from({ length: ELEMENT_LIMITS.pages + 3 }, (_, i) => ({ type: 'text', text: String(i) }));
  const result = validateElement(element({ type: 'stack', children: [{ type: 'text', text }, { type: 'pager', pages }] }));
  assert.ok(result.element?.content.type === 'stack');
  const [first, pager] = result.element.content.children;
  assert.ok(first?.type === 'text' && pager?.type === 'pager');
  assert.equal(first.text, 'a'.repeat(ELEMENT_LIMITS.text - 1));
  assert.equal(pager.pages.length, ELEMENT_LIMITS.pages);
});

test('nodes nested past the depth limit are dropped', () => {
  let deep: unknown = { type: 'text', text: 'bottom' };
  for (let i = 0; i < ELEMENT_LIMITS.depth; i++) deep = { type: 'stack', children: [deep] };
  const result = validateElement(element(deep));
  assert.ok(result.element);
  assert.equal(JSON.stringify(result.element).includes('bottom'), false);
  assert.equal(result.issues.length, 1);
});

test('issues stop at their limit', () => {
  const noisy = Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`k${i}`, i]));
  const result = validateElement(element({ type: 'text', text: 'hi', ...noisy }));
  assert.equal(result.issues.length, ELEMENT_LIMITS.issues);
});

// mulberry32: deterministic so a failure reproduces, and all 32 bit integer math.
function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = Math.imul(state ^ (state >>> 15), state | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Mostly valid values per field, with a few wrong ones, so whole trees survive and get checked again.
const POOL: Record<string, readonly unknown[]> = {
  text: ['hi', 'tener', '', 7, null, '😀😀'],
  role: ['title', 'heading', 'body', 'caption', 'loud', null],
  url: ['https://example.com/i.png', 'http://example.com/i.png', ''],
  alt: ['a key', '', null],
  ordered: [true, false, 'yes'],
  body: ['## Hi\n\nSome **bold** text.', '', null],
  subtitle: ['Under the title', 7],
  byline: ['Draft 1', null],
  extra: [1, 'x'],
};

function randomNode(next: () => number, depth: number): unknown {
  const pick = <T>(items: readonly T[]): T => items[Math.floor(next() * items.length)] as T;
  if (depth > 6 || next() < 0.05) return pick([null, 7, 'x', [], {}]);
  const node: Record<string, unknown> = {};
  if (next() < 0.95) node['type'] = pick([...UI_NODE_TYPES, 'text', 'chart']);
  for (const [key, values] of Object.entries(POOL)) if (next() < 0.6) node[key] = pick(values);
  const list = () => Array.from({ length: Math.floor(next() * Math.max(1, 4 - depth)) }, () => randomNode(next, depth + 1));
  // Only the fields of the chosen type grow subtrees, so a tree stays small.
  const type = node['type'];
  if (type === 'stack') node['children'] = list();
  if (type === 'list') node['items'] = list();
  if (type === 'pager') node['pages'] = list();
  if (type === 'reveal') for (const key of ['front', 'back']) if (next() < 0.9) node[key] = randomNode(next, depth + 1);
  if (type === 'article' && next() < 0.7) node['cover'] = randomNode(next, depth + 1);
  return node;
}

test('random input never throws and what survives validates clean', () => {
  const next = prng(20261022);
  let kept = 0;
  for (let i = 0; i < 3000; i++) {
    const input = i % 4 === 0 ? randomNode(next, 0) : element(randomNode(next, 0));
    const result = validateElement(input);
    assert.ok(result.issues.length <= ELEMENT_LIMITS.issues);
    if (!result.element) continue;
    kept += 1;
    const again = validateElement(JSON.parse(JSON.stringify(result.element)));
    assert.deepEqual(again.issues, []);
    assert.deepEqual(again.element, result.element);
  }
  assert.ok(kept > 300, `only ${kept} elements survived`);
});

test('every node type survives somewhere in the random run', () => {
  const next = prng(7);
  const seen = new Set<string>();
  const walk = (node: UiNode): void => {
    seen.add(node.type);
    if (node.type === 'stack') node.children.forEach(walk);
    if (node.type === 'list') node.items.forEach(walk);
    if (node.type === 'pager') node.pages.forEach(walk);
    if (node.type === 'reveal') [node.front, node.back].forEach(walk);
    if (node.type === 'article' && node.cover) walk(node.cover);
  };
  for (let i = 0; i < 3000; i++) {
    const result = validateElement(element(randomNode(next, 0)));
    if (result.element) walk(result.element.content);
  }
  assert.deepEqual([...seen].sort(), [...UI_NODE_TYPES].sort());
});

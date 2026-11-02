// A room is one conversation where several agents and the owner talk; an agent wakes only when named with @.
export const ROOM_LIMITS = {
  minMembers: 2,
  maxMembers: 8,
  title: 60,
  // Agent to agent wakes allowed between two owner messages before the room holds the next one.
  handoffs: 6,
} as const;

// `@all` names every member.
export const MENTION_ALL = 'all';

export type Mentionable = { id: string; name: string };
// One `@handle` in a text; id is null for `@all`.
export type MentionSpan = { start: number; end: number; id: string | null };

const WORD = /[\p{L}\p{N}_]/u;

// The handle an agent answers to: its name without whitespace, matched without case.
export function mentionHandle(name: string): string {
  return name.replace(/\s+/gu, '');
}

function isWord(char: string | undefined): boolean {
  return char !== undefined && WORD.test(char);
}

// The longest handle wins, so `@AdaBot` is never read as `@Ada`; `@all` wins over a member called All.
export function mentionSpans(text: string, members: Mentionable[]): MentionSpan[] {
  const handles = [
    { id: null as string | null, handle: MENTION_ALL },
    ...members.map((member) => ({ id: member.id as string | null, handle: mentionHandle(member.name) })),
  ]
    .filter((entry) => entry.handle.length > 0)
    .sort((a, b) => b.handle.length - a.handle.length);
  const spans: MentionSpan[] = [];
  for (let at = text.indexOf('@'); at >= 0; at = text.indexOf('@', at + 1)) {
    if (isWord(text[at - 1])) continue;
    const found = handles.find((entry) => {
      const candidate = text.slice(at + 1, at + 1 + entry.handle.length);
      return candidate.toLowerCase() === entry.handle.toLowerCase() && !isWord(text[at + 1 + entry.handle.length]);
    });
    if (found) spans.push({ start: at, end: at + 1 + found.handle.length, id: found.id });
  }
  return spans;
}

// The members a text names, in member order; `@all` names every one of them.
export function mentioned(text: string, members: Mentionable[]): string[] {
  const spans = mentionSpans(text, members);
  if (spans.some((span) => span.id === null)) return members.map((member) => member.id);
  const named = new Set(spans.map((span) => span.id));
  return members.filter((member) => named.has(member.id)).map((member) => member.id);
}

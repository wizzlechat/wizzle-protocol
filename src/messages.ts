import { concat, fromUtf8, readU32, utf8, writeU32 } from './bytes.ts';

export const PROTOCOL_VERSION = 1;

export type Capabilities = {
  streaming: boolean;
  questions: boolean;
  approvals: boolean;
  tasks: boolean;
  files: boolean;
  history: boolean;
  clearSession: boolean;
  abort: boolean;
  createAgent: boolean;
  topics: boolean;
  templates: boolean;
  // Pause, resume and restart; delete is its own flag because it is destructive.
  lifecycle: boolean;
  deleteAgent: boolean;
  // The host's credential vault: list, create, update and delete keys, and attach them to agents.
  keys: boolean;
};

export type AgentStatus = 'idle' | 'running' | 'waiting' | 'offline' | 'error' | 'paused';
export type Agent = { id: string; name: string; description?: string; status: AgentStatus; model?: string };
// lastAgentAt is the newest agent message in the conversation's latest history page.
export type Conversation = { id: string; agentId: string; title: string; lastAt?: number; topic?: boolean; createdAt?: number; lastAgentAt?: number };
export type TextFormat = 'text' | 'markdown';
export type ChatRole = 'agent' | 'user' | 'system';
export type ChatMessage = { conv: string; msgId: string; role: ChatRole; text: string; format: TextFormat; at: number };
export type ActivityState = 'idle' | 'thinking' | 'tool';
export type Activity = { conv: string; state: ActivityState; tool?: string; label?: string; startedAt?: number; timeoutMs?: number };
export type QuestionOption = { label: string; value: string; style?: 'default' | 'primary' | 'danger' };
export type Question = {
  conv: string;
  questionId: string;
  title?: string;
  question: string;
  options: QuestionOption[];
  multi?: boolean;
  expiresAt?: number;
};
export type ApprovalDecision = 'allow' | 'deny' | 'allow_always';
export type Approval = {
  conv: string;
  approvalId: string;
  title: string;
  description?: string;
  command?: string;
  decisions: ApprovalDecision[];
  expiresAt?: number;
};
export type TaskStatus = 'ok' | 'error' | 'skipped';
export type Task = {
  id: string;
  agentId?: string;
  name: string;
  schedule: string;
  enabled: boolean;
  lastRunAt?: number;
  lastStatus?: TaskStatus;
  nextRunAt?: number;
};
export type FileMeta = { name: string; mime: string; size: number };
// One agent plugin the host can stamp a new agent from. Counts are known once a copy is on the host.
export type TemplateInfo = {
  ref: string;
  name: string;
  agentName?: string;
  description?: string;
  version?: string;
  tasks?: number;
  mcpServers?: number;
  skills?: number;
  // Set on the public library's templates; downloaded once a copy is on the host.
  category?: string;
  downloaded?: boolean;
};
export type SecretType = 'generic' | 'anthropic' | 'openai';
// Where the gateway puts a generic key in a matching request; `{value}` marks the key.
export type SecretInjection =
  | { headerName: string; valueFormat?: string }
  | { paramName: string; paramFormat?: string }
  | { pathTemplate: string }
  | { pathRegex: string; pathReplacement: string };
// A vault key as wizzle sees it. Its value never leaves the host.
export type Secret = {
  id: string;
  name: string;
  type: SecretType;
  host: string;
  path?: string;
  injection?: SecretInjection;
  createdAt?: number;
};
export type SecretInput = { name: string; type: SecretType; host: string; path?: string; injection?: SecretInjection; value: string };
// Only the fields present change; a null path or injection clears it, and the type is fixed.
export type SecretChanges = {
  name?: string;
  host?: string;
  path?: string | null;
  injection?: SecretInjection | null;
  value?: string;
};
export type SessionEvent = 'cleared' | 'compacted' | 'reset' | 'error';

// Bridge to wizzle. 'file' carries its bytes in the packet body.
export type BridgeMessage =
  | { t: 'hello'; protocol: number; runtime: string; runtimeVersion?: string; bridgeVersion: string; host: string; capabilities: Capabilities }
  | { t: 'agents'; agents: Agent[] }
  | { t: 'agent'; agent: Agent }
  | { t: 'conversations'; conversations: Conversation[] }
  | { t: 'conversation'; conversation: Conversation }
  | { t: 'conversation_deleted'; conv: string }
  | { t: 'message'; message: ChatMessage }
  | { t: 'delta'; conv: string; msgId: string; append: string }
  | { t: 'activity'; activity: Activity }
  | { t: 'question'; question: Question }
  | { t: 'question_resolved'; questionId: string; value?: string | string[]; by?: string }
  | { t: 'approval'; approval: Approval }
  | { t: 'approval_resolved'; approvalId: string; decision: ApprovalDecision; by?: string }
  | { t: 'card'; conv: string; msgId: string; card: unknown; fallbackText: string; at: number }
  | { t: 'file'; conv: string; msgId: string; file: FileMeta; caption?: string; at: number }
  | { t: 'edit'; conv: string; msgId: string; text: string; format?: TextFormat; terminal?: { resolution: string } }
  | { t: 'reaction'; conv: string; msgId: string; emoji: string; op: 'add' | 'remove' }
  | { t: 'tasks'; tasks: Task[] }
  | { t: 'task_run'; taskId: string; runId: string; status: 'started' | TaskStatus; at: number; summary?: string }
  | { t: 'session'; conv: string; event: SessionEvent; detail?: string }
  | { t: 'history'; conv: string; messages: ChatMessage[]; before?: string; hasMore: boolean }
  | { t: 'templates'; templates: TemplateInfo[] }
  | { t: 'agent_deleted'; agentId: string }
  | { t: 'secrets'; secrets: Secret[] }
  // The key a create_secret or update_secret saved; ref is that request's id.
  | { t: 'secret'; ref?: string; secret: Secret }
  | { t: 'secret_deleted'; secretId: string }
  | { t: 'agent_secrets'; agentId: string; secretIds: string[] }
  | { t: 'error'; ref?: string; code: string; message: string };

// Wizzle to bridge. 'upload' carries its bytes in the packet body.
export type WizzleMessage =
  | { t: 'send'; conv: string; msgId: string; text: string; attachments?: string[] }
  | { t: 'upload'; uploadId: string; file: FileMeta }
  | { t: 'answer'; questionId: string; value: string | string[] }
  | { t: 'resolve'; approvalId: string; decision: ApprovalDecision }
  | { t: 'clear'; conv: string }
  | { t: 'abort'; conv: string }
  | { t: 'history'; conv: string; before?: string; limit?: number }
  | { t: 'tasks' }
  | { t: 'run_task'; taskId: string }
  | {
      t: 'create_agent';
      name: string;
      description?: string;
      purpose?: string;
      template?: string;
      copyFrom?: string;
      timezone?: string;
      secrets?: string[];
    }
  | { t: 'templates' }
  | { t: 'secrets' }
  | { t: 'create_secret'; secret: SecretInput }
  | { t: 'update_secret'; secretId: string; changes: SecretChanges }
  | { t: 'delete_secret'; secretId: string }
  | { t: 'agent_secrets'; agentId: string }
  | { t: 'attach_secret'; agentId: string; secretId: string }
  | { t: 'detach_secret'; agentId: string; secretId: string }
  | { t: 'create_conversation'; agentId: string; title: string }
  | { t: 'rename_conversation'; conv: string; title: string }
  | { t: 'delete_conversation'; conv: string }
  | { t: 'pause_agent'; agentId: string }
  | { t: 'resume_agent'; agentId: string }
  | { t: 'restart_agent'; agentId: string; message?: string }
  | { t: 'delete_agent'; agentId: string; removeWorkspace: boolean }
  | { t: 'sync' };

export type Packet<M> = M & { id: string };
export type AnyMessage = BridgeMessage | WizzleMessage;

export type DecodedPacket = {
  header: Packet<{ t: string }> & Record<string, unknown>;
  body: Uint8Array;
};

// Plaintext layout: headerLength(4) JSON header, then an optional binary body.
export function encodePacket(packet: Packet<AnyMessage>, body: Uint8Array = new Uint8Array(0)): Uint8Array {
  const header = utf8(JSON.stringify(packet));
  return concat(writeU32(header.length), header, body);
}

export function decodePacket(plaintext: Uint8Array): DecodedPacket {
  if (plaintext.length < 4) throw new Error('packet too short');
  const length = readU32(plaintext);
  if (4 + length > plaintext.length) throw new Error('packet header overruns');
  const parsed: unknown = JSON.parse(fromUtf8(plaintext.subarray(4, 4 + length)));
  if (typeof parsed !== 'object' || parsed === null) throw new Error('packet header not an object');
  const header = parsed as Record<string, unknown>;
  if (typeof header['t'] !== 'string' || typeof header['id'] !== 'string') throw new Error('packet missing t or id');
  return { header: header as DecodedPacket['header'], body: plaintext.subarray(4 + length) };
}

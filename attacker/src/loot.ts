import type { Response } from 'express';
import type { AttackId, LootEvent, Target } from './types.js';

const MAX_HISTORY = 100;

/** Keeps recent loot and pushes new events to every open loot panel (Server-Sent Events). */
export class LootHub {
  private readonly history: LootEvent[] = [];
  private readonly subscribers = new Set<Response>();

  publish(event: LootEvent): void {
    this.history.push(event);
    if (this.history.length > MAX_HISTORY) this.history.shift();
    const frame = `data: ${JSON.stringify(event)}\n\n`;
    for (const res of this.subscribers) res.write(frame);
  }

  subscribe(res: Response): void {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    for (const event of this.history) res.write(`data: ${JSON.stringify(event)}\n\n`);
    this.subscribers.add(res);
    res.on('close', () => this.subscribers.delete(res));
  }

  clear(): void {
    this.history.length = 0;
  }
}

// ---- Parsing untrusted input into typed events ---------------------------

const TARGETS: readonly Target[] = ['vulnerable', 'hardened'];
const ATTACKS: readonly AttackId[] = ['xss', 'cors', 'csrf', 'clickjacking'];

export const isTarget = (value: unknown): value is Target =>
  typeof value === 'string' && (TARGETS as readonly string[]).includes(value);

const isAttackId = (value: unknown): value is AttackId =>
  typeof value === 'string' && (ATTACKS as readonly string[]).includes(value);

const MAX_DATA = 4000;
const clip = (value: string): string => value.slice(0, MAX_DATA);

/**
 * Attack pages POST their results to /report as JSON. The body is `unknown`
 * until every field has been checked - nothing is trusted because it "should" be right.
 */
export function parseReport(body: unknown): LootEvent | null {
  if (typeof body !== 'object' || body === null) return null;
  const r = body as Record<string, unknown>;
  const at = new Date().toISOString();
  if (!isTarget(r['target'])) return null;

  switch (r['kind']) {
    case 'cors-read':
      return typeof r['data'] === 'string'
        ? { kind: 'cors-read', at, target: r['target'], data: clip(r['data']) }
        : null;
    case 'blocked':
      return isAttackId(r['attack']) && typeof r['reason'] === 'string'
        ? { kind: 'blocked', at, target: r['target'], attack: r['attack'], reason: clip(r['reason']) }
        : null;
    default:
      return null;
  }
}

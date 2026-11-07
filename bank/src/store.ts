/**
 * In-memory demo data. Fake users, fake money. Resets on restart or POST /__reset.
 * Passwords are plaintext ON PURPOSE to keep the lab small - never do this for real.
 */

export interface Transaction {
  readonly at: string;
  readonly from: string;
  readonly to: string;
  readonly amount: number;
}

export interface Account {
  readonly username: string;
  readonly password: string;
  balance: number;
}

export interface BoardPost {
  readonly at: string;
  readonly author: string;
  readonly message: string;
}

const SEED = [
  { username: 'alice', password: 'alice123', balance: 1000 },
  { username: 'mallory', password: 'mallory123', balance: 10 },
] as const satisfies readonly Account[];

const accounts = new Map<string, Account>();
const transactions: Transaction[] = [];
const board: BoardPost[] = [];

export function resetStore(): void {
  accounts.clear();
  for (const seed of SEED) accounts.set(seed.username, { ...seed });
  transactions.length = 0;
  board.length = 0;
  board.push({
    at: new Date().toISOString(),
    author: 'support',
    message: 'Welcome to the community board! Be nice.',
  });
}
resetStore();

export function checkCredentials(username: string, password: string): boolean {
  return accounts.get(username)?.password === password;
}

export function getAccount(username: string): Account | undefined {
  return accounts.get(username);
}

export type TransferResult =
  | { ok: true; transaction: Transaction }
  | { ok: false; reason: 'unknown-recipient' | 'same-account' | 'invalid-amount' | 'insufficient-funds' };

export function transfer(from: string, to: string, amount: number): TransferResult {
  const source = accounts.get(from);
  const target = accounts.get(to);
  if (!source || !target) return { ok: false, reason: 'unknown-recipient' };
  if (source === target) return { ok: false, reason: 'same-account' };
  if (!Number.isInteger(amount) || amount <= 0) return { ok: false, reason: 'invalid-amount' };
  if (source.balance < amount) return { ok: false, reason: 'insufficient-funds' };

  source.balance -= amount;
  target.balance += amount;
  const transaction: Transaction = { at: new Date().toISOString(), from, to, amount };
  transactions.push(transaction);
  return { ok: true, transaction };
}

export function transactionsFor(username: string): readonly Transaction[] {
  return transactions.filter((t) => t.from === username || t.to === username);
}

export function addPost(author: string, message: string): void {
  board.push({ at: new Date().toISOString(), author, message });
}

export function listPosts(): readonly BoardPost[] {
  return board;
}

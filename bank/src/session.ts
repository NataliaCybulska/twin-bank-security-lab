import { randomBytes, timingSafeEqual } from 'node:crypto';

export interface Session {
  readonly id: string;
  readonly username: string;
  /** Per-session anti-CSRF token (synchronizer token pattern). */
  readonly csrfToken: string;
}

const sessions = new Map<string, Session>();

const randomToken = (): string => randomBytes(32).toString('base64url');

/** A brand-new session ID on every login (no session fixation). */
export function createSession(username: string): Session {
  const session: Session = { id: randomToken(), username, csrfToken: randomToken() };
  sessions.set(session.id, session);
  return session;
}

export function getSession(id: string | undefined): Session | undefined {
  return id === undefined ? undefined : sessions.get(id);
}

export function destroySession(id: string | undefined): void {
  if (id !== undefined) sessions.delete(id);
}

export function clearSessions(): void {
  sessions.clear();
}

/** Constant-time comparison, so response timing doesn't leak how much of the token matched. */
export function csrfTokenMatches(session: Session, candidate: unknown): boolean {
  if (typeof candidate !== 'string') return false;
  const expected = Buffer.from(session.csrfToken);
  const actual = Buffer.from(candidate);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** Minimal Cookie header parser - written by hand instead of adding a dependency. */
export function parseCookies(header: string | undefined): ReadonlyMap<string, string> {
  const cookies = new Map<string, string>();
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try {
      cookies.set(name, decodeURIComponent(value));
    } catch {
      // malformed percent-encoding: ignore this cookie
    }
  }
  return cookies;
}

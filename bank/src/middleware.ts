import { randomBytes } from 'node:crypto';
import type { ErrorRequestHandler, RequestHandler } from 'express';
import type { SecurityProfile } from './profiles/types.js';
import { csrfTokenMatches, getSession, parseCookies } from './session.js';

/** One log line per security decision, so `docker compose logs -f` tells the story live. */
export type Logger = (message: string) => void;

export function createLogger(instance: string): Logger {
  return (message) => console.log(`[${instance}] ${message}`);
}

/** 1. Request log: method, path, Origin and whether a session cookie came along. */
export function requestLog(profile: SecurityProfile, log: Logger): RequestHandler {
  return (req, _res, next) => {
    const origin = req.get('origin') ?? '-';
    const hasCookie = parseCookies(req.get('cookie')).has(profile.sessionCookie.name);
    log(`${req.method} ${req.path}  origin=${origin}  session-cookie=${hasCookie ? 'yes' : 'no'}`);
    next();
  };
}

/** 2. Fresh CSP nonce for every response. */
export const nonce: RequestHandler = (_req, res, next) => {
  res.locals.nonce = randomBytes(16).toString('base64');
  next();
};

/** 3. Security headers: CSP, framing, and the profile's static headers. */
export function securityHeaders(profile: SecurityProfile): RequestHandler {
  return (_req, res, next) => {
    const directives: string[] = [];
    const csp = profile.csp(res.locals.nonce);
    if (csp !== null) directives.push(csp);

    if (profile.frameProtection) {
      directives.push("frame-ancestors 'none'"); // modern browsers
      res.setHeader('X-Frame-Options', 'DENY'); // legacy fallback
    }

    if (directives.length > 0) res.setHeader('Content-Security-Policy', directives.join('; '));
    for (const [name, value] of Object.entries(profile.extraHeaders)) res.setHeader(name, value);
    next();
  };
}

/** 4. CORS: which other origins may read responses *with the user's cookies*. */
export function cors(profile: SecurityProfile, log: Logger): RequestHandler {
  return (req, res, next) => {
    const origin = req.get('origin');
    res.vary('Origin'); // caches must not serve one origin's CORS answer to another

    if (origin !== undefined) {
      if (profile.isAllowedOrigin(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        log(`  CORS: allowed origin ${origin}`);
      } else {
        log(`  CORS: rejected origin ${origin}`);
      }
    }

    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
      res.sendStatus(204);
      return;
    }
    next();
  };
}

/** 5. Session: look up the session cookie and expose it as res.locals.session. */
export function session(profile: SecurityProfile): RequestHandler {
  return (req, res, next) => {
    const id = parseCookies(req.get('cookie')).get(profile.sessionCookie.name);
    const found = getSession(id);
    if (found) res.locals.session = found;
    next();
  };
}

/** Requests that are allowed without a CSRF token (no session exists yet / lab tooling). */
const CSRF_EXEMPT = new Set(['/login', '/__reset']);

/** 6. Anti-CSRF: state-changing requests must carry this session's token. */
export function csrf(profile: SecurityProfile, log: Logger): RequestHandler {
  return (req, res, next) => {
    if (req.method !== 'POST' || CSRF_EXEMPT.has(req.path)) return next();

    const current = res.locals.session;
    if (!profile.csrfTokenRequired || current === undefined) return next();

    const body: unknown = req.body;
    const candidate =
      (typeof body === 'object' && body !== null && 'csrf' in body ? body.csrf : undefined) ??
      req.get('x-csrf-token');

    if (!csrfTokenMatches(current, candidate)) {
      log(`  CSRF: rejected ${req.method} ${req.path} (missing or wrong token)`);
      res.status(403).type('text/plain').send('Forbidden: invalid CSRF token');
      return;
    }
    log('  CSRF: token OK');
    next();
  };
}

/** 8. Errors: stack traces to the client only in the vulnerable profile. */
export function errorHandler(profile: SecurityProfile, log: Logger): ErrorRequestHandler {
  return (err: unknown, _req, res, _next) => {
    const stack = err instanceof Error ? (err.stack ?? err.message) : String(err);
    log(`  ERROR: ${stack}`);
    res.status(500).type('text/plain').send(profile.exposeErrors ? stack : 'Internal server error');
  };
}

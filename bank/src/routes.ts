import { Router, type Request, type Response } from 'express';
import type { SecurityProfile } from './profiles/types.js';
import { clearSessions, createSession, destroySession, type Session } from './session.js';
import {
  addPost,
  checkCredentials,
  getAccount,
  listPosts,
  resetStore,
  transactionsFor,
  transfer,
} from './store.js';
import type { Logger } from './middleware.js';
import type { Views } from './views.js';

/** Read one form/JSON field from an untrusted body. Anything that isn't a string is "missing". */
function field(body: unknown, name: string): string | undefined {
  if (typeof body !== 'object' || body === null) return undefined;
  const value: unknown = (body as Record<string, unknown>)[name];
  return typeof value === 'string' ? value : undefined;
}

function sendHtml(res: Response, page: { value: string }, status = 200): void {
  res.status(status).type('html').send(page.value);
}

export function createRoutes(profile: SecurityProfile, views: Views, log: Logger): Router {
  const router = Router();

  /** Returns the session, or answers the request itself (401) and returns undefined. */
  const requireSession = (req: Request, res: Response): Session | undefined => {
    const current = res.locals.session;
    if (current) return current;
    if (req.path.startsWith('/api/')) res.status(401).json({ error: 'not logged in' });
    else sendHtml(res, views.message('Not logged in', 'Please log in first.'), 401);
    return undefined;
  };

  router.get('/health', (_req, res) => {
    res.json({ ok: true, profile: profile.name });
  });

  router.get('/', (_req, res) => {
    res.redirect(res.locals.session ? '/account' : '/login');
  });

  // ---- Auth -------------------------------------------------------------
  router.get('/login', (_req, res) => sendHtml(res, views.login()));

  router.post('/login', (req, res) => {
    const username = field(req.body, 'username') ?? '';
    const password = field(req.body, 'password') ?? '';
    if (!checkCredentials(username, password)) {
      log(`  login failed for ${JSON.stringify(username)}`);
      sendHtml(res, views.login('Wrong username or password.'), 401);
      return;
    }
    destroySession(res.locals.session?.id); // rotate: never reuse a pre-login session
    const created = createSession(username);
    res.cookie(profile.sessionCookie.name, created.id, profile.sessionCookie.options);
    log(`  login ok: ${username}`);
    res.redirect('/account');
  });

  router.post('/logout', (_req, res) => {
    destroySession(res.locals.session?.id);
    res.clearCookie(profile.sessionCookie.name, profile.sessionCookie.options);
    res.redirect('/login');
  });

  // ---- Account ----------------------------------------------------------
  router.get('/account', (req, res) => {
    const current = requireSession(req, res);
    if (!current) return;
    const account = getAccount(current.username);
    if (!account) throw new Error(`session for unknown user ${current.username}`);
    const notice = typeof req.query['notice'] === 'string' ? req.query['notice'] : undefined;
    sendHtml(
      res,
      views.account({
        username: account.username,
        balance: account.balance,
        csrfToken: current.csrfToken,
        transactions: transactionsFor(account.username),
        ...(notice !== undefined ? { notice } : {}),
      }),
    );
  });

  // F-02 target: credentialed JSON that includes the CSRF token. Protected only by CORS.
  router.get('/api/account', (req, res) => {
    const current = requireSession(req, res);
    if (!current) return;
    const account = getAccount(current.username);
    res.json({
      username: current.username,
      balance: account?.balance ?? 0,
      csrfToken: current.csrfToken,
      transactions: transactionsFor(current.username),
    });
  });

  // ---- Transfers --------------------------------------------------------
  // F-04 target: pre-filled confirmation page. Displays only - no state change on GET.
  router.get('/transfer', (req, res) => {
    const current = requireSession(req, res);
    if (!current) return;
    const to = typeof req.query['to'] === 'string' ? req.query['to'] : '';
    const amount = typeof req.query['amount'] === 'string' ? req.query['amount'] : '';
    sendHtml(res, views.confirmTransfer({ to, amount, csrfToken: current.csrfToken }));
  });

  // F-03 target (and the final step of the XSS and clickjacking attacks).
  router.post('/transfer', (req, res) => {
    const current = requireSession(req, res);
    if (!current) return;
    const to = field(req.body, 'to') ?? '';
    const amount = Number(field(req.body, 'amount'));
    const result = transfer(current.username, to, amount);
    if (!result.ok) {
      log(`  transfer refused: ${result.reason}`);
      sendHtml(res, views.message('Transfer failed', result.reason), 400);
      return;
    }
    log(`  TRANSFER €${amount} ${current.username} -> ${to}`);
    res.redirect(`/account?notice=${encodeURIComponent(`Sent €${amount} to ${to}`)}`);
  });

  // ---- Community board (F-01: stored XSS) --------------------------------
  router.get('/board', (_req, res) => {
    const current = res.locals.session;
    sendHtml(
      res,
      views.board({ username: current?.username, csrfToken: current?.csrfToken, posts: listPosts() }),
    );
  });

  router.post('/board', (req, res) => {
    const current = requireSession(req, res);
    if (!current) return;
    const message = (field(req.body, 'message') ?? '').slice(0, 2000);
    if (message.trim().length > 0) addPost(current.username, message);
    res.redirect('/board');
  });

  // ---- Lab tooling -------------------------------------------------------
  /** Restore seed data between rehearsal runs. Lab only - never ship an endpoint like this. */
  router.post('/__reset', (_req, res) => {
    resetStore();
    clearSessions();
    log('  store reset');
    res.status(204).end();
  });

  return router;
}

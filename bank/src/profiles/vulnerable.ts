import type { SecurityProfile } from './types.js';

/**
 * DELIBERATELY INSECURE. Every member below is a finding.
 * Each comment names the finding file in /findings that documents it.
 */
export const vulnerable: SecurityProfile = {
  name: 'vulnerable',

  // Cookie flags (root cause shared by F-01..F-04):
  // - no HttpOnly: JavaScript (and so an XSS payload) can read it
  // - SameSite=None: sent on cross-site requests, frames and fetches. Typically
  //   added "to make the SSO login / embedded widget work". Chrome only accepts
  //   SameSite=None together with Secure; http://*.localhost counts as secure.
  sessionCookie: { name: 'sid', options: { path: '/', sameSite: 'none', secure: true } },

  // F-01: a CSP that a scanner reports as "present" but that does not stop XSS:
  // 'unsafe-inline' lets injected <script> run, and img-src * (allowed "for
  // external avatars") gives the payload an exfiltration channel.
  csp: () =>
    "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; img-src * data:",

  // F-04: the bank can be framed by any site -> clickjacking.
  frameProtection: false,

  // F-02: substring check. "http://evilbank.localhost:4000" contains "bank.localhost".
  isAllowedOrigin: (origin) => origin !== undefined && origin.includes('bank.localhost'),

  // F-03: the token is rendered into forms but never checked.
  csrfTokenRequired: false,

  // F-01: no output encoding - user input goes into HTML as-is.
  escapeHtml: (input) => input,

  exposeErrors: true,
  hidePoweredBy: false,
  extraHeaders: {},
};

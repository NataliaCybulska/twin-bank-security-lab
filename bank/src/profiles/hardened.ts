import type { SecurityProfile } from './types.js';

const HTML_ESCAPES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** Parse once at startup. Invalid entries crash the app instead of being ignored. */
function parseOrigins(list: string): ReadonlySet<string> {
  return new Set(
    list
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
      .map((entry) => new URL(entry).origin),
  );
}

export function createHardened(trustedOrigins: string): SecurityProfile {
  const allowlist = parseOrigins(trustedOrigins);

  return {
    name: 'hardened',

    // HttpOnly: invisible to JavaScript. SameSite=Lax: not sent on cross-site POSTs.
    // (Strict would also break normal links into the bank from e-mail etc.)
    // Secure is off only because the lab runs on plain http://localhost; in
    // production this would be Secure + the __Host- name prefix.
    sessionCookie: {
      name: 'sid',
      options: { path: '/', httpOnly: true, sameSite: 'lax', secure: false },
    },

    // Nonce-based CSP: only <script nonce="..."> tags the server wrote can run.
    // Injected scripts don't know this request's nonce.
    csp: (nonce) =>
      [
        "default-src 'none'",
        `script-src 'nonce-${nonce}' 'strict-dynamic'`,
        "style-src 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "base-uri 'none'",
        "object-src 'none'",
      ].join('; '),

    frameProtection: true,

    // Exact match on the parsed origin, never substring / endsWith / regex.
    isAllowedOrigin: (origin) => {
      if (origin === undefined) return false;
      try {
        return allowlist.has(new URL(origin).origin);
      } catch {
        return false; // includes the literal string "null"
      }
    },

    csrfTokenRequired: true,

    escapeHtml: (input) => input.replace(/[&<>"']/g, (char) => HTML_ESCAPES[char] ?? char),

    exposeErrors: false,
    hidePoweredBy: true,
    extraHeaders: {
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Cross-Origin-Opener-Policy': 'same-origin',
    },
  };
}

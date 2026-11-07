import type { CookieOptions } from 'express';

export type ProfileName = 'vulnerable' | 'hardened';

/**
 * Every security decision the bank makes goes through this interface.
 * Routes and middleware never check "if (hardened)": they ask the profile.
 *
 * Both profiles must implement every member, so adding a new control to one
 * profile and forgetting the other is a compile error.
 */
export interface SecurityProfile {
  readonly name: ProfileName;

  /** Name + Set-Cookie attributes of the session cookie (HttpOnly, SameSite, Secure). */
  readonly sessionCookie: { readonly name: string; readonly options: CookieOptions };

  /** Content-Security-Policy value for this response, or null for no CSP at all. */
  csp(nonce: string): string | null;

  /** Anti-clickjacking: X-Frame-Options: DENY + CSP frame-ancestors 'none'. */
  readonly frameProtection: boolean;

  /** CORS: may this Origin read credentialed responses? */
  isAllowedOrigin(origin: string | undefined): boolean;

  /** Reject state-changing requests without a valid anti-CSRF token. */
  readonly csrfTokenRequired: boolean;

  /** Output encoding for every value interpolated into HTML. */
  escapeHtml(input: string): string;

  /** Send stack traces to the client on errors. */
  readonly exposeErrors: boolean;

  /** Remove Express's "X-Powered-By: Express" banner. */
  readonly hidePoweredBy: boolean;

  /** Additional static response headers (nosniff, Referrer-Policy, ...). */
  readonly extraHeaders: Readonly<Record<string, string>>;
}

import type { Session } from './session.js';

// Typed res.locals: set by middleware, read by routes.
declare global {
  namespace Express {
    interface Locals {
      /** Per-request CSP nonce. */
      nonce: string;
      /** Present when the request carries a valid session cookie. */
      session?: Session;
    }
  }
}

export {};

/** Which bank instance an attack was aimed at. */
export type Target = 'vulnerable' | 'hardened';

export type AttackId = 'xss' | 'cors' | 'csrf' | 'clickjacking';

/**
 * The attacker site answers on several hostnames, each playing a different role:
 *  - attacker.localhost      cross-site to both banks (XSS loot, clickjacking, CSRF)
 *  - evilbank.localhost      cross-site, but passes the vulnerable includes('bank.localhost') CORS check
 *  - evil.bank.localhost      SAME-SITE as bank.localhost: SameSite cookies do not stop it
 *  - evil.bank-safe.localhost SAME-SITE as bank-safe.localhost: only the CSRF token stops it
 */
export type Persona = 'attacker' | 'evilbank' | 'evil-subdomain' | 'evil-safe-subdomain';

export const PERSONA_HOSTS: Readonly<Record<Persona, string>> = {
  attacker: 'attacker.localhost',
  evilbank: 'evilbank.localhost',
  'evil-subdomain': 'evil.bank.localhost',
  'evil-safe-subdomain': 'evil.bank-safe.localhost',
};

/** Everything that can show up in the live loot panel. */
export type LootEvent =
  | { kind: 'xss-exfil'; at: string; target: Target; data: string }
  | { kind: 'cors-read'; at: string; target: Target; data: string }
  | { kind: 'blocked'; at: string; target: Target; attack: AttackId; reason: string };

/** Everything an attack page needs to render itself for one request. */
export interface PageContext {
  /** Hostname the page was opened on (decides the persona). */
  readonly host: string;
  readonly port: number;
  /** Bank origins as the browser sees them. */
  readonly targets: Readonly<Record<Target, string>>;
  /** Where XSS payloads send loot (any attacker hostname reaches the same server). */
  readonly collectOrigin: string;
  /** ?target=... if the URL has a valid one. */
  readonly target: Target | undefined;
}

/** A link on the landing page: one scenario of an attack. */
export interface AttackEntry {
  readonly label: string;
  readonly persona: Persona;
  readonly query?: string;
}

export interface AttackInfo {
  readonly id: AttackId;
  readonly title: string;
  readonly finding: string;
  readonly path: string;
  /** Hostnames this page makes sense on (the origin is part of the attack). */
  readonly personas: readonly Persona[];
  readonly summary: string;
  readonly entries: readonly AttackEntry[];
  render(ctx: PageContext): string;
}

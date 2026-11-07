/** Which bank instance an attack was aimed at. */
export type Target = 'vulnerable' | 'hardened';

export type AttackId = 'xss' | 'cors' | 'csrf' | 'clickjacking';

/**
 * The attacker site answers on several hostnames, each playing a different role:
 *  - attacker.localhost      cross-site to both banks (XSS loot, clickjacking, CSRF)
 *  - evilbank.localhost      cross-site, but passes the vulnerable includes('bank.localhost') CORS check
 *  - evil.bank.localhost     SAME-SITE as bank.localhost: SameSite cookies do not stop it
 */
export type Persona = 'attacker' | 'evilbank' | 'evil-subdomain';

export const PERSONA_HOSTS: Readonly<Record<Persona, string>> = {
  attacker: 'attacker.localhost',
  evilbank: 'evilbank.localhost',
  'evil-subdomain': 'evil.bank.localhost',
};

/** Everything that can show up in the live loot panel. */
export type LootEvent =
  | { kind: 'xss-exfil'; at: string; target: Target; data: string }
  | { kind: 'cors-read'; at: string; target: Target; data: string }
  | { kind: 'blocked'; at: string; target: Target; attack: AttackId; reason: string };

/** Static description of an attack page, used to build the landing page. */
export interface AttackInfo {
  readonly id: AttackId;
  readonly title: string;
  readonly finding: string;
  readonly path: string;
  /** The hostname the page must be opened on for the attack to make sense. */
  readonly persona: Persona;
  /** What still has to be built - shown on the stub page. */
  readonly todo: readonly string[];
}

import type { Target } from './types.js';

export interface Config {
  readonly port: number;
  /** Bank origins as the browser sees them. */
  readonly targets: Readonly<Record<Target, string>>;
}

function requireOrigin(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return new URL(value).origin; // throws on anything that isn't a URL
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const port = Number(env['ATTACKER_PORT'] ?? '4000');
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`ATTACKER_PORT is not a valid port: ${JSON.stringify(env['ATTACKER_PORT'])}`);
  }
  return {
    port,
    targets: {
      vulnerable: requireOrigin(env, 'VULN_ORIGIN'),
      hardened: requireOrigin(env, 'SAFE_ORIGIN'),
    },
  };
}

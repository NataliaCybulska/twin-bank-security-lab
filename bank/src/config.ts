import { createHardened } from './profiles/hardened.js';
import type { ProfileName, SecurityProfile } from './profiles/types.js';
import { vulnerable } from './profiles/vulnerable.js';

export interface Config {
  readonly profile: SecurityProfile;
  readonly instance: string;
  readonly port: number;
}

function isProfileName(value: unknown): value is ProfileName {
  return value === 'vulnerable' || value === 'hardened';
}

/** Fail fast: a typo in PROFILE must crash, never silently fall back to a default. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const name = env['PROFILE'];
  if (!isProfileName(name)) {
    throw new Error(`PROFILE must be "vulnerable" or "hardened", got: ${JSON.stringify(name)}`);
  }

  const port = Number(env['PORT'] ?? '3000');
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`PORT is not a valid port: ${JSON.stringify(env['PORT'])}`);
  }

  const profile = name === 'vulnerable' ? vulnerable : createHardened(env['TRUSTED_ORIGINS'] ?? '');

  return { profile, instance: env['INSTANCE'] ?? `bank-${name}`, port };
}

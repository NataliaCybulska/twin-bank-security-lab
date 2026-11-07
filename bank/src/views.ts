import type { Transaction, BoardPost } from './store.js';

/**
 * HTML that has already been rendered. Interpolating it into html`` does not
 * escape it again; everything else is passed through profile.escapeHtml().
 */
export class SafeHtml {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

export type HtmlTag = (strings: TemplateStringsArray, ...values: unknown[]) => SafeHtml;

/**
 * Tagged template whose only escaping is the profile's escapeHtml().
 * Vulnerable profile -> identity function -> every interpolation is an XSS sink.
 * Hardened profile   -> real output encoding.
 */
export function createHtml(escape: (input: string) => string): HtmlTag {
  const render = (value: unknown): string => {
    if (value instanceof SafeHtml) return value.value;
    if (Array.isArray(value)) return value.map(render).join('');
    if (value === null || value === undefined || value === false) return '';
    return escape(String(value));
  };

  return (strings, ...values) => {
    let out = strings[0] ?? '';
    values.forEach((value, i) => {
      out += render(value) + (strings[i + 1] ?? '');
    });
    return new SafeHtml(out);
  };
}

export interface Views {
  login(error?: string): SafeHtml;
  account(input: {
    username: string;
    balance: number;
    csrfToken: string;
    transactions: readonly Transaction[];
    notice?: string;
  }): SafeHtml;
  board(input: { username: string | undefined; csrfToken: string | undefined; posts: readonly BoardPost[] }): SafeHtml;
  confirmTransfer(input: { to: string; amount: string; csrfToken: string }): SafeHtml;
  message(title: string, text: string): SafeHtml;
}

export function createViews(html: HtmlTag, instance: string): Views {
  const layout = (title: string, body: SafeHtml): SafeHtml => html`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${title} · TS Bank (${instance})</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/account">TS Bank</a>
    <span class="instance">${instance}</span>
    <nav><a href="/account">Account</a> <a href="/board">Community board</a></nav>
  </header>
  <main>${body}</main>
</body>
</html>`;

  const csrfField = (token: string): SafeHtml => html`<input type="hidden" name="csrf" value="${token}">`;

  return {
    login: (error) =>
      layout(
        'Log in',
        html`<h1>Log in</h1>
${error ? html`<p class="error">${error}</p>` : ''}
<form method="post" action="/login" class="card">
  <label>Username <input name="username" autocomplete="username" value="alice"></label>
  <label>Password <input name="password" type="password" autocomplete="current-password"></label>
  <button type="submit">Log in</button>
</form>
<p class="hint">Demo users: alice / alice123 · mallory / mallory123</p>`,
      ),

    account: ({ username, balance, csrfToken, transactions, notice }) =>
      layout(
        'Account',
        html`<h1>Hello, ${username}</h1>
${notice ? html`<p class="notice">${notice}</p>` : ''}
<section class="card">
  <p class="balance">Balance: <strong>€${balance}</strong></p>
  <form method="post" action="/logout">${csrfField(csrfToken)}<button type="submit">Log out</button></form>
</section>
<section class="card">
  <h2>Send money</h2>
  <form method="post" action="/transfer">
    ${csrfField(csrfToken)}
    <label>To <input name="to" value="mallory"></label>
    <label>Amount (€) <input name="amount" type="number" min="1" value="10"></label>
    <button type="submit">Send</button>
  </form>
</section>
<section class="card">
  <h2>Transactions</h2>
  ${
    transactions.length === 0
      ? html`<p>No transactions yet.</p>`
      : html`<table>
    <tr><th>Time</th><th>From</th><th>To</th><th>Amount</th></tr>
    ${transactions.map(
      (t) => html`<tr><td>${t.at}</td><td>${t.from}</td><td>${t.to}</td><td>€${t.amount}</td></tr>`,
    )}
  </table>`
  }
</section>`,
      ),

    board: ({ username, csrfToken, posts }) =>
      layout(
        'Community board',
        html`<h1>Community board</h1>
<section class="card posts">
  ${posts.map(
    (p) => html`<article class="post"><header>${p.author} · ${p.at}</header><div>${p.message}</div></article>`,
  )}
</section>
${
  username && csrfToken
    ? html`<form method="post" action="/board" class="card">
  ${csrfField(csrfToken)}
  <label>Message <textarea name="message" rows="3"></textarea></label>
  <button type="submit">Post as ${username}</button>
</form>`
    : html`<p><a href="/login">Log in</a> to post.</p>`
}`,
      ),

    // Clickjacking target (F-04). Fixed layout so an overlay lines up reliably.
    // GET only DISPLAYS the transfer; money moves on POST.
    confirmTransfer: ({ to, amount, csrfToken }) =>
      layout(
        'Confirm transfer',
        html`<section class="confirm">
  <h1>Confirm transfer</h1>
  <p>Send <strong>€${amount}</strong> to <strong>${to}</strong>?</p>
  <form method="post" action="/transfer">
    ${csrfField(csrfToken)}
    <input type="hidden" name="to" value="${to}">
    <input type="hidden" name="amount" value="${amount}">
    <button type="submit" class="confirm-button">Confirm transfer</button>
  </form>
</section>`,
      ),

    message: (title, text) => layout(title, html`<h1>${title}</h1><p>${text}</p><p><a href="/account">Back</a></p>`),
  };
}

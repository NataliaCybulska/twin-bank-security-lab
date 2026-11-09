# Attack walkthrough

Step-by-step guide to the four attacks in this lab. Each one is run against **both** banks:

|                 | URL                             | Profile                           |
| --------------- | ------------------------------- | --------------------------------- |
| Vulnerable bank | http://bank.localhost:3000      | `bank/src/profiles/vulnerable.ts` |
| Hardened bank   | http://bank-safe.localhost:3001 | `bank/src/profiles/hardened.ts`   |
| Attacker        | http://attacker.localhost:4000  | `attacker/src/attacks.ts`         |

## Before you start

1. **Start the lab** and keep the logs visible. Every security decision is logged:

   ```bash
   docker compose up
   ```

2. **Open the demo browser** (a throwaway Chrome profile, separate from your everyday one):

   ```bash
   open -na "Google Chrome" --args \
     --user-data-dir="$HOME/.ts-security-chrome" \
     --no-first-run --no-default-browser-check
   ```

   Keep browser zoom at **100%** (clickjacking depends on pixel positions).

3. **Log in as alice on both banks** in a normal window: `alice / alice123`.

4. **Open the loot panel** in its own tab: http://attacker.localhost:4000/loot

5. **Open the attack list**: http://attacker.localhost:4000

**Reset between runs.** This restores alice's €1,000 and clears the board and all sessions (log in again afterwards):

```bash
curl -X POST http://localhost:3000/__reset
curl -X POST http://localhost:3001/__reset
```

Restarting the containers or saving a file in `src/` also resets everything, because data and sessions live in memory.

**Root cause shared by F-02 to F-04:** the vulnerable bank's session cookie is `SameSite=None; Secure`, so the browser attaches it to requests that other sites trigger (frames, `fetch`, form posts). In real apps this is usually added on purpose, for example to make an SSO login or an embedded widget work. The hardened bank uses `HttpOnly; SameSite=Lax`.

---

## F-01 · Stored XSS through a CSP that is "present"

**Idea:** mallory posts a `<script>` on the community board. Whoever reads the board runs it *as themselves*: it steals their cookie and sends money to mallory.

**Root cause (vulnerable profile):**

- `escapeHtml` returns its input unchanged, so posts are inserted into the page as raw HTML.
- The CSP exists but contains `script-src 'unsafe-inline'`, which allows injected inline scripts, and `img-src *`, which gives the script a way to send data out.
- The session cookie has no `HttpOnly`, so JavaScript can read it.

### Steps

1. Open http://attacker.localhost:4000/xss. It shows one payload per bank.
2. Open an **Incognito window** of the demo Chrome (`Cmd+Shift+N`). It has its own cookies, so you can be mallory there while alice stays logged in in the normal window.
3. In the Incognito window, log in to http://bank.localhost:3000 as `mallory / mallory123`.
4. Copy the **vulnerable bank** payload, open http://bank.localhost:3000/board, paste it into *Message* and click **Post as mallory**. Nothing visible happens: the script deliberately does nothing for mallory.
5. Back in the **normal window** (alice), open http://bank.localhost:3000/board.
6. Check the **loot panel**. Two entries appear:
   - `[vulnerable] xss-exfil  alice cookie: sid=…`
   - `[vulnerable] xss-exfil  alice sent €100 to mallory: HTTP 200`
7. Open http://bank.localhost:3000/account: a new €100 transfer to mallory. Every further view of the board sends another €100.

**Optional, session hijacking:** in the Incognito window open DevTools → *Application* → *Cookies* → `http://bank.localhost:3000`, replace the `sid` value with the stolen one and reload `/account`. You are now alice.

### Hardened bank

Repeat steps 3–5 on http://bank-safe.localhost:3001 with the **hardened bank** payload.

- The post appears as visible text (`<script>…`), not as code.
- Nothing reaches the loot panel and alice's balance doesn't change.

### Evidence

| Where | Vulnerable | Hardened |
|---|---|---|
| DevTools → *Elements* | A real `<script>` element inside the post | Text `&lt;script&gt;…` |
| DevTools → *Network* | Image requests to `attacker.localhost:4000/collect` and a `POST /transfer` | Nothing |
| Response header `Content-Security-Policy` | `script-src 'self' 'unsafe-inline'` | `script-src 'nonce-…' 'strict-dynamic'` (new nonce on every response) |
| DevTools → *Application* → *Cookies* | `sid` without `HttpOnly` | `sid` with `HttpOnly` |

### Why the fix works

- **Output encoding (the real fix):** user input is escaped, so it can never become HTML or script.
- **Nonce-based CSP (defence in depth):** even if an encoding bug slipped through, only scripts carrying this response's random nonce may run, and an attacker can't know it.
- **`HttpOnly` (limits damage):** stops cookie theft, but **not** the transfer. The script runs as alice and can do anything she can. That's why encoding, not `HttpOnly`, is the fix.

---

## F-02 · CORS substring check leaks the account and CSRF token

**Idea:** a page on another site asks the browser to fetch alice's account *with her cookies* and reads the answer.

**Root cause (vulnerable profile):** `isAllowedOrigin` uses `origin.includes('bank.localhost')`. The origin `http://evilbank.localhost:4000` contains that string, so the bank answers with `Access-Control-Allow-Origin: http://evilbank.localhost:4000` and `Access-Control-Allow-Credentials: true`, which tells the browser to let that site read the response.

### Steps

1. Make sure alice is logged in on both banks (normal window, **not** Incognito: Incognito blocks third-party cookies).
2. Open http://evilbank.localhost:4000/cors. It must be this hostname: the origin is the attack.
3. Click **Steal alice's account from both banks**.
4. Results:
   - **Vulnerable bank:** `LEAKED` with alice's balance, transactions and `csrfToken`.
   - **Hardened bank:** `Blocked by the browser` (`TypeError: Failed to fetch`).
5. The loot panel shows a `cors-read` entry for the vulnerable bank and a `blocked` entry for the hardened one.

### Evidence

- **DevTools → *Network*** → the `/api/account` request to the vulnerable bank:
  - *Request headers:* `Origin: http://evilbank.localhost:4000` and a `Cookie: sid=…` header.
  - *Response headers:* `Access-Control-Allow-Origin: http://evilbank.localhost:4000` and `Access-Control-Allow-Credentials: true`.
- **DevTools → *Console*** for the hardened bank: *"blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present"*.
- **Server logs:** `CORS: allowed origin http://evilbank.localhost:4000` (bank-vuln) vs `CORS: rejected origin …` (bank-safe).
- **Retest without a browser.** The server's decision is visible with curl:

  ```bash
  curl -s -D - -o /dev/null -H 'Origin: http://evilbank.localhost:4000' http://localhost:3000/api/account | grep -i access-control
  curl -s -D - -o /dev/null -H 'Origin: http://evilbank.localhost:4000' http://localhost:3001/api/account | grep -i access-control
  ```

  The first prints the two `Access-Control-*` headers; the second prints nothing.

### Why the fix works

- **Exact-match allowlist:** the hardened bank parses the origin with `new URL(origin).origin` and checks it against a fixed set. No `includes`, `endsWith` or regex, and the literal `null` origin is rejected.
- **`SameSite=Lax`:** the hardened cookie isn't sent on this cross-site `fetch` at all, a second, independent layer.
- **The leaked `csrfToken` matters:** stealing it would let an attacker get past CSRF protection, so a CORS bug can quietly break other defences.

---

## F-03 · Cross-site request forgery

**Idea:** alice just *visits* a page. A hidden form on it sends `POST /transfer` (to mallory, €100) to her bank, and the browser attaches her cookie.

**Root cause (vulnerable profile):** `csrfTokenRequired: false` (the token is in the forms but never checked) plus the `SameSite=None` cookie.

### Steps

Open http://attacker.localhost:4000/csrf. It links three scenarios, each in a new tab. Each page shows "Loading your free gift card…" and submits the form after about a second.

| # | Link | Attacker's relation to the bank | Result |
|---|---|---|---|
| 1 | Vulnerable bank, from `attacker.localhost` | cross-site | Lands on alice's account: **"Sent €100 to mallory"** |
| 2 | Hardened bank, from `attacker.localhost` | cross-site | **401 "Not logged in"**: `SameSite=Lax` kept the cookie back |
| 3 | Hardened bank, from `evil.bank-safe.localhost` | **same-site** | **403 "invalid CSRF token"**: the cookie *was* sent, the token check stopped it |

### Evidence

- **DevTools → *Network*** → the `transfer` request → *Cookies* tab:
  - Scenario 1: `sid` sent.
  - Scenario 2: `sid` filtered out, with Chrome's note that it has `SameSite=Lax` and the request came from another site.
  - Scenario 3: `sid` sent.
- **Server logs** for scenario 3: `CSRF: rejected POST /transfer (missing or wrong token)`.

### Why scenario 3 matters

"Same-site" means same registrable domain (`*.bank-safe.localhost`), not same origin. A compromised or user-controlled subdomain (an old marketing page, a hosted blog) counts as same-site, and **`SameSite` cookies don't protect against it**. The anti-CSRF token does, because the attacker's page can't read it. That's why the hardened bank uses both.

---

## F-04 · Clickjacking: "Claim your prize"

**Idea:** the attacker page loads the bank's pre-filled "Confirm transfer" page (€500 to mallory) in an **invisible** frame, exactly on top of a "Claim your prize" button. Alice thinks she clicks the prize; she actually clicks **Confirm transfer**.

**Root cause (vulnerable profile):** `frameProtection: false`, so no `X-Frame-Options` and no CSP `frame-ancestors`. Any site can frame the bank. With the `SameSite=None` cookie, alice is logged in inside the frame.

### Steps

1. Alice logged in on both banks (normal window, browser zoom 100%).
2. Open http://attacker.localhost:4000/prize?target=vulnerable.
3. Drag the **Reveal hidden frame** slider to about 50%: the bank's "Confirm transfer" page sits exactly over the prize button. Drag it back to 0%.
4. Click **Claim your prize**.
5. Open http://bank.localhost:3000/account: a €500 transfer to mallory. (Reveal the frame again: it now shows alice's account page.)

### Hardened bank

1. Open http://attacker.localhost:4000/prize?target=hardened and reveal the frame: Chrome refuses to show the bank inside it.
2. Clicking the button does nothing to alice's account.
3. **DevTools → *Console*:** *"Framing 'http://bank-safe.localhost:3001/' violates the following Content Security Policy directive: "frame-ancestors 'none'"…"* (exact wording varies between Chrome versions).

### Why the fix works

- **`Content-Security-Policy: frame-ancestors 'none'`:** the modern control, telling the browser this page may not be framed by anyone.
- **`X-Frame-Options: DENY`:** the legacy equivalent, for older browsers.
- **`SameSite=Lax` (bonus):** even if framing were allowed, the cookie wouldn't be sent inside a cross-site frame, so alice would appear logged out.
- **Server side:** the "Confirm transfer" page only *displays* on GET; money only moves on POST, which also requires the CSRF token.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "Not logged in" on the **vulnerable** bank inside an attack | The lab restarted (data and sessions reset). Log in as alice again. Or you're in an Incognito window, which blocks third-party cookies. |
| XSS payload does nothing | The board was viewed by mallory (skipped on purpose) or by a logged-out user. View it as alice. |
| Clickjacking click misses the button | Browser zoom isn't 100%. Reset with `Cmd+0`. |
| CORS page shows `HTTP 401` for the vulnerable bank | alice isn't logged in on `bank.localhost:3000` in this browser profile. |
| Loot panel stays empty | Reload `/loot`; it replays the last 100 events. |

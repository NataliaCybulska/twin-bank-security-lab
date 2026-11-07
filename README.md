# Twin Bank Security Lab: vulnerable vs hardened, side by side

> ⚠️ **Deliberately vulnerable.** Runs on `127.0.0.1` only. Fake users, fake money, no real secrets.
> Never deploy it anywhere and never bind its ports to `0.0.0.0`.

One TypeScript bank runs twice from the same image: once with a **vulnerable** security profile and
once with a **hardened** one. An attacker site fires the same attacks at both.

| Finding | Attack | Fix |
|---|---|---|
| F-01 | Stored XSS through a CSP that is "present" but has `'unsafe-inline'` | Output encoding + nonce-based CSP + `HttpOnly` |
| F-02 | CORS check `origin.includes('bank.localhost')`, so `evilbank.localhost` can read the account | Exact-match origin allowlist |
| F-03 | Cross-site request forgery on `POST /transfer` | Anti-CSRF token + `SameSite=Lax` |
| F-04 | Clickjacking the "Confirm transfer" page | `frame-ancestors 'none'` + `X-Frame-Options: DENY` |

## Run it

Requires Docker Desktop. Node, npm and TypeScript only exist inside the containers.

```bash
docker compose build
docker compose up
```

| URL | What |
|---|---|
| http://bank.localhost:3000 | Bank, **vulnerable** profile |
| http://bank-safe.localhost:3001 | Bank, **hardened** profile |
| http://attacker.localhost:4000 | Attacker: attack list + loot panel |
| http://evilbank.localhost:4000 | Attacker persona that passes the vulnerable CORS check |

Users: `alice / alice123`, `mallory / mallory123`.

## Demo browser

A throwaway Chrome instance with its own profile: real Chrome defaults, no access to your
everyday cookies, logins or extensions. Don't sign in to Google in it.

```bash
open -na "Google Chrome" --args \
  --user-data-dir="$HOME/.ts-security-chrome" \
  --no-first-run --no-default-browser-check
```

Delete `~/.ts-security-chrome` to reset it.

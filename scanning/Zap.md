# Dynamic scanning with ZAP

ZAP is the DAST half of this: instead of reading the code, it talks to the running app and judges the responses. I ran it in two passes. First the baseline scan (`zap-baseline.py`), which spiders briefly and runs passive checks only, no attacks, which is a good first look because most of the four findings show up in headers, cookies and the CSP. Then an authenticated active scan to go after the one that doesn't surface passively: the XSS.

## Getting ZAP onto the app's network

Running ZAP in Docker has one quirk worth knowing (see the [ZAP docker notes](https://www.zaproxy.org/docs/docker/about/)): it's about container networking. To reach an app running in another container, the ZAP container has to join that app's network.

The lab already has a network from `docker compose`, so there's nothing to create, just attach to it:

```
docker network ls | grep twin-bank
ed9317df578a   twin-bank-security-lab_default   bridge    local
```

Then scan each bank by its service name and internal port (the host-published `127.0.0.1` ports don't exist inside the container):

```
docker run --rm --network twin-bank-security-lab_default \
  -v "$PWD/zap:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://bank-vuln:3000 -w report-vuln.md
```

Swap `bank-vuln` for `bank-safe` (and the report name) for the hardened run. The two reports are in `zap` folder.

## What it found

Zap not only raises issues, it also provides explanation for each one, which I really appreciate, Both scans were unauthenticated, so they only saw public pages.

| Risk | Vulnerable | Hardened |
| --- | --- | --- |
| High | 0 | 0 |
| Medium | 6 | 1 |
| Low | 6 | 2 |
| Informational | 4 | 3 |

Alert by alert:

| Alert                                                   | Risk   | Vulnerable | Hardened |
| ------------------------------------------------------- | ------ | ---------- | -------- |
| CSP: `script-src` unsafe-inline                         | Medium | 5          | cleared  |
| CSP: `style-src` unsafe-inline                          | Medium | 5          | cleared  |
| CSP: Wildcard Directive (`img-src *`)                   | Medium | 5          | cleared  |
| CSP: missing `frame-ancestors` / `form-action` fallback | Medium | systemic   | cleared  |
| Missing Anti-clickjacking Header                        | Medium | 1          | cleared  |
| `X-Powered-By` leak                                     | Low    | systemic   | cleared  |
| `X-Content-Type-Options` missing                        | Low    | 4          | cleared  |
| Permissions-Policy not set                              | Low    | systemic   | cleared  |
| Cross-Origin-Opener-Policy missing                      | Low    | 3          | cleared  |
| Absence of Anti-CSRF Tokens (login form)                | Medium | 3          | 2        |
| Cross-Origin-Embedder-Policy missing                    | Low    | 3          | 3        |
| Cross-Origin-Resource-Policy missing                    | Low    | 4          | 4        |

## Reading the results

The diff is the point. Every CSP and clickjacking alert that fires on the vulnerable bank is gone on the hardened one, because the nonce-based CSP drops `unsafe-inline` and the wildcard, adds `frame-ancestors`, and `X-Frame-Options` covers the anti-clickjacking rule. This is ZAP confirming, dynamically, what the [CSP Evaluator](Google-CSP-evaluator.md) write-up showed statically.

**Anti-CSRF tokens** stays Medium on both banks - this is login CSRF (a genuine but lower-priority gap the lab doesn't defend), and it is separate from the transfer CSRF in [F-03](../attack-flows/CSRF.md), which the scan never reached.

## What the passive pass missed

Unauthenticated and passive, so the actual logic flaws are invisible here:

- **No XSS.** Passive scanning doesn't inject anything, and the scan never logged in, so it never reached the board or the authenticated reflected sinks. The stored XSS needs an authenticated active scan.
- **No CORS bypass.** The substring origin check isn't visible to a passive scan; it only shows when you send a crafted `Origin` and read the response, which is the browser demo or an active test.
- **The real transfer CSRF** never appears, because `/transfer` is behind auth. ZAP flagged login CSRF instead, which is adjacent but not the finding.

In other words, the passive scan is blind exactly where the app holds state. Reaching the XSS needs an authenticated active scan, so that's the second pass below. The CORS and CSRF chains still need the browser demos, for reasons I'll get to.

## The authenticated active scan

Getting ZAP logged in took a detour worth recording, because it comes straight out of one of the security controls. ZAP talks plain HTTP to the bank containers, but the session cookie is set `Secure`, so ZAP's browser-style cookie jar never sent it back over HTTP and every authenticated request came back 401. Form-based auth in the Automation Framework failed 100% for the same reason.

The fix was to log in once by hand, grab the `sid` cookie, and inject it on every request with a Replacer rule instead of relying on the cookie jar:

```
-config replacer.full_list(0).description=sid \
-config replacer.full_list(0).enabled=true \
-config replacer.full_list(0).matchtype=REQ_HEADER \
-config replacer.full_list(0).matchstr=Cookie \
-config replacer.full_list(0).replacement=sid=<captured-value>
```

This works, and it is a shortcut. Injecting the cookie by hand skips everything ZAP normally does to stay logged in: the cookie jar, the form-auth flow, the session detection. For this lab that was fine, because I only needed the scanner past the login wall. Against a real deployment you would want ZAP driving the login itself, so it can notice when the session drops and re-authenticate.

The clean way to get there is to stop scanning over plain HTTP. The whole detour exists because the `Secure` cookie will not travel over HTTP, so a small reverse proxy that terminates TLS in front of the banks fixes it at the root. Caddy is a good fit: it issues and renews certificates on its own and can run its own internal CA, so you point ZAP at `https://bank-vuln` instead of `http://bank-vuln:3000`. Once ZAP trusts Caddy's root, the `Secure` cookie flows normally and ZAP's built-in form auth works without the hack. It also makes the lab look more like production, where these apps would sit behind TLS anyway. A good next step for the project.

With a session held, the active scanner could reach the board and the authenticated `/account` and `/transfer` sinks and actually inject payloads. The headline numbers:

| Risk | Vulnerable | Hardened |
| --- | --- | --- |
| High | 3 | 1 |
| Medium | 5 | 1 |
| Low | 2 | 0 |
| Informational | 2 | 2 |

### The XSS showed up

This is the payoff. On the vulnerable bank, the active scan found all three categories:

| XSS type | Instances | Where |
| --- | --- | --- |
| Reflected | 4 | `/account?notice=`, `/transfer?to=`, `/transfer?amount=`, `POST /board` message |
| Persistent (stored) | 1 | `/board` message |
| DOM-based | 2 | `/account` notice, `/transfer` to |

ZAP planted `<script>alert(1)</script>` style payloads and watched them come back live in the HTML. The stored one is the loud result: it posted a payload to the board that survives and fires for the next visitor. It also lines up with what Semgrep flagged statically on the same `/account?notice=` sink, so the static and dynamic tools are pointing at the same code from opposite directions.

On the hardened bank, zero XSS of any kind. Same payloads, same endpoints, and the output encoding turned every one into inert text. That is the clearest before/after in the whole lab.

### One false positive worth triaging

The hardened scan reported one High: SQL Injection on `/account?notice=`. There is no database anywhere in this lab, the bank is entirely in-memory, so this can't be real. It's a textbook false positive: ZAP sends `... AND 1=1 --` and `... OR 1=1 --`, compares the two responses, and ZAP's heuristic decided it had manipulated a query. No query exists. This is the kind of thing a DAST report hands you to rule out by hand, and a good reminder that a High from a scanner is a starting point you still have to confirm.

The one remaining Medium on the hardened bank is the CSP fallback warning again, this time only on the non-HTML endpoints (`robots.txt`, `sitemap.xml`, `/static`) that serve `default-src 'none'`. On those, `frame-ancestors` and `form-action` don't inherit from `default-src`, so ZAP notes it. 

### Still out of reach

The active pass found the XSS, but two findings still didn't surface, for structural reasons:

- **CORS.** The substring origin check only misbehaves when you send a crafted `Origin` header and read what comes back. ZAP's active rules don't fuzz `Origin` that way, so this stays a browser-demo finding.
- **Transfer CSRF.** ZAP can reach `/transfer` now, but confirming CSRF means proving a cross-site request succeeds without the token, which is cross-origin browser behavior that the single-origin scanner doesn't model.

## Takeaway

Two passes, two different jobs. The passive baseline is strong at the header and CSP layer. The authenticated active pass then went after the thing passive couldn't see and found the XSS on the vulnerable bank (reflected, stored and DOM) while the hardened bank came back clean, which is the F-01 before/after in dynamic form. It also handed over one SQLi false positive to triage, which is part of the job too.

What ZAP still doesn't cover is the CORS substring bypass and the transfer CSRF, both of which live in cross-origin browser behavior. So the division of labor holds: ZAP for the header, CSP and injectable sinks, Semgrep for the code-level sinks, and the browser demos for the cross-site chains. Each one reaches what the others can't.

# Scanning

Five tools across four angles on the same two banks. Every scanner has blind spots, so the trick is to come at the app from a few directions at once: read the code, poke the live server, and check what the dependencies drag in. If one tool caught everything, the other four would be out of a job and this folder would be a lot shorter.

Each write-up has the full story. This is the map.

## The tools

| Tool                                     | Angle                               | Good at                                                                                            | What it earned its place for                                                                                        |
| ---------------------------------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| [Semgrep](Semgrep.md)                    | SAST, static code analysis          | tracing user input through the code to the spot it hits a dangerous sink, with exact file and line | flagged where request params (like `notice` on `/account`) get written into the page unescaped, the root of the XSS |
| [CSP Evaluator](Google-CSP-evaluator.md) | CSP analysis                        | grading a `Content-Security-Policy` directive by directive                                         | showed why the vulnerable CSP stops nothing and the hardened one does                                               |
| [Trivy](Trivy.md)                        | container image CVE scan            | known CVEs in the base image's OS packages and libraries                                           | confirmed the pinned base image is clean, and gave a second opinion on the Brotli false positive                    |
| [npm audit](Trivy.md)                    | dependency scan, reads the lockfile | known CVEs in the app's own npm dependency tree                                                    | covers `express`, `tsx` and the rest of `package-lock.json`, the layer Trivy's image scan skips                     |
| [ZAP](Zap.md)                            | DAST, scans the live app            | runtime behaviour: headers, cookies, CSP, and injectable sinks                                     | caught the XSS live (reflected, stored, DOM), confirming Semgrep from the other side                                |

## How they fit together

- **Static meets dynamic.** Semgrep reads the code and says "this value reaches the page unescaped." ZAP never reads a line of code, throws payloads at the running app, and watches one come back alive. Same bug, approached from opposite ends, which is exactly the kind of agreement you want to see.
- **Dependencies are a separate question.** Your own code can be spotless while a package quietly sinks you, so Trivy and `npm audit` cover the supply-chain angle the other two never look at.

## A note on false positives

Scanners are confident and occasionally wrong. Semgrep's Pro scan flagged a Node Brotli CVE that wasn't real (the image is pinned to a patched build), and ZAP reported SQL injection on a bank that has no database. A "High" from a scanner means "go look" and a good chunk of these write-ups are the looking.

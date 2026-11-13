# Static analysis with Semgrep

Semgrep ships a few ways. I've used the pipx install before; this time I wanted the Docker image (can you tell I'm a fan?). 

The Docker path is lightly documented: they give you one starting command and not much else.
```
$ docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep --help
Usage: semgrep [OPTIONS] COMMAND [ARGS]...

  To get started quickly, run `semgrep scan --config auto`

  Run `semgrep SUBCOMMAND --help` for more information on each subcommand

  If no subcommand is passed, will show a welcome message with usage info

Options:
  -h, --help  Show this message and exit.

Commands:
  ci                   Run Semgrep on a git diff (for use in CI)
  install-semgrep-pro  Install the Semgrep Pro Engine
  login                Obtain and save credentials for semgrep.dev
  logout               Remove locally stored credentials to semgrep.dev
  lsp                  Start the Semgrep LSP server (useful for IDEs)
  publish              Upload rule to semgrep.dev
  scan                 Run Semgrep rules on local folders or files
  show                 Show various types of information
  test                 Test the rules (EXPERIMENTAL improvements over scan --test)
  validate             Validate the rules (EXPERIMENTAL improvements over scan --validate)
  mcp                  Start the Semgrep MCP server
```


The shape is `docker run [options] IMAGE COMMAND`: `semgrep/semgrep` is the image and the second `semgrep` is the command run inside it, while `-v "${PWD}:/src"` mounts the current directory to `/src` so the scanner can read the code. From the repo root:

```
docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep scan
```

To run it from anywhere, swap `${PWD}` for an absolute path; the left side of that colon is the host directory the container mounts.


The default scan runs the free Community rules:

```
┌─────────────┐
│ Scan Status │
└─────────────┘
  Scanning 41 files tracked by git with 1074 Code rules:
                                                                                                                        
  Language      Rules   Files          Origin      Rules                                                                
 ─────────────────────────────        ───────────────────                                                               
  <multilang>      47      41          Community    1074                                                                
  ts              163      17                                                                                           
  json              4       6                                                                                           
  dockerfile        6       2                                                                                           
  yaml             35       1                                                                                           
  bash              4       1                                                                                           
                                                                                                                        
                   
                   
┌─────────────────┐
│ 7 Code Findings │
└─────────────────┘
                           
    attacker/src/attacks.ts
    ❯❱ javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag
          ❰❰ Blocking ❱❱
          Cannot determine what 'columns' is and it is used with a '<script>' tag. This could be susceptible  
          to cross-site scripting (XSS). Ensure 'columns' is not externally controlled, or sanitize this data.
          Details: https://sg.run/1Zy1                                                                        
                                                                                                              
           65┆ <div class="cols">${columns}</div>
            ⋮┆----------------------------------------
          111┆ <div class="cols">${columns}</div>
                         
    attacker/src/pages.ts
     ❱ javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization
          ❰❰ Blocking ❱❱
          Detected a call to `replaceAll()` in an attempt to HTML escape the string `input`. Manually    
          sanitizing input through a manually built list can be circumvented in many situations, and it's
          better to use a well known sanitization library such as `sanitize-html` or `DOMPurify`.        
          Details: https://sg.run/AzoB                                                                   
                                                                                                         
            6┆ return input
            7┆   .replaceAll('&', '&amp;')
            ⋮┆----------------------------------------
     ❱ javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization
          ❰❰ Blocking ❱❱
          Detected a call to `replaceAll()` in an attempt to HTML escape the string `input                 
          .replaceAll('&', '&amp;')`. Manually sanitizing input through a manually built list can be       
          circumvented in many situations, and it's better to use a well known sanitization library such as
          `sanitize-html` or `DOMPurify`.                                                                  
          Details: https://sg.run/AzoB                                                                     
                                                                                                           
            6┆ return input
            7┆   .replaceAll('&', '&amp;')
            8┆   .replaceAll('<', '&lt;')
            ⋮┆----------------------------------------
     ❱ javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization
          ❰❰ Blocking ❱❱
          Detected a call to `replaceAll()` in an attempt to HTML escape the string `input               
          .replaceAll('&', '&amp;')     .replaceAll('<', '&lt;')`. Manually sanitizing input through a   
          manually built list can be circumvented in many situations, and it's better to use a well known
          sanitization library such as `sanitize-html` or `DOMPurify`.                                   
          Details: https://sg.run/AzoB                                                                   
                                                                                                         
            6┆ return input
            7┆   .replaceAll('&', '&amp;')
            8┆   .replaceAll('<', '&lt;')
            9┆   .replaceAll('>', '&gt;')
            ⋮┆----------------------------------------
     ❱ javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization
          ❰❰ Blocking ❱❱
          Detected a call to `replaceAll()` in an attempt to HTML escape the string `input               
          .replaceAll('&', '&amp;')     .replaceAll('<', '&lt;')     .replaceAll('>', '&gt;')`. Manually 
          sanitizing input through a manually built list can be circumvented in many situations, and it's
          better to use a well known sanitization library such as `sanitize-html` or `DOMPurify`.        
          Details: https://sg.run/AzoB                                                                   
                                                                                                         
            6┆ return input
            7┆   .replaceAll('&', '&amp;')
            8┆   .replaceAll('<', '&lt;')
            9┆   .replaceAll('>', '&gt;')
           10┆   .replaceAll('"', '&quot;')
                          
    attacker/src/server.ts
    ❯❱ javascript.express.security.audit.res-render-injection.res-render-injection
          ❰❰ Blocking ❱❱
          User controllable data `req` enters `res.render(...)` this can lead to the loading of other         
          HTML/templating pages that they may not be authorized to render. An attacker may attempt to use     
          directory traversal techniques e.g. `../folder/index` to access other HTML pages on the file system.
          Where possible, do not allow users to define what should be  loaded in res.render or use an allow   
          list for the existing application.                                                                  
          Details: https://sg.run/eLjd                                                                        
                                                                                                              
           43┆ res.type('html').send(attack.render(ctx));

                
                
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 7 (7 blocking)
 • Rules run: 255
 • Targets scanned: 41
 • Parsed lines: ~100.0%
 • Scan was limited to files tracked by git
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 255 rules on 41 files: 7 findings.
```


From earlier runs I knew Semgrep finds a lot more with its Pro rules, which are free for non-commercial use but need an account token. That token is the login: `semgrep login` only writes it to a file, and with `--rm` the file disappears when the container exits, so logging in one container and scanning in the next doesn't carry over.

Two ways to hand the token over:

1. Run the container interactively (`-it`) with a shell as the entrypoint and `semgrep login` inside it. It works, but it's more steps than it needs.
2. Pass the token as an environment variable with `-e`. Keep it exported in your shell or in a CI secret rather than typed inline, since `-e SEMGREP_APP_TOKEN=abc123` on the command line lands in your shell history.

`semgrep ci` reads that variable directly and pulls the Pro rules, so login and scan become one command: 

```
docker run --rm -e SEMGREP_APP_TOKEN=$SEMGREP_APP_TOKEN -v "${PWD}:/src" \
  semgrep/semgrep semgrep ci
```

That run pulls far more rules (Pro plus Supply Chain) and uploads the results to the Semgrep platform:

```
┌────────────────┐
│ Debugging Info │
└────────────────┘
                  
  SCAN ENVIRONMENT
  versions    - semgrep 1.184.0 on python 3.12.16                      
  environment - running in environment git, triggering event is unknown
            
  CONNECTION
  Initializing scan (deployment=natalia_cybulska-personal-org, scan_id=266389700)  
  Enabled products: Supply Chain, Code                                                     
        
  ENGINE
  Using Semgrep Pro Version: 1.184.0
  Installed at /usr/lib/python3.12/site-packages/semgrep/bin/semgrep-core-proprietary
Rule javascript.vulnerable-components.mise-brotli.mise-brotli contains an include pattern '.mise/config.toml' that will soon be interpreted as '/.mise/config.toml' to comply with the Semgrepignore v2 and Gitignore specifications. To make this pattern permanently unanchored, edit rule javascript.vulnerable-components.mise-brotli.mise-brotli and change it to '**/.mise/config.toml'. To confirm the anchored behavior and avoid this warning, change it to '/.mise/config.toml'.
Rule javascript.vulnerable-components.mise-brotli.mise-brotli contains an include pattern '.config/mise/config.toml' that will soon be interpreted as '/.config/mise/config.toml' to comply with the Semgrepignore v2 and Gitignore specifications. To make this pattern permanently unanchored, edit rule javascript.vulnerable-components.mise-brotli.mise-brotli and change it to '**/.config/mise/config.toml'. To confirm the anchored behavior and avoid this warning, change it to '/.config/mise/config.toml'.
Rule javascript.vulnerable-components.mise-brotli.mise-brotli contains an include pattern '.config/mise.toml' that will soon be interpreted as '/.config/mise.toml' to comply with the Semgrepignore v2 and Gitignore specifications. To make this pattern permanently unanchored, edit rule javascript.vulnerable-components.mise-brotli.mise-brotli and change it to '**/.config/mise.toml'. To confirm the anchored behavior and avoid this warning, change it to '/.config/mise.toml'.
               
               
┌─────────────┐
│ Scan Status │
└─────────────┘
  Scanning 41 files tracked by git with 2969 Code rules, 93953 Supply Chain rules:
            
            
  CODE RULES
                                                                                                                        
  Language      Rules   Files          Origin      Rules                                                                
 ─────────────────────────────        ───────────────────                                                               
  <multilang>      47      41          Pro rules    1894                                                                
  ts              340      17          Community    1075                                                                
  json              5       6                                                                                           
  dockerfile       11       2                                                                                           
  yaml             35       1                                                                                           
  bash              4       1                                                                                           
                                                                                                                        
                    
  SUPPLY CHAIN RULES
                                                                                                                        
  Dependency Sources           Resolution Method   Ecosystem   Dependencies   Rules                                     
 ───────────────────────────────────────────────────────────────────────────────────                                    
  attacker/package-lock.json   Lockfile            Npm         126            93953                                     
  bank/package-lock.json       Lockfile            Npm         126            93953                                     
                                                                                                                        
                                                                                                                        
  Analysis       Rules                                                                                                  
 ──────────────────────                                                                                                 
  Malicious      85164                                                                                                  
  Basic           5982                                                                                                  
  Reachability    2807                                                                                                  
                                                                                                                        
Rule javascript.vulnerable-components.mise-brotli.mise-brotli contains an include pattern '.mise/config.toml' that will soon be interpreted as '/.mise/config.toml' to comply with the Semgrepignore v2 and Gitignore specifications. To make this pattern permanently unanchored, edit rule javascript.vulnerable-components.mise-brotli.mise-brotli and change it to '**/.mise/config.toml'. To confirm the anchored behavior and avoid this warning, change it to '/.mise/config.toml'.
Rule javascript.vulnerable-components.mise-brotli.mise-brotli contains an include pattern '.config/mise/config.toml' that will soon be interpreted as '/.config/mise/config.toml' to comply with the Semgrepignore v2 and Gitignore specifications. To make this pattern permanently unanchored, edit rule javascript.vulnerable-components.mise-brotli.mise-brotli and change it to '**/.config/mise/config.toml'. To confirm the anchored behavior and avoid this warning, change it to '/.config/mise/config.toml'.
Rule javascript.vulnerable-components.mise-brotli.mise-brotli contains an include pattern '.config/mise.toml' that will soon be interpreted as '/.config/mise.toml' to comply with the Semgrepignore v2 and Gitignore specifications. To make this pattern permanently unanchored, edit rule javascript.vulnerable-components.mise-brotli.mise-brotli and change it to '**/.config/mise.toml'. To confirm the anchored behavior and avoid this warning, change it to '/.config/mise.toml'.
  Uploading scan results  
  Finalizing scan                                          
                                 
┌───────────────────────────────┐
│ 11 Non-blocking Code Findings │
└───────────────────────────────┘
                       
    attacker/Dockerfile
   ❯❯❱ dockerfile.node.vulnerable-components.node-brotli-usage.node-brotli-usage
          This Dockerfile builds on a Node.js image that is affected by CVE-2026-111497 (Brotli decoder out-  
          of-bounds write, remote code execution) or whose patch level cannot be verified from the tag. Pin to
          a fixed release 22.23.4, 24.22.1, 26.12.1 or later on the same line. Node.js 20 and older, 23 and 25
          are end-of-life and will not receive a fix.                                                         
          Details: https://sg.run/8xbrQ                                                                       
                                                                                                              
            5┆ FROM node:24-trixie-                                                        
               slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d
                           
    attacker/src/attacks.ts
    ❯❱ javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag
          Cannot determine what 'columns' is and it is used with a '<script>' tag. This could be susceptible  
          to cross-site scripting (XSS). Ensure 'columns' is not externally controlled, or sanitize this data.
          Details: https://sg.run/1Zy1                                                                        
                                                                                                              
           65┆ <div class="cols">${columns}</div>
            ⋮┆----------------------------------------
          111┆ <div class="cols">${columns}</div>
                         
    attacker/src/pages.ts
     ❱ javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization
          Detected a call to `replaceAll()` in an attempt to HTML escape the string `input`. Manually    
          sanitizing input through a manually built list can be circumvented in many situations, and it's
          better to use a well known sanitization library such as `sanitize-html` or `DOMPurify`.        
          Details: https://sg.run/AzoB                                                                   
                                                                                                         
            6┆ return input
            7┆   .replaceAll('&', '&amp;')
            ⋮┆----------------------------------------
     ❱ javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization
          Detected a call to `replaceAll()` in an attempt to HTML escape the string `input                 
          .replaceAll('&', '&amp;')`. Manually sanitizing input through a manually built list can be       
          circumvented in many situations, and it's better to use a well known sanitization library such as
          `sanitize-html` or `DOMPurify`.                                                                  
          Details: https://sg.run/AzoB                                                                     
                                                                                                           
            6┆ return input
            7┆   .replaceAll('&', '&amp;')
            8┆   .replaceAll('<', '&lt;')
            ⋮┆----------------------------------------
     ❱ javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization
          Detected a call to `replaceAll()` in an attempt to HTML escape the string `input               
          .replaceAll('&', '&amp;')     .replaceAll('<', '&lt;')`. Manually sanitizing input through a   
          manually built list can be circumvented in many situations, and it's better to use a well known
          sanitization library such as `sanitize-html` or `DOMPurify`.                                   
          Details: https://sg.run/AzoB                                                                   
                                                                                                         
            6┆ return input
            7┆   .replaceAll('&', '&amp;')
            8┆   .replaceAll('<', '&lt;')
            9┆   .replaceAll('>', '&gt;')
            ⋮┆----------------------------------------
     ❱ javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization
          Detected a call to `replaceAll()` in an attempt to HTML escape the string `input               
          .replaceAll('&', '&amp;')     .replaceAll('<', '&lt;')     .replaceAll('>', '&gt;')`. Manually 
          sanitizing input through a manually built list can be circumvented in many situations, and it's
          better to use a well known sanitization library such as `sanitize-html` or `DOMPurify`.        
          Details: https://sg.run/AzoB                                                                   
                                                                                                         
            6┆ return input
            7┆   .replaceAll('&', '&amp;')
            8┆   .replaceAll('<', '&lt;')
            9┆   .replaceAll('>', '&gt;')
           10┆   .replaceAll('"', '&quot;')
                          
    attacker/src/server.ts
     ❱ javascript.express.log.console-log-express.console-log-express
          Detected a logger that logs user input without properly neutralizing the output. The log message  
          could contain characters like ` ` and ` ` and cause an attacker to forge log entries or include   
          malicious content into the logs. Use proper input validation and/or output encoding to prevent log
          entries from being forged.                                                                        
          Details: https://sg.run/pK7Ok                                                                     
                                                                                                            
           12┆ const log = (message: string): void => console.log(`[attacker] ${message}`);
    
    
          Taint comes from:
    
           56┆ const { target, data } = req.query;
    
    
          Taint flows through these intermediate variables:
    
           56┆ const { target, data } = req.query;
    
           56┆ const { target, data } = req.query;
    
           59┆ log(`  LOOT from ${target}: ${data.slice(0, 80)}`);
    
    
                This is how taint reaches the sink:
    
           59┆ log(`  LOOT from ${target}: ${data.slice(0, 80)}`);
    
          Taint flows through these intermediate variables:
    
           12┆ const log = (message: string): void => console.log(`[attacker] ${message}`);
    
           12┆ const log = (message: string): void => console.log(`[attacker] ${message}`);
    
          then reaches:
    
           12┆ const log = (message: string): void => console.log(`[attacker] ${message}`);
    
    
            ⋮┆----------------------------------------
   
    ❯❱ javascript.express.security.audit.res-render-injection.res-render-injection
          User controllable data `req` enters `res.render(...)` this can lead to the loading of other         
          HTML/templating pages that they may not be authorized to render. An attacker may attempt to use     
          directory traversal techniques e.g. `../folder/index` to access other HTML pages on the file system.
          Where possible, do not allow users to define what should be  loaded in res.render or use an allow   
          list for the existing application.                                                                  
          Details: https://sg.run/eLjd                                                                        
                                                                                                              
           43┆ res.type('html').send(attack.render(ctx));
    
    
          Taint comes from:
    
           35┆ const target = req.query['target'];
    
    
          Taint flows through these intermediate variables:
    
           35┆ const target = req.query['target'];
    
           36┆ const ctx: PageContext = {
    
    
                This is how taint reaches the sink:
    
           43┆ res.type('html').send(attack.render(ctx));
    
                   
    bank/Dockerfile
   ❯❯❱ dockerfile.node.vulnerable-components.node-brotli-usage.node-brotli-usage
          This Dockerfile builds on a Node.js image that is affected by CVE-2026-111497 (Brotli decoder out-  
          of-bounds write, remote code execution) or whose patch level cannot be verified from the tag. Pin to
          a fixed release 22.23.4, 24.22.1, 26.12.1 or later on the same line. Node.js 20 and older, 23 and 25
          are end-of-life and will not receive a fix.                                                         
          Details: https://sg.run/8xbrQ                                                                       
                                                                                                              
            5┆ FROM node:24-trixie-                                                        
               slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d
                      
    bank/src/routes.ts
    ❯❱ javascript.express.web.tainted-redirect-express.tainted-redirect-express
          The application builds a URL using user-controlled input which can lead to an open redirect         
          vulnerability. An attacker can manipulate the URL and redirect users to an arbitrary domain. Open   
          redirect vulnerabilities can lead to issues such as Cross-site scripting (XSS) or redirecting to a  
          malicious domain for activities such as phishing to capture users' credentials. To prevent this     
          vulnerability perform strict input validation of the domain against an allowlist of approved        
          domains. Notify a user in your application that they are leaving the website. Display a domain where
          they are redirected to the user. A user can then either accept or deny the redirect to an untrusted 
          site.                                                                                               
          Details: https://sg.run/7KEAw                                                                       
                                                                                                              
          126┆ res.redirect(`/account?notice=${encodeURIComponent(`Sent €${amount} to ${to}`)}`);
    
    
          Taint comes from:
    
          117┆ const to = field(req.body, 'to') ?? '';
    
    
          Taint flows through these intermediate variables:
    
          117┆ const to = field(req.body, 'to') ?? '';
    
           17┆ function field(body: unknown, name: string): string | undefined {
    
           19┆ const value: unknown = (body as Record<string, unknown>)[name];
    
          117┆ const to = field(req.body, 'to') ?? '';
    
          126┆ res.redirect(`/account?notice=${encodeURIComponent(`Sent €${amount} to ${to}`)}`);
    
    
                This is how taint reaches the sink:
    
          126┆ res.redirect(`/account?notice=${encodeURIComponent(`Sent €${amount} to ${to}`)}`);
    

                
                
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ CI scan completed successfully.
 • Findings: 11 (0 blocking)
 • Rules run: 144092
 • Targets scanned: 41
 • Parsed lines: ~100.0%
 • Scan was limited to files tracked by git
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
CI scan completed successfully.
  View results in Semgrep Cloud Platform:
    https://semgrep.dev/orgs/natalia_cybulska-personal-org/findings?repo=local_scan/src&ref=main
    https://semgrep.dev/orgs/natalia_cybulska-personal-org/supply-chain/vulnerabilities?repo=local_scan/src&ref=main
  No blocking findings so exiting with code 0
```

## Triaging the findings

Eleven findings, zero blocking, and most of them are not what they look like. This is where the real work is: the scanner raises its hand, and someone has to decide which hands mean anything. A couple turn out to be false positives; the rest are true positives that mostly don't matter here, which is its own kind of result. 

### False positives

The Dockerfile "Brotli RCE" (CVE-2026-111497), flagged on both Dockerfiles above. The rule reads the tag `node:24-trixie-slim`, can't verify the patch level from it, and assumes the worst. The image is pinned by digest, though, and that digest resolves to a patched build:

```
docker run --rm node:24-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d node -v

v24.22.2
```

24.22.2 is past the 24.22.1 fix line, so the image isn't affected. The rule flagged the tag it could read, not the version behind the digest it couldn't. Pinning by digest is what makes this safe and also what blinds the rule.

---

The open redirect in `bank/src/routes.ts`. Semgrep traces `to` from `req.body` into `res.redirect(...)` and calls it an open redirect, but the redirect target is the fixed path `/account`. The line is still worth a look, for a different reason: that `notice` value is reflected back into the page, which is the authenticated reflected-XSS sink from the [XSS write-up](../attack-flows/XSS.md). Right line, wrong reason.

### True positives

These are real matches: the pattern Semgrep flagged genuinely exists. What changes from one to the next is whether it matters, and most of them sit in `attacker/src`, the attack harness rather than the bank.

The closest thing to an actual bug is the log forging in `attacker/src/server.ts`: `req.query` data reaches `console.log` without stripping newlines, so a crafted request could forge log entries. 

Worth a closer look is the XSS flag, because it's the one place Semgrep says "XSS" out loud. The `unknown-value-with-script-tag` rule fires on `attacker/src/attacks.ts` (lines 65 and 111), where `columns` is rendered into the page, warning it "could be susceptible to cross-site scripting." Next to it, `req.query.target` reaching `attack.render(...)` trips the render-injection rule. Both are the attacker app building its own pages from values it controls (`target` is validated against a fixed set of attack names). Semgrep did raise XSS, just on the harness and not on the bank. 

The manual HTML escaping in `attacker/src/pages.ts` rounds it out, tripping the "use a sanitizer like DOMPurify" rule once per `replaceAll`, four times over. For a small attacker-side loot panel that escapes its own output it's fine (but honestly they should know better after all of the shenanigans they did), and the general advice still holds: hand-rolled allowlist escaping is easy to get subtly wrong.

## What Semgrep missed

The more useful result is what isn't in the output. The bank's deliberate vulnerabilities, the four this lab is built around, barely register. The vulnerable profile's `escapeHtml` that returns its input untouched, the `sameSite: 'none'` cookie, the `origin.includes()` CORS check, the absent `frame-ancestors`: none of them tripped a rule.

They don't, because they aren't shaped like the patterns Semgrep hunts for. The stored XSS isn't a dangerous-looking call; it's the absence of escaping, a function that hands back its own argument. The one time Semgrep said "XSS" it was pointing at the attacker's own harness, not the bank's reflected sink or the stored one on the board. SAST is strong at spotting a known-bad call sitting in the code, and much weaker on a control that is simply missing or quietly misconfigured.

So the scan flagged the defensive escaping and the attack harness, and walked past the planted bugs. The honest version: a quiet Semgrep run doesn't mean the app is safe, and the findings it does raise still need a person to sort the real from the noise.

## Takeaway

Semgrep through Docker is quick to run, and the Pro rules are worth looking into. On this repo it produced eleven findings and none I would change the code for as written: two false positives (a digest-pinned image it couldn't see into, and a redirect that doesn't redirect), and the rest true positives that don't bite here, from a low-severity log-forging line to the attacker harness flagging its own pages. Meanwhile the vulnerabilities the lab exists to demonstrate slipped straight past, because they are missing controls rather than dangerous calls. Worth running. Its output is where triage starts.

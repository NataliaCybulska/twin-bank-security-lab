# Security notes

> **Not a vulnerability-disclosure policy.** The whole application is insecure on purpose, it is really about running that insecure app *safely* on your own machine.

> **Instructions assume macOS.** The browser-launch command and keyboard shortcuts below are macOS; on Linux/Windows use the equivalent flags and keys (e.g. `Ctrl` for `Cmd`).

The vulnerabilities live in the bank's application layer (security headers, cookie flags, CORS, CSRF, framing) and they are there on purpose. Everything around that, the Docker setup, the ports, the dependencies, is hardened so that running the lab on your machine doesn't put the host at risk. I don't actively maintain this repository, so treat it as a dated snapshot and read this file before you run it.

## What is insecure on purpose

The whole point of the `vulnerable` profile is to be attackable, so it is. Pointed at `bank.localhost:3000`, a scanner will light up, and that is expected:

- Missing or weak security headers, cookie flags without `HttpOnly`/`SameSite`, a CORS check that accepts lookalike origins, no CSRF token, and a page that can be framed. These are findings F-01 to F-04, documented in [attack-flows/](attack-flows/).
- Lab simplifications that keep the code small: plaintext passwords, in-memory data, demo users with known passwords, and a `/__reset` endpoint. None of this is production code.

The `hardened` profile on `bank-safe.localhost:3001` is the opposite side of each of those, for comparison.

## Precautions already in place

So that an attackable app can be run safely on a laptop, the harness around it is locked down:

- **Localhost only.** Every port is published on `127.0.0.1`, so nothing is reachable from your network. The deliberately vulnerable app is never exposed to the LAN.
- **Non-root containers.** Each service runs as the unprivileged `node` user, on a read-only root filesystem with only `/tmp` writable (a tmpfs).
- **Dropped privileges.** `cap_drop: [ALL]`, `no-new-privileges`, no `--privileged`, and the Docker socket is never mounted, so a container has no path to the host.
- **Resource limits.** Each container is capped at 256 MB of RAM, half a CPU, and 100 processes. The process cap also neutralises fork bombs.
- **Read-only source.** The app code is mounted read-only, so a running container can't rewrite its own code or reach outside the mount.
- **No autostart.** There is no `restart:` policy, so nothing comes back after a reboot. The lab runs only while you have it up.
- **Supply chain.** The base image is pinned by digest; `npm ci` verifies every package against the `sha512` hashes in the lockfile and fails on a mismatch; package install scripts are disabled (`ignore-scripts`), a common supply-chain attack path; versions are exact.
- **No real secrets.** Only fake users and fake money. There is nothing sensitive in the repo to leak.

## Before you run it

- **Check the dependencies first.** This is a dated snapshot, so advisories may have appeared since it was last reviewed. Run `./scripts/check-updates.sh` (Docker only, it just reports) and glance at the result before building. See [Applying updates](#applying-updates) below.
- **Keep the ports on `127.0.0.1`.** Don't change the bindings to `0.0.0.0`, and don't expose the lab through a tunnel like ngrok or cloudflared. It is built to be attacked; you want to be the only one who can reach it.
- **Don't weaken the harness.** No `--privileged`, don't mount the Docker socket, and leave the `cap_drop` / `read_only` / resource limits in `docker-compose.yml` as they are.
- **Use the throwaway browser.** Drive the attacks from a separate Chrome profile, not one logged into real accounts. Launch a throwaway instance with real Chrome defaults but none of your everyday cookies, logins or extensions (don't sign in to Google in it). The command below is macOS; on Linux/Windows launch Chrome directly with the same `--user-data-dir`, `--no-first-run` and `--no-default-browser-check` flags:

  ```bash
  open -na "Google Chrome" --args \
    --user-data-dir="$HOME/.ts-security-chrome" \
    --no-first-run --no-default-browser-check
  ```

  Delete `~/.ts-security-chrome` to reset it. The attacks move "money" between demo users, but there's no reason to point live sessions at a lab full of working exploits.
- **Stop it when you're done:** `docker compose down`. The app holds no state, so nothing persists.


## Applying updates

Everything below runs in a container, so you still don't need node or npm on your machine. Do it in a fork, then rebuild and walk through the attacks to confirm nothing broke before relying on it. `docker compose build` runs `npm ci`, which fails if `package.json` and the lockfile disagree, so a half-finished edit can't slip through.

**A newer base image.** `./scripts/check-updates.sh` prints the exact line to use. Paste it into the `FROM` of **both** `bank/Dockerfile` and `attacker/Dockerfile` (they must stay on the same digest), then rebuild:

```bash
docker compose build --pull
docker compose up
```

**An npm package.** Update the lockfile in a throwaway container. This writes `package.json` and `package-lock.json` back into the folder and nothing else:

```bash
# one package to a specific version, for the bank app
docker run --rm -v "$PWD/bank:/app" -w /app node:24-trixie-slim \
  npm install --save-exact --ignore-scripts --package-lock-only <package>@<version>
```

Repeat for `attacker/` if it uses the same package, then `docker compose build` to rebuild against the new lock.

**Advisories.** To let npm pull in fixed versions of vulnerable dependencies, then review the diff before keeping it:

```bash
docker run --rm -v "$PWD/bank:/app" -w /app node:24-trixie-slim \
  npm audit fix --ignore-scripts --package-lock-only
```

After any of these, run `./scripts/check-updates.sh` again to confirm it comes back clean, and walk through [ATTACKS.md](ATTACKS.md) to confirm the lab still behaves as documented.

**One version to leave alone:** `@types/node` tracks the Node major of the base image, so it will always show as "outdated" while you stay on Node 24. Bump it only when you move the base image to a newer Node major, and move both together.

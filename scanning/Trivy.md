# Image scanning with Trivy

Semgrep's Pro scan has a Supply Chain section, and on this repo it raised one finding against the Dockerfile: a Node.js Brotli CVE that was a false positive, inferred from the image tag (the image is pinned to a patched version, see the [Semgrep write-up](Semgrep.md)). Trivy is built specifically for scanning images, so I ran it on the same base image for a second opinion.

Using this command:

```
docker run --rm \
  -v trivy-cache:/root/.cache/ \
  aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb \
  image node:24.22.2-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d
```


Both the Trivy image and the target image are pinned by digest. The `-v trivy-cache:/root/.cache/` volume keeps Trivy's vulnerability database between runs, so it isn't re-downloaded every time. 

```
2026-11-11T15:39:42Z	INFO	Detected OS	family="debian" version="13.7"
2026-11-11T15:39:42Z	INFO	[debian] Detecting vulnerabilities...	os_version="13" pkg_num=79
2026-11-11T15:39:42Z	INFO	Number of language-specific files	num=1
2026-11-11T15:39:42Z	INFO	[node-pkg] Detecting vulnerabilities...
2026-11-11T15:39:42Z	WARN	Using severities from other vendors for some vulnerabilities. Read https://trivy.dev/docs/v0.76/guide/scanner/vulnerability#severity-selection for details.
2026-11-11T15:39:43Z	INFO	Table result includes only package filenames. Use '--format json' option to get the full path to the package file.
```

```
node:24.22.2-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d (debian 13.7)

==============================================================================================================

Total: 197 (UNKNOWN: 10, LOW: 64, MEDIUM: 75, HIGH: 48, CRITICAL: 0)
```

```
Node.js (node-pkg)

==================

Total: 19 (UNKNOWN: 0, LOW: 1, MEDIUM: 12, HIGH: 6, CRITICAL: 0)
```

## What Trivy is scanning

Trivy reports vulnerabilities in the things an image is built from, in two groups here.

- **OS packages (Debian).** `apt`, `bash`, `util-linux` and the rest of the Debian 13 base: 197 findings, none critical, spread across low, medium and high. This is the normal background of any Linux base image. Much of it isn't reachable in a container that only runs Node, and all of it belongs to the image maintainers to fix. It reaches you as a newer image digest, which is what the base-image bump in `check-updates.sh` is for.
- **Node packages (`node-pkg`).** `brace-expansion`, `glob`, `ip-address` and the rest: 19 findings, none critical. They are the packages bundled inside the Node image itself, the dependency trees of `npm`, `corepack` and `yarn` that ship with `node:24-trixie-slim`. The bank and attacker apps don't use them at runtime.

What's absent is this project's own dependencies (`express`, `tsx`, `@types/node`). That's on purpose: I scanned the base image, not a built app image, so the only Node packages present are the ones the base image ships with. To cover the app's dependencies you'd point Trivy at a built image (`trivy image twin-bank-security-lab/bank:dev`) or at the repo's lockfiles (`trivy fs .`, which reads `package-lock.json` directly). The `npm audit` step in `check-updates.sh` already covers that second angle.

So the 197 and the 19 are the surface of the stock Node image, not a verdict on the app.

## Takeaway

Trivy reads the versions actually installed in the image, so it gives a truer picture than Semgrep's Supply Chain check, which inferred a Node CVE from the Dockerfile tag and got it wrong. A tool built for one job usually does it better than the all-in-one.
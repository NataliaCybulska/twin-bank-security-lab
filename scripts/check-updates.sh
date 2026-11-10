#!/usr/bin/env bash
# check-updates.sh - report what needs updating, using Docker only.
#
# Read-only: it never writes to your folders and never changes any version.
# It only tells you what is stale. Needs only Docker (with buildx, which ships
# with Docker Desktop). No node or npm on your machine.
#
# What it checks, per app folder (any top-level dir with package.json + lockfile):
#   1. npm security advisories (npm audit) and version drift (npm outdated),
#      run inside a throwaway container so node_modules never touches your disk.
#   2. Base image freshness: the pinned FROM digest vs the current tag on the registry.
#   3. (--image-scan) base image CVEs via Trivy in a container; heavier, off by default.
#
# Flags:
#   --image-scan   also scan the pinned base image for HIGH/CRITICAL CVEs (Trivy)
#   --strict       exit non-zero if anything needs attention (useful in CI)
#   -h, --help     show this help
#
# To update something: do it in a fork (bump the lockfile or the FROM digest),
# then review and test before merging. This script never does it for you.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_SCAN=0
STRICT=0
NEEDS=0

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --image-scan) IMAGE_SCAN=1 ;;
    --strict) STRICT=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

command -v docker >/dev/null 2>&1 || { echo "Error: Docker is required but was not found." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Error: the Docker daemon is not reachable. Start Docker Desktop and retry." >&2; exit 1; }

# Discover app folders (top-level dirs with a lockfile).
APPS=()
for d in "$ROOT"/*/; do
  name="$(basename "$d")"
  [ -f "$d/package.json" ] && [ -f "$d/package-lock.json" ] && APPS+=("$name")
done
if [ "${#APPS[@]}" -eq 0 ]; then
  echo "No app folders with package.json + package-lock.json found under $ROOT." >&2
  exit 1
fi

# Node image for the npm checks: reuse the project's own pinned base if present.
NODE_IMAGE=""
for app in "${APPS[@]}"; do
  df="$ROOT/$app/Dockerfile"
  [ -f "$df" ] || continue
  ref="$(grep -m1 '^FROM ' "$df" | awk '{print $2}')"
  case "$ref" in node:*) NODE_IMAGE="$ref"; break ;; esac
done
[ -n "$NODE_IMAGE" ] || NODE_IMAGE="node:24-trixie-slim"

echo "============================================================"
echo " check-updates - $(date -u '+%Y-%m-%d %H:%M UTC')"
echo " apps: ${APPS[*]}"
echo " node image for checks: $NODE_IMAGE"
echo "============================================================"

# ---------------------------------------------------------------------------
# 1. npm advisories + outdated, per app
# ---------------------------------------------------------------------------
echo
echo "## 1. npm packages (advisories + outdated)"
INNER='
  set +e
  cp /src/package.json /src/package-lock.json /work/ 2>/dev/null
  cd /work || exit 97
  npm ci --ignore-scripts --no-audit --no-fund --silent || exit 98
  echo "-- npm audit --"
  npm audit
  A=$?
  echo "-- npm outdated --"
  npm outdated
  O=$?
  echo "__STATUS__ audit=$A outdated=$O"
'
for app in "${APPS[@]}"; do
  echo
  echo "### $app"
  out="$(docker run --rm -v "$ROOT/$app:/src:ro" -w /work "$NODE_IMAGE" sh -c "$INNER" 2>&1)"
  printf '%s\n' "$out" | grep -v '^__STATUS__'
  line="$(printf '%s\n' "$out" | grep '^__STATUS__' | tail -1)"
  if [ -z "$line" ]; then
    echo "  !! could not complete checks for $app (see output above)"
    NEEDS=1
    continue
  fi
  a="$(printf '%s' "$line" | sed -n 's/.*audit=\([0-9]*\).*/\1/p')"; a="${a:-0}"
  o="$(printf '%s' "$line" | sed -n 's/.*outdated=\([0-9]*\).*/\1/p')"; o="${o:-0}"
  [ "$a" != "0" ] && { echo "  -> $app: security advisories found (details above)"; NEEDS=1; }
  [ "$o" != "0" ] && { echo "  -> $app: outdated packages listed above"; NEEDS=1; }
  [ "$a" = "0" ] && [ "$o" = "0" ] && echo "  -> $app: no advisories, nothing outdated"
done

# ---------------------------------------------------------------------------
# 2. Base image freshness: pinned digest vs current tag on the registry
# ---------------------------------------------------------------------------
echo
echo "## 2. Base image freshness"
if docker buildx version >/dev/null 2>&1; then
  for app in "${APPS[@]}"; do
    df="$ROOT/$app/Dockerfile"
    [ -f "$df" ] || { echo "  $app: no Dockerfile"; continue; }
    ref="$(grep -m1 '^FROM ' "$df" | awk '{print $2}')"
    tag="${ref%@*}"
    pinned=""
    case "$ref" in *@sha256:*) pinned="${ref#*@}" ;; esac
    echo
    echo "### $app  ($tag)"
    if [ -z "$pinned" ]; then
      echo "  !! not pinned by digest. Add @sha256:... to FROM for reproducible builds."
      NEEDS=1
    fi
    current="$(docker buildx imagetools inspect "$tag" 2>/dev/null | awk '/^Digest:/ {print $2; exit}')"
    if [ -z "$current" ]; then
      echo "  !! could not read the current digest for $tag (registry unreachable, rate-limited, or a buildx error)"
      continue
    fi
    if [ -n "$pinned" ] && [ "$pinned" = "$current" ]; then
      echo "  -> up to date ($current)"
    else
      echo "  -> newer image available"
      echo "       pinned:  ${pinned:-<none>}"
      echo "       current: $current"
      echo "       update:  FROM $tag@$current"
      NEEDS=1
    fi
  done
else
  echo "  (docker buildx not available; skipping base-image check)"
fi

# ---------------------------------------------------------------------------
# 3. Base image CVE scan (optional, heavier)
# ---------------------------------------------------------------------------
if [ "$IMAGE_SCAN" -eq 1 ]; then
  echo
  echo "## 3. Base image CVE scan (Trivy, HIGH/CRITICAL)"
  SCANNED=" "
  for app in "${APPS[@]}"; do
    df="$ROOT/$app/Dockerfile"
    [ -f "$df" ] || continue
    ref="$(grep -m1 '^FROM ' "$df" | awk '{print $2}')"
    case "$SCANNED" in *" $ref "*) continue ;; esac
    SCANNED="$SCANNED$ref "
    echo
    echo "### $ref"
    docker run --rm aquasec/trivy:latest image --quiet --severity HIGH,CRITICAL --exit-code 1 "$ref" || NEEDS=1
  done
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "============================================================"
if [ "$NEEDS" -eq 0 ]; then
  echo " SUMMARY: everything checked is up to date."
else
  echo " SUMMARY: some items need attention (see the -> lines above)."
  echo " Update in a fork, then review and test before merging."
fi
echo "============================================================"

[ "$STRICT" -eq 1 ] && exit "$NEEDS"
exit 0

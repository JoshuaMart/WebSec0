#!/usr/bin/env bash
# scan.sh — drive the WebSec0 API end-to-end.
#
#   Usage:
#     scan.sh <target> [--server URL] [--api-key KEY] [--wait SECONDS]
#                       [--format json|markdown|sarif] [--private]
#
#   Defaults:
#     --server      $WEBSEC0_SERVER or http://localhost:8080
#     --api-key     $WEBSEC0_API_KEY (omitted if empty)
#     --wait        60   (synchronous wait window, max 120)
#     --format      json
#
#   Exits non-zero on any error and writes a diagnostic to stderr.
#   Stdout receives only the scan body in the requested format.
#
#   Requires: bash, curl, jq.
set -euo pipefail

usage() {
  sed -n '2,16p' "$0"
}

SERVER="${WEBSEC0_SERVER:-http://localhost:8080}"
API_KEY="${WEBSEC0_API_KEY:-}"
WAIT_SECS=60
FORMAT=json
PRIVATE=false
TARGET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)  SERVER="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --wait)    WAIT_SECS="$2"; shift 2 ;;
    --format)  FORMAT="$2"; shift 2 ;;
    --private) PRIVATE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; TARGET="${1:-}"; shift; break ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *)  TARGET="$1"; shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "scan.sh: missing target" >&2
  usage >&2
  exit 2
fi
case "$FORMAT" in
  json|markdown|sarif) ;;
  *) echo "scan.sh: --format must be json|markdown|sarif" >&2; exit 2 ;;
esac
if [[ "$WAIT_SECS" -lt 0 || "$WAIT_SECS" -gt 120 ]]; then
  echo "scan.sh: --wait must be in [0,120]" >&2
  exit 2
fi

for tool in curl jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "scan.sh: $tool is required" >&2; exit 1; }
done

auth_header=()
if [[ -n "$API_KEY" ]]; then
  auth_header=(-H "Authorization: Bearer $API_KEY")
fi

# 1. Create the scan.
post_body=$(jq -n \
  --arg t "$TARGET" \
  --argjson w "$WAIT_SECS" \
  --argjson priv "$PRIVATE" \
  '{target:$t, options:{wait_seconds:$w, private:$priv}}')

resp_body=$(mktemp); trap 'rm -f "$resp_body"' EXIT
http_code=$(curl -sS -o "$resp_body" -w '%{http_code}' \
  -X POST "$SERVER/api/v1/scans" \
  -H 'content-type: application/json' \
  "${auth_header[@]}" \
  --data "$post_body")

# 2. Inspect the create response. The server returns 202 even for short
#    waits; if the scan completed inside the wait window, the body is
#    already the full report.
case "$http_code" in
  202|200) : ;;
  422) jq -r '"scan.sh: target blocked: \(.message // .code)"' "$resp_body" >&2; exit 3 ;;
  451) jq -r '"scan.sh: domain blocklisted: \(.message // .code)"' "$resp_body" >&2; exit 3 ;;
  429)
    code=$(jq -r '.code // ""' "$resp_body")
    case "$code" in
      cooldown)      echo "scan.sh: target on cooldown — try again in 5 min" >&2 ;;
      rate_limited)  echo "scan.sh: per-IP rate limit hit — back off" >&2 ;;
      abuse_flagged) echo "scan.sh: IP flagged for abuse — stop scanning" >&2 ;;
      *)             jq -r '.message // "rate limited"' "$resp_body" >&2 ;;
    esac
    exit 4 ;;
  401) echo "scan.sh: authentication required (set --api-key or \$WEBSEC0_API_KEY)" >&2; exit 5 ;;
  *)
    echo "scan.sh: unexpected HTTP $http_code from $SERVER/api/v1/scans" >&2
    head -c 1024 "$resp_body" >&2 || true
    exit 1
    ;;
esac

guid=$(jq -r '.id' "$resp_body")
private_token=$(jq -r '.private_token // ""' "$resp_body")
if [[ -z "$guid" || "$guid" == "null" ]]; then
  echo "scan.sh: server response missing id field" >&2
  head -c 1024 "$resp_body" >&2
  exit 1
fi
echo "scan.sh: scan id=$guid" >&2
if [[ -n "$private_token" ]]; then
  echo "scan.sh: private token (save this — not retrievable later): $private_token" >&2
fi

scan_auth=("${auth_header[@]}")
if [[ -n "$private_token" ]]; then
  scan_auth=(-H "Authorization: Bearer $private_token")
fi

status=$(jq -r '.status // ""' "$resp_body")

# 3. Poll until completed/failed, capped at 180 s past the synchronous
#    wait window. Backoff: 2 s → 5 s.
deadline=$(( $(date +%s) + 180 ))
while [[ "$status" != "completed" && "$status" != "failed" ]]; do
  if (( $(date +%s) >= deadline )); then
    echo "scan.sh: timed out waiting for scan completion (last status: $status)" >&2
    exit 6
  fi
  sleep 5
  http_code=$(curl -sS -o "$resp_body" -w '%{http_code}' \
    "${scan_auth[@]}" \
    "$SERVER/api/v1/scans/$guid")
  if [[ "$http_code" != "200" ]]; then
    echo "scan.sh: poll returned HTTP $http_code" >&2
    exit 1
  fi
  status=$(jq -r '.status // ""' "$resp_body")
done

if [[ "$status" == "failed" ]]; then
  jq -r '"scan.sh: scan failed: \(.error.message // "unknown error")"' "$resp_body" >&2
  exit 7
fi

# 4. Emit the requested format.
case "$FORMAT" in
  json)
    cat "$resp_body"
    ;;
  markdown)
    curl -sS --fail-with-body "${scan_auth[@]}" \
      -H 'accept: text/markdown' \
      "$SERVER/api/v1/scans/$guid/markdown"
    ;;
  sarif)
    curl -sS --fail-with-body "${scan_auth[@]}" \
      -H 'accept: application/sarif+json' \
      "$SERVER/api/v1/scans/$guid/sarif"
    ;;
esac

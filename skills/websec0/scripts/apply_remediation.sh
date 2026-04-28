#!/usr/bin/env bash
# apply_remediation.sh — pick a remediation snippet for a given stack.
#
#   Usage:
#     apply_remediation.sh --finding ID --stack STACK \
#                          (--file PATH | --scan GUID)
#                          [--server URL] [--api-key KEY]
#
#     --finding ID    Finding ID (e.g. HEADER-CSP-MISSING)
#     --stack STACK   Stack key (nginx, apache, caddy, haproxy, cloudflare,
#                     express_helmet, spring_boot, iis_web_config, …)
#     --file PATH     Path to a saved scan JSON (output of scan.sh --format json)
#     --scan GUID     Live scan ID — fetched from --server
#     --server URL    Default: $WEBSEC0_SERVER or http://localhost:8080
#     --api-key KEY   Default: $WEBSEC0_API_KEY
#
#   Stdout: the snippet alone (no banner, no trailing newline trickery).
#   Stderr: diagnostics. Exits non-zero if the finding or the stack key
#   is not present.
#
#   Requires: bash, jq, curl (only with --scan).
set -euo pipefail

usage() {
  sed -n '2,20p' "$0"
}

FINDING=""
STACK=""
FILE=""
SCAN=""
SERVER="${WEBSEC0_SERVER:-http://localhost:8080}"
API_KEY="${WEBSEC0_API_KEY:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --finding) FINDING="$2"; shift 2 ;;
    --stack)   STACK="$2"; shift 2 ;;
    --file)    FILE="$2"; shift 2 ;;
    --scan)    SCAN="$2"; shift 2 ;;
    --server)  SERVER="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$FINDING" || -z "$STACK" ]]; then
  echo "apply_remediation.sh: --finding and --stack are required" >&2
  usage >&2
  exit 2
fi
if [[ -z "$FILE" && -z "$SCAN" ]]; then
  echo "apply_remediation.sh: pass either --file or --scan" >&2
  exit 2
fi
if [[ -n "$FILE" && -n "$SCAN" ]]; then
  echo "apply_remediation.sh: --file and --scan are mutually exclusive" >&2
  exit 2
fi
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

# Resolve the scan body into a single JSON document on stdin of jq.
if [[ -n "$FILE" ]]; then
  if [[ ! -r "$FILE" ]]; then
    echo "apply_remediation.sh: cannot read $FILE" >&2
    exit 1
  fi
  scan_input=("$FILE")
else
  command -v curl >/dev/null 2>&1 || { echo "curl is required for --scan" >&2; exit 1; }
  auth_header=()
  if [[ -n "$API_KEY" ]]; then
    auth_header=(-H "Authorization: Bearer $API_KEY")
  fi
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  http_code=$(curl -sS -o "$tmp" -w '%{http_code}' \
    "${auth_header[@]}" \
    "$SERVER/api/v1/scans/$SCAN")
  if [[ "$http_code" != "200" ]]; then
    echo "apply_remediation.sh: GET /api/v1/scans/$SCAN returned HTTP $http_code" >&2
    exit 1
  fi
  scan_input=("$tmp")
fi

# Try `findings[]` first (full scan body), then a single-finding shape.
finding_json=$(jq --arg id "$FINDING" '
  if has("findings") then
    (.findings[] | select(.id == $id))
  elif .id == $id then
    .
  else
    empty
  end
' "${scan_input[@]}")

if [[ -z "$finding_json" ]]; then
  echo "apply_remediation.sh: finding $FINDING not present in the scan" >&2
  exit 1
fi

# Pull the snippet. Fall back to a clear error listing the keys we *do*
# have rather than punting to the caller.
snippet=$(jq -r --arg s "$STACK" '
  if (.remediation.snippets // {}) | has($s) then
    .remediation.snippets[$s]
  else
    empty
  end
' <<<"$finding_json")

if [[ -z "$snippet" ]]; then
  available=$(jq -r '.remediation.snippets // {} | keys | join(", ")' <<<"$finding_json")
  if [[ -z "$available" ]]; then
    echo "apply_remediation.sh: $FINDING has no remediation snippets at all" >&2
  else
    echo "apply_remediation.sh: $FINDING has no snippet for stack '$STACK'" >&2
    echo "  available stacks: $available" >&2
  fi
  exit 1
fi

# Snippets are stored as raw text — print verbatim, no quoting.
printf '%s\n' "$snippet"

#!/usr/bin/env bash
# safe-request.sh — Send a single authenticated request to the authorized target.
#
# Enforces scope: refuses to send requests to any host other than
# bounty.cryptobox.com. Verifies the final URL after redirects.
# Redacts sensitive headers from output.
#
# Usage:
#   bash safe-request.sh <method> <path> [cookie_file] [body]
#
# Examples:
#   bash safe-request.sh GET /api/me /tmp/session_a.cookie
#   bash safe-request.sh POST /api/workspaces /tmp/session_a.cookie '{"name":"test"}'

set -euo pipefail

AUTHORIZED_ORIGIN="https://bounty.cryptobox.com"
AUTHORIZED_HOST="bounty.cryptobox.com"

METHOD="${1:?Usage: safe-request.sh <METHOD> <PATH> [COOKIE_FILE] [BODY]}"
PATH_ARG="${2:?Usage: safe-request.sh <METHOD> <PATH> [COOKIE_FILE] [BODY]}"
COOKIE_FILE="${3:-}"
BODY="${4:-}"

FULL_URL="${AUTHORIZED_ORIGIN}${PATH_ARG}"

# Validate the URL is on the authorized origin
if ! echo "$FULL_URL" | grep -qE "^https://${AUTHORIZED_HOST}(/|$)"; then
    echo "ERROR: URL $FULL_URL is not on the authorized origin ($AUTHORIZED_ORIGIN)."
    echo "Refusing to send request."
    exit 1
fi

# Build curl arguments
CURL_ARGS=(
    -sS
    --max-time 30
    -X "$METHOD"
    -w "\n--- Response Info ---\nHTTP Status: %{http_code}\nFinal URL: %{url_effective}\nTime: %{time_total}s\nSize: %{size_download} bytes\n"
)

if [ -n "$COOKIE_FILE" ] && [ -f "$COOKIE_FILE" ]; then
    CURL_ARGS+=(-b "$COOKIE_FILE" -c "$COOKIE_FILE")
fi

if [ -n "$BODY" ]; then
    CURL_ARGS+=(-H "Content-Type: application/json" -d "$BODY")
fi

# Do NOT follow redirects automatically — check them manually
CURL_ARGS+=(--max-redirs 0)

# Execute
RESPONSE=$(curl "${CURL_ARGS[@]}" "$FULL_URL" 2>&1) || true

# Check if we were redirected off-origin
FINAL_URL=$(echo "$RESPONSE" | grep "^Final URL:" | sed 's/Final URL: //')
if [ -n "$FINAL_URL" ] && ! echo "$FINAL_URL" | grep -qE "^https://${AUTHORIZED_HOST}(/|$)"; then
    echo "WARNING: Response indicates redirect to off-origin URL: $FINAL_URL"
    echo "Refusing to follow. The redirect target is outside the authorized scope."
    echo ""
fi

# Redact sensitive values from output
REDACTED=$(echo "$RESPONSE" \
    | sed -E 's/(Authorization|Cookie|Set-Cookie|X-Auth-Token|X-CSRF-Token):\s*.*/\1: [REDACTED]/gi' \
    | sed -E 's/"(password|token|secret|key|session_id|access_token|refresh_token)"\s*:\s*"[^"]*"/"\1": "[REDACTED]"/gi')

echo "$REDACTED"

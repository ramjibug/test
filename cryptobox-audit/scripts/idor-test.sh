#!/usr/bin/env bash
# idor-test.sh — Test a single endpoint for IDOR by comparing responses
# between two authenticated sessions.
#
# Sends the same request using Account A's session and Account B's session,
# then compares the HTTP status codes. A successful response from the
# non-owning account indicates a potential IDOR.
#
# Usage:
#   bash idor-test.sh <path> <owner_cookie> <other_cookie> [method] [body]
#
# Example:
#   bash idor-test.sh "/api/workspaces/WS123/files" \
#       /tmp/session_a.cookie /tmp/session_b.cookie GET

set -euo pipefail

AUTHORIZED_ORIGIN="https://bounty.cryptobox.com"
AUTHORIZED_HOST="bounty.cryptobox.com"

PATH_ARG="${1:?Usage: idor-test.sh <PATH> <OWNER_COOKIE> <OTHER_COOKIE> [METHOD] [BODY]}"
OWNER_COOKIE="${2:?Provide the owning account's cookie file}"
OTHER_COOKIE="${3:?Provide the non-owning account's cookie file}"
METHOD="${4:-GET}"
BODY="${5:-}"

FULL_URL="${AUTHORIZED_ORIGIN}${PATH_ARG}"

# Scope check
if ! echo "$FULL_URL" | grep -qE "^https://${AUTHORIZED_HOST}(/|$)"; then
    echo "ERROR: URL is not on the authorized origin. Aborting."
    exit 1
fi

echo "=== IDOR Test ==="
echo "Endpoint: $METHOD $PATH_ARG"
echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo ""

CURL_BASE=(
    -sS
    --max-time 30
    -X "$METHOD"
    --max-redirs 0
    -o /dev/null
    -w "%{http_code}"
)

if [ -n "$BODY" ]; then
    CURL_BASE+=(-H "Content-Type: application/json" -d "$BODY")
fi

# Request as owner
echo -n "Owner account (expected: 200): "
OWNER_STATUS=$(curl "${CURL_BASE[@]}" -b "$OWNER_COOKIE" "$FULL_URL" 2>/dev/null || echo "ERR")
echo "HTTP $OWNER_STATUS"

# Brief pause to avoid looking like automated scanning
sleep 1

# Request as non-owner
echo -n "Other account (expected: 403/404): "
OTHER_STATUS=$(curl "${CURL_BASE[@]}" -b "$OTHER_COOKIE" "$FULL_URL" 2>/dev/null || echo "ERR")
echo "HTTP $OTHER_STATUS"

# Request unauthenticated
echo -n "Unauthenticated (expected: 401/403): "
UNAUTH_STATUS=$(curl "${CURL_BASE[@]}" "$FULL_URL" 2>/dev/null || echo "ERR")
echo "HTTP $UNAUTH_STATUS"

echo ""
echo "--- Analysis ---"

if [ "$OWNER_STATUS" = "ERR" ]; then
    echo "BLOCKED: Could not reach the endpoint. Check network connectivity."
elif [ "$OWNER_STATUS" -ge 200 ] && [ "$OWNER_STATUS" -lt 300 ]; then
    if [ "$OTHER_STATUS" -ge 200 ] && [ "$OTHER_STATUS" -lt 300 ]; then
        echo "POTENTIAL IDOR: Non-owning account received HTTP $OTHER_STATUS."
        echo "Requires manual verification — inspect the response body to confirm"
        echo "the non-owner received the owner's data (not a generic/empty 200)."
    else
        echo "OK: Non-owning account was denied (HTTP $OTHER_STATUS)."
    fi

    if [ "$UNAUTH_STATUS" -ge 200 ] && [ "$UNAUTH_STATUS" -lt 300 ]; then
        echo "POTENTIAL ISSUE: Unauthenticated request received HTTP $UNAUTH_STATUS."
        echo "The endpoint may not require authentication."
    fi
else
    echo "NOTE: Owner account received HTTP $OWNER_STATUS (not 2xx)."
    echo "The endpoint may require different parameters or the path may be wrong."
fi

echo ""
echo "=== Test complete ==="

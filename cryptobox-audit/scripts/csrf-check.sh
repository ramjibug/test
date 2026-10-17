#!/usr/bin/env bash
# csrf-check.sh — Check whether a state-changing endpoint has CSRF protection.
#
# Inspects: anti-CSRF tokens in forms/responses, SameSite cookie attributes,
# CORS headers, and whether the server validates Origin/Referer.
#
# Usage:
#   bash csrf-check.sh <path> <cookie_file> [body]
#
# Example:
#   bash csrf-check.sh "/api/workspaces/WS123/members" /tmp/session_a.cookie \
#       '{"email":"test@test.com","role":"viewer"}'

set -euo pipefail

AUTHORIZED_ORIGIN="https://bounty.cryptobox.com"
AUTHORIZED_HOST="bounty.cryptobox.com"

PATH_ARG="${1:?Usage: csrf-check.sh <PATH> <COOKIE_FILE> [BODY]}"
COOKIE_FILE="${2:?Provide a cookie file}"
BODY="${3:-'{}'}"

FULL_URL="${AUTHORIZED_ORIGIN}${PATH_ARG}"

if ! echo "$FULL_URL" | grep -qE "^https://${AUTHORIZED_HOST}(/|$)"; then
    echo "ERROR: URL is not on the authorized origin. Aborting."
    exit 1
fi

echo "=== CSRF Protection Check ==="
echo "Endpoint: POST $PATH_ARG"
echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo ""

# Check 1: SameSite cookie attribute
echo "[1/4] Cookie SameSite attribute..."
COOKIES=$(cat "$COOKIE_FILE" 2>/dev/null || echo "")
# Also check Set-Cookie headers from a fresh request
SET_COOKIE=$(curl -sS -I --max-time 15 -b "$COOKIE_FILE" \
    "$AUTHORIZED_ORIGIN/" 2>/dev/null \
    | grep -i "^set-cookie:" || echo "")

if echo "$SET_COOKIE" | grep -qi "samesite=strict"; then
    echo "  SameSite=Strict found — strong CSRF protection via cookies."
elif echo "$SET_COOKIE" | grep -qi "samesite=lax"; then
    echo "  SameSite=Lax found — protects GET-based CSRF but not POST from subdomains."
elif echo "$SET_COOKIE" | grep -qi "samesite=none"; then
    echo "  SameSite=None — cookies sent cross-origin. CSRF protection depends on other mechanisms."
else
    echo "  No SameSite attribute detected in Set-Cookie headers."
    echo "  [REDACTED cookie values from output]"
fi

# Check 2: CORS preflight
echo "[2/4] CORS preflight response..."
CORS_HEADERS=$(curl -sS -I --max-time 15 \
    -X OPTIONS \
    -H "Origin: https://evil.example.com" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: Content-Type" \
    "$FULL_URL" 2>/dev/null || echo "")

ACAO=$(echo "$CORS_HEADERS" | grep -i "^access-control-allow-origin:" || echo "not present")
ACAC=$(echo "$CORS_HEADERS" | grep -i "^access-control-allow-credentials:" || echo "not present")

echo "  Access-Control-Allow-Origin: $ACAO"
echo "  Access-Control-Allow-Credentials: $ACAC"

if echo "$ACAO" | grep -qi "evil.example.com"; then
    echo "  WARNING: Server reflects arbitrary origins — CORS misconfiguration."
elif echo "$ACAO" | grep -qi "\*"; then
    echo "  NOTE: Wildcard origin. If credentials are not allowed, CSRF via fetch is blocked."
else
    echo "  OK — arbitrary origin not reflected."
fi

# Check 3: Origin/Referer validation
echo "[3/4] Origin header validation..."
# Send a POST with a wrong Origin header
WRONG_ORIGIN_STATUS=$(curl -sS -o /dev/null -w "%{http_code}" \
    --max-time 15 \
    -X POST \
    -b "$COOKIE_FILE" \
    -H "Content-Type: application/json" \
    -H "Origin: https://evil.example.com" \
    -d "$BODY" \
    "$FULL_URL" 2>/dev/null || echo "ERR")

CORRECT_ORIGIN_STATUS=$(curl -sS -o /dev/null -w "%{http_code}" \
    --max-time 15 \
    -X POST \
    -b "$COOKIE_FILE" \
    -H "Content-Type: application/json" \
    -H "Origin: $AUTHORIZED_ORIGIN" \
    -d "$BODY" \
    "$FULL_URL" 2>/dev/null || echo "ERR")

echo "  With Origin: evil.example.com → HTTP $WRONG_ORIGIN_STATUS"
echo "  With Origin: $AUTHORIZED_ORIGIN → HTTP $CORRECT_ORIGIN_STATUS"

if [ "$WRONG_ORIGIN_STATUS" = "ERR" ]; then
    echo "  BLOCKED: Cannot reach endpoint."
elif [ "$WRONG_ORIGIN_STATUS" -ge 400 ] && [ "$CORRECT_ORIGIN_STATUS" -lt 400 ]; then
    echo "  OK — Server rejects requests with incorrect Origin."
elif [ "$WRONG_ORIGIN_STATUS" -lt 400 ] && [ "$CORRECT_ORIGIN_STATUS" -lt 400 ]; then
    echo "  POTENTIAL ISSUE: Server accepted request with foreign Origin."
    echo "  Check whether an anti-CSRF token provides additional protection."
fi

# Check 4: Anti-CSRF token in response
echo "[4/4] Anti-CSRF token presence..."
PAGE_BODY=$(curl -sS --max-time 15 -b "$COOKIE_FILE" \
    "$AUTHORIZED_ORIGIN/" 2>/dev/null || echo "")

if echo "$PAGE_BODY" | grep -qiE '(csrf|xsrf|_token|authenticity_token)'; then
    echo "  Anti-CSRF token reference found in page body."
else
    echo "  No obvious anti-CSRF token found in the main page."
    echo "  The application may use a header-based or double-submit approach."
fi

echo ""
echo "=== Check complete ==="

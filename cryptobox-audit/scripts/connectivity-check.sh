#!/usr/bin/env bash
# Connectivity check for the authorized Cryptobox bounty target.
# Does NOT perform security testing. Only verifies that the network
# policy allows HTTPS to the authorized host.

set -euo pipefail

AUTHORIZED_ORIGIN="https://bounty.cryptobox.com"
AUTHORIZED_HOST="bounty.cryptobox.com"
LOG_FILE="/tmp/claude-0/-home-user-test/84c2f1a6-178f-5df7-a9dd-88f58c3d7f81/scratchpad/connectivity-check.log"

mkdir -p "$(dirname "$LOG_FILE")"

echo "=== Cryptobox Bounty Connectivity Check ==="
echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Target: $AUTHORIZED_ORIGIN"
echo ""

# Step 1: DNS resolution
echo "[1/4] DNS resolution..."
if host "$AUTHORIZED_HOST" > /dev/null 2>&1; then
    echo "  OK — $AUTHORIZED_HOST resolves."
elif nslookup "$AUTHORIZED_HOST" > /dev/null 2>&1; then
    echo "  OK — $AUTHORIZED_HOST resolves (nslookup)."
else
    echo "  FAIL — $AUTHORIZED_HOST does not resolve. Check DNS."
fi

# Step 2: TCP connectivity through proxy
echo "[2/4] HTTPS connectivity through agent proxy..."
HTTP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
    --max-time 15 "$AUTHORIZED_ORIGIN" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "000" ]; then
    echo "  FAIL — connection refused or timed out (HTTP 000)."
    echo "  The egress proxy is likely blocking $AUTHORIZED_HOST."
    echo "  Add $AUTHORIZED_HOST to the environment's Allowed domains."
    echo ""
    echo "  Proxy status:"
    curl -sS "${HTTPS_PROXY:-http://127.0.0.1:39433}/__agentproxy/status" 2>/dev/null \
        | grep -o '"recentRelayFailures":\[.*\]' || echo "  (could not read proxy status)"
elif [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 400 ]; then
    echo "  OK — received HTTP $HTTP_CODE."
elif [ "$HTTP_CODE" -ge 300 ] && [ "$HTTP_CODE" -lt 400 ]; then
    REDIRECT=$(curl -sS -o /dev/null -w "%{redirect_url}" \
        --max-time 15 "$AUTHORIZED_ORIGIN" 2>/dev/null)
    echo "  REDIRECT — HTTP $HTTP_CODE to $REDIRECT"
    # Verify redirect stays on the authorized origin
    if echo "$REDIRECT" | grep -q "^https://$AUTHORIZED_HOST"; then
        echo "  OK — redirect stays on authorized origin."
    else
        echo "  WARNING — redirect leaves the authorized origin: $REDIRECT"
        echo "  Do NOT follow this redirect for security testing."
    fi
else
    echo "  RECEIVED — HTTP $HTTP_CODE (may indicate a login page or error)."
fi

# Step 3: TLS certificate check
echo "[3/4] TLS certificate..."
CERT_INFO=$(echo | openssl s_client -connect "$AUTHORIZED_HOST:443" \
    -servername "$AUTHORIZED_HOST" 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates 2>/dev/null || echo "FAIL")

if echo "$CERT_INFO" | grep -q "subject="; then
    echo "  $CERT_INFO" | head -3
else
    echo "  FAIL — could not retrieve TLS certificate (proxy may be blocking)."
fi

# Step 4: Response headers (security-relevant, no sensitive data)
echo "[4/4] Response headers..."
if [ "$HTTP_CODE" != "000" ]; then
    HEADERS=$(curl -sS -I --max-time 15 "$AUTHORIZED_ORIGIN" 2>/dev/null)
    for HDR in "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" \
               "Strict-Transport-Security" "X-XSS-Protection" "Set-Cookie"; do
        VALUE=$(echo "$HEADERS" | grep -i "^$HDR:" | head -1)
        if [ -n "$VALUE" ]; then
            # Redact cookie values
            if echo "$VALUE" | grep -qi "set-cookie"; then
                echo "  $HDR: [REDACTED — cookie present]"
            else
                echo "  $VALUE"
            fi
        else
            echo "  $HDR: not present"
        fi
    done
else
    echo "  Skipped — no connectivity."
fi

echo ""
echo "=== Check complete ==="
echo "Results logged to: $LOG_FILE"

# Log results (without sensitive data)
{
    echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "Target: $AUTHORIZED_ORIGIN"
    echo "HTTP Status: $HTTP_CODE"
    echo "DNS: $(host "$AUTHORIZED_HOST" 2>/dev/null | head -1 || echo 'failed')"
} > "$LOG_FILE"

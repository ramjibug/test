# Cryptobox Bug Bounty — Environment Status

**Audit start:** 2026-10-17 10:59 UTC
**Authorized origin:** `https://bounty.cryptobox.com`
**Program platform:** YesWeHack

---

## Current connectivity status

| Check | Result |
|---|---|
| Target host | `bounty.cryptobox.com:443` |
| HTTPS CONNECT | **BLOCKED — HTTP 403** from egress proxy |
| Proxy type | Agent proxy at `127.0.0.1:39433` (selective=false, toolScoped=false) |
| Failure kind | `connect_rejected` — gateway policy denial |
| Failure timestamp | 2026-10-17T10:59:47.410Z |

The cloud container's network policy does not include `bounty.cryptobox.com` in its
allowed-hosts list. All outbound HTTPS to this host is refused before a TLS handshake
occurs.

## Recommended fix

Add **only** the authorized hostname to the environment's network allowlist:

1. Open the cloud environment menu (session title bar).
2. Select **Edit** on the current environment.
3. Under **Network access**, choose the **Limited** level.
4. Under **Allowed domains**, add: `bounty.cryptobox.com`
5. Leave the **Allow package managers** box ticked (for tooling dependencies).
6. Save and restart the session.

Do **not** set unrestricted network access. The program prohibits testing any host
other than `bounty.cryptobox.com`, so a narrow allowlist enforces scope compliance
at the infrastructure level.

Reference: <https://code.claude.com/docs/en/cloud-environments#network-access>

## Verifying access after the allowlist update

Run the connectivity check script:

```bash
bash cryptobox-audit/scripts/connectivity-check.sh
```

Or manually:

```bash
curl -sS -o /dev/null -w "HTTP %{http_code} in %{time_total}s\n" \
  --max-time 15 "https://bounty.cryptobox.com"
```

Expected result: `HTTP 200` (or `HTTP 302` redirecting to a login page on the same origin).

## Tools available in this environment

| Tool | Path | Available |
|---|---|---|
| curl | `/usr/bin/curl` | Yes |
| wget | `/usr/bin/wget` | Yes |
| python3 | Check `/usr/bin/python3` | To verify |
| jq | Check `/usr/bin/jq` | To verify |
| nmap | — | No |
| nikto | — | No |
| sqlmap | — | No |
| Burp Suite / ZAP | — | No |
| Browser (Chromium) | `/opt/pw-browsers/chromium` | Headless only via Playwright |

### Limitations

- **No GUI browser.** DOM-based XSS and client-side logic must be tested via headless
  Chromium (Playwright) or by inspecting JavaScript source and curl responses.
- **No interception proxy.** Request tampering relies on curl with manually crafted
  headers and bodies. This is sufficient for IDOR, CSRF, injection, and access-control
  tests but slower than a proxy workflow.
- **No scanning tools.** All testing is manual and hypothesis-driven, which aligns with
  the program's prohibition on brute force and high-volume scanning.

## Authentication setup (when accounts are available)

The program provides each hunter with two test accounts on the bounty platform.

**Do not paste credentials into files, logs, chat messages, or scripts.**

Recommended procedure:

1. Set credentials as environment variables in the shell session (not persisted):
   ```bash
   read -rs ACCOUNT_A_PASS  # type password, press Enter
   read -rs ACCOUNT_B_PASS
   export ACCOUNT_A_USER="<email-when-known>"
   export ACCOUNT_B_USER="<email-when-known>"
   ```
2. Authenticate using the application's login endpoint (to be discovered during recon):
   ```bash
   # Example — actual endpoint TBD during reconnaissance
   curl -sS -c /tmp/session_a.cookie -X POST \
     "https://bounty.cryptobox.com/api/auth/login" \
     -H "Content-Type: application/json" \
     -d "{\"email\":\"$ACCOUNT_A_USER\",\"password\":\"$ACCOUNT_A_PASS\"}"
   ```
3. Store session cookies in temporary files (`/tmp/session_a.cookie`,
   `/tmp/session_b.cookie`) that are not committed to version control.
4. Verify the session:
   ```bash
   curl -sS -b /tmp/session_a.cookie "https://bounty.cryptobox.com/api/me"
   ```

**Note:** The actual login endpoint, parameter names, and session mechanism are unknown
until reconnaissance. The examples above are placeholders — do not assume they are correct.

## Prohibited targets

The following are **out of scope** and must never receive test traffic:

- `admin.bounty.cryptobox.com`
- Any other `*.cryptobox.com` subdomain
- Any `*.ercom.fr` host
- Cloud metadata endpoints (`169.254.169.254`, etc.)
- Internal network ranges
- Any third-party service referenced by the application

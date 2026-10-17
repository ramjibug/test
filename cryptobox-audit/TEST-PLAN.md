# Cryptobox Bug Bounty — Test Plan

**Target:** `https://bounty.cryptobox.com`
**Program:** YesWeHack Cryptobox Bug Bounty
**Status:** PREPARATION ONLY — no active testing performed
**Date:** 2026-10-17

---

## Table of contents

1. [Scope and rules summary](#1-scope-and-rules-summary)
2. [Reconnaissance phase](#2-reconnaissance-phase)
3. [Priority 1 — Trustee and account-recovery security](#3-priority-1--trustee-and-account-recovery-security)
4. [Priority 2 — Cross-account file and workspace authorization](#4-priority-2--cross-account-file-and-workspace-authorization)
5. [Priority 3 — Workspace role enforcement and privilege escalation](#5-priority-3--workspace-role-enforcement-and-privilege-escalation)
6. [Priority 4 — Sharing-key validation and access controls](#6-priority-4--sharing-key-validation-and-access-controls)
7. [Priority 5 — File-history integrity and unauthorized restoration](#7-priority-5--file-history-integrity-and-unauthorized-restoration)
8. [Priority 6 — Device-key exposure and key-to-account binding](#8-priority-6--device-key-exposure-and-key-to-account-binding)
9. [Priority 7 — Authentication and object-ownership confusion](#9-priority-7--authentication-and-object-ownership-confusion)
10. [Priority 8 — XSS, injection, CSRF, SSRF, and input-handling issues](#10-priority-8--xss-injection-csrf-ssrf-and-input-handling-issues)
11. [Priority 9 — Additional business-logic weaknesses](#11-priority-9--additional-business-logic-weaknesses)
12. [Coverage tracking](#12-coverage-tracking)

---

## 1. Scope and rules summary

### In-scope assets

| Asset | Type | Notes |
|---|---|---|
| `https://bounty.cryptobox.com` | Web application | Primary target |
| Cryptobox Android app | Mobile (via bounty env) | Only against the bounty instance |
| Cryptobox iOS app | Mobile (via bounty env) | Only against the bounty instance |

### Prohibited targets

- `admin.bounty.cryptobox.com`
- Other `*.cryptobox.com` subdomains
- Any `*.ercom.fr` hosts
- All other infrastructure

### Test accounts

Two hunter-controlled accounts per the program rules. All testing uses only these
accounts and synthetic data created within them. Never target another hunter's account.

### Qualifying vulnerability categories (from program description)

1. Access to files in a workspace the user is not authorized to access.
2. Access to a shared file without knowledge of the sharing key.
3. Unauthorized alteration of file history.
4. Permission bypass in workspace collaboration.
5. Private device-key exposure to unauthorized accounts.
6. Authentication bypass.
7. Account-recovery / trustee mechanism weaknesses.
8. Cross-account object confusion.
9. XSS with demonstrated execution context.
10. SQL injection with demonstrated database interaction.
11. CSRF on security-sensitive state changes.
12. SSRF / XXE / LFI where actual server-side operations occur.
13. Business-logic violations affecting confidentiality, integrity, authentication,
    or authorization.

### Explicit exclusions (do not pursue)

- Authenticated user enumeration (emails, names, public certificates)
- Unauthenticated account-existence checks
- File extraction by viewers through the browser
- Sharing malicious files with other users
- Acknowledging a download without downloading
- Downloading without acknowledging / circumventing unique-download limits
- Denial of service, missing rate limits, brute force
- Reusing authentication session IDs from another context
- Accessing a shared file through a valid sharing link after deletion
- Tabnabbing
- Outdated dependencies without demonstrated impact
- Stack traces, path disclosure, version disclosure without direct impact
- Password policy complaints
- Autocomplete attributes
- Email / SMS / message flooding
- Physical-access scenarios
- Recent zero-days (<30 days post-patch)
- Theoretical weaknesses without PoC

### Safety rules

- No DoS, brute force, rate-limit attacks, or stress testing.
- No social engineering against any person.
- No data modification in accounts other than the two test accounts.
- Max 1 GB data per account; prefer tiny synthetic test files.
- No extraction of large data volumes, credentials, or PII.
- If sensitive data is found: stop, record minimum evidence, redact.
- No stealth techniques, identity rotation, or monitoring evasion.
- No destructive payloads or commands on out-of-scope systems.
- No fabricated test results.

---

## 2. Reconnaissance phase

**Status: NOT STARTED — requires network access**

### Objectives

Map the application's authenticated and unauthenticated surfaces from the authorized
origin only. Produce an endpoint inventory.

### Tasks

| # | Task | Method | Status |
|---|---|---|---|
| R1 | Load the application root and identify the technology stack | curl + response headers | NOT TESTED |
| R2 | Identify the login/authentication mechanism | Browser or curl to login page | NOT TESTED |
| R3 | Authenticate with Account A and capture the session mechanism | Login flow | NOT TESTED |
| R4 | Enumerate visible navigation and functional areas | Authenticated browsing | NOT TESTED |
| R5 | Inspect JavaScript bundles for API route definitions | Source inspection | NOT TESTED |
| R6 | Map API endpoints from network traffic during normal use | Headless Chromium / curl | NOT TESTED |
| R7 | Identify object identifier formats (workspace IDs, file IDs, user IDs, sharing keys) | Response inspection | NOT TESTED |
| R8 | Determine role model (owner, admin, member, viewer, etc.) | Application UI + API responses | NOT TESTED |
| R9 | Identify the deposit-box feature and its availability | Feature exploration | NOT TESTED |
| R10 | Identify device-registration and key-management surfaces | Account settings | NOT TESTED |
| R11 | Identify trustee / account-recovery configuration | Account settings | NOT TESTED |
| R12 | Identify file-sharing and external-link creation flows | Workspace operations | NOT TESTED |
| R13 | Document all identified API endpoints with auth requirements | Compilation | NOT TESTED |

### Questions to resolve during reconnaissance

- What authentication mechanism is used (session cookies, JWT, OAuth, certificate-based)?
- What are the exact API base paths?
- What object identifier format does the application use (UUIDs, sequential integers, hashes)?
- How are sharing keys structured and transmitted (URL fragment, query parameter, request body)?
- What roles exist and how are they assigned?
- Is the deposit-box feature enabled on the bounty instance?
- How does device registration work (browser-based keys, mobile app keys)?
- What is the trustee invitation and recovery flow?
- Are there WebSocket connections for real-time features?

---

## 3. Priority 1 — Trustee and account-recovery security

### Context

Cryptobox supports a trustee-based account recovery mechanism. A user can designate
trustees who can assist in recovering their account. This involves cryptographic key
escrow or split-knowledge schemes.

### Test cases

| ID | Test | Procedure | Status |
|---|---|---|---|
| T1.1 | Recovery request cross-account binding | Using Account A, initiate recovery. Inspect whether the recovery token or flow can be bound to Account B instead. | NOT TESTED |
| T1.2 | Trustee designation without consent | From Account A, attempt to designate Account B as a trustee without B's explicit acceptance. | NOT TESTED |
| T1.3 | Trustee removal authorization | As Account B (trustee), attempt to remove self or alter trustee relationship of Account A without A's authorization. | NOT TESTED |
| T1.4 | Recovery token reuse | After a successful recovery, verify that the token/link is invalidated and cannot be replayed. | NOT TESTED |
| T1.5 | Recovery flow state confusion | Start a recovery flow, then attempt to alter the target account mid-flow by modifying identifiers in requests. | NOT TESTED |
| T1.6 | Credential change during active recovery | While a recovery is pending, test whether Account A's credentials can be changed by the recovery flow targeting a different account. | NOT TESTED |
| T1.7 | Trustee key material exposure | Inspect whether the trustee flow exposes key material, recovery secrets, or tokens in responses visible to unauthorized parties. | NOT TESTED |

See `HYPOTHESES.md` for detailed hypothesis documentation per test.

---

## 4. Priority 2 — Cross-account file and workspace authorization

### Context

Cryptobox organizes files into workspaces. Each workspace has members with specific
roles. Files, directories, and versions should only be accessible to authorized members.

### Test cases

| ID | Test | Procedure | Status |
|---|---|---|---|
| A1.1 | Direct file access with another user's file ID | Create a file in Account A's workspace. As Account B (not a member), request the file by its ID. | NOT TESTED |
| A1.2 | Direct workspace access with another user's workspace ID | As Account B, request Account A's workspace by ID. | NOT TESTED |
| A1.3 | Directory listing cross-workspace | As Account B, request a directory listing of Account A's workspace. | NOT TESTED |
| A1.4 | File download cross-workspace | As Account B, attempt to download a file from Account A's private workspace. | NOT TESTED |
| A1.5 | File upload to another user's workspace | As Account B, attempt to upload a file to Account A's workspace. | NOT TESTED |
| A1.6 | File deletion cross-workspace | As Account B, attempt to delete a file in Account A's workspace. | NOT TESTED |
| A1.7 | File move cross-workspace | As Account B, attempt to move a file from Account A's workspace to Account B's. | NOT TESTED |
| A1.8 | Workspace metadata read cross-account | As Account B, attempt to read Account A's workspace metadata (name, settings, members). | NOT TESTED |
| A1.9 | Sequential ID enumeration (if applicable) | If IDs are sequential, test whether incrementing/decrementing reveals other users' objects. | NOT TESTED |

---

## 5. Priority 3 — Workspace role enforcement and privilege escalation

### Context

Workspaces support multiple roles (likely: owner, administrator, member, viewer).
Authorization should be enforced server-side for every operation.

### Test cases

| ID | Test | Procedure | Status |
|---|---|---|---|
| P1.1 | Viewer performs write operations | Add Account B to Account A's workspace as a viewer. As B, attempt file upload, edit, delete. | NOT TESTED |
| P1.2 | Member performs admin operations | Add Account B as a member. As B, attempt to add/remove other members, change roles, modify workspace settings. | NOT TESTED |
| P1.3 | Removed member retains access | Remove Account B from a workspace. Verify B can no longer access any workspace resource using previously captured requests. | NOT TESTED |
| P1.4 | Role downgrade enforcement | Downgrade Account B from admin to viewer. Verify all admin operations are immediately rejected. | NOT TESTED |
| P1.5 | Self-promotion | As Account B (member or viewer), attempt to change own role to admin or owner via API. | NOT TESTED |
| P1.6 | Workspace settings modification by non-owner | As a non-owner member, attempt to rename the workspace, change sharing defaults, or delete the workspace. | NOT TESTED |
| P1.7 | Hidden UI vs server enforcement | Identify operations where the UI hides buttons for non-privileged roles. Replay those requests directly via curl. | NOT TESTED |

---

## 6. Priority 4 — Sharing-key validation and access controls

### Context

Cryptobox uses sharing keys to control access to shared files. A sharing key is a
secret that must be known to access a shared file. This is a program-qualifying category.

### Test cases

| ID | Test | Procedure | Status |
|---|---|---|---|
| S1.1 | Shared file access without sharing key | Create a sharing link from Account A. As Account B, attempt to access the shared file without providing the sharing key. | NOT TESTED |
| S1.2 | Sharing key brute force resistance | Inspect the sharing key length and character set. Assess entropy. (Do not actually brute force.) | NOT TESTED |
| S1.3 | Sharing key in URL vs body | Determine how the sharing key is transmitted. If in URL, check server logs / referrer leakage concerns. | NOT TESTED |
| S1.4 | Sharing link permission escalation | A sharing link may grant read-only access. Attempt write operations through the sharing interface. | NOT TESTED |
| S1.5 | Sharing link scope bypass | A sharing link for File X — attempt to use the associated session/token to access File Y in the same workspace. | NOT TESTED |
| S1.6 | Revoked sharing link enforcement | Revoke a sharing link. Verify the key is immediately invalid. | NOT TESTED |
| S1.7 | Sharing key and file ID mismatch | Provide a valid sharing key for File X but request File Y. Test whether authorization is file-specific. | NOT TESTED |
| S1.8 | Deposit-box authorization boundary | If deposit boxes are enabled: test whether deposit-box access grants broader workspace access. | NOT TESTED |

---

## 7. Priority 5 — File-history integrity and unauthorized restoration

### Context

Cryptobox maintains file version history. Qualifying issues include unauthorized
alteration of file history.

### Test cases

| ID | Test | Procedure | Status |
|---|---|---|---|
| H1.1 | Version history read cross-workspace | As Account B, request the version history of a file in Account A's workspace. | NOT TESTED |
| H1.2 | Version restore by unauthorized user | As Account B (viewer or non-member), attempt to restore a previous version of Account A's file. | NOT TESTED |
| H1.3 | Version deletion by non-owner | As Account B (member), attempt to delete a version entry from Account A's file history. | NOT TESTED |
| H1.4 | Version ID manipulation | Request a specific version ID belonging to another file or workspace to test cross-object confusion. | NOT TESTED |
| H1.5 | History modification via upload | Upload a file with the same name to test whether it overwrites history entries belonging to the original. | NOT TESTED |
| H1.6 | Restore to different target | Initiate a version restore but modify the target file/workspace ID in the request. | NOT TESTED |

---

## 8. Priority 6 — Device-key exposure and key-to-account binding

### Context

Cryptobox uses device-specific cryptographic keys. Private keys should never be
accessible to unauthorized accounts.

### Test cases

| ID | Test | Procedure | Status |
|---|---|---|---|
| K1.1 | Device key listing cross-account | As Account B, request the device-key list for Account A. | NOT TESTED |
| K1.2 | Device key export/download | Attempt to export or download a device's private key through the application interface. | NOT TESTED |
| K1.3 | Device registration to wrong account | Register a device under Account A's session but submit Account B's user ID in the registration request. | NOT TESTED |
| K1.4 | Key material in API responses | Inspect API responses during normal operations for leaked private key material. | NOT TESTED |
| K1.5 | Device deregistration cross-account | As Account B, attempt to deregister one of Account A's devices. | NOT TESTED |
| K1.6 | Key-management operations without authentication | Test key endpoints without a session cookie / auth token. | NOT TESTED |
| K1.7 | Cryptographic metadata tampering | Modify metadata fields (key IDs, algorithm identifiers) in encryption-related requests and observe server behavior. | NOT TESTED |

---

## 9. Priority 7 — Authentication and object-ownership confusion

### Test cases

| ID | Test | Procedure | Status |
|---|---|---|---|
| AU1.1 | Session fixation | Obtain a session token before login. Login and check if the token changes. | NOT TESTED |
| AU1.2 | Session invalidation on logout | Logout and replay the previous session token. | NOT TESTED |
| AU1.3 | Session invalidation on password change | Change password on Account A. Verify all existing sessions are invalidated. | NOT TESTED |
| AU1.4 | Concurrent session isolation | Login to Account A and Account B in the same client. Verify requests are correctly bound to the intended account. | NOT TESTED |
| AU1.5 | Object ownership transfer | Transfer a workspace object from Account A to Account B. Verify the original owner loses access if intended. | NOT TESTED |
| AU1.6 | Authentication token scope | Inspect whether auth tokens grant access only to the authenticated user's data. | NOT TESTED |

---

## 10. Priority 8 — XSS, injection, CSRF, SSRF, and input-handling issues

### XSS

| ID | Test | Procedure | Status |
|---|---|---|---|
| X1.1 | Stored XSS in file name | Upload a file with an XSS payload as the file name. View the workspace listing. | NOT TESTED |
| X1.2 | Stored XSS in workspace name | Create or rename a workspace with an XSS payload. | NOT TESTED |
| X1.3 | Stored XSS in comments/notes | If the application supports comments: inject XSS payload. | NOT TESTED |
| X1.4 | Reflected XSS in search/filter | Test search parameters and filter inputs for reflected script execution. | NOT TESTED |
| X1.5 | DOM-based XSS in sharing flow | Inspect client-side JavaScript for unsafe DOM manipulation of sharing-key parameters. | NOT TESTED |
| X1.6 | XSS via file content preview | Upload an HTML or SVG file. Check if it renders in the browser's origin. | NOT TESTED |

### SQL injection

| ID | Test | Procedure | Status |
|---|---|---|---|
| Q1.1 | Search parameter injection | Test search and filter endpoints with diagnostic SQL characters (`'`, `"`, `--`, `;`). | NOT TESTED |
| Q1.2 | Sort/order parameter injection | If the application accepts sort parameters, test for injection. | NOT TESTED |
| Q1.3 | ID parameter type confusion | Submit string values where integer IDs are expected; submit very large integers. | NOT TESTED |

### CSRF

| ID | Test | Procedure | Status |
|---|---|---|---|
| C1.1 | CSRF on workspace member addition | Test whether adding a member requires an anti-CSRF token. | NOT TESTED |
| C1.2 | CSRF on sharing link creation | Test whether creating a sharing link requires an anti-CSRF token. | NOT TESTED |
| C1.3 | CSRF on password/email change | Test whether account changes require re-authentication or CSRF protection. | NOT TESTED |
| C1.4 | CSRF on trustee designation | Test whether designating a trustee requires CSRF protection. | NOT TESTED |

### SSRF / XXE / LFI

| ID | Test | Procedure | Status |
|---|---|---|---|
| SS1.1 | SSRF in file import/URL fetch | If the application fetches remote URLs (file import, link preview): test for SSRF with safe internal targets. | NOT TESTED |
| SS1.2 | XXE in file upload | Upload an XML-based file (DOCX, SVG, XML) with an external entity reference to a controlled indicator. | NOT TESTED |
| SS1.3 | LFI in file download path | Test whether file download endpoints accept path traversal sequences. | NOT TESTED |

---

## 11. Priority 9 — Additional business-logic weaknesses

| ID | Test | Procedure | Status |
|---|---|---|---|
| B1.1 | Workspace creation limits | Test whether account-level workspace limits can be bypassed via API. | NOT TESTED |
| B1.2 | Deposit-box to workspace escalation | Test whether deposit-box access can be leveraged to gain workspace membership. | NOT TESTED |
| B1.3 | Invitation link reuse | Test whether a workspace invitation link remains valid after being used or revoked. | NOT TESTED |
| B1.4 | Race conditions in sharing operations | Test whether concurrent requests can bypass sharing-key validation or role checks. | NOT TESTED |
| B1.5 | Internal link scope bypass | Test whether internal links can reference objects outside the user's authorization. | NOT TESTED |
| B1.6 | Open redirect in auth/sharing flows | Test redirect parameters for off-origin redirection with security consequence. | NOT TESTED |

---

## 12. Coverage tracking

| Category | Priority | Tests defined | Tests executed | Confirmed findings |
|---|---|---|---|---|
| Trustee / recovery | 1 | 7 | 0 | 0 |
| Cross-account authorization | 2 | 9 | 0 | 0 |
| Role enforcement | 3 | 7 | 0 | 0 |
| Sharing-key validation | 4 | 8 | 0 | 0 |
| File-history integrity | 5 | 6 | 0 | 0 |
| Device-key exposure | 6 | 7 | 0 | 0 |
| Auth / ownership confusion | 7 | 6 | 0 | 0 |
| XSS | 8 | 6 | 0 | 0 |
| SQL injection | 8 | 3 | 0 | 0 |
| CSRF | 8 | 4 | 0 | 0 |
| SSRF / XXE / LFI | 8 | 3 | 0 | 0 |
| Business logic | 9 | 6 | 0 | 0 |
| **TOTAL** | — | **72** | **0** | **0** |

**No active testing has been performed. All 72 tests are NOT TESTED.**

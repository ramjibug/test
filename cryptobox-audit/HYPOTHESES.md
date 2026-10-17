# Cryptobox Bug Bounty — Security Hypotheses

**Status:** PREPARATION ONLY — no hypotheses validated
**Date:** 2026-10-17

Each hypothesis documents the security property under test, what evidence would
confirm or deny a vulnerability, and what false positives to watch for. All are
marked NOT TESTED until active, authorized testing produces evidence.

---

## Priority 1 — Trustee and account-recovery security

### H-T1: Recovery flow can be re-bound to a different account

- **Security property:** A recovery request must be cryptographically and logically
  bound to the account that initiated it. The recovery flow must not allow mid-flow
  substitution of the target account.
- **Feature:** Account recovery / trustee recovery flow.
- **Authorization boundary:** The recovery token/request should be usable only for the
  account that created it, and only by the designated trustee(s).
- **Preconditions:** Two test accounts (A and B). Account A has configured at least one
  trustee. A recovery request has been initiated for Account A.
- **Test procedure:**
  1. Initiate recovery for Account A.
  2. Capture the recovery request (token, URL, or API call).
  3. Modify the target account identifier to point to Account B.
  4. Submit the modified request.
  5. Observe whether the server rejects or accepts the modified target.
- **Expected secure behavior:** Server rejects the request. The recovery token is bound
  to Account A and cannot be used to recover or access Account B.
- **Evidence for vulnerability:** Server accepts the modified request and begins a
  recovery flow for Account B using Account A's recovery token.
- **False positives:**
  - Error messages that differ between "wrong account" and "invalid token" may not
    indicate a vulnerability — they may be generic.
  - A rejected request with a different error code is not evidence of partial success.
- **Program exclusions:** None — this is a qualifying category.
- **Risk if confirmed:** CRITICAL — would allow an attacker to hijack arbitrary accounts
  by initiating recovery against a victim's account.
- **Status:** NOT TESTED
- **Open questions:** What is the recovery flow's structure? Does it use a URL-based
  token, an API call with account identifiers, or a trustee-mediated key exchange?

### H-T2: Trustee designation without target user consent

- **Security property:** A user should not become a trustee for another account without
  explicit acceptance.
- **Feature:** Trustee configuration in account settings.
- **Authorization boundary:** The trustee relationship requires mutual consent.
- **Preconditions:** Two test accounts (A and B).
- **Test procedure:**
  1. From Account A, designate Account B as a trustee.
  2. Check whether Account B must accept the designation before it becomes active.
  3. If acceptance is required: inspect whether the acceptance step can be bypassed by
     replaying or modifying the API request.
- **Expected secure behavior:** Account B must explicitly accept. The trustee
  relationship is not active until both parties have consented.
- **Evidence for vulnerability:** Account B becomes an active trustee without any action
  on B's part, OR the acceptance check can be bypassed via API manipulation.
- **False positives:**
  - An invitation sent to Account B that requires action is not a vulnerability.
  - A pending state visible to Account A is normal.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — could allow an attacker to insert themselves as a trustee
  for a victim account, enabling future account takeover through the recovery mechanism.
- **Status:** NOT TESTED

### H-T3: Recovery token remains valid after use or password change

- **Security property:** Recovery tokens must be single-use and invalidated after
  successful recovery, password change, or explicit cancellation.
- **Feature:** Account recovery flow.
- **Authorization boundary:** Token validity is time-limited and single-use.
- **Preconditions:** Two test accounts. Account A with trustee configured.
- **Test procedure:**
  1. Initiate and complete a recovery for Account A.
  2. Attempt to reuse the same recovery token/URL.
  3. Separately: initiate recovery, then change Account A's password before completing
     recovery. Attempt to complete the stale recovery.
- **Expected secure behavior:** Token is rejected in both cases.
- **Evidence for vulnerability:** Token remains usable after recovery completes, or after
  a password change occurs.
- **False positives:**
  - A brief validity window (seconds) after completion is unlikely but possible in
    async systems — confirm with multiple retries.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — persistent recovery tokens enable repeated account access.
- **Status:** NOT TESTED

### H-T4: Trustee can access account data without triggering full recovery

- **Security property:** A trustee should only be able to assist in account recovery,
  not directly access the account's data, sessions, or cryptographic keys outside the
  recovery flow.
- **Feature:** Trustee relationship and its associated API surface.
- **Authorization boundary:** Trustee role grants recovery assistance only.
- **Preconditions:** Account A designates Account B as trustee (both accept).
- **Test procedure:**
  1. As Account B (trustee of Account A), enumerate available API endpoints.
  2. Attempt to access Account A's workspace data, files, keys, or session using
     trustee-related tokens or identifiers.
  3. Attempt to invoke recovery-related key operations without initiating an actual
     recovery request.
- **Expected secure behavior:** Being a trustee grants no data access. Recovery requires
  an explicit, logged, multi-step recovery initiation.
- **Evidence for vulnerability:** Account B can access Account A's data or crypto keys
  through the trustee relationship without a formal recovery.
- **False positives:**
  - Account B seeing Account A's name or email in a trustee list is expected.
  - Trustee configuration metadata is not data access.
- **Program exclusions:** Authenticated enumeration of email/names is excluded.
- **Risk if confirmed:** CRITICAL — trustee relationship becomes a backdoor to data.
- **Status:** NOT TESTED

---

## Priority 2 — Cross-account file and workspace authorization (IDOR)

### H-A1: File access via direct ID without workspace membership

- **Security property:** A file can only be accessed by authenticated users who are
  members of the workspace containing that file, or who have a valid sharing key.
- **Feature:** File download / file metadata API.
- **Authorization boundary:** Workspace membership + role.
- **Preconditions:** Account A creates a workspace with a test file. Account B is not a
  member.
- **Test procedure:**
  1. As Account A, create a file and note its file ID from API responses.
  2. As Account B, request the file by ID via the API.
  3. Vary the request: metadata endpoint, download endpoint, version-history endpoint.
- **Expected secure behavior:** Server returns 403 or 404 for all requests from Account B.
- **Evidence for vulnerability:** Account B receives file content, metadata, or version
  history from Account A's private workspace.
- **False positives:**
  - 404 vs 403: a 404 that always returns for non-member requests is acceptable (it
    does not confirm the file exists to the unauthorized user).
  - If the workspace has public sharing enabled, access may be intentional.
- **Program exclusions:** File extraction by viewers through the browser is excluded, but
  this test targets a non-member, not a viewer.
- **Risk if confirmed:** CRITICAL — breaks the core confidentiality model.
- **Status:** NOT TESTED
- **Open questions:** What is the file ID format? Are IDs UUIDs or sequential integers?

### H-A2: Workspace metadata accessible to non-members

- **Security property:** Workspace name, member list, settings, and configuration should
  not be accessible to non-members.
- **Feature:** Workspace detail / settings API.
- **Authorization boundary:** Workspace membership.
- **Preconditions:** Account A creates a workspace. Account B is not a member.
- **Test procedure:**
  1. As Account A, note the workspace ID.
  2. As Account B, request workspace details by ID.
- **Expected secure behavior:** Server returns 403 or 404.
- **Evidence for vulnerability:** Account B sees workspace name, member list, or settings.
- **False positives:**
  - A workspace name visible to invited (but not yet joined) users may be by design.
  - Authenticated enumeration of names is excluded by the program.
- **Program exclusions:** Authenticated enumeration of email/names is excluded. However,
  full workspace metadata exposure goes beyond name enumeration.
- **Risk if confirmed:** MEDIUM to HIGH — depends on what metadata is exposed. Member
  list + settings = organizational intelligence.
- **Status:** NOT TESTED

### H-A3: File upload to foreign workspace

- **Security property:** Only members with write permission can upload files to a workspace.
- **Feature:** File upload API.
- **Authorization boundary:** Workspace membership + write role.
- **Preconditions:** Account A owns a workspace. Account B is not a member.
- **Test procedure:**
  1. As Account A, note the workspace ID and any upload endpoint parameters.
  2. As Account B, submit an upload request to Account A's workspace ID.
- **Expected secure behavior:** Server rejects the upload with 403.
- **Evidence for vulnerability:** The file appears in Account A's workspace.
- **False positives:**
  - Deposit boxes may intentionally allow uploads from non-members — this is separate.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — breaks workspace integrity.
- **Status:** NOT TESTED

---

## Priority 3 — Workspace role enforcement and privilege escalation

### H-P1: Viewer can perform write operations via direct API calls

- **Security property:** Server-side authorization must enforce role restrictions
  regardless of the client interface.
- **Feature:** All write operations (upload, edit, delete, move, rename).
- **Authorization boundary:** Viewer role should have read-only access.
- **Preconditions:** Account A owns a workspace. Account B is added as viewer.
- **Test procedure:**
  1. Add Account B as a viewer in Account A's workspace.
  2. As Account B, attempt each write operation directly via API (bypassing any
     UI restrictions).
  3. Record server responses for each operation.
- **Expected secure behavior:** All write operations return 403.
- **Evidence for vulnerability:** Any write operation succeeds (file created, modified,
  deleted, or moved).
- **False positives:**
  - A 200 response that does not actually change state (dry-run or no-op) is not a
    vulnerability.
  - Ensure the change persists by verifying as Account A.
- **Program exclusions:** None — this is a qualifying permission bypass.
- **Risk if confirmed:** HIGH — role model is broken.
- **Status:** NOT TESTED

### H-P2: Member can self-promote to admin/owner

- **Security property:** A user cannot change their own role to a higher privilege level.
- **Feature:** Workspace membership / role management API.
- **Authorization boundary:** Only the workspace owner (or admin, depending on the model)
  can change roles.
- **Preconditions:** Account A owns a workspace. Account B is a member.
- **Test procedure:**
  1. As Account B (member), submit an API request to change own role to admin or owner.
  2. Inspect whether the server validates the requestor's current role.
- **Expected secure behavior:** Server rejects the role change with 403.
- **Evidence for vulnerability:** Account B's role is changed to admin or owner.
- **False positives:**
  - A success response that does not actually change the role (verify via Account A).
- **Program exclusions:** None.
- **Risk if confirmed:** CRITICAL — full workspace takeover.
- **Status:** NOT TESTED

### H-P3: Removed member retains API access

- **Security property:** Removing a user from a workspace must immediately revoke their
  access to all workspace resources.
- **Feature:** Workspace membership management.
- **Authorization boundary:** Active membership required.
- **Preconditions:** Account B is a member of Account A's workspace.
- **Test procedure:**
  1. As Account B, capture authenticated requests to workspace resources.
  2. As Account A, remove Account B from the workspace.
  3. Immediately replay Account B's captured requests.
- **Expected secure behavior:** All replayed requests return 403 or 404.
- **Evidence for vulnerability:** Account B can still access workspace resources after
  removal.
- **False positives:**
  - Caching: a brief window where cached permissions allow access may exist but should
    be very short. More than a few seconds is a finding.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — membership revocation is ineffective.
- **Status:** NOT TESTED

---

## Priority 4 — Sharing-key validation and access controls

### H-S1: Shared file accessible without sharing key

- **Security property:** A sharing link must require the correct sharing key to grant
  access. Without the key, the file content must not be returned.
- **Feature:** External sharing / sharing-link verification.
- **Authorization boundary:** Possession of the sharing key.
- **Preconditions:** Account A creates a sharing link for a file.
- **Test procedure:**
  1. Create a sharing link in Account A's workspace.
  2. Identify the sharing URL structure (likely includes a link ID and a key).
  3. As Account B (unauthenticated or with own session), request the sharing URL
     without the key, or with the key portion removed/modified.
- **Expected secure behavior:** Server returns 403 or an error without file content.
- **Evidence for vulnerability:** File content or metadata is returned without a valid
  sharing key.
- **False positives:**
  - A landing page that shows the file exists but requires the key is not a
    vulnerability (it may show a "enter key" prompt).
  - Metadata like file name visible without the key may or may not be intended.
- **Program exclusions:** None — this is explicitly qualifying.
- **Risk if confirmed:** CRITICAL — sharing keys are the access control for shared files.
- **Status:** NOT TESTED

### H-S2: Sharing key for File X grants access to File Y

- **Security property:** A sharing key must be bound to the specific file it was created
  for. It must not grant access to other files in the same workspace.
- **Feature:** Sharing link verification.
- **Authorization boundary:** Per-file sharing key binding.
- **Preconditions:** Account A creates sharing links for File X and File Y.
- **Test procedure:**
  1. Obtain the sharing key for File X.
  2. Attempt to use File X's sharing key with File Y's link ID (or vice versa).
  3. Attempt to modify the file ID parameter while keeping File X's sharing key.
- **Expected secure behavior:** Server rejects the mismatched key+file combination.
- **Evidence for vulnerability:** File Y's content is returned using File X's sharing key.
- **False positives:**
  - Both files having the same sharing key would be suspicious but is distinct from
    a key-mismatch bypass. Confirm that different files have different keys first.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — sharing-key isolation is broken.
- **Status:** NOT TESTED

### H-S3: Sharing link grants write access when read-only was intended

- **Security property:** Sharing links with read-only permission must not allow the
  recipient to modify, delete, or create versions of the shared file.
- **Feature:** Shared-file write operations.
- **Authorization boundary:** Sharing-link permission level.
- **Preconditions:** Account A creates a read-only sharing link.
- **Test procedure:**
  1. Access the shared file using the read-only sharing link.
  2. Attempt write operations (upload new version, rename, delete) via API.
- **Expected secure behavior:** All write operations are rejected.
- **Evidence for vulnerability:** A write operation succeeds through a read-only sharing
  link.
- **False positives:**
  - The sharing flow may create a temporary session — ensure the session does not
    inherit workspace-level permissions beyond the sharing-link scope.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — breaks sharing permission model.
- **Status:** NOT TESTED

---

## Priority 5 — File-history integrity and unauthorized restoration

### H-H1: Non-member can read file version history

- **Security property:** Version history is part of the file and shares its access
  controls.
- **Feature:** File version-history API.
- **Authorization boundary:** Workspace membership + role.
- **Preconditions:** Account A has a file with multiple versions. Account B is not a
  member.
- **Test procedure:**
  1. As Account B, request the version-history endpoint for Account A's file.
- **Expected secure behavior:** 403 or 404.
- **Evidence for vulnerability:** Version list or version content is returned.
- **False positives:** Same as H-A1.
- **Program exclusions:** None — unauthorized alteration of file history is qualifying,
  and unauthorized read of history is a precondition.
- **Risk if confirmed:** HIGH — version history may contain sensitive earlier drafts.
- **Status:** NOT TESTED

### H-H2: Viewer can restore a previous version

- **Security property:** Restoring a file version is a write operation that should
  require a write-capable role.
- **Feature:** Version restore API.
- **Authorization boundary:** Write role in the workspace.
- **Preconditions:** Account B is a viewer in Account A's workspace. A file has multiple
  versions.
- **Test procedure:**
  1. As Account B (viewer), submit a version-restore request via API.
- **Expected secure behavior:** 403.
- **Evidence for vulnerability:** The file is reverted to a previous version.
- **False positives:**
  - Confirm the restore actually changed the current version (check as Account A).
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — integrity violation via role bypass.
- **Status:** NOT TESTED

### H-H3: Version restore with cross-file ID substitution

- **Security property:** A version restore request must validate that the version belongs
  to the target file.
- **Feature:** Version restore API.
- **Authorization boundary:** File ownership + version binding.
- **Preconditions:** Account A has File X (v1, v2) and File Y. Both in the same workspace.
- **Test procedure:**
  1. Submit a restore request for File Y but specify a version ID from File X.
- **Expected secure behavior:** Server rejects the mismatched version.
- **Evidence for vulnerability:** File Y's content changes to match File X's version.
- **False positives:**
  - If versions are globally unique and the server correctly rejects mismatches,
    the error type doesn't matter.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — cross-file data corruption.
- **Status:** NOT TESTED

---

## Priority 6 — Device-key exposure and key-to-account binding

### H-K1: Device key listing accessible cross-account

- **Security property:** A user's device key list and key material must not be accessible
  to other users.
- **Feature:** Device management / key management API.
- **Authorization boundary:** Account ownership.
- **Preconditions:** Both test accounts have at least one registered device.
- **Test procedure:**
  1. As Account A, identify the device-list API endpoint and account A's user ID.
  2. As Account B, request Account A's device list by substituting the user ID.
- **Expected secure behavior:** 403 or 404.
- **Evidence for vulnerability:** Account A's device list (with key identifiers or key
  material) is returned to Account B.
- **False positives:**
  - Public key material (as opposed to private keys) may be intentionally shared for
    encryption purposes. Distinguish public from private key exposure.
- **Program exclusions:** None — private device-key exposure is qualifying.
- **Risk if confirmed:** CRITICAL if private keys are exposed. MEDIUM if only public keys
  or device metadata.
- **Status:** NOT TESTED

### H-K2: Device registration bound to wrong account

- **Security property:** A device registration request must bind the new device to the
  authenticated user only.
- **Feature:** Device registration API.
- **Authorization boundary:** Authentication session.
- **Preconditions:** Account A and Account B authenticated.
- **Test procedure:**
  1. As Account A, initiate device registration.
  2. Modify the user identifier in the registration request to Account B's ID.
  3. Submit the modified request.
- **Expected secure behavior:** Server ignores the modified user ID and binds the device
  to the authenticated user (Account A), or rejects the request.
- **Evidence for vulnerability:** A device is registered to Account B using Account A's
  session.
- **False positives:**
  - The server may derive the user ID from the session and ignore the request body
    field. Verify by checking Account B's device list.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — device impersonation and potential key compromise.
- **Status:** NOT TESTED

---

## Priority 7 — Authentication and object-ownership confusion

### H-AU1: Session token not rotated on login

- **Security property:** Session fixation must be prevented by issuing a new session
  token upon authentication.
- **Feature:** Login / authentication flow.
- **Authorization boundary:** Session lifecycle.
- **Preconditions:** One test account.
- **Test procedure:**
  1. Obtain a session token from the application before authenticating.
  2. Authenticate.
  3. Compare the pre-auth and post-auth session tokens.
- **Expected secure behavior:** Token changes on login.
- **Evidence for vulnerability:** Same token before and after authentication.
- **False positives:**
  - Some frameworks issue a new cookie but keep an internal session ID. Inspect all
    cookies and headers.
- **Program exclusions:** "Reusing authentication session IDs from another context" is
  excluded. Session fixation where an attacker sets the token is different from reuse
  — clarify applicability.
- **Risk if confirmed:** MEDIUM — session fixation requires an attacker to set the
  victim's session token, which depends on the cookie configuration.
- **Status:** NOT TESTED

### H-AU2: Logout does not invalidate session server-side

- **Security property:** After logout, the session token must be rejected by the server.
- **Feature:** Logout endpoint.
- **Authorization boundary:** Session validity.
- **Preconditions:** One test account.
- **Test procedure:**
  1. Login and capture the session token.
  2. Logout.
  3. Replay the captured session token in a new request.
- **Expected secure behavior:** Server returns 401 or 403.
- **Evidence for vulnerability:** Server accepts the stale session token and returns
  authenticated data.
- **False positives:**
  - JWT-based sessions may remain valid until expiration. This is a finding if the
    expiration is long and no revocation mechanism exists.
- **Program exclusions:** None.
- **Risk if confirmed:** MEDIUM — depends on session lifetime and attacker's access to
  the token.
- **Status:** NOT TESTED

---

## Priority 8 — Input-handling vulnerabilities

### H-X1: Stored XSS in file name rendered to workspace members

- **Security property:** User-supplied file names must be sanitized before rendering in
  any HTML context.
- **Feature:** File upload, workspace file listing.
- **Authorization boundary:** Affects other workspace members who view the listing.
- **Preconditions:** Account A is a member of a workspace.
- **Test procedure:**
  1. Upload a file named `<img src=x onerror=alert(document.domain)>.txt` (or similar
     safe proof-of-execution payload).
  2. As Account A (or Account B if they share the workspace), view the workspace listing.
  3. Inspect whether the payload executes in the browser context.
- **Expected secure behavior:** File name is displayed as text, not rendered as HTML.
- **Evidence for vulnerability:** JavaScript executes in the application's origin.
- **False positives:**
  - HTML entities being displayed literally is safe.
  - The file name being truncated is safe.
  - A content-security-policy blocking execution does not mean the injection is safe —
    CSP bypass may be possible.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — stored XSS affecting other workspace members.
- **Status:** NOT TESTED

### H-C1: CSRF on workspace member addition

- **Security property:** State-changing operations must validate request origin.
- **Feature:** Workspace member management.
- **Authorization boundary:** Same-origin policy + anti-CSRF mechanism.
- **Preconditions:** Account A owns a workspace.
- **Test procedure:**
  1. Inspect the "add member" request for anti-CSRF tokens, SameSite cookies, or
     origin/referer validation.
  2. Construct a cross-origin form that submits the same request.
  3. Test whether the server accepts the cross-origin request.
- **Expected secure behavior:** Request is rejected without a valid CSRF token or fails
  SameSite cookie validation.
- **Evidence for vulnerability:** A cross-origin request successfully adds a member.
- **False positives:**
  - API endpoints requiring `Content-Type: application/json` may be naturally resistant
    to simple CSRF (but not to fetch-based CSRF without CORS).
  - CORS preflight rejection is a defense, but verify it's enforced.
- **Program exclusions:** None.
- **Risk if confirmed:** HIGH — arbitrary workspace membership manipulation.
- **Status:** NOT TESTED

---

## Summary

| Priority | Category | Hypotheses | Status |
|---|---|---|---|
| 1 | Trustee / recovery | H-T1 through H-T4 | NOT TESTED |
| 2 | Cross-account auth (IDOR) | H-A1 through H-A3 | NOT TESTED |
| 3 | Role enforcement | H-P1 through H-P3 | NOT TESTED |
| 4 | Sharing-key validation | H-S1 through H-S3 | NOT TESTED |
| 5 | File-history integrity | H-H1 through H-H3 | NOT TESTED |
| 6 | Device-key exposure | H-K1, H-K2 | NOT TESTED |
| 7 | Auth / ownership | H-AU1, H-AU2 | NOT TESTED |
| 8 | XSS, CSRF (representative) | H-X1, H-C1 | NOT TESTED |

**Total hypotheses documented: 22** (representative set — full test matrix in TEST-PLAN.md
covers 72 test cases).

All hypotheses require network access to `bounty.cryptobox.com` and authenticated
sessions with the two hunter-controlled test accounts.

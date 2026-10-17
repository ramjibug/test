---
title: "CLAUDE CODE BUG BOUNTY TOOLKIT — ENHANCED EDITION"
subtitle: "AI Prompts • Workflows • Chaining Strategies • Pro Tips"
---

# CLAUDE CODE BUG BOUNTY TOOLKIT — ENHANCED EDITION

**AI PROMPTS • WORKFLOWS • CHAINING STRATEGIES • PRO TIPS**

*Enhanced Edition | Web Application Security*

**A practical field guide for authorized security research**
120+ copy-ready prompts • step-by-step workflows • prompt chaining maps • vulnerability escalation paths • tooling integration • platform tips • report templates

---

# About This Enhanced Edition

This enhanced edition builds on the original 75-prompt Beginner Edition with:

- **45+ new prompts** covering OAuth/JWT, GraphQL, WebSocket, race conditions, cache poisoning, prototype pollution, subdomain takeover, and cloud/infrastructure security
- **Prompt chaining maps** showing how to combine prompts for deeper investigations
- **Vulnerability escalation paths** for chaining low-severity findings into higher impact
- **Tooling integration** guidance for Burp Suite, browser DevTools, and CLI tools
- **Platform-specific tips** for HackerOne, Bugcrowd, and Intigriti
- **Decision trees** for choosing what to test and when to stop
- **HTTP request templates** for common test patterns
- **Common mistakes** section with real-world anti-patterns
- **OWASP Top 10 mapping** connecting prompts to vulnerability categories
- **Report quality scoring** rubric for self-assessment

AI output is a lead, not proof. A reportable finding needs a clear security property, reproducible evidence, and demonstrated impact. You remain responsible for scope, authorization, verification, and disclosure.

---

# How to Use This Toolkit

1. Read the scope and safety chapter before testing any target.
2. Use the **Decision Tree** (Chapter 8) to pick your starting point based on the target type.
3. Use setup prompts to understand the repository or application before hunting specific bugs.
4. Run **one investigation at a time**. Ask Claude to cite files, functions, routes, and evidence.
5. Follow the **Prompt Chaining Maps** (Chapter 9) to connect prompts into full investigation flows.
6. Use validation prompts to disprove hypotheses — not just confirm them.
7. Keep timestamped notes of requests, responses, test accounts, and control tests.
8. Only submit findings you personally reproduced and that comply with the program's rules.

---

# Contents

- **Part I: Foundations**
  - 1. Scope, Safety, and the Evidence Standard
  - 2. Claude Code Setup and Working Habits
  - 3. Program Selection Strategy

- **Part II: The 120+ Prompt Library**
  - 4. Reconnaissance and Architecture (Prompts 9–18)
  - 5. Authentication and Account Recovery (Prompts 19–28)
  - 6. Access Control and IDOR (Prompts 29–38)
  - 7. Input Handling and Injection (Prompts 39–48)
  - 8. API and Business Logic (Prompts 49–58)
  - 9. OAuth, JWT, and Token Security (Prompts 86–93) — NEW
  - 10. GraphQL Security (Prompts 94–99) — NEW
  - 11. WebSocket and Real-Time Security (Prompts 100–103) — NEW
  - 12. Race Conditions and Concurrency (Prompts 104–107) — NEW
  - 13. Cloud and Infrastructure (Prompts 108–113) — NEW
  - 14. Cache Poisoning and HTTP Smuggling (Prompts 114–117) — NEW
  - 15. Client-Side and Browser Security (Prompts 118–122) — NEW
  - 16. Validation and False-Positive Reduction (Prompts 59–68)
  - 17. Report Writing and Prioritization (Prompts 69–85)
  - 18. Efficiency and Session Management (Prompts 79–85)

- **Part III: Advanced Methodology**
  - 19. Prompt Chaining Maps
  - 20. Vulnerability Chaining and Escalation
  - 21. Decision Trees
  - 22. Tooling Integration Guide

- **Part IV: Practical References**
  - 23. HTTP Request Templates
  - 24. Common Mistakes and Anti-Patterns
  - 25. Platform-Specific Tips
  - 26. OWASP Top 10 Prompt Mapping
  - 27. Report Quality Scoring Rubric

- **Appendices**
  - A. Enhanced Quick-Reference Checklists
  - B. Severity Decision Framework
  - C. Expanded Glossary
  - D. One-Liner Quick Prompts

---

# PART I: FOUNDATIONS

# 1. Scope, Safety, and the Evidence Standard

## 1.1 Start with Written Authorization

Before any active testing, identify the exact program, assets in scope, excluded assets, allowed test methods, rate limits, account rules, data-handling requirements, and disclosure process. Scope can differ between subdomains, mobile apps, APIs, staging environments, and third-party services. Never assume that ownership of a parent domain authorizes every connected system.

**Enhancement — The Authorization Checklist:**

- [ ] I have the program's current scope document (not a cached version)
- [ ] I know which specific domains, IPs, and API endpoints are in scope
- [ ] I know which test methods are explicitly prohibited
- [ ] I understand the program's rate-limit and safe-harbor policies
- [ ] I have created dedicated test accounts (not personal accounts)
- [ ] I know the program's data-handling and privacy requirements
- [ ] I know the disclosure timeline and communication channel
- [ ] I have documented the authorization source and date

## 1.2 Safe Operating Rules

- Use only assets and techniques explicitly permitted by the program.
- Prefer your own test accounts and synthetic data. Do not access, retain, or disclose other users' private information.
- Avoid destructive tests, denial-of-service, bulk enumeration, persistence, malware, credential theft, or actions that affect availability unless explicitly authorized.
- Do not upload secrets, customer data, private keys, or confidential source code to an AI service unless permitted under the program and your organization's policies.
- Review every command before execution. Start with read-only analysis and ask before commands that modify files, make network requests, install packages, or alter state.
- Stop if a test exposes real user data, affects another account unexpectedly, or risks service disruption. Preserve minimal evidence and follow the program's reporting instructions.

**Enhancement — The STOP Conditions:**

Stop immediately and document when:

1. You see another user's real personal data (PII, financial, medical)
2. Your test affects a resource you don't own
3. A service becomes degraded or unresponsive
4. You discover you're testing an out-of-scope asset
5. The rate limiter blocks you — do not attempt to circumvent
6. You find evidence of an active breach by someone else — report it through the program's emergency channel

## 1.3 Evidence Ladder

| Level | Description | What You Need |
|-------|-------------|---------------|
| **Observation** | A behavior or code pattern was noticed | Screenshot, code snippet, or log entry |
| **Hypothesis** | A plausible explanation for how the behavior could violate a security property | Written statement of the expected vs. suspected behavior |
| **Controlled Validation** | A minimal test that distinguishes the suspected flaw from expected behavior | Two-account test, before/after comparison, or isolated reproduction |
| **Demonstrated Impact** | Evidence shows a concrete security consequence under the program's rules | Clear proof of confidentiality, integrity, or availability violation |
| **Report-Ready** | Another reviewer can reproduce the result from precise steps and sanitized evidence | Complete report with redacted evidence, reproduction steps, and impact |

## 1.4 The Core Question

Ask: **"What security property should hold, what evidence shows it fails, and what control test rules out a benign explanation?"**

This question is more useful than asking an AI to label behavior as a vulnerability.

### Prompt 1 — Scope Extraction

> Read the program rules I provide below. Extract:
> - explicitly in-scope assets and asset types
> - out-of-scope assets and exclusions
> - prohibited techniques and rate limits
> - account, privacy, and data-handling restrictions
> - reporting requirements and communication channels
> - safe harbor provisions and legal protections
> - any time-limited scope changes or temporary additions
>
> Create a checklist. Quote or reference the exact rule text for each item.
> If a rule is ambiguous, label it AMBIGUOUS and recommend asking the program owner.
> Do not infer authorization from domain relationships.
> Flag any conflict between rules (e.g., a subdomain listed as both in-scope and excluded).
>
> PROGRAM RULES:
> [PASTE RULES HERE]

### Prompt 2 — Test-Plan Safety Review

> Review this proposed test plan against the supplied program rules.
> For each step, classify it as: ALLOWED BY PROVIDED TEXT, PROHIBITED, or UNCLEAR.
> Explain the rule supporting each classification. Flag destructive, high-volume,
> privacy-invasive, or state-changing steps. Suggest a lower-impact alternative for each flagged step.
> Rate the overall plan risk as LOW / MEDIUM / HIGH and explain why.
> Do not execute anything.
>
> PROGRAM RULES:
> [PASTE RULES]
> PROPOSED PLAN:
> [PASTE PLAN]

---

# 2. Claude Code Setup and Working Habits

## 2.1 Session Architecture

Structure your Claude Code sessions for maximum effectiveness:

**Session Types:**

| Session Type | Duration | Goal | When to Use |
|-------------|----------|------|-------------|
| **Recon Session** | 30–60 min | Map architecture, identify attack surfaces | First session on any new target |
| **Deep-Dive Session** | 60–90 min | Investigate one specific hypothesis | After recon identifies a promising lead |
| **Validation Session** | 30–45 min | Confirm or disprove a finding | Before writing a report |
| **Report Session** | 30–60 min | Draft and review a submission | After validation confirms the finding |

## 2.2 Effective Prompting Patterns

**The STAR Pattern for Investigation Prompts:**

- **S**ecurity property: What should be true?
- **T**arget: Which specific route, function, or flow?
- **A**rtifacts: What code, requests, or responses are relevant?
- **R**estrictions: What must Claude NOT do?

**Example:**

> Security property: Only the report owner should access their report via GET /api/reports/{id}
> Target: src/controllers/reports.js:getReport() and src/middleware/auth.js
> Artifacts: [paste relevant code]
> Restrictions: Do not probe the live API. Do not claim exploitability without tracing the full code path.

### Prompt 3 — Repository Orientation

> Inspect this local repository without changing files or contacting external systems.
> Summarize in a structured table:
> - Language(s) and framework(s) with version numbers
> - Entry points and routing mechanism
> - Authentication method (session, JWT, OAuth, API key, etc.)
> - Authorization model (RBAC, ABAC, ownership, etc.)
> - Data storage (database type, ORM, raw queries)
> - Third-party integrations and external API clients
> - Security middleware and libraries in use
>
> For every item, cite the file path and symbol.
> Separate CONFIRMED (from code) from INFERRED (from patterns).
> Finish with the five most security-relevant areas to review and why, ranked by potential impact.

### Prompt 4 — Create a Security Map

> Build a security map from the code available in this repository using this structure:
>
> **User Roles:** List each role and its source (config, enum, database)
> **Sensitive Objects:** List objects with access controls (user data, payments, admin functions)
> **Trust Boundaries:** Where does untrusted input cross into privileged operations?
> **Input Sources:** HTTP params, headers, cookies, WebSocket messages, file uploads, webhooks
> **Sensitive Operations:** Database writes, file operations, external API calls, email sends
> **Security Controls:** Auth middleware, validation libraries, rate limiters, CSP headers
>
> For every item, cite file paths and symbols. Mark missing evidence as UNKNOWN.
> Create a visual summary: Input Source → Validation → Auth Check → Operation → Output
> Do not claim a vulnerability yet.

### Prompt 5 — Plan a Focused Session

> Given this security map and the program rules, propose a 60-minute investigation plan:
>
> 1. **Target:** One specific high-value question (not "find all bugs")
> 2. **Why it matters:** Business impact and likelihood of a real issue
> 3. **Files to inspect:** Specific paths, not "look at auth code"
> 4. **Success criteria:** What evidence would confirm the hypothesis?
> 5. **Failure criteria:** What evidence would disprove it?
> 6. **Stop conditions:** When to abandon this lead
> 7. **Time budget:** How to split 60 minutes across steps
> 8. **Risk controls:** What could go wrong and how to avoid it
>
> Do not execute the plan yet.

### Prompt 6 — Session Handoff Notes

> Create a concise handoff note for the next session with these exact sections:
>
> **CONFIRMED FACTS:** Architecture decisions verified in code (with file references)
> **OPEN HYPOTHESES:** Suspected issues with current evidence strength (HIGH/MEDIUM/LOW)
> **TESTS PERFORMED:** What was tested, the result, and the control comparison
> **REJECTED LEADS:** What was investigated and why it was dropped
> **NEXT ACTIONS:** Prioritized list of what to investigate next
> **SENSITIVE CONTEXT:** Any test accounts, tokens, or state to preserve (redacted)
>
> Keep secrets and personal data out of the note. Use placeholders for sensitive values.

### Prompt 7 — Explain Code to a Beginner

> Explain this code path in beginner-friendly language using this structure:
>
> 1. **What it does:** One-sentence summary a non-developer could understand
> 2. **Data flow:** Trace the data from entry point to sensitive operation, step by step
> 3. **Security controls:** What checks exist? Where are they applied?
> 4. **Key terms:** Define any unfamiliar terms (ORM, middleware, sanitization, etc.)
> 5. **What could go wrong:** Hypothetical concerns — but do NOT call it vulnerable without evidence
>
> Use exact code references (file:line).
>
> CODE OR FILE REFERENCES:
> [PASTE RELEVANT MATERIAL]

### Prompt 8 — Review Proposed Commands

> Assess these proposed terminal commands before I run them.
> For each command, provide:
>
> | Command | Action | Modifies State? | Network? | Risk Level | Safer Alternative |
> |---------|--------|-----------------|----------|------------|-------------------|
>
> Flag any command that: creates files, modifies system state, makes network requests,
> installs packages, or could affect other users. Do not run the commands.
>
> COMMANDS:
> [PASTE COMMANDS]

---

# 3. Program Selection Strategy — NEW

### Prompt P1 — Evaluate a Bug Bounty Program

> Analyze this bug bounty program for a beginner researcher. Evaluate:
>
> 1. **Scope breadth:** How many assets? Are they web apps, APIs, mobile, or infrastructure?
> 2. **Technology stack:** Can you identify the tech from public information? Is it a stack you know?
> 3. **Maturity indicators:** How long has the program run? Response time? Resolution time?
> 4. **Payout history:** Average bounties? Ratio of resolved to informative?
> 5. **Competition level:** Is this a popular program with many researchers?
> 6. **Beginner fit:** Are there areas less likely to be already picked over?
> 7. **Learning potential:** Will testing this teach transferable skills?
>
> Rate the program as GOOD FIT / MODERATE FIT / POOR FIT for a beginner and explain why.
> Do not access the live target; base this only on the program description and public metrics.
>
> PROGRAM DETAILS:
> [PASTE PROGRAM PAGE]

### Prompt P2 — Map a Target Before Testing

> From the publicly available information I've provided (program scope, public documentation,
> marketing pages), create a pre-testing map:
>
> 1. **Technology fingerprint:** Frameworks, CDNs, APIs visible from public sources
> 2. **User-facing features:** Login, registration, profiles, payments, file uploads, etc.
> 3. **API surface:** Documented endpoints, versioning, authentication methods
> 4. **Integration points:** Third-party services, SSO providers, payment processors
> 5. **High-value targets:** Features that handle sensitive data or privileged operations
>
> Do not probe the live target. Do not make network requests. Base this only on provided documentation.
>
> PUBLIC INFORMATION:
> [PASTE DOCUMENTATION/SCOPE]

---

# PART II: THE 120+ PROMPT LIBRARY

# 4. Reconnaissance and Architecture (Prompts 9–18)

### Prompt 9 — Map Exposed Routes from Local Source

**Category:** Reconnaissance and architecture

> From this repository, identify ALL route definitions and HTTP methods.
> Present as a table:
>
> | Method | Path | Controller | Auth Required? | Auth Type | Input Params | Middleware |
> |--------|------|------------|----------------|-----------|--------------|------------|
>
> Flag routes that: accept user input but lack validation middleware, handle sensitive data
> without authentication, use different auth patterns than siblings, or accept file uploads.
> Do not probe a live service or invent routes.

### Prompt 10 — Identify Trust Boundaries

**Category:** Reconnaissance and architecture

> Trace where untrusted input crosses into privileged code or sensitive operations.
> For each trust boundary crossing, document:
>
> | Source | Input Type | Transformations | Validation Checks | Sink (Sensitive Op) | Missing Controls | Risk Level |
> |--------|-----------|-----------------|-------------------|---------------------|-----------------|------------|
>
> Treat each concern as a hypothesis, not a confirmed finding.
> Prioritize boundaries where user input reaches: database queries, file operations,
> command execution, template rendering, or external API calls.

### Prompt 11 — Inventory Sensitive Data

**Category:** Reconnaissance and architecture

> Identify code paths that read, write, export, or log sensitive data.
> Categorize by data type:
>
> - **Authentication:** Passwords, tokens, API keys, session IDs
> - **Personal:** Email, name, address, phone, SSN, DOB
> - **Financial:** Credit cards, bank accounts, transaction amounts
> - **Business:** Internal pricing, admin configs, feature flags
>
> For each, document: where it enters the system, how it's stored, where it's logged,
> who can access it, and what minimization controls exist.
> Do not print secrets or real user data.

### Prompt 12 — Map Roles and Permissions

**Category:** Reconnaissance and architecture

> Extract roles, permissions, ownership checks, and policy helpers from this repository.
> Create a matrix:
>
> | Role | Action | Object | Enforcement Point | Evidence |
> |------|--------|--------|--------------------|----------|
>
> For each cell: ALLOWED (cite code), DENIED (cite code), or UNKNOWN (not found).
> Highlight any role that has UNKNOWN cells for sensitive actions.
> Mark inconsistencies between roles (e.g., admin and superadmin having identical permissions).

### Prompt 13 — Review API Documentation

**Category:** Reconnaissance and architecture

> Compare the provided API documentation with route/controller code.
> Create a discrepancy table:
>
> | Endpoint | Doc Says | Code Does | Type | Security Relevant? |
> |----------|----------|-----------|------|-------------------|
>
> Types: UNDOCUMENTED_ENDPOINT, MISSING_AUTH, EXTRA_FIELDS, WRONG_METHOD, DEPRECATED_ACTIVE
> Do not assume a mismatch is exploitable — explain what additional context is needed.

### Prompt 14 — Find Security-Sensitive Configuration

**Category:** Reconnaissance and architecture

> Locate security-relevant configuration patterns and present as a security posture table:
>
> | Control | Setting | File | Secure? | Notes |
> |---------|---------|------|---------|-------|
>
> Check for: cookie flags (Secure, HttpOnly, SameSite), CORS origins, CSRF protection toggle,
> debug/development mode, trusted proxy settings, secret rotation, TLS configuration,
> Content-Security-Policy, X-Frame-Options, HSTS, rate limit thresholds,
> session timeout values, password policy settings.
> Report file references and deployment caveats; do not expose secret values.

### Prompt 15 — Prioritize Attack Surfaces

**Category:** Reconnaissance and architecture

> Rank the supplied routes by potential security relevance.
> Score each on a 1–5 scale for:
>
> - **Data sensitivity:** What data does this endpoint handle?
> - **Privilege level:** What permissions does it require?
> - **Input complexity:** How much user-controlled data does it accept?
> - **Business impact:** What would a breach of this endpoint mean?
> - **Control maturity:** How well-protected does the code look?
>
> Present as a ranked table with total score and recommended investigation order.
> Explain the evidence behind each score. Avoid severity claims without validation.

### Prompt 16 — Review Third-Party Boundaries

**Category:** Reconnaissance and architecture

> Identify integrations, webhooks, external API clients, and trust assumptions.
> For each boundary:
>
> | Service | Direction | Auth Method | Input Validated? | Secret Storage | Error Handling |
> |---------|-----------|-------------|------------------|----------------|----------------|
>
> Flag: hardcoded credentials, missing webhook signature verification, unvalidated callback URLs,
> secrets in environment vs. vault, and missing retry/timeout configurations.
> Do not contact third parties.

### Prompt 17 — Build an Investigation Backlog

**Category:** Reconnaissance and architecture

> Turn the security map into a prioritized backlog.
> Each item must contain:
>
> | # | Question | Files/Routes | Priority (H/M/L) | Why | Safe Test Idea | Evidence Needed | Est. Time |
> |---|----------|-------------- |-------------------|-----|----------------|-----------------|-----------|
>
> Priority criteria: data sensitivity × control weakness × scope confidence.
> Include estimated investigation time per item.

### Prompt 18 — Compare Two Implementations

**Category:** Reconnaissance and architecture

> Compare these two code paths side by side:
>
> | Aspect | Path A | Path B | Difference | Security Relevant? |
> |--------|--------|--------|------------|-------------------|
>
> Check: authorization method, input validation, error responses, data exposure,
> rate limiting, logging, and session handling.
> Explain which differences could lead to a bypass if one path is weaker.
> State what context is needed before concluding.

---

# 5. Authentication and Account Recovery (Prompts 19–28)

### Prompt 19 — Review Login Flow

**Category:** Authentication and account recovery

> Trace login from request to session/token issuance. Document the complete flow:
>
> 1. **Input handling:** How are credentials received and validated?
> 2. **Credential verification:** Hashing algorithm, comparison method, timing safety
> 3. **Rate limiting:** By what key? IP, username, combination? Threshold?
> 4. **Error responses:** Do failed login errors differ by failure type? (username vs. password)
> 5. **Session creation:** How is the session/token created? What claims or data does it contain?
> 6. **Session rotation:** Is the session ID rotated after successful login?
> 7. **Logging:** What is logged? Are passwords or tokens accidentally logged?
> 8. **MFA integration:** Where in the flow is MFA checked? Can it be skipped?
>
> Cite code for each step. List what must be verified in a controlled test environment.

### Prompt 20 — Review Password Reset Lifecycle

**Category:** Authentication and account recovery

> Trace the complete password-reset lifecycle:
>
> | Step | Implementation | Security Control | Concern |
> |------|---------------|------------------|---------|
> | Token generation | | Entropy, predictability | |
> | Token storage | | Hashing, expiry | |
> | Token delivery | | Email only? SMS? | |
> | Token validation | | One-use? Time-bound? | |
> | Token-to-account binding | | Is it bound to the right account? | |
> | Password update | | Old sessions invalidated? | |
> | Post-reset state | | Token consumed? Account locked out? | |
>
> Do not claim exploitability without evidence. Identify what runtime tests would confirm each concern.

### Prompt 21 — Review Email-Change Flow

**Category:** Authentication and account recovery

> Trace email change from request through verification and persistence.
> Check each security control:
>
> - [ ] Requires reauthentication (password or MFA) before change
> - [ ] Sends notification to BOTH old and new email addresses
> - [ ] New email requires verification before becoming active
> - [ ] Sessions are invalidated or re-validated after change
> - [ ] Pending password-reset tokens are invalidated
> - [ ] Rate-limited to prevent enumeration
> - [ ] Change is logged with timestamp and IP
>
> List control tests using accounts you own. Do not test with other users' accounts.

### Prompt 22 — Review MFA Enforcement

**Category:** Authentication and account recovery

> Map the complete MFA enforcement surface:
>
> | Flow | MFA Required? | Bypass Possible? | Evidence |
> |------|--------------|------------------|----------|
> | Normal login | | | |
> | API login | | | |
> | Password reset | | | |
> | Email change | | | |
> | OAuth/SSO login | | | |
> | Remember device | | | |
> | Recovery codes | | | |
> | Session refresh | | | |
> | Admin actions | | | |
> | API key creation | | | |
>
> Base conclusions on code references; do not attempt to access another user's account.
> Identify the weakest enforcement path.

### Prompt 23 — Review Session Lifecycle

**Category:** Authentication and account recovery

> Identify session management implementation:
>
> | Event | What Happens | Configured or Default? | Evidence |
> |-------|-------------|----------------------|----------|
> | Login | | | |
> | Logout | | | |
> | Password change | | | |
> | Email change | | | |
> | Role change | | | |
> | Idle timeout | | | |
> | Absolute timeout | | | |
> | Concurrent sessions | | | |
>
> Separate framework defaults from explicitly configured behavior.
> Flag any event where sessions should be invalidated but aren't.

### Prompt 24 — Check Token Binding Assumptions

**Category:** Authentication and account recovery

> Inspect how security tokens (reset, verification, invitation, API) are constructed and validated:
>
> | Token Type | Bound To | Expiry | One-Use? | State Check | Concern |
> |-----------|----------|--------|----------|-------------|---------|
>
> "Bound To" = what account state is embedded or checked (user ID, email, password hash, etc.)
> "State Check" = does validation check current account state or just token validity?
> Identify missing checks as hypotheses. Propose non-destructive tests with test accounts.

### Prompt 25 — Review Registration Validation

**Category:** Authentication and account recovery

> Trace registration fields through the full pipeline:
>
> | Field | Client Validation | Server Validation | Storage | Sanitized on Output? |
> |-------|-------------------|-------------------|---------|---------------------|
>
> Check for: email format bypass, username collisions (case, unicode, whitespace),
> password policy enforcement, duplicate account handling, and confirmation flow.
> Assess whether inconsistencies affect security vs. usability.

### Prompt 26 — Analyze Authentication Errors

**Category:** Authentication and account recovery

> Compare error responses across authentication flows:
>
> | Scenario | Status Code | Response Body | Timing | Headers |
> |----------|-------------|---------------|--------|---------|
> | Valid user, wrong password | | | | |
> | Invalid user | | | | |
> | Locked account | | | | |
> | Disabled account | | | | |
> | Valid reset email | | | | |
> | Invalid reset email | | | | |
>
> Determine whether differences reveal account existence. Describe realistic impact
> without exaggeration — account enumeration is not the same as account takeover.

### Prompt 27 — Check Rate-Limit Design

**Category:** Authentication and account recovery

> Find rate-limit implementation for auth endpoints and document:
>
> | Endpoint | Keying Strategy | Threshold | Window | Response | Bypass Hypothesis |
> |----------|----------------|-----------|--------|----------|-------------------|
>
> Keying strategy = what identifies a requester (IP, user, session, combination)
> Bypass hypothesis = theoretical ways the limit could be circumvented (header injection,
> distributed requests, parameter variation, endpoint aliasing).
> Do not perform high-volume tests. Identify what a safe test would look like.

### Prompt 28 — Build an Auth Test Matrix

**Category:** Authentication and account recovery

> Create a test matrix for all authentication flows:
>
> | Test Case | Flow | Account Setup | Steps | Expected Secure Result | Evidence to Collect | Status |
> |-----------|------|---------------|-------|----------------------|--------------------| --------|
>
> Cover: login, logout, password reset, email change, MFA enrollment/removal,
> session invalidation, concurrent sessions, and account deletion.
> Use only accounts I control. Include cleanup steps for each test.

---

# 6. Access Control and IDOR (Prompts 29–38)

### Prompt 29 — Trace Object Ownership Checks

**Category:** Access control and IDOR

> For this route and object type, trace the complete authorization chain:
>
> Request → Authentication → Object Lookup → Ownership Check → Action
>
> For each step, cite the code. Answer:
> 1. How is the current user identified?
> 2. How is the target object looked up? (sequential ID, UUID, slug?)
> 3. Where does the ownership/permission check occur?
> 4. Is the check in middleware, controller, or service layer?
> 5. What happens if the check fails? (403, 404, redirect, or nothing?)
>
> Do not infer a flaw from an identifier format alone. UUIDs are not security controls.

### Prompt 30 — Compare User Roles

**Category:** Access control and IDOR

> Compare the same action across two test roles I control:
>
> | Aspect | Role A (expected: allowed) | Role B (expected: denied) | Evidence |
> |--------|---------------------------|--------------------------|----------|
> | HTTP request | | | |
> | Status code | | | |
> | Response body | | | |
> | Side effects | | | |
> | Error message | | | |
>
> Define what result would indicate a role enforcement failure vs. expected behavior.
> Include the exact requests to send (with placeholders for tokens and IDs).

### Prompt 31 — Review Server-Side Authorization

**Category:** Access control and IDOR

> Identify whether authorization is enforced server-side or only in UI/client code.
> For each protected action:
>
> | Action | Client-Side Check | Server-Side Check | Middleware | Service Layer | Verdict |
> |--------|-------------------|-------------------|------------|---------------|---------|
>
> Verdict: SERVER_ENFORCED, CLIENT_ONLY, or UNCLEAR.
> Cite route middleware and service-layer checks. Explain what runtime evidence is needed
> to confirm server enforcement (e.g., replaying a request without the UI).

### Prompt 32 — Review Tenant Isolation

**Category:** Access control and IDOR

> Trace tenant/organization identifiers through the request lifecycle:
>
> 1. Where does the tenant ID come from? (URL, header, session, subdomain, JWT claim)
> 2. Is it derived from trusted session state or user-controlled input?
> 3. Do database queries always filter by tenant?
> 4. Are there shared tables without tenant scoping?
> 5. Can a user's request reference objects from another tenant?
> 6. Do background jobs and cron tasks respect tenant boundaries?
>
> Mark uncertain assumptions. Cross-tenant access is high-severity — require strong evidence.

### Prompt 33 — Review Mass Assignment

**Category:** Access control and IDOR

> Inspect request-to-model binding for each update endpoint:
>
> | Endpoint | Accepted Fields | Protected Fields | Allowlist Method | Unprotected? |
> |----------|----------------|-----------------|-----------------|-------------|
>
> Protected fields = role, admin, verified, tenant_id, price, balance, permissions, etc.
> Allowlist method = strong_params, DTO, whitelist, schema validation, or NONE.
> Propose tests using a disposable test account with harmless field values.

### Prompt 34 — Review Administrative Routes

**Category:** Access control and IDOR

> Inventory administrative actions:
>
> | Admin Route | Auth Check | Role Check | Middleware Stack | Alternate Path? |
> |-------------|-----------|------------|-----------------|----------------|
>
> Look for: inconsistent middleware application, direct service calls bypassing auth,
> debug or internal endpoints without protection, admin APIs on the same origin as user APIs.
> Do not attempt privileged actions against production data.

### Prompt 35 — Check Access After Ownership Change

**Category:** Access control and IDOR

> Analyze permission behavior when ownership changes:
>
> | Scenario | Expected | Code Path | Cached? | Background Job? |
> |----------|----------|-----------|---------|----------------|
> | User removed from team | Lose access immediately | | | |
> | Object transferred | Old owner loses access | | | |
> | Role downgraded | Permissions reduced | | | |
> | Account deactivated | All access revoked | | | |
>
> Identify cache, stale authorization, and background-job considerations.
> Request runtime evidence before concluding.

### Prompt 36 — Review Download and Export Permissions

**Category:** Access control and IDOR

> Trace authorization for file downloads and exports:
>
> | Endpoint | Auth Check | Object Ownership Check | Link Expiry | Predictable URL? |
> |----------|-----------|----------------------|-------------|-----------------|
>
> Check: signed URLs, time-limited tokens, direct file path access, and whether
> download links can be shared or guessed. Do not access other users' files.

### Prompt 37 — Create an Authorization Matrix

**Category:** Access control and IDOR

> Build a comprehensive matrix:
>
> | Action | Anonymous | User | Admin | Owner | Team Member |
> |--------|-----------|------|-------|-------|-------------|
> | View own profile | | | | | |
> | Edit own profile | | | | | |
> | View other's profile | | | | | |
> | Create resource | | | | | |
> | Delete resource | | | | | |
> | Admin panel | | | | | |
> [Add rows for each action in the application]
>
> Mark each cell: ALLOWED (cite code), DENIED (cite code), or UNKNOWN.
> List minimal tests to verify every UNKNOWN cell using test accounts.

### Prompt 38 — Challenge an IDOR Hypothesis

**Category:** Access control and IDOR

> Given this suspected IDOR:
>
> 1. **List 5 benign explanations** for the observed behavior
> 2. **Design a minimal two-account control test:**
>    - Account A creates Object X
>    - Account B creates Object Y
>    - Test: Can Account B access Object X?
>    - Control: Can Account A access Object X? (should succeed)
>    - Control: Can Account B access Object Y? (should succeed)
> 3. **Define clear pass/fail evidence:** What exact response proves/disproves the IDOR?
> 4. **Set stop conditions:** When to abandon this lead
>
> Use only objects created by test accounts. Do not enumerate existing identifiers.

---

# 7. Input Handling and Injection (Prompts 39–48)

### Prompt 39 — Trace Untrusted Input to SQL

**Category:** Input handling and injection

> Trace request input to database operations for each endpoint that accepts user data:
>
> | Endpoint | Input | Query Method | Parameterized? | ORM? | Dynamic Parts | Concern |
> |----------|-------|-------------|----------------|------|---------------|---------|
>
> Dynamic Parts = any string concatenation, template literals, or format strings in queries.
> Check for: raw queries alongside ORM use, search/filter/sort parameters in query construction,
> JSON/array input expanded into queries, and stored procedures with dynamic SQL.
> Do not run payloads; propose safe local tests if a concern remains.

### Prompt 40 — Review Output Encoding for XSS

**Category:** Input handling and injection

> Trace user-controlled data to output contexts:
>
> | Source | Output Context | Encoding Applied | Framework Auto-Escape? | Bypass Risk |
> |--------|---------------|-----------------|----------------------|------------|
>
> Contexts: HTML body, HTML attribute, URL, JavaScript string, CSS value, DOM manipulation.
> Each context requires different encoding. Flag mismatched encoding (e.g., HTML encoding in a JS context).
> Explain what browser evidence is required to establish code execution — reflection alone is not XSS.

### Prompt 41 — Review Template Rendering

**Category:** Input handling and injection

> Inspect template rendering:
>
> | Template File | Engine | Auto-Escape? | Raw/Unescaped Outputs | User-Controlled? |
> |--------------|--------|-------------|----------------------|-----------------|
>
> For each raw/unescaped output: trace the value back to its source.
> Separate unsafe patterns (raw output of user input) from safe patterns (raw output of admin-controlled config).
> Check for server-side template injection (SSTI) by identifying if user input reaches template compilation.

### Prompt 42 — Review Command Execution Sinks

**Category:** Input handling and injection

> Search for process execution:
>
> | Location | Function/API | Input Source | Argument Handling | Validated? |
> |----------|-------------|-------------|-------------------|-----------|
>
> Functions to check: exec, spawn, system, popen, subprocess, shell_exec, backticks, etc.
> Check: Is input passed as a separate argument (safe) or concatenated into a shell string (dangerous)?
> Are there allowlists for accepted commands or arguments?
> Do not execute commands or propose destructive payloads.

### Prompt 43 — Review Path Handling

**Category:** Input handling and injection

> Trace file path inputs:
>
> | Endpoint | Path Source | Normalization | Traversal Protection | Chroot/Jail? |
> |----------|-----------|---------------|---------------------|-------------|
>
> Check for: path.join vs. path.resolve behavior, null byte handling, URL-encoded sequences,
> double-encoding, OS-specific path separators, symlink following, and zip extraction paths.
> Use only a disposable local fixture for validation.

### Prompt 44 — Review XML Parsing

**Category:** Input handling and injection

> Identify XML parsers:
>
> | Library/Parser | External Entities | DTD Processing | XInclude | Billion Laughs Protection |
> |---------------|-------------------|----------------|----------|--------------------------|
>
> For each parser: what is the default configuration? Is it explicitly hardened?
> Check for: XXE (external entity injection), SSRF via entity URLs, and denial of service
> via entity expansion. Explain safe configuration and how to validate in isolation.

### Prompt 45 — Review Server-Side URL Fetching

**Category:** Input handling and injection

> Trace user-controlled URLs into HTTP clients:
>
> | Endpoint | URL Source | Scheme Validation | Host Validation | Redirect Following | DNS Rebinding? |
> |----------|-----------|-------------------|-----------------|-------------------|----------------|
>
> Check: allowed schemes (http/https only?), host allowlist/denylist, private IP blocking,
> redirect chain following (can it redirect to internal IPs?), DNS resolution timing.
> Do not request internal or metadata addresses (169.254.169.254, localhost, etc.).
> Propose a controlled mock-based validation using a canary server you control.

### Prompt 46 — Review Deserialization

**Category:** Input handling and injection

> Locate deserialization of untrusted data:
>
> | Location | Format | Library | Type Restrictions | Gadget Risk |
> |----------|--------|---------|-------------------|-------------|
>
> Formats: JSON (usually safe), YAML (dangerous with load()), pickle (always dangerous),
> Java serialization (dangerous), PHP unserialize (dangerous), XML (context-dependent).
> Identify accepted types and whether arbitrary class instantiation is possible.
> Describe safe local verification without executing untrusted objects.

### Prompt 47 — Review Regex Denial-of-Service Risk

**Category:** Input handling and injection

> Inspect regexes applied to user input:
>
> | Location | Pattern | Input Source | Backtracking Risk | Input Length Limit |
> |----------|---------|-------------|-------------------|-------------------|
>
> High-risk patterns: nested quantifiers (a+)+, overlapping alternation, backreferences with repetition.
> Recommend bounded local performance tests with gradually increasing input length.
> Do not load-test a live target.

### Prompt 48 — Review Validation Consistency

**Category:** Input handling and injection

> Compare validation across the stack:
>
> | Field | Client Validation | Server Validation | Database Constraint | Gap? |
> |-------|-------------------|-------------------|--------------------|----- |
>
> Flag fields where: server is more permissive than client, database accepts values
> server should reject, or related endpoints validate differently.
> Identify security-relevant gaps (not just cosmetic differences).

---

# 8. API and Business Logic (Prompts 49–58)

### Prompt 49 — Review API Object Properties

**Category:** API and business logic

> For this API response and update path:
>
> | Property | Readable By | Writable By | Filtered? | Protected? | Evidence |
> |----------|------------ |-------------|-----------|-----------|----------|
>
> Identify properties that leak sensitive data in responses or accept privileged values in updates.
> Trace filtering and assignment logic. Propose tests with test data.

### Prompt 50 — Review Pagination and Filtering

**Category:** API and business logic

> Inspect pagination, filters, and sorting:
>
> | Endpoint | Pagination Method | Max Page Size | Auth-Scoped? | Filter Injection? | Unbounded? |
> |----------|------------------|---------------|-------------|-------------------|-----------|
>
> Check: Can a user request all records? Can filter parameters expose other tenants' data?
> Can sort parameters cause database-level errors or information disclosure?
> Do not scrape or enumerate production records.

### Prompt 51 — Review Webhook Verification

**Category:** API and business logic

> Trace webhook handling:
>
> | Webhook Source | Signature Method | Replay Protection | Event Validation | Idempotency |
> |---------------|-----------------|-------------------|-----------------|-------------|
>
> Check: HMAC verification, timestamp validation (replay window), event type filtering,
> payload schema validation, and whether webhook handlers trigger privileged actions.
> Propose unit tests using fabricated events.

### Prompt 52 — Review Payment or Pricing Logic

**Category:** API and business logic

> Inspect the payment flow:
>
> | Step | Source of Truth | Client-Controlled? | Validation | Concern |
> |------|----------------|-------------------|------------|---------|
> | Price display | | | | |
> | Cart total | | | | |
> | Discount application | | | | |
> | Quantity update | | | | |
> | Currency selection | | | | |
> | Payment submission | | | | |
> | Entitlement grant | | | | |
>
> Is the price recalculated server-side at payment time?
> Can quantities, discounts, or currency be manipulated client-side?
> Recommend test cases in a sandbox only.

### Prompt 53 — Review Invitation Flow

**Category:** API and business logic

> Trace invitation handling:
>
> | Step | Implementation | Bound to Invitee? | Role Check | Expiry | Concern |
> |------|---------------|-------------------|-----------|--------|---------|
>
> Check: Can an invitation token be used by someone other than the intended recipient?
> Can the role be elevated after invitation creation? Is the token single-use?
> Does accepting an invitation in one tenant affect another?

### Prompt 54 — Review Workflow State Transitions

**Category:** API and business logic

> Model this workflow as a state machine:
>
> State A → [required steps] → State B → [required steps] → State C
>
> | Transition | Required Checks | Endpoint | Can Be Skipped? | Evidence |
> |-----------|----------------|----------|----------------|----------|
>
> Identify endpoints that may skip required states or approvals.
> Check for: direct state manipulation via API, missing server-side state validation,
> and race conditions between state checks and updates.
> Propose tests with disposable accounts and non-sensitive records.

### Prompt 55 — Review Idempotency and Replay

**Category:** API and business logic

> Inspect replay safety:
>
> | Action | Idempotency Key? | Scope | Validated? | Replay Impact |
> |--------|-----------------|-------|-----------|---------------|
>
> Check: Can payment confirmations be replayed? Can invitation acceptances be repeated?
> Can vote/like/rating actions be duplicated? Distinguish expected retries from
> duplicate business effects.

### Prompt 56 — Review File Upload Handling

**Category:** API and business logic

> Trace the complete upload pipeline:
>
> | Check | Implementation | Bypass Risk |
> |-------|---------------|-------------|
> | File type validation | | Extension-only? Magic bytes? |
> | Filename sanitization | | Path traversal? Null bytes? |
> | Size limits | | Server-side enforced? |
> | Storage location | | Within webroot? |
> | Serving mechanism | | Direct URL? Signed? Auth-gated? |
> | Content-Type on serve | | Matches actual type? Sniffing? |
> | Processing | | Image resize? PDF parse? Zip extract? |
>
> Use harmless test files in an authorized environment.

### Prompt 57 — Review CORS and CSRF Assumptions

**Category:** API and business logic

> Inspect browser security controls:
>
> | Control | Configuration | State-Changing Routes Protected? | Evidence |
> |---------|--------------|--------------------------------|----------|
> | CORS | Origins, methods, credentials | | |
> | CSRF tokens | Present, validated, per-request? | | |
> | SameSite cookies | Strict, Lax, None | | |
> | Content-Type enforcement | | | |
>
> Explain the browser security assumptions. Identify routes where a cross-origin request
> could trigger a state change. What controlled browser evidence is needed?

### Prompt 58 — Review Cache and Sensitive Responses

**Category:** API and business logic

> Identify sensitive responses:
>
> | Endpoint | Contains PII/Tokens? | Cache-Control | Vary Header | CDN Cached? | Concern |
> |----------|---------------------|---------------|-------------|-------------|---------|
>
> Check for: missing no-store on authenticated responses, shared cache keys that include
> auth tokens, and CDN caching of personalized content.
> Avoid testing shared caches with real user data.

---

# 9. OAuth, JWT, and Token Security (Prompts 86–93) — NEW

### Prompt 86 — Review OAuth Implementation

**Category:** OAuth, JWT, and token security

> Trace the OAuth/OpenID Connect flow:
>
> | Step | Implementation | Security Control | Concern |
> |------|---------------|------------------|---------|
> | Authorization request | | state parameter? PKCE? | |
> | Redirect URI validation | | Exact match? Wildcard? | |
> | Authorization code exchange | | Server-to-server? | |
> | Token storage | | HttpOnly cookie? localStorage? | |
> | Token refresh | | Rotation? Revocation? | |
> | Scope enforcement | | Minimal scope? | |
> | Account linking | | Verified email? | |
>
> Check for: open redirect via redirect_uri manipulation, missing state parameter (CSRF),
> missing PKCE (authorization code interception), token leakage in URLs or logs,
> and account takeover via OAuth account linking.
> Do not test with other users' OAuth accounts.

### Prompt 87 — Review JWT Implementation

**Category:** OAuth, JWT, and token security

> Inspect JWT creation, validation, and usage:
>
> | Aspect | Implementation | Secure? | Evidence |
> |--------|---------------|---------|----------|
> | Algorithm | HS256/RS256/ES256/none? | Explicit whitelist? | |
> | Secret/Key management | | Rotation? Strength? | |
> | Claims validation | iss, aud, exp, nbf, iat | All checked? | |
> | Token storage | Cookie/localStorage/memory | HttpOnly? Secure? | |
> | Token revocation | Blacklist? Short expiry? | | |
> | Token refresh | Refresh token rotation? | | |
> | Payload sensitivity | PII in claims? | Encrypted? | |
>
> Check for: algorithm confusion (alg:none, RS256→HS256), missing signature verification,
> expired token acceptance, sensitive data in unencrypted payloads, JWK injection,
> and kid parameter injection.
> Do not forge tokens for accounts you don't control.

### Prompt 88 — Review Token Refresh Mechanism

**Category:** OAuth, JWT, and token security

> Trace the token refresh flow:
>
> 1. How are refresh tokens generated? (Entropy, format)
> 2. Where are they stored? (Database, Redis, cookie)
> 3. Are they rotated on use? (Is the old refresh token invalidated?)
> 4. What is the expiry? (Short-lived vs. long-lived)
> 5. Can a refresh token be reused after rotation? (Replay detection)
> 6. Does revoking access also revoke refresh tokens?
> 7. Are refresh tokens bound to the client? (Device, IP, fingerprint)
>
> A stolen refresh token can be more damaging than a stolen access token.
> Identify the worst-case scenario and mitigation.

### Prompt 89 — Review API Key Management

**Category:** OAuth, JWT, and token security

> Inspect API key lifecycle:
>
> | Aspect | Implementation | Secure? | Evidence |
> |--------|---------------|---------|----------|
> | Key generation | Entropy, format, prefix | | |
> | Key storage | Hashed? Encrypted? Plaintext? | | |
> | Key rotation | Supported? Forced? Grace period? | | |
> | Key scoping | Per-resource? Per-action? Global? | | |
> | Key revocation | Immediate? Cached? | | |
> | Key transmission | Header? Query param? Body? | | |
> | Key logging | Masked in logs? | | |
>
> Flag: keys in URLs (logged by proxies/CDNs), keys in client-side code,
> overly permissive key scopes, and missing key rotation.

### Prompt 90 — Review OAuth Redirect URI Handling

**Category:** OAuth, JWT, and token security

> Inspect redirect URI validation specifically:
>
> 1. Is the redirect_uri compared using exact string match or pattern match?
> 2. Are wildcards, subdomains, or path prefixes allowed?
> 3. Is the scheme enforced (https only)?
> 4. Can URL fragments, query parameters, or path traversal bypass validation?
> 5. What happens with a malformed or missing redirect_uri?
> 6. Are redirect URIs registered per-client or globally?
>
> Open redirect via OAuth redirect_uri is a common high-severity finding.
> Propose safe tests using only your own registered redirect URIs.

### Prompt 91 — Review Single Sign-On (SSO) Integration

**Category:** OAuth, JWT, and token security

> Trace the SSO flow from identity provider to application session:
>
> 1. How is the SSO assertion validated? (Signature, expiry, audience)
> 2. Can a user bypass SSO and login directly?
> 3. Is account linking based on email? Is the email verified by the IdP?
> 4. What happens when SSO is disabled for a user? Are sessions revoked?
> 5. Can a user have both SSO and password-based access?
> 6. Are SSO assertions replayed or cached?
>
> Check for: assertion replay, account takeover via unverified email linking,
> and bypass of SSO enforcement through alternative login flows.

### Prompt 92 — Review Token Scope Enforcement

**Category:** OAuth, JWT, and token security

> Check whether token scopes are actually enforced:
>
> | Endpoint | Required Scope | Enforced? | Evidence |
> |----------|---------------|-----------|----------|
>
> A common weakness: scopes are requested during authorization but not checked
> when the token is used. Identify if scope checks are in middleware (consistent)
> or per-endpoint (error-prone). Propose tests using a minimal-scope token
> against privileged endpoints.

### Prompt 93 — Review Token Revocation

**Category:** OAuth, JWT, and token security

> Trace what happens when access should be revoked:
>
> | Revocation Event | Access Token | Refresh Token | API Keys | Sessions |
> |-----------------|-------------|---------------|----------|----------|
> | User changes password | | | | |
> | Admin disables account | | | | |
> | User revokes app access | | | | |
> | Suspicious activity detected | | | | |
> | Token expiry | | | | |
>
> JWTs are especially problematic for revocation since they're self-contained.
> Identify the maximum window during which a revoked token still works.

---

# 10. GraphQL Security (Prompts 94–99) — NEW

### Prompt 94 — Review GraphQL Schema and Introspection

**Category:** GraphQL security

> Analyze the GraphQL implementation:
>
> 1. Is introspection enabled in production? (It should usually be disabled)
> 2. What types, queries, mutations, and subscriptions are exposed?
> 3. Are there admin-only types visible to regular users via introspection?
> 4. Is the schema documented or only discoverable via introspection?
>
> If introspection is enabled, extract the schema and identify sensitive types.
> If disabled, check if it can be enabled via headers or alternate endpoints.
> Do not run introspection queries against production unless authorized.

### Prompt 95 — Review GraphQL Authorization

**Category:** GraphQL security

> Check authorization at every resolver:
>
> | Type.Field | Auth Check | Where Enforced | Concern |
> |-----------|-----------|----------------|---------|
>
> Common weakness: authorization checked on the query but not on nested resolvers.
> Example: User can query their own order, but order.customer resolves ANY customer.
> Check for: missing auth on nested fields, mutations without ownership checks,
> and subscriptions that leak data from other users.

### Prompt 96 — Review GraphQL Query Complexity

**Category:** GraphQL security

> Check for denial-of-service via query complexity:
>
> 1. Are there depth limits on nested queries?
> 2. Are there complexity/cost limits?
> 3. Can a client request deeply nested relationships? (user.friends.friends.friends...)
> 4. Can a client batch many queries in one request?
> 5. Is there rate limiting per-query or per-request?
> 6. Can aliases be used to duplicate expensive operations?
>
> Propose a safe test with a mildly complex query to observe server behavior.
> Do not send queries designed to crash or overload the server.

### Prompt 97 — Review GraphQL Input Validation

**Category:** GraphQL security

> Check validation on GraphQL inputs:
>
> | Mutation | Input Type | Scalar Validation | Custom Validation | Concern |
> |---------|-----------|------------------|-------------------|---------|
>
> GraphQL's type system provides basic validation, but custom scalars (Email, URL, JSON)
> may not validate correctly. Check for: SQL injection via string inputs,
> XSS via user-controlled fields returned in responses, and oversized payloads.

### Prompt 98 — Review GraphQL Batching and Aliases

**Category:** GraphQL security

> Check batching abuse vectors:
>
> 1. Can multiple queries be batched in a single request?
> 2. Can aliases be used to call the same query/mutation multiple times?
> 3. Are rate limits per-request or per-operation?
> 4. Can batching bypass authentication rate limits? (100 login attempts in one request)
> 5. Are there limits on batch size?
>
> This is especially relevant for brute-force attacks against login mutations.
> Do not perform high-volume tests; propose a safe validation approach.

### Prompt 99 — Review GraphQL Error Handling

**Category:** GraphQL security

> Inspect GraphQL error responses:
>
> 1. Do errors expose internal implementation details? (Stack traces, SQL errors, file paths)
> 2. Do authorization errors differ from not-found errors? (Information disclosure)
> 3. Are partial responses returned with some fields erroring? (Data leakage)
> 4. Do error extensions contain sensitive information?
>
> GraphQL often returns 200 OK with errors in the response body, which means
> standard error monitoring may miss security issues.

---

# 11. WebSocket and Real-Time Security (Prompts 100–103) — NEW

### Prompt 100 — Review WebSocket Authentication

**Category:** WebSocket and real-time security

> Trace WebSocket authentication:
>
> 1. How is the WebSocket connection authenticated? (Cookie, token in URL, first message)
> 2. Is auth checked only at connection time or on every message?
> 3. Can a connection outlive its authentication? (User logs out, token expires)
> 4. Is the WebSocket origin validated? (Cross-site WebSocket hijacking)
> 5. Are there separate permissions for subscribe vs. publish?
>
> WebSocket connections are long-lived — stale authentication is a common issue.
> Check if session invalidation propagates to active WebSocket connections.

### Prompt 101 — Review WebSocket Message Handling

**Category:** WebSocket and real-time security

> Inspect message handling:
>
> | Message Type | Input Validation | Auth Check | Rate Limited? | Concern |
> |-------------|-----------------|-----------|--------------|---------|
>
> Check for: injection via message content (if rendered as HTML), missing input validation,
> channel authorization (can a user subscribe to another user's channel?),
> and message replay attacks.

### Prompt 102 — Review WebSocket Channel Authorization

**Category:** WebSocket and real-time security

> Trace channel/room subscription:
>
> 1. How are channels named? (Predictable IDs? User-controlled?)
> 2. Is channel subscription authorized? (Can user A subscribe to user B's channel?)
> 3. Are presence channels protected? (Can I see who else is online?)
> 4. Can a user publish to channels they shouldn't? (Write authorization)
> 5. Is the channel list enumerable?
>
> Test with two accounts you control to verify channel isolation.

### Prompt 103 — Review Server-Sent Events (SSE) Security

**Category:** WebSocket and real-time security

> Inspect SSE implementation:
>
> 1. How is the SSE endpoint authenticated? (Cookies? Bearer token in URL?)
> 2. Is the event stream scoped to the authenticated user?
> 3. Can the Last-Event-ID header be used to access missed events from other users?
> 4. Does the event stream respect access changes in real time?
> 5. Are sensitive data fields filtered from the event payload?

---

# 12. Race Conditions and Concurrency (Prompts 104–107) — NEW

### Prompt 104 — Identify Race-Condition-Prone Operations

**Category:** Race conditions and concurrency

> Identify operations vulnerable to race conditions:
>
> | Operation | Read-Check-Modify? | Lock/Mutex? | Atomic? | Concern |
> |-----------|-------------------|-------------|---------|---------|
>
> High-risk patterns:
> - **Balance/credit operations:** Check balance → deduct → credit (TOCTOU)
> - **Coupon/discount redemption:** Check usage → apply → record
> - **Invitation acceptance:** Check status → accept → update
> - **Account creation:** Check uniqueness → create
> - **Vote/like operations:** Check existence → create
>
> Identify whether the code uses database transactions, optimistic locking,
> or application-level locks. Do not perform high-volume concurrent requests.

### Prompt 105 — Review Transaction Isolation

**Category:** Race conditions and concurrency

> For database operations that should be atomic:
>
> | Operation | Transaction Used? | Isolation Level | Rollback on Failure? | Concern |
> |-----------|------------------|----------------|---------------------|---------|
>
> Check for: operations that read and write across multiple queries without a transaction,
> SELECT ... FOR UPDATE or advisory locks where needed, and whether the ORM
> wraps related operations in a single transaction.

### Prompt 106 — Review Idempotency Key Implementation

**Category:** Race conditions and concurrency

> If idempotency keys are used:
>
> 1. How is the key generated? (Client-supplied UUID? Server-generated?)
> 2. Is the key scoped to a user/session? (Can user A replay user B's key?)
> 3. What is the key lifetime? (Can old keys be reused?)
> 4. Is the key checked before or after authorization?
> 5. Does the response match the original for a replayed key?
>
> If idempotency keys are NOT used on sensitive operations (payments, transfers, invitations),
> flag this as a concern.

### Prompt 107 — Design a Race Condition Test

**Category:** Race conditions and concurrency

> For this suspected race condition, design a safe controlled test:
>
> 1. **Setup:** Create a test account with a known starting state (e.g., balance = 100)
> 2. **Action:** Define the exact concurrent requests to send (e.g., two simultaneous withdrawals of 80)
> 3. **Expected result:** What should happen? (One succeeds, one fails; balance = 20)
> 4. **Actual evidence:** What would confirm the race condition? (Both succeed; balance = -60)
> 5. **Cleanup:** How to restore the test account
> 6. **Risk controls:** Maximum concurrent requests, test environment only
>
> Use only test accounts with synthetic data. Do not race operations that could affect other users.

---

# 13. Cloud and Infrastructure (Prompts 108–113) — NEW

### Prompt 108 — Review Cloud Storage Configuration

**Category:** Cloud and infrastructure

> Inspect cloud storage integration:
>
> | Bucket/Container | Public Access? | Signed URLs? | Expiry | Listing Enabled? |
> |-----------------|---------------|-------------|--------|-----------------|
>
> Check for: public bucket access, overly long signed URL expiry,
> directory listing enabled, sensitive files in storage (backups, logs, configs),
> and missing server-side encryption.
> Do not attempt to access buckets you don't own.

### Prompt 109 — Review Environment Variable Usage

**Category:** Cloud and infrastructure

> Trace environment variable usage:
>
> | Variable | Purpose | Where Used | Exposed? | Concern |
> |----------|---------|-----------|----------|---------|
>
> Check for: secrets in environment variables logged or exposed via error pages,
> debug endpoints that dump environment, default/fallback values for secrets,
> and environment variables that affect security controls (DEBUG=true, NODE_ENV=development).
> Do not expose actual secret values.

### Prompt 110 — Review Error Handling and Information Disclosure

**Category:** Cloud and infrastructure

> Trace error handling across the application:
>
> | Error Type | Response to Client | Logged? | Stack Trace? | Internal Details? |
> |-----------|-------------------|---------|-------------|------------------|
>
> Check for: stack traces in production responses, database error messages with table/column names,
> different error formats for different failure modes (information leakage),
> and error pages that reveal framework version, server software, or file paths.

### Prompt 111 — Review Logging for Sensitive Data

**Category:** Cloud and infrastructure

> Inspect logging configuration:
>
> | Log Statement | Contains | Masked? | Level | Concern |
> |--------------|---------|---------|-------|---------|
>
> Check for: passwords in login logs, tokens in URL query parameters logged by access logs,
> PII in application logs, full request/response bodies in debug logs,
> and log injection (user input in log messages without sanitization).

### Prompt 112 — Review Deployment Configuration

**Category:** Cloud and infrastructure

> Check deployment security:
>
> - [ ] Debug mode is disabled in production
> - [ ] Default credentials are changed
> - [ ] Admin interfaces are not publicly accessible
> - [ ] HTTPS is enforced (HSTS, redirects)
> - [ ] Security headers are set (CSP, X-Frame-Options, etc.)
> - [ ] Error pages don't leak information
> - [ ] Unnecessary services/ports are not exposed
> - [ ] Source maps are not publicly accessible
> - [ ] .env, .git, and backup files are not accessible
>
> Do not probe production infrastructure. Base analysis on configuration files in the repository.

### Prompt 113 — Review Secrets in Source Code

**Category:** Cloud and infrastructure

> Search for hardcoded secrets:
>
> | Pattern | Location | Type | Risk |
> |---------|----------|------|------|
>
> Search for: API keys, passwords, tokens, private keys, connection strings,
> encryption keys, webhook secrets, and OAuth client secrets.
> Check: .env.example for real values, test fixtures with production credentials,
> comments containing secrets, and git history for removed secrets.
> Do not expose actual secret values in your report — confirm existence and location only.

---

# 14. Cache Poisoning and HTTP Smuggling (Prompts 114–117) — NEW

### Prompt 114 — Review HTTP Response Headers for Cache Poisoning

**Category:** Cache poisoning and HTTP smuggling

> Analyze caching behavior:
>
> | Endpoint | Cache-Control | Vary | CDN Cache | Unkeyed Headers | Concern |
> |----------|-------------|------|-----------|----------------|---------|
>
> Check for: responses that vary by unkeyed headers (X-Forwarded-Host, X-Original-URL),
> missing Vary headers on content that changes by Accept, Accept-Language, or cookies,
> and CDN caching of authenticated responses.
> Unkeyed inputs that influence response content can enable cache poisoning.

### Prompt 115 — Review HTTP Request Handling

**Category:** Cache poisoning and HTTP smuggling

> Check for HTTP-level vulnerabilities:
>
> 1. **Request smuggling:** Does the app sit behind a reverse proxy? Do they agree on Content-Length vs. Transfer-Encoding?
> 2. **HTTP method override:** Does the app accept X-HTTP-Method-Override or _method parameter?
> 3. **Host header injection:** Is the Host header used in generating URLs (password reset links, redirects)?
> 4. **Header injection:** Can user input be reflected in response headers? (CRLF injection)
>
> Base analysis on code and configuration. Do not send smuggling payloads to live targets.

### Prompt 116 — Review CDN and Proxy Configuration

**Category:** Cache poisoning and HTTP smuggling

> Check CDN/proxy trust assumptions:
>
> 1. How does the application determine the client's IP? (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)
> 2. Is the trusted proxy list configured correctly?
> 3. Can an attacker inject X-Forwarded-For to bypass IP-based restrictions?
> 4. Are there paths that bypass the CDN/WAF? (Direct origin access)
> 5. Does the CDN strip security headers?
>
> IP-based security controls that trust X-Forwarded-For without validating the proxy chain are bypassable.

### Prompt 117 — Review Content-Type Handling

**Category:** Cache poisoning and HTTP smuggling

> Check Content-Type processing:
>
> | Endpoint | Expected Content-Type | Alternative Types Accepted? | Parsing Differences? |
> |----------|----------------------|---------------------------|---------------------|
>
> Check for: endpoints that accept both JSON and form data (can enable CSRF),
> content-type confusion attacks (sending XML to a JSON endpoint),
> and file upload endpoints that trust Content-Type without validation.

---

# 15. Client-Side and Browser Security (Prompts 118–122) — NEW

### Prompt 118 — Review Content Security Policy

**Category:** Client-side and browser security

> Analyze the CSP implementation:
>
> | Directive | Value | Effective? | Bypass Risk |
> |-----------|-------|-----------|-------------|
> | default-src | | | |
> | script-src | | | |
> | style-src | | | |
> | img-src | | | |
> | connect-src | | | |
> | frame-ancestors | | | |
> | base-uri | | | |
>
> Flag: unsafe-inline, unsafe-eval, overly broad wildcards (*.example.com),
> CDN domains that host user-uploaded content, and missing base-uri restriction.
> A weak CSP may not mitigate XSS even if other controls are in place.

### Prompt 119 — Review Subdomain Security

**Category:** Client-side and browser security

> Identify subdomain-related risks:
>
> 1. Are there CNAME records pointing to decommissioned services? (Subdomain takeover)
> 2. Do subdomains share cookies with the main domain? (Cookie scope)
> 3. Are there development/staging subdomains exposed? (Information disclosure)
> 4. Is wildcard DNS used? (Potential for abuse)
> 5. Can subdomains be used to bypass same-origin restrictions?
>
> Do not probe subdomains that are out of scope.
> Base analysis on DNS records and configuration files available in the repository.

### Prompt 120 — Review postMessage Security

**Category:** Client-side and browser security

> Trace window.postMessage usage:
>
> | Sender | Receiver | Origin Check? | Data Validation? | Concern |
> |--------|---------|--------------|-----------------|---------|
>
> Check for: missing origin validation in event listeners (accepting messages from any origin),
> sensitive data sent via postMessage without recipient verification,
> and postMessage used for authentication or authorization decisions.

### Prompt 121 — Review Client-Side Storage

**Category:** Client-side and browser security

> Inspect client-side storage usage:
>
> | Store | Data Type | Sensitive? | Encrypted? | Expiry | XSS Accessible? |
> |-------|-----------|-----------|-----------|--------|----------------|
> | localStorage | | | | | |
> | sessionStorage | | | | | |
> | Cookies (non-HttpOnly) | | | | | |
> | IndexedDB | | | | | |
>
> Sensitive data in localStorage/sessionStorage is accessible via XSS.
> Auth tokens should be in HttpOnly cookies, not JavaScript-accessible storage.

### Prompt 122 — Review Open Redirect Vectors

**Category:** Client-side and browser security

> Search for redirect/URL parameters:
>
> | Endpoint | Parameter | Validation | Bypass Risk | Chain Potential |
> |----------|----------|-----------|-------------|----------------|
>
> Check for: redirect after login (return_url, next, redirect_to), OAuth redirect_uri,
> email confirmation links, and error page redirects.
> An open redirect alone is often low severity — but when chained with OAuth or
> phishing, it can become critical. Document the chain potential.

---

# 16. Validation and False-Positive Reduction (Prompts 59–68)

### Prompt 59 — Try to Disprove a Finding

**Category:** Validation and false-positive reduction

> Act as a skeptical reviewer. For this observation:
>
> 1. List at least **seven** benign explanations (not five):
>    - Framework default behavior
>    - Intentional design choice
>    - Test environment artifact
>    - Missing context from code I haven't read
>    - Different behavior in production vs. development
>    - Client-side vs. server-side distinction
>    - Timing or caching artifact
> 2. For each explanation, identify the **smallest safe test** that would distinguish it
> 3. Rate each explanation's plausibility as HIGH/MEDIUM/LOW
> 4. Identify the single most informative test to run first
>
> Do not assume the original hypothesis is correct.

### Prompt 60 — Separate Facts from Inference

**Category:** Validation and false-positive reduction

> Rewrite these notes into exactly four categories:
>
> **CONFIRMED FACTS:** Directly observed with evidence (cite the evidence)
> **REASONABLE INFERENCES:** Logical conclusions from facts (cite the supporting facts)
> **UNSUPPORTED ASSUMPTIONS:** Claims without evidence (explain what evidence is needed)
> **MISSING EVIDENCE:** What we'd need to see to confirm or deny the hypothesis
>
> Remove claims that are not supported by the supplied artifacts.
> If more than 30% of claims are assumptions, the investigation needs more work before reporting.

### Prompt 61 — Build a Control Test

**Category:** Validation and false-positive reduction

> Design a control test with exactly these sections:
>
> **Preconditions:** Exact account state, roles, and data required
> **Variable:** The single thing being changed between test and control
> **Test case:** Step-by-step actions with the variable active
> **Control case:** Step-by-step actions with the variable absent
> **Expected secure result:** What should happen in both cases
> **Failure indicator:** What result proves the vulnerability
> **Success indicator:** What result disproves the vulnerability
> **Evidence to capture:** Exact requests, responses, timestamps
> **Cleanup:** How to restore state after testing

### Prompt 62 — Check Reproducibility

**Category:** Validation and false-positive reduction

> Review these reproduction steps for a first-time reviewer:
>
> For each step, flag if it's missing:
> - [ ] Account type and role required
> - [ ] Exact URL or API endpoint
> - [ ] HTTP method and headers
> - [ ] Request body (with placeholders for secrets)
> - [ ] Authentication state
> - [ ] Expected response (status, body, headers)
> - [ ] State that must exist before the step
> - [ ] What to check after the step
>
> Do not add details not present in evidence. Flag gaps, don't fill them.

### Prompt 63 — Assess Impact Conservatively

**Category:** Validation and false-positive reduction

> Map demonstrated behavior to impact using this framework:
>
> | Impact Type | Demonstrated? | Evidence | Prerequisites | Realistic? |
> |------------|--------------|----------|---------------|-----------|
> | Confidentiality | Read unauthorized data? | | | |
> | Integrity | Modify unauthorized data? | | | |
> | Availability | Disrupt service? | | | |
>
> **Demonstrated = actually happened in testing.** Not "could theoretically happen."
> State the attack prerequisites honestly. An IDOR requiring admin access is different
> from one requiring only a free account. Do not chain hypothetical impacts.

### Prompt 64 — Check Scope Fit

**Category:** Validation and false-positive reduction

> Compare the asset and technique against program rules:
>
> | Aspect | Finding | Program Rule | Verdict |
> |--------|---------|-------------|---------|
> | Asset | | | IN_SCOPE / OUT_OF_SCOPE / UNCLEAR |
> | Technique used | | | ALLOWED / PROHIBITED / UNCLEAR |
> | Impact type | | | QUALIFYING / EXCLUDED / UNCLEAR |
>
> For UNCLEAR items: quote the ambiguous rule text and suggest asking the program.
> Do not guess if scope is unclear — an out-of-scope submission wastes everyone's time.

### Prompt 65 — Assess Duplicate Risk

**Category:** Validation and false-positive reduction

> Compare this finding with provided prior reports:
>
> | Aspect | My Finding | Prior Report(s) | Same Root Cause? |
> |--------|-----------|----------------|-----------------|
> | Component | | | |
> | Vulnerability type | | | |
> | Attack vector | | | |
> | Root cause | | | |
> | Impact | | | |
>
> Same symptoms ≠ same root cause. A different bypass for the same control IS a new finding.
> The same bypass in a different endpoint is usually a duplicate.
> Do not claim a duplicate without enough detail.

### Prompt 66 — Review Evidence Quality

**Category:** Validation and false-positive reduction

> Audit each claim against its evidence:
>
> | Claim | Evidence Type | Present? | Sufficient? | Sensitive Data? |
> |-------|-------------|---------|-------------|----------------|
>
> Required evidence types: request/response pairs, code references, screenshots of browser behavior,
> timestamps, account identifiers (redacted). Flag claims backed only by "AI said so."
> List sensitive data that must be redacted before submission.

### Prompt 67 — Make a Verdict

**Category:** Validation and false-positive reduction

> Based only on supplied evidence, choose one and explain:
>
> | Verdict | Criteria |
> |---------|---------|
> | **CONFIRMED** | Reproduced, evidenced, impactful, in scope |
> | **PLAUSIBLE BUT UNVERIFIED** | Code suggests a flaw, but no runtime proof |
> | **NOT DEMONSTRATED** | Evidence doesn't support the claim |
> | **OUT OF SCOPE / UNCLEAR** | Asset or technique not clearly permitted |
>
> For each: cite the evidence (or absence), identify the one most important missing fact,
> and recommend the single safest next step.

### Prompt 68 — Prepare a Minimal PoC

**Category:** Validation and false-positive reduction

> Create a minimal PoC with these constraints:
>
> 1. **Smallest possible:** Remove every step that isn't required to demonstrate the issue
> 2. **Self-contained:** A reviewer can follow it without prior context
> 3. **Safe:** Uses test accounts, synthetic data, and placeholders for secrets
> 4. **Honest:** Shows only what was demonstrated, not theoretical extensions
> 5. **Clean:** Include setup and cleanup steps
>
> Format: Numbered steps with exact HTTP requests (curl format with placeholders).
> Never include real tokens, passwords, or personal data.

---

# 17. Report Writing and Prioritization (Prompts 69–85)

### Prompt 69 — Generate a Report Outline

**Category:** Report writing and prioritization

> Turn the verified finding into a report with this structure:
>
> **Title:** [Root cause] allows [specific security impact] in [asset]
> **Severity:** [Only if program rubric supports it; otherwise "To be assessed"]
> **Asset:** [Exact in-scope URL, endpoint, or component]
> **Summary:** [2–4 sentences: what, why, and demonstrated impact]
> **Prerequisites:** [Account role, user interaction, configuration needed]
> **Steps to Reproduce:** [Numbered, deterministic, with sanitized requests]
> **Expected Result:** [Security property that should hold]
> **Actual Result:** [What happened, with evidence]
> **Impact:** [Only demonstrated impact; label hypotheticals as such]
> **Evidence:** [Sanitized request/response pairs, screenshots, code refs]
> **Remediation Suggestion:** [Optional but appreciated by triage teams]
>
> Do not invent severity or fabricate results.

### Prompt 70 — Improve a Report Title

**Category:** Report writing and prioritization

> Generate five titles using this formula: [Root Cause] + [Impact] + [Where]
>
> Good: "Missing ownership check on GET /api/reports/{id} allows any authenticated user to read other users' reports"
> Bad: "Critical IDOR — Full Account Takeover Possible!!!"
>
> Rules:
> - Name the root cause (missing check, not "vulnerability")
> - Name the demonstrated impact (not the theoretical worst case)
> - Name the specific asset
> - No severity adjectives unless demonstrated
> - No exclamation marks

### Prompt 71 — Write Technical Root Cause

**Category:** Report writing and prioritization

> Explain the root cause using this structure:
>
> 1. **What should happen:** The intended security control
> 2. **What actually happens:** The implementation gap (cite code)
> 3. **Why it fails:** The specific mistake (missing check, wrong comparison, race condition, etc.)
> 4. **Where it fails:** File, function, and line reference
> 5. **Contributing factors:** Framework defaults, library misuse, or design assumptions that enabled it
>
> Separate root cause from symptoms and impact.

### Prompt 72 — Write Reproduction Steps

**Category:** Report writing and prioritization

> Convert my notes into numbered steps. Each step must have:
>
> **[Step N]:** [Action]
> - Method: [HTTP method]
> - URL: [Full URL with placeholders]
> - Headers: [Required headers]
> - Body: [Request body with placeholders]
> - Auth: [How authenticated]
> - Expected: [What should happen]
> - Actual: [What does happen]
>
> Include account setup as Step 0. Include cleanup as the final step.
> Never fabricate tokens, response values, or screenshots.

### Prompt 73 — Explain Impact to Triage

**Category:** Report writing and prioritization

> Write an impact section in three paragraphs:
>
> **Paragraph 1 — What was demonstrated:** Exactly what the test showed (not "could lead to")
> **Paragraph 2 — Attack prerequisites:** What an attacker needs (account type, knowledge, interaction)
> **Paragraph 3 — Scope of impact:** How many users/records are affected? Is it targeted or mass?
>
> Label any untested escalation as "HYPOTHETICAL — not demonstrated in testing."
> Triage teams downgrade reports that overclaim.

### Prompt 74 — Redact Evidence

**Category:** Report writing and prioritization

> Review evidence for sensitive data:
>
> | Data Type | Found? | Location | Redaction |
> |-----------|--------|----------|-----------|
> | Session cookies | | | → [SESSION_COOKIE] |
> | Access tokens | | | → [ACCESS_TOKEN] |
> | Passwords | | | → [REDACTED_PASSWORD] |
> | Email addresses | | | → user1@example.com |
> | Names | | | → [TEST_USER_1] |
> | Internal IPs | | | → [INTERNAL_IP] |
> | API keys | | | → [API_KEY] |
> | File paths | | | Keep if relevant to repro |
>
> Use stable placeholders that a reviewer can follow across multiple steps.

### Prompt 75 — Estimate Severity Carefully

**Category:** Report writing and prioritization

> Use the program's severity policy if supplied. Otherwise:
>
> | Factor | Assessment | Evidence |
> |--------|-----------|----------|
> | Impact type (C/I/A) | | |
> | Impact scope | | |
> | Attack complexity | | |
> | Privileges required | | |
> | User interaction | | |
>
> If key factors are unknown, say: "Severity cannot be reliably assigned because [reason]."
> Let the triage team make the final severity decision — they have more context than you.

### Prompt 76 — Create a Final Submission Checklist

**Category:** Report writing and prioritization

> Audit this report and return three lists:
>
> **BLOCKERS** (must fix before submitting):
> - Missing reproduction steps
> - Unredacted sensitive data
> - Claims without evidence
> - Out-of-scope testing
>
> **RECOMMENDED IMPROVEMENTS** (strengthen the report):
> - Additional context or evidence
> - Clearer impact description
> - Better title
>
> **READY-TO-SUBMIT ITEMS** (meets the standard):
> - Sections that are complete and well-evidenced

### Prompt 77 — Summarize a Long Investigation

**Category:** Report writing and prioritization

> Summarize in under 200 words for a triager:
>
> **Root cause:** [One sentence]
> **Affected asset:** [Specific URL/endpoint]
> **Prerequisites:** [What an attacker needs]
> **Reproduction:** [2–3 sentence summary of key steps]
> **Result:** [What happened]
> **Impact:** [Demonstrated consequence]
>
> Exclude speculation, secrets, and unnecessary technical detail.

### Prompt 78 — Turn a Rejected Lead into Learning

**Category:** Report writing and prioritization

> For this rejected lead:
>
> 1. **What I thought:** The original hypothesis
> 2. **Why it was wrong:** The mistaken assumption
> 3. **What the evidence actually showed:** The correct interpretation
> 4. **What I needed:** The evidence that would have confirmed or denied it earlier
> 5. **Reusable lesson:** One takeaway for future investigations
>
> Do not relabel a non-bug as a vulnerability.

---

# 18. Efficiency and Session Management (Prompts 79–85)

### Prompt 79 — Choose the Next Best Task

**Category:** Efficiency and session management

> Rank these leads using a scoring matrix:
>
> | Lead | Impact (1-5) | Evidence (1-5) | Effort (1-5) | Scope (1-5) | FP Risk (1-5) | Score |
> |------|-------------|---------------|-------------|------------|--------------|-------|
>
> Score = (Impact × Evidence × Scope) / (Effort × FP Risk)
> Recommend the highest-scoring lead and explain the single best next step.

### Prompt 80 — Reduce Context Safely

**Category:** Efficiency and session management

> Create a compact handoff in under 500 words:
>
> **FACTS:** [Verified architecture and code findings]
> **HYPOTHESES:** [Open questions with evidence strength: HIGH/MEDIUM/LOW]
> **TESTED:** [What was tested and the result]
> **REJECTED:** [Leads that were disproved and why]
> **NEXT:** [Top 3 prioritized next actions]
>
> Preserve uncertainty labels. Omit secrets or personal data.
> This note should let the next session start investigating in under 5 minutes.

### Prompt 81 — Review a Diff for Security Regressions

**Category:** Efficiency and session management

> Analyze this code diff for security-relevant changes:
>
> | Changed Line | Category | Before | After | Concern Level |
> |-------------|----------|--------|-------|--------------|
>
> Categories: authentication, authorization, validation, data exposure, trust boundary,
> error handling, logging, configuration, dependency.
> Propose one focused test for each HIGH concern.

### Prompt 82 — Generate Local Unit-Test Ideas

**Category:** Efficiency and session management

> Propose unit tests for this security invariant:
>
> | Test Case | Type | Input | Expected | Rationale |
> |-----------|------|-------|----------|-----------|
>
> Types: POSITIVE (valid input succeeds), NEGATIVE (invalid input fails),
> BOUNDARY (edge cases), REGRESSION (previously found issues).
> Use synthetic fixtures only. Do not execute tests.

### Prompt 83 — Review Dependency Risk

**Category:** Efficiency and session management

> Inspect dependencies:
>
> | Package | Version | Last Updated | Known Advisories? | Risk |
> |---------|---------|-------------|-------------------|------|
>
> Check for: outdated packages with known CVEs, packages with suspicious names (typosquatting),
> postinstall scripts, and unmaintained dependencies (no updates in 2+ years).
> Do not claim a package is vulnerable without verified advisory evidence.
> List items requiring current verification against an advisory database.

### Prompt 84 — Prepare a Responsible Disclosure Note

**Category:** Efficiency and session management

> Draft a disclosure message:
>
> **To:** [Security team or program]
> **Subject:** Security issue in [asset] — [brief description]
>
> **Summary:** [2 sentences: what and demonstrated impact]
> **Affected Asset:** [Specific URL/endpoint]
> **Evidence Available:** [What you can provide: PoC, screenshots, code refs]
> **Timeline:** [When discovered, when reported]
> **Contact:** [How to reach you for follow-up]
>
> Do not include actual secrets, tokens, or personal data in the note.
> Keep it professional — the triage team's first impression matters.

### Prompt 85 — Conduct a Post-Investigation Review

**Category:** Efficiency and session management

> Review my process:
>
> | Phase | Time Spent | Productive? | Lesson |
> |-------|-----------|-------------|--------|
> | Recon | | | |
> | Hypothesis | | | |
> | Testing | | | |
> | Validation | | | |
> | Reporting | | | |
>
> Identify: strongest evidence found, assumptions that were wrong, time wasted on dead ends,
> scope or safety concerns, and three specific improvements for next time.
> Separate lessons from evidence vs. speculation.

---

# PART III: ADVANCED METHODOLOGY

# 19. Prompt Chaining Maps

Prompt chaining connects multiple prompts into complete investigation flows. Each chain shows the recommended sequence and decision points.

## Chain A: Full Reconnaissance Flow

```
Prompt 3 (Repo Orientation)
    ↓
Prompt 4 (Security Map)
    ↓
Prompt 12 (Roles & Permissions) + Prompt 14 (Security Config)  [parallel]
    ↓
Prompt 15 (Prioritize Attack Surfaces)
    ↓
Prompt 17 (Investigation Backlog)
    ↓
Prompt 5 (Plan Focused Session)
```

**When to use:** First session on any new target. ~90 minutes.

## Chain B: Authentication Deep-Dive

```
Prompt 19 (Login Flow)
    ↓
Prompt 23 (Session Lifecycle) + Prompt 22 (MFA Enforcement)  [parallel]
    ↓
Prompt 24 (Token Binding)
    ↓
Prompt 20 (Password Reset) OR Prompt 21 (Email Change)  [based on findings]
    ↓
Prompt 26 (Auth Errors) + Prompt 27 (Rate Limits)  [parallel]
    ↓
Prompt 28 (Auth Test Matrix)
```

**When to use:** After recon identifies auth as a priority. ~60–90 minutes.

## Chain C: IDOR Investigation

```
Prompt 29 (Trace Ownership)
    ↓
Prompt 31 (Server-Side Auth)
    ↓
Prompt 37 (Auth Matrix)
    ↓ [if suspect found]
Prompt 38 (Challenge IDOR Hypothesis)
    ↓
Prompt 59 (Try to Disprove)
    ↓ [if confirmed]
Prompt 61 (Build Control Test)
    ↓
Prompt 69 (Report Outline)
```

**When to use:** When you suspect an authorization bypass. ~60 minutes.

## Chain D: Injection Testing

```
Prompt 10 (Trust Boundaries)
    ↓
Prompt 39 (SQL) OR Prompt 40 (XSS) OR Prompt 42 (Command) OR Prompt 45 (SSRF)  [pick one]
    ↓
Prompt 48 (Validation Consistency)
    ↓
Prompt 59 (Try to Disprove)
    ↓
Prompt 61 (Build Control Test)
    ↓ [if confirmed]
Prompt 68 (Minimal PoC) → Prompt 69 (Report)
```

**When to use:** When trust boundary analysis reveals unvalidated input paths. ~45–60 minutes.

## Chain E: OAuth/JWT Investigation

```
Prompt 86 (OAuth Implementation)
    ↓
Prompt 87 (JWT Implementation) + Prompt 90 (Redirect URI)  [parallel]
    ↓
Prompt 88 (Token Refresh) + Prompt 92 (Scope Enforcement)  [parallel]
    ↓
Prompt 93 (Token Revocation)
    ↓ [if concern found]
Prompt 59 (Try to Disprove) → Prompt 61 (Control Test) → Prompt 69 (Report)
```

**When to use:** Applications using OAuth/OpenID Connect or JWTs. ~60–90 minutes.

## Chain F: Report Writing

```
Prompt 60 (Separate Facts from Inference)
    ↓
Prompt 63 (Assess Impact)
    ↓
Prompt 69 (Report Outline)
    ↓
Prompt 72 (Repro Steps) + Prompt 74 (Redact Evidence)  [parallel]
    ↓
Prompt 70 (Title) + Prompt 71 (Root Cause) + Prompt 73 (Impact)  [parallel]
    ↓
Prompt 76 (Submission Checklist)
```

**When to use:** After validation confirms a finding. ~45 minutes.

---

# 20. Vulnerability Chaining and Escalation

Low-severity findings can combine into high-severity chains. Document each link separately and test the chain with controlled accounts.

## Common Chains

| Link 1 | Link 2 | Link 3 | Combined Impact |
|--------|--------|--------|----------------|
| Open redirect | OAuth redirect_uri bypass | — | Token theft via phishing |
| IDOR (read) | PII exposure | Phishing with real data | Targeted account compromise |
| XSS (stored) | Session hijacking | — | Account takeover |
| CSRF | Email change | Password reset | Account takeover |
| SSRF (blind) | Cloud metadata access | — | Infrastructure compromise |
| Information disclosure | Rate limit bypass | Brute force | Account enumeration + access |
| Subdomain takeover | Cookie scope abuse | — | Session hijacking across subdomain |

## How to Report a Chain

1. Report each link as a separate finding if it has independent impact
2. Document the chain as an additional "Impact" section in the highest-severity link
3. Demonstrate each link independently before claiming the chain works
4. Do not claim a chain impact you haven't tested end-to-end
5. Label untested chain links as "HYPOTHETICAL"

### Prompt C1 — Identify Chaining Opportunities

> Review these individual findings and identify potential chains:
>
> For each possible chain:
> 1. **Links:** Which findings connect?
> 2. **Prerequisites:** What does an attacker need for the full chain?
> 3. **End impact:** What can the attacker achieve?
> 4. **Tested?** Has each link been independently confirmed?
> 5. **Chain tested?** Has the end-to-end chain been demonstrated?
> 6. **Risk of chain test:** Could testing the chain affect other users or systems?
>
> Only suggest chains where each link has been independently verified.
> Do not suggest chains that require attacking other users.
>
> FINDINGS:
> [PASTE FINDINGS]

---

# 21. Decision Trees

## What to Test First

```
Is this your first session on this target?
├── YES → Start with Chain A (Full Reconnaissance)
│   After recon, what looks most promising?
│   ├── Auth concerns → Chain B (Authentication Deep-Dive)
│   ├── IDOR concerns → Chain C (IDOR Investigation)
│   ├── Input handling → Chain D (Injection Testing)
│   └── OAuth/JWT → Chain E (OAuth/JWT Investigation)
└── NO → Review previous session handoff notes
    What's the highest-priority lead?
    ├── Unconfirmed hypothesis → Jump to Prompt 59 (Disprove)
    ├── Confirmed finding → Jump to Chain F (Report Writing)
    └── No strong leads → Prompt 79 (Choose Next Task)
```

## When to Stop an Investigation

```
Have you spent >30 minutes without new evidence?
├── YES → Is the hypothesis specific enough?
│   ├── NO → Refine it (Prompt 60)
│   └── YES → Is there a simpler test?
│       ├── YES → Try it, then reassess
│       └── NO → Park it (Prompt 80) and move to next lead
└── NO → Continue
```

## When to Report

```
Do you have demonstrated impact?
├── NO → Can you design a safe test? (Prompt 61)
│   ├── YES → Run it, then reassess
│   └── NO → Park as PLAUSIBLE BUT UNVERIFIED
└── YES → Is it in scope? (Prompt 64)
    ├── UNCLEAR → Ask the program, don't submit
    ├── NO → Do not submit
    └── YES → Is it a duplicate? (Prompt 65)
        ├── LIKELY → Do not submit unless your root cause is different
        └── NO → Write the report (Chain F)
```

---

# 22. Tooling Integration Guide

## Using Claude Code with Burp Suite

Claude Code analyzes source code; Burp Suite captures live traffic. Use them together:

1. **Export from Burp → Analyze with Claude:**
   - Export interesting requests as curl commands from Burp
   - Paste into Claude: "Analyze this request against the code for [route]. What security checks should it pass through?"

2. **Code analysis → Burp testing:**
   - Ask Claude to identify parameter names and expected types for a route
   - Use those parameters to craft targeted Burp Intruder payloads

3. **Burp findings → Claude validation:**
   - When Burp flags an issue, paste the request/response
   - Ask Claude to trace the code path and determine if the finding is real

## Using Claude Code with Browser DevTools

1. **Network tab:** Capture actual API requests and compare against Claude's route analysis
2. **Application tab:** Inspect cookies, localStorage, session storage for sensitive data
3. **Console:** Test JavaScript security controls Claude identified in source
4. **Sources:** Compare deployed code with repository code (debug vs. production)

## Useful CLI Commands (Run Before Claude Analysis)

```bash
# Find all route definitions (Express.js example)
grep -rn "app\.\(get\|post\|put\|delete\|patch\)" src/

# Find authentication middleware usage
grep -rn "isAuthenticated\|requireAuth\|passport\|jwt\.verify" src/

# Find raw SQL queries
grep -rn "raw\|query\|execute\|sequelize\.literal" src/

# Find environment variable usage
grep -rn "process\.env\." src/

# Find eval and dangerous functions
grep -rn "eval\|exec\|spawn\|child_process\|vm\.run" src/

# Check for sensitive files in git history
git log --all --diff-filter=D --summary | grep -E "\.(env|key|pem|p12)"
```

**Always review command output yourself — Claude's analysis of grep results is a lead, not proof.**

---

# PART IV: PRACTICAL REFERENCES

# 23. HTTP Request Templates

Use these as starting points for manual testing. Replace placeholders with your test values.

## IDOR Test Template

```
# Step 1: Create object as User A
curl -X POST https://target.com/api/objects \
  -H "Authorization: Bearer [USER_A_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-object-a"}'
# Note the returned object ID: [OBJECT_A_ID]

# Step 2: Verify User A can access their object (control)
curl -X GET https://target.com/api/objects/[OBJECT_A_ID] \
  -H "Authorization: Bearer [USER_A_TOKEN]"
# Expected: 200 OK with object data

# Step 3: Attempt access as User B (test)
curl -X GET https://target.com/api/objects/[OBJECT_A_ID] \
  -H "Authorization: Bearer [USER_B_TOKEN]"
# Expected (secure): 403 or 404
# Actual: [DOCUMENT ACTUAL RESPONSE]

# Step 4: Cleanup
curl -X DELETE https://target.com/api/objects/[OBJECT_A_ID] \
  -H "Authorization: Bearer [USER_A_TOKEN]"
```

## Mass Assignment Test Template

```
# Step 1: Normal profile update (control)
curl -X PUT https://target.com/api/profile \
  -H "Authorization: Bearer [USER_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User"}'

# Step 2: Attempt adding privileged field
curl -X PUT https://target.com/api/profile \
  -H "Authorization: Bearer [USER_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User", "role": "admin"}'
# Expected (secure): role field ignored or 403
# Actual: [DOCUMENT ACTUAL RESPONSE]

# Step 3: Verify role unchanged
curl -X GET https://target.com/api/profile \
  -H "Authorization: Bearer [USER_TOKEN]"
```

## CSRF Test Template (HTML Page)

```html
<!-- Save as csrf_test.html, open in a browser where User A is logged in -->
<!-- Only test if the program allows CSRF testing -->
<html>
<body>
  <h1>CSRF Test — Authorized Testing Only</h1>
  <form id="csrf-form" action="https://target.com/api/email/change" method="POST">
    <input type="hidden" name="email" value="attacker-test@example.com" />
  </form>
  <script>
    // document.getElementById('csrf-form').submit();
    // UNCOMMENT ONLY IF AUTHORIZED
    console.log('Form ready — uncomment submit line to test');
  </script>
</body>
</html>
```

---

# 24. Common Mistakes and Anti-Patterns

## Mistake 1: Reporting Observations as Vulnerabilities

**Wrong:** "The API returns sequential IDs — this is an IDOR vulnerability."
**Right:** Sequential IDs are an observation. An IDOR requires demonstrating that one user can access another user's object through those IDs.

## Mistake 2: Severity Inflation

**Wrong:** "Critical: Account Takeover via Missing Rate Limit on Login"
**Right:** Missing rate limit enables brute-force attacks against accounts with weak passwords, requiring [X] attempts over [Y] time. This is a defense-in-depth gap, not a direct account takeover.

## Mistake 3: Testing Beyond Scope

**Wrong:** Finding a subdomain via recon tools and testing it without checking scope.
**Right:** Check every asset against the program's in-scope list before testing. When in doubt, ask the program.

## Mistake 4: Not Doing Control Tests

**Wrong:** "I got a 200 response — the IDOR works!"
**Right:** Compare with a control: Does the authorized user also get 200? Does the response actually contain different user's data or just a generic success page?

## Mistake 5: Reporting AI Analysis as Evidence

**Wrong:** "Claude Code identified this as a critical SQL injection."
**Right:** "Code review identified a potential SQL injection in [file:line]. The user-controlled parameter [param] is concatenated into a query at [location]. I confirmed this by [safe test evidence]."

## Mistake 6: Submitting Without Redaction

**Wrong:** Including real session tokens, other users' email addresses, or production API keys in your report.
**Right:** Use stable placeholders ([TOKEN_A], user1@example.com, [API_KEY]) and a redaction table showing what was replaced.

## Mistake 7: Duplicate Submissions

**Wrong:** Submitting the same IDOR pattern for every endpoint without checking if it's the same root cause.
**Right:** If 10 endpoints share the same auth middleware bug, that's one finding with 10 affected endpoints — not 10 findings.

## Mistake 8: Not Cleaning Up

**Wrong:** Leaving test objects, modified accounts, or uploaded files on the target after testing.
**Right:** Document cleanup steps in your test plan and execute them after every test.

---

# 25. Platform-Specific Tips

## HackerOne

- **Signal and Impact:** Your reports contribute to a signal score. Low-quality reports hurt your signal.
- **Mediation:** If you disagree with a triage decision, use mediation — don't argue in comments.
- **Retesting:** Some programs offer retesting bounties for verifying fixes. Opt in when available.
- **Collaboration:** Some programs allow collaboration. Don't share details outside the platform.
- **Report format:** HackerOne supports Markdown. Use headers, code blocks, and tables.

## Bugcrowd

- **Vulnerability Rating Taxonomy (VRT):** Bugcrowd uses their own taxonomy. Familiarize yourself with it.
- **Priority (P1–P5):** Understand the priority levels — P1 is not always "Critical."
- **Kudos:** Community reputation matters. High-quality reports earn kudos.
- **Duplicate window:** Bugcrowd has specific policies on duplicate handling.

## Intigriti

- **Triage SLA:** Intigriti has triage SLAs. Be patient but follow up appropriately.
- **Leaderboard:** Activity and quality contribute to leaderboard ranking.
- **Bounty tables:** Check the program's bounty table for expected payout ranges.

## General Platform Tips

1. **Read the program page completely** before testing — every word.
2. **Check the response time** — active programs respond faster.
3. **Start with newer programs** — less picked over by experienced researchers.
4. **Look at the bounty table** — make sure the payout justifies your time.
5. **Read disclosed reports** — learn what the program considers valid.
6. **Don't rush to submit** — a well-written report gets resolved faster than a hasty one.

---

# 26. OWASP Top 10 (2021) Prompt Mapping

| OWASP Category | Primary Prompts | Supporting Prompts |
|---------------|----------------|-------------------|
| **A01: Broken Access Control** | 29–38 (IDOR/Access Control) | 12, 31, 32, 34, 86, 95 |
| **A02: Cryptographic Failures** | 11 (Sensitive Data), 113 (Secrets) | 87, 88, 89, 109 |
| **A03: Injection** | 39 (SQL), 40 (XSS), 42 (Command), 44 (XXE) | 41, 43, 45, 46, 97 |
| **A04: Insecure Design** | 10 (Trust Boundaries), 54 (Workflow) | 52, 53, 55, 104 |
| **A05: Security Misconfiguration** | 14 (Config), 112 (Deployment) | 94, 108, 116, 118 |
| **A06: Vulnerable Components** | 83 (Dependencies) | 109, 113 |
| **A07: Identification & Auth Failures** | 19–28 (Auth) | 86–93 (OAuth/JWT), 100 |
| **A08: Software & Data Integrity** | 46 (Deserialization), 51 (Webhooks) | 55, 81, 83 |
| **A09: Security Logging & Monitoring** | 111 (Logging) | 110, 26 |
| **A10: Server-Side Request Forgery** | 45 (SSRF) | 108, 116 |

---

# 27. Report Quality Scoring Rubric

Score your report before submitting (0–2 per category):

| Category | 0 (Missing) | 1 (Partial) | 2 (Complete) | Score |
|----------|------------|------------|-------------|-------|
| **Clear title** | Vague or clickbait | Names impact but not root cause | Names root cause AND impact | |
| **Reproduction steps** | Missing or vague | Present but missing details | Deterministic and complete | |
| **Evidence** | No evidence | Code refs only | Code + runtime evidence | |
| **Impact** | Not stated or inflated | Stated but not demonstrated | Demonstrated with evidence | |
| **Control test** | Not performed | Mentioned but not detailed | Documented with results | |
| **Redaction** | Sensitive data present | Partially redacted | Fully sanitized | |
| **Scope** | Not verified | Probably in scope | Confirmed against program rules | |
| **Root cause** | Not identified | Symptoms described | Root cause with code reference | |
| **Remediation** | Not mentioned | Generic suggestion | Specific, actionable fix | |
| **Writing quality** | Unclear, disorganized | Readable but wordy | Concise and professional | |

**Total: ___/20**

- **16–20:** Ready to submit
- **12–15:** Review and improve weak areas
- **8–11:** Significant gaps — more validation needed
- **0–7:** Not ready — continue investigating

---

# Appendix A. Enhanced Quick-Reference Checklists

## Before Starting a New Target

- [ ] Read the complete program scope and rules (not just the summary)
- [ ] Confirm the exact assets and test techniques are permitted
- [ ] Note data-handling and rate-limit requirements
- [ ] Create dedicated test accounts (do not use personal accounts)
- [ ] Define the expected secure behavior for your first hypothesis
- [ ] Plan a low-impact investigation with clear stop conditions
- [ ] Set up your testing environment (proxy, browser profile, notes file)
- [ ] Check for previously disclosed reports on this program

## During Testing

- [ ] One hypothesis at a time — don't scatter
- [ ] Cite file paths and line numbers for every claim
- [ ] Run control tests before claiming a finding
- [ ] Stop if you see real user data, unknown accounts, or service impact
- [ ] Keep timestamped notes of every request and response
- [ ] Clean up test objects after each test
- [ ] Check rate limits before repeating requests

## Before Calling a Lead a Vulnerability

- [ ] I can name the security property that failed
- [ ] I have direct evidence, not just AI analysis
- [ ] I have considered at least 5 benign explanations
- [ ] I performed a safe control test
- [ ] I can explain the demonstrated impact with prerequisites
- [ ] The issue is clearly in scope
- [ ] The issue is not already known or disclosed
- [ ] My evidence is reproducible and sanitized

## Before Submitting a Report

- [ ] Title names root cause and demonstrated impact
- [ ] Reproduction steps are deterministic (numbered, specific)
- [ ] Expected and actual behavior are clearly separated
- [ ] Evidence is sanitized — no secrets, tokens, or PII
- [ ] Severity follows the program's rubric (or is left for triage)
- [ ] Every claim is supported by evidence
- [ ] Control tests are documented
- [ ] Cleanup was performed and documented
- [ ] Report follows the program's format and submission process
- [ ] Self-assessment score is 16+ (using the rubric above)

---

# Appendix B. Severity Decision Framework

## Step 1: What impact was demonstrated?

| Impact | Description |
|--------|-------------|
| **Confidentiality** | Unauthorized read of data |
| **Integrity** | Unauthorized modification of data |
| **Availability** | Service disruption or denial |

## Step 2: What privileges are required?

| Level | Description |
|-------|-------------|
| **None** | No account needed |
| **Low** | Free/basic account |
| **High** | Admin or privileged account |

## Step 3: What user interaction is required?

| Level | Description |
|-------|-------------|
| **None** | No victim interaction |
| **Passive** | Victim visits a link |
| **Active** | Victim must perform specific actions |

## Step 4: What is the scope of impact?

| Level | Description |
|-------|-------------|
| **Single user** | One targeted user affected |
| **Multiple users** | A group of users affected |
| **All users** | Potentially all users affected |

## Severity Matrix (Approximate)

| Impact | Privileges | Interaction | Scope | Approximate Severity |
|--------|-----------|-------------|-------|---------------------|
| C+I | None | None | All | Critical |
| C+I | Low | None | All | High |
| C | None | None | Single | Medium–High |
| C | Low | Passive | Single | Medium |
| I | Low | None | Single | Medium |
| A (temporary) | None | None | All | Medium |
| C (limited) | High | None | Single | Low–Medium |

**Always defer to the program's own severity rubric when available.**

---

# Appendix C. Expanded Glossary

- **Attack surface:** The set of places where a user or system can interact with an application.
- **Authentication (AuthN):** The process of establishing who or what an identity is.
- **Authorization (AuthZ):** The decision about what an authenticated identity is allowed to do.
- **BOLA / IDOR:** Broken Object-Level Authorization — accessing objects by manipulating identifiers without proper authorization checks.
- **BFLA:** Broken Function-Level Authorization — accessing administrative functions without proper role checks.
- **Cache poisoning:** Manipulating cached responses to serve malicious content to other users.
- **Control test:** A comparison test designed to distinguish a real issue from expected behavior.
- **CORS:** Cross-Origin Resource Sharing — browser mechanism controlling cross-domain requests.
- **CSRF:** Cross-Site Request Forgery — causing a browser to submit an unwanted authenticated action.
- **DNS rebinding:** An attack where a DNS record changes during a request, bypassing same-origin restrictions.
- **False positive:** A suspected finding that is not actually a vulnerability.
- **GraphQL introspection:** A feature that exposes the full API schema — often left enabled in production.
- **HMAC:** Hash-based Message Authentication Code — used for webhook signature verification.
- **HTTP smuggling:** Exploiting differences in how proxies and servers parse HTTP requests.
- **JWT:** JSON Web Token — a self-contained, signed token often used for stateless authentication.
- **Mass assignment:** When a server binds all request properties to a model, including protected fields.
- **OAuth:** Open Authorization — a protocol for delegated access to APIs.
- **OIDC:** OpenID Connect — an identity layer built on top of OAuth 2.0.
- **PKCE:** Proof Key for Code Exchange — protects OAuth authorization code flow against interception.
- **PoC:** Proof of concept — a minimal, reproducible demonstration of a security issue.
- **Prototype pollution:** A JavaScript vulnerability where attackers modify Object.prototype.
- **Race condition:** A flaw where the outcome depends on the timing of concurrent operations.
- **Root cause:** The underlying implementation or design mistake that allows the issue.
- **SSRF:** Server-Side Request Forgery — influencing a server to make a request it should not.
- **SSTI:** Server-Side Template Injection — injecting template syntax that the server evaluates.
- **Subdomain takeover:** Claiming a subdomain's DNS target (e.g., expired cloud service) to serve content.
- **TOCTOU:** Time-of-Check to Time-of-Use — a race condition between validating and using a value.
- **Trust boundary:** A point where data or control crosses between components with different trust levels.
- **XSS:** Cross-Site Scripting — attacker-controlled content executed as script in a browser context.

---

# Appendix D. One-Liner Quick Prompts

When you need a fast, focused answer:

```
# Quick route audit
"List all routes that accept user input but don't have auth middleware. Cite file:line."

# Quick IDOR check
"For GET /api/items/{id} — trace the ownership check from request to database query. Cite code."

# Quick XSS check
"Find all places user input is rendered without encoding in templates. Cite file:line and context."

# Quick SQL injection check
"Find all raw SQL queries that include string concatenation or template literals. Cite file:line."

# Quick auth check
"Does the password-reset token get invalidated after use? Trace the code. Cite file:line."

# Quick mass assignment check
"For PUT /api/profile — what fields does the server accept? Is there an allowlist? Cite code."

# Quick SSRF check
"Find all places the server fetches a user-provided URL. What validation exists? Cite file:line."

# Quick config check
"Are cookies set with Secure, HttpOnly, and SameSite flags? Where is this configured? Cite file:line."

# Quick JWT check
"How is the JWT signature verified? Is the algorithm explicitly whitelisted? Cite code."

# Quick GraphQL check
"Is GraphQL introspection enabled? Are resolvers individually authorized? Cite code."

# Quick race condition check
"Does this payment flow use database transactions? Is the balance check atomic? Cite code."

# Quick secret check
"Search for hardcoded API keys, passwords, or tokens in the source. Report file:line only, not values."
```

---

# Closing Note

The strongest use of Claude Code is not asking it to promise bugs. It is using it to **map code, generate testable questions, challenge assumptions, organize evidence, and write clear reports**. The researcher supplies authorization, judgment, controlled validation, and accountability.

This enhanced toolkit covers 120+ prompts across 15 vulnerability categories, provides prompt chaining maps for complete investigation flows, and includes practical tooling guidance, platform tips, and a self-assessment rubric. Use it as a living document — adapt the prompts to your target, refine your process after each investigation, and always prioritize safety and authorization.

**Version:** Enhanced Edition | Web Application Security | Educational material for authorized testing

---

*AI output is a lead, not proof. You are responsible for authorization, verification, and ethical conduct.*

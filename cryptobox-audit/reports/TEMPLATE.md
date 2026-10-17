# Vulnerability Report — [TITLE]

**Program:** Cryptobox Bug Bounty (YesWeHack)
**Affected asset:** `https://bounty.cryptobox.com`
**Date discovered:** [YYYY-MM-DD]
**Severity:** [Critical / High / Medium / Low]
**Category:** [e.g., IDOR, Privilege Escalation, XSS, Authentication Bypass]
**Hypothesis ID:** [e.g., H-A1 from HYPOTHESES.md]

---

## Summary

[One or two sentences describing the vulnerability and its security impact.]

---

## Affected feature

[Name the specific application feature, endpoint, or workflow.]

---

## Prerequisite access

[Describe what an attacker needs before exploitation:]
- [ ] Authenticated account
- [ ] Membership in the target workspace (specify role)
- [ ] Knowledge of specific identifiers (file ID, workspace ID, etc.)
- [ ] Valid sharing key
- [ ] Other: [specify]

---

## Reproduction steps

1. [Step-by-step instructions to reproduce the vulnerability.]
2. [Include exact API paths, methods, headers, and body content.]
3. [Use the two authorized test accounts only.]
4. [Each step should be independently verifiable.]

---

## Request / response evidence

### Request (Account performing the unauthorized action)

```http
[METHOD] [PATH] HTTP/1.1
Host: bounty.cryptobox.com
Cookie: [REDACTED]
Content-Type: application/json

[BODY — with sensitive values redacted]
```

### Response

```http
HTTP/1.1 [STATUS CODE] [STATUS TEXT]
Content-Type: [type]

[BODY — with sensitive values redacted, showing only what demonstrates the vulnerability]
```

---

## Expected behavior

[Describe what should happen if the application is secure.]

---

## Actual behavior

[Describe what actually happens, and why it constitutes a security violation.]

---

## Evidence summary

| Evidence item | Description |
|---|---|
| Request from unauthorized account | [Brief description] |
| Response showing unauthorized data/action | [Brief description] |
| Verification from owning account | [Confirm the action persisted / data was real] |

---

## Security impact

[Describe the concrete impact:]
- **Confidentiality:** [What data is exposed?]
- **Integrity:** [What data can be modified?]
- **Authentication:** [Is authentication bypassed?]
- **Authorization:** [What access control is violated?]

[Describe a realistic attack scenario in 2-3 sentences.]

---

## Severity justification

[Explain why the chosen severity is appropriate. Reference the program's qualifying
categories where applicable. Do not inflate severity.]

---

## Remediation guidance

[Specific, actionable recommendations:]
1. [Primary fix]
2. [Defense in depth]
3. [Detection / monitoring suggestion]

---

## Program eligibility

- [ ] The vulnerability is on the authorized asset (`bounty.cryptobox.com`).
- [ ] The vulnerability falls within a qualifying category.
- [ ] The vulnerability is not on the explicit exclusion list.
- [ ] Testing used only the two authorized hunter accounts.
- [ ] No data belonging to other users was accessed or modified.
- [ ] Evidence is reproducible and sufficient.

---

## Limitations and assumptions

[Note any conditions, timing dependencies, or environmental factors that affect
reproducibility. Be transparent about what was and was not verified.]

---

## Attachments

- [ ] Redacted HTTP request/response logs
- [ ] Screenshot(s) showing the vulnerability (if applicable)
- [ ] Minimal proof-of-concept (safe, non-destructive)

# Allekabels Bug Bounty - Security Analysis Report
## Target: www.allekabels.nl
## Program: Intigriti RPIP/Allekabels (Tier 2)
## Researcher: ramjiapi049
## Date: 2026-10-15

---

## 1. OSINT / Reconnaissance Summary

### Technology Stack (from public sources)
| Technology | Category | Security Implication |
|---|---|---|
| Cloudflare CDN | CDN/WAF | WAF filtering, IP masking, DDoS protection |
| Cloudflare Website Optimization | Performance | May cache responses — test for cache poisoning |
| reCAPTCHA | Anti-bot | Rate limiting on forms — test for bypass |
| Google Tag Manager | Analytics | Check for GTM container misconfig / data leakage |
| Custom CMS | Backend | Self-built = higher chance of logic bugs |
| Custom Logistics System | Backend | Partner integrations = potential IDOR/auth issues |

### Historical Breach Intel (2021)
- **Scale**: 3.6 million customer records stolen
- **Data**: Emails, names, addresses, phone numbers, DOB, hashed passwords, 109K IBANs
- **34 other webshops** also had data in the breach (shared codebase/DB)
- **Attack vector**: Reportedly a "backdoor" (unverified) discovered Aug 2020
- **Passwords**: Stored hashed (algorithm unknown)
- **Implication**: Custom codebase has had critical vulns before — likely still has logic bugs

### Known Subdomains (from program scope)
- `www.allekabels.nl` — Main site (IN SCOPE, Tier 2)
- `image.allekabels.nl` — Image CDN (OUT OF SCOPE)
- Other subdomains unknown (crt.sh query blocked from this environment)

### Key Infrastructure Notes
- Cloudflare sits in front — direct origin IP not known
- Custom-built CMS, logistics, and partner integration systems
- Self-registration available (use @intigriti.me email)
- Orders from @intigriti.me accounts auto-cancelled

---

## 2. Attack Surface Analysis

### HIGH PRIORITY TARGETS (most likely to yield findings)

#### A. IDOR on Order/Account/Invoice Endpoints
- **Why**: E-commerce sites with custom CMS are notorious for IDOR
- **Where to test**:
  - Order history page — change order ID in URL/request
  - Invoice/receipt download — change document ID
  - Address book — try accessing other users' addresses
  - Account settings API calls — change user ID parameter
  - Wishlist/cart sharing features
- **Past context**: The 2021 breach involved 3.6M customer records, suggesting the DB schema ties users to sequential/guessable IDs

#### B. SQL Injection in Search/Filter/Product Parameters
- **Why**: Custom CMS without ORM = higher SQLi risk
- **Where to test**:
  - Search bar (`?q=` or `?search=` parameter)
  - Product category filters
  - Product sorting parameters
  - Price range filters
  - Pagination parameters
  - Product ID in URL path

#### C. XSS in User-Generated Content Areas
- **Why**: Custom CMS may not sanitize all inputs
- **Where to test**:
  - Search results (reflected XSS)
  - Account profile fields (stored XSS)
  - Product reviews/questions
  - Contact/support forms
  - Address fields
  - Newsletter signup
  - Error messages reflecting input

#### D. Authentication & Session Issues
- **Why**: Custom auth = custom bugs
- **Where to test**:
  - Password reset flow — token predictability, no rate limit
  - Session fixation after login
  - Session token in URL
  - Account takeover via parameter manipulation
  - JWT issues (if using JWT)
  - OAuth misconfig (if using social login)

#### E. Privilege Escalation (Vertical/Horizontal)
- **Why**: Customer vs staff roles in custom CMS
- **Where to test**:
  - Access admin/staff-only endpoints as regular user
  - Modify user role parameter during registration
  - API calls that accept role/permission parameters
  - Partner/logistics system endpoints accessible to customers

### MEDIUM PRIORITY TARGETS

#### F. Server-Side Request Forgery (SSRF)
- **Where**: Image upload, URL import, webhook configurations
- **Blind SSRF**: Use Burp Collaborator or similar OOB tool

#### G. Business Logic Flaws
- **Where to test**:
  - Negative quantity/price manipulation in cart
  - Coupon/discount code stacking
  - Race conditions in checkout
  - Free shipping threshold manipulation
  - Order cancellation after shipment
  - Refund logic abuse

#### H. Information Disclosure
- **Where to test**:
  - Error pages with stack traces
  - Debug endpoints left enabled
  - .git directory exposure
  - Backup files (.bak, .old, .sql)
  - phpinfo() or similar
  - API documentation endpoints
  - GraphQL introspection

---

## 3. Specific Test Cases by Vulnerability Class

### SQLi Test Matrix
| Endpoint | Parameter | Payload | Expected if Vulnerable |
|---|---|---|---|
| Search | q | `test' OR '1'='1` | Returns all products |
| Product page | id | `1 AND 1=1` vs `1 AND 1=2` | Different response |
| Category | cat_id | `1' UNION SELECT NULL--` | Column count disclosure |
| Sort | sort | `price,(SELECT SLEEP(5))` | 5-second delay |
| Pagination | page | `1; WAITFOR DELAY '0:0:5'` | 5-second delay |

### XSS Test Matrix
| Endpoint | Input | Payload | Check |
|---|---|---|---|
| Search | q | `<img src=x onerror=alert(1)>` | Reflected in results? |
| Profile | name | `"><svg onload=alert(1)>` | Stored in page? |
| Review | body | `javascript:alert(1)` | Clickable link? |
| Contact | message | `{{7*7}}` | Template injection? |
| Address | street | `<script>alert(1)</script>` | Reflected in order? |

### IDOR Test Matrix
| Endpoint | Parameter | Test |
|---|---|---|
| /account/orders/{id} | order id | Increment/decrement ID |
| /account/invoice/{id} | invoice id | Change to another user's |
| /account/address/{id} | address id | Access other user's address |
| /api/user/{id} | user id | Change user ID |
| /account/returns/{id} | return id | View other user's return |

---

## 4. Recommended Testing Workflow

1. **Register** with @intigriti.me email
2. **Map the application** — browse all features, note all endpoints
3. **Intercept traffic** with Burp Suite — log all requests
4. **Test IDOR first** — highest reward-to-effort ratio for e-commerce
5. **Test SQLi** on search and filter parameters
6. **Test XSS** on all input fields, especially search
7. **Test auth flows** — password reset, session management
8. **Test business logic** — cart manipulation, pricing
9. **Check for info disclosure** — error pages, hidden endpoints
10. **Document everything** with screenshots and HTTP requests

---

## 5. Environment Limitation

**This cloud session cannot directly reach allekabels.nl** (proxy blocks non-allowed domains).

To enable direct testing from this session:
- Edit the cloud environment → Network access → Add `allekabels.nl` and `www.allekabels.nl` to Allowed domains

Alternatively, use the testing toolkit below from your local machine.

---

## 6. Out of Scope Reminders
- image.allekabels.nl
- Third-party services (PayPal, Multisafepay)
- Self-XSS
- Missing cookie flags alone
- Missing security headers alone
- Rate limiting issues
- CSRF with no/low impact
- Email enumeration
- Clickjacking without proven impact

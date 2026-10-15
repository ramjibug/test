#!/usr/bin/env python3
"""
Allekabels.nl Bug Bounty - Manual Reconnaissance Toolkit
Researcher: ramjiapi049
Program: Intigriti RPIP/Allekabels

IMPORTANT: This is a MANUAL testing tool. Run one test at a time.
Respects rate limit: max 5 requests/sec as per program rules.
NOT an automated scanner.

Usage: python3 allekabels_recon.py
"""

import requests
import time
import json
import sys
import re
from urllib.parse import urljoin, urlparse, quote
from collections import defaultdict

BASE_URL = "https://www.allekabels.nl"
RATE_LIMIT_DELAY = 0.25  # 4 req/sec max (under 5/sec limit)
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7",
})


def rate_limit():
    time.sleep(RATE_LIMIT_DELAY)


def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def print_finding(severity, title, detail):
    icons = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[.]", "INFO": "[i]"}
    print(f"\n{icons.get(severity, '[?]')} [{severity}] {title}")
    print(f"    {detail}")


# ============================================================
# 1. SECURITY HEADERS CHECK
# ============================================================
def check_security_headers():
    print_header("SECURITY HEADERS ANALYSIS")
    rate_limit()
    try:
        resp = SESSION.get(BASE_URL, timeout=15, allow_redirects=True)
        print(f"Status: {resp.status_code}")
        print(f"Final URL: {resp.url}")
        print(f"\nAll Response Headers:")
        for k, v in resp.headers.items():
            print(f"  {k}: {v}")

        expected_headers = {
            "Strict-Transport-Security": "HSTS not set — no forced HTTPS",
            "Content-Security-Policy": "No CSP — XSS risk elevated",
            "X-Content-Type-Options": "No XCTO — MIME sniffing possible",
            "X-Frame-Options": "No XFO — clickjacking possible",
            "Referrer-Policy": "No referrer policy — URL leakage possible",
            "Permissions-Policy": "No permissions policy",
        }

        print("\nMissing Security Headers (NOTE: missing headers alone are out of scope):")
        for header, msg in expected_headers.items():
            if header.lower() not in [h.lower() for h in resp.headers]:
                print(f"  [-] {header}: {msg}")
            else:
                print(f"  [+] {header}: {resp.headers.get(header, '')[:80]}")

        server = resp.headers.get("Server", "Not disclosed")
        powered = resp.headers.get("X-Powered-By", "Not disclosed")
        print(f"\nServer: {server}")
        print(f"X-Powered-By: {powered}")

        for cookie in resp.cookies:
            flags = []
            if cookie.secure:
                flags.append("Secure")
            if "httponly" in str(cookie._rest).lower():
                flags.append("HttpOnly")
            samesite = cookie._rest.get("SameSite", "Not set")
            flags.append(f"SameSite={samesite}")
            print(f"\nCookie: {cookie.name}")
            print(f"  Domain: {cookie.domain}")
            print(f"  Path: {cookie.path}")
            print(f"  Flags: {', '.join(flags)}")

    except Exception as e:
        print(f"Error: {e}")


# ============================================================
# 2. TECHNOLOGY FINGERPRINTING
# ============================================================
def fingerprint_tech():
    print_header("TECHNOLOGY FINGERPRINTING")
    rate_limit()
    try:
        resp = SESSION.get(BASE_URL, timeout=15)
        body = resp.text

        tech_signatures = {
            "jQuery": (r'jquery[.-](\d+\.\d+\.\d+)', "JavaScript Library"),
            "Bootstrap": (r'bootstrap[.-](\d+\.\d+\.\d+)', "CSS Framework"),
            "React": (r'react[.-](\d+\.\d+\.\d+)|__NEXT_DATA__|_react', "JS Framework"),
            "Vue.js": (r'vue[.-](\d+\.\d+\.\d+)|__vue__', "JS Framework"),
            "Angular": (r'angular[.-](\d+\.\d+\.\d+)|ng-app|ng-controller', "JS Framework"),
            "WordPress": (r'wp-content|wp-includes|wp-json', "CMS"),
            "Magento": (r'Mage\.|magento|/skin/frontend', "E-commerce"),
            "Shopify": (r'cdn\.shopify\.com|Shopify\.', "E-commerce"),
            "WooCommerce": (r'woocommerce|wc-ajax', "E-commerce"),
            "Google Tag Manager": (r'googletagmanager\.com|GTM-\w+', "Analytics"),
            "Google Analytics": (r'google-analytics\.com|UA-\d+|G-\w+', "Analytics"),
            "reCAPTCHA": (r'recaptcha|grecaptcha', "Anti-bot"),
            "Cloudflare": (r'cloudflare|__cf_bm|cf-ray', "CDN/WAF"),
            "PHP": (r'\.php|PHPSESSID', "Backend Language"),
            "ASP.NET": (r'__VIEWSTATE|ASP\.NET|\.aspx', "Backend Framework"),
            "Laravel": (r'laravel_session|XSRF-TOKEN.*laravel', "PHP Framework"),
        }

        print("Detected Technologies:")
        for name, (pattern, category) in tech_signatures.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            header_match = any(re.search(pattern, v, re.IGNORECASE) for v in resp.headers.values())
            if matches or header_match:
                version = matches[0] if matches and matches[0] else "version unknown"
                print(f"  [+] {name} ({category}): {version}")

        # Extract all script sources
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body)
        print(f"\nExternal Scripts ({len(scripts)} found):")
        for s in scripts[:20]:
            print(f"  - {s}")

        # Extract all link hrefs (CSS)
        links = re.findall(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*rel=["\']stylesheet["\']', body)
        print(f"\nStylesheets ({len(links)} found):")
        for l in links[:10]:
            print(f"  - {l}")

        # Extract meta tags
        metas = re.findall(r'<meta\s+([^>]+)>', body)
        print(f"\nMeta Tags:")
        for m in metas:
            print(f"  - {m[:100]}")

        # Look for HTML comments (info disclosure)
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        if comments:
            print(f"\nHTML Comments ({len(comments)} found):")
            for c in comments[:10]:
                content = c.strip()[:200]
                if content and not content.startswith('[if'):
                    print(f"  - {content}")

    except Exception as e:
        print(f"Error: {e}")


# ============================================================
# 3. ENDPOINT DISCOVERY
# ============================================================
def discover_endpoints():
    print_header("ENDPOINT DISCOVERY")

    paths_to_check = [
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/admin",
        "/login",
        "/register",
        "/account",
        "/cart",
        "/checkout",
        "/search",
        "/contact",
        "/wp-admin",
        "/wp-login.php",
        "/.git/HEAD",
        "/.env",
        "/.htaccess",
        "/server-status",
        "/info.php",
        "/phpinfo.php",
        "/swagger",
        "/swagger-ui",
        "/api-docs",
        "/debug",
        "/test",
        "/backup",
        "/db",
        "/config",
        "/actuator",
        "/actuator/health",
        "/status",
    ]

    print("Checking common paths (one at a time, rate limited)...\n")
    for path in paths_to_check:
        rate_limit()
        url = urljoin(BASE_URL, path)
        try:
            resp = SESSION.get(url, timeout=10, allow_redirects=False)
            status = resp.status_code
            size = len(resp.content)
            location = resp.headers.get("Location", "")

            if status == 200:
                print(f"  [200] {path} ({size} bytes) <-- INVESTIGATE")
            elif status in (301, 302, 303, 307, 308):
                print(f"  [{status}] {path} -> {location}")
            elif status == 403:
                print(f"  [403] {path} (Forbidden - exists but blocked)")
            elif status == 401:
                print(f"  [401] {path} (Auth required - exists!)")
            elif status == 405:
                print(f"  [405] {path} (Method not allowed - endpoint exists)")
            # Skip 404s silently
        except Exception as e:
            print(f"  [ERR] {path}: {e}")


# ============================================================
# 4. SEARCH PARAMETER TESTING (XSS/SQLi reflection check)
# ============================================================
def test_search_reflection():
    print_header("SEARCH PARAMETER REFLECTION TEST")

    test_payloads = [
        ("Basic HTML", "<b>test123</b>"),
        ("Script tag", "<script>alert(1)</script>"),
        ("Event handler", '<img src=x onerror="alert(1)">'),
        ("Template expr", "{{7*7}}"),
        ("SQL single quote", "test'"),
        ("SQL double quote", 'test"'),
        ("SQL comment", "test'--"),
        ("Canary", "CANARY_XSS_TEST_12345"),
    ]

    # Try common search URL patterns
    search_urls = [
        f"{BASE_URL}/search?q={{payload}}",
        f"{BASE_URL}/zoeken?q={{payload}}",
        f"{BASE_URL}/?s={{payload}}",
        f"{BASE_URL}/search?query={{payload}}",
    ]

    for name, payload in test_payloads:
        for url_template in search_urls:
            rate_limit()
            url = url_template.format(payload=quote(payload))
            try:
                resp = SESSION.get(url, timeout=10)
                if resp.status_code == 200:
                    if payload in resp.text:
                        print_finding("HIGH", f"Unencoded reflection: {name}",
                                     f"URL: {url}\nPayload reflected without encoding!")
                    elif payload.replace("<", "&lt;").replace(">", "&gt;") in resp.text:
                        print(f"  [OK] {name} on {urlparse(url).path}: HTML-encoded (safe)")
                    break  # Found a working search URL
            except Exception:
                continue


# ============================================================
# 5. IDOR TESTING HELPER
# ============================================================
def test_idor_helper():
    print_header("IDOR TESTING GUIDE")
    print("""
IDOR testing requires TWO authenticated accounts.
Register two accounts with your @intigriti.me email:
  - Account A: your-name-a@intigriti.me
  - Account B: your-name-b@intigriti.me

Steps:
1. Log in as Account A, create an order, note the order ID
2. Log in as Account B in a different browser/incognito
3. Try to access Account A's resources from Account B

Common IDOR endpoints to check:
  - /account/orders/{ORDER_ID}
  - /account/orders/{ORDER_ID}/invoice
  - /api/orders/{ORDER_ID}
  - /account/addresses/{ADDRESS_ID}
  - /api/user/{USER_ID}
  - /account/returns/{RETURN_ID}
  - /account/wishlist/{WISHLIST_ID}

Tips:
  - Use Burp Suite to intercept and modify requests
  - Try decrementing/incrementing IDs
  - Try UUID guessing if UUIDs are used
  - Check if API responses leak more data than the UI shows
  - Look at JSON API responses — sometimes the UI hides fields
    that the API still returns
""")


# ============================================================
# 6. FORM ENUMERATION
# ============================================================
def enumerate_forms():
    print_header("FORM ENUMERATION")
    rate_limit()
    try:
        resp = SESSION.get(BASE_URL, timeout=15)
        forms = re.findall(r'<form([^>]*)>(.*?)</form>', resp.text, re.DOTALL | re.IGNORECASE)
        print(f"Found {len(forms)} forms on homepage:\n")
        for i, (attrs, body) in enumerate(forms):
            action = re.search(r'action=["\']([^"\']*)["\']', attrs)
            method = re.search(r'method=["\']([^"\']*)["\']', attrs)
            inputs = re.findall(r'<input([^>]*)>', body)

            print(f"Form #{i+1}:")
            print(f"  Action: {action.group(1) if action else '(same page)'}")
            print(f"  Method: {method.group(1) if method else 'GET'}")
            for inp in inputs:
                name = re.search(r'name=["\']([^"\']*)["\']', inp)
                type_ = re.search(r'type=["\']([^"\']*)["\']', inp)
                print(f"  Input: name={name.group(1) if name else '?'}, type={type_.group(1) if type_ else 'text'}")
            print()
    except Exception as e:
        print(f"Error: {e}")


# ============================================================
# 7. GTM CONTAINER ANALYSIS
# ============================================================
def check_gtm():
    print_header("GOOGLE TAG MANAGER ANALYSIS")
    rate_limit()
    try:
        resp = SESSION.get(BASE_URL, timeout=15)
        gtm_ids = re.findall(r'GTM-(\w+)', resp.text)
        if gtm_ids:
            for gtm_id in set(gtm_ids):
                print(f"  [+] Found GTM Container: GTM-{gtm_id}")
                print(f"      Check: https://www.googletagmanager.com/gtm.js?id=GTM-{gtm_id}")
                print(f"      Look for: custom HTML tags, data layer variables, third-party scripts")
                print(f"      Security: GTM can inject arbitrary JS if misconfigured")
        else:
            print("  [-] No GTM containers found in page source")
    except Exception as e:
        print(f"Error: {e}")


# ============================================================
# MAIN MENU
# ============================================================
def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║  Allekabels.nl Bug Bounty - Manual Recon Toolkit        ║
║  Researcher: ramjiapi049 | Program: Intigriti            ║
║  Rate Limited: max 4 req/sec (under 5/sec program limit) ║
╚══════════════════════════════════════════════════════════╝
    """)

    tests = {
        "1": ("Security Headers", check_security_headers),
        "2": ("Technology Fingerprinting", fingerprint_tech),
        "3": ("Endpoint Discovery", discover_endpoints),
        "4": ("Search Reflection Test (XSS/SQLi)", test_search_reflection),
        "5": ("IDOR Testing Guide", test_idor_helper),
        "6": ("Form Enumeration", enumerate_forms),
        "7": ("GTM Container Analysis", check_gtm),
        "0": ("Run ALL Tests", None),
    }

    print("Available Tests:")
    for k, (name, _) in tests.items():
        print(f"  [{k}] {name}")

    choice = input("\nSelect test (0-7): ").strip()

    if choice == "0":
        for k, (name, func) in tests.items():
            if func:
                func()
    elif choice in tests and tests[choice][1]:
        tests[choice][1]()
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()

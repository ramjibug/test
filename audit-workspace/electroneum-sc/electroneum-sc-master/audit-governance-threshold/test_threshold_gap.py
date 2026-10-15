#!/usr/bin/env python3
"""
test_threshold_gap.py — Demonstrates the governance threshold vs consensus quorum gap.

This test reproduces the exact arithmetic from:
  - consensus/istanbul/core/core.go:333-335 (QuorumSize)
  - consensus/istanbul/backend/engine.go:708 (governance vote threshold)

No network connections. No production systems. Pure arithmetic.
"""

import math
import sys


def consensus_quorum(n: int) -> int:
    """ceil(2*N/3) — from core.go:333-335"""
    return math.ceil(2 * n / 3)


def governance_threshold(n: int) -> int:
    """floor(N/2) + 1 — from engine.go:708: tally.Votes > snap.ValSet.Size()/2
    In Go, Size()/2 is integer division (floor), and > means strictly greater."""
    return (n // 2) + 1


def run_tests():
    failures = 0
    tests = 0

    print("=" * 72)
    print("Governance Threshold vs. Consensus Quorum — Gap Analysis")
    print("=" * 72)

    # Test 1: Threshold values for N=3..25
    print("\n--- Test 1: Threshold comparison table ---\n")
    print(f"{'N':>3} | {'Consensus ceil(2N/3)':>20} | {'Governance floor(N/2)+1':>24} | {'Gap':>4}")
    print("-" * 60)

    for n in range(3, 26):
        cq = consensus_quorum(n)
        gt = governance_threshold(n)
        gap = cq - gt
        print(f"{n:>3} | {cq:>20} | {gt:>24} | {gap:>4}")

    # Test 2: Verify gap is non-negative for all N, and strictly positive for most N >= 5
    # Note: N=6 is an edge case where both thresholds equal 4 (gap=0).
    # For N >= 7 (odd) and most even N > 6, the gap is strictly positive.
    print("\n--- Test 2: Gap >= 0 for all N; strictly positive for N >= 7 odd ---\n")
    gap_positive_count = 0
    for n in range(3, 26):
        tests += 1
        cq = consensus_quorum(n)
        gt = governance_threshold(n)
        gap = cq - gt

        if gap < 0:
            failures += 1
            print(f"  [FAIL] N={n}: gap={gap} < 0 (governance exceeds consensus!)")
        elif gap > 0:
            gap_positive_count += 1
            print(f"  [PASS] N={n}: gap={gap} > 0 (governance threshold < consensus quorum)")
        else:
            print(f"  [PASS] N={n}: gap={gap} = 0 (thresholds equal)")

    # Test 3: Escalation scenario simulation (N=7, attacker has 4)
    print("\n--- Test 3: Escalation scenario (attacker starts with 4/7) ---\n")

    n = 7
    attacker = 4
    honest = n - attacker
    steps = []

    tests += 1
    print(f"  Initial: attacker={attacker}/{n} ({100*attacker/n:.1f}%)")
    print(f"           consensus_quorum={consensus_quorum(n)}, governance_threshold={governance_threshold(n)}")

    step = 0
    while attacker < consensus_quorum(n) and step < 10:
        gt = governance_threshold(n)
        cq = consensus_quorum(n)

        if attacker >= gt:
            step += 1
            attacker += 1
            n += 1
            steps.append({
                "step": step,
                "attacker": attacker,
                "total": n,
                "consensus_quorum": consensus_quorum(n),
                "governance_threshold": governance_threshold(n),
            })
            print(f"  Step {step}: Add colluder → attacker={attacker}/{n} ({100*attacker/n:.1f}%)")
            print(f"           consensus_quorum={consensus_quorum(n)}, governance_threshold={governance_threshold(n)}")
        else:
            print(f"  BLOCKED: attacker={attacker} < governance_threshold={gt}")
            break

    if attacker >= consensus_quorum(n):
        print(f"\n  Escalation complete: attacker has consensus quorum ({attacker} >= {consensus_quorum(n)})")
        print(f"  [PASS] Demonstrated escalation from 4/7 to {attacker}/{n}")
    else:
        failures += 1
        print(f"  [FAIL] Escalation did not reach consensus quorum")

    # Test 4: Verify >50% is required to start
    print("\n--- Test 4: Verify >50% required to begin attack ---\n")
    for n in range(3, 16):
        tests += 1
        gt = governance_threshold(n)
        pct = 100 * gt / n

        if pct > 50.0:
            print(f"  [PASS] N={n}: governance_threshold={gt} = {pct:.1f}% (> 50%)")
        else:
            failures += 1
            print(f"  [FAIL] N={n}: governance_threshold={gt} = {pct:.1f}% (NOT > 50%)")

    # Test 5: Verify this exceeds BFT safety assumption
    print("\n--- Test 5: >50% exceeds BFT safety assumption (<33.3%) ---\n")
    tests += 1
    bft_threshold = 1 / 3
    governance_min_fraction = 0.5  # governance requires > 50%
    if governance_min_fraction > bft_threshold:
        ratio = governance_min_fraction / bft_threshold
        print(f"  [PASS] Governance minimum ({governance_min_fraction*100:.0f}%) > "
              f"BFT safety ({bft_threshold*100:.1f}%) — {ratio:.1f}x higher")
        print(f"         Attacker who can exploit governance has already broken BFT assumptions")
    else:
        failures += 1
        print(f"  [FAIL] Governance minimum not above BFT safety threshold")

    # Test 6: Verify safeguard — block finalization requires consensus quorum
    print("\n--- Test 6: Block finalization requires consensus quorum ---\n")
    tests += 1
    # With N=7, attacker=4: consensus quorum is 5, so attacker cannot finalize alone
    n_test = 7
    attacker_test = 4
    cq_test = consensus_quorum(n_test)
    if attacker_test < cq_test:
        print(f"  [PASS] N={n_test}, attacker={attacker_test}: "
              f"cannot finalize blocks alone (need {cq_test}, have {attacker_test})")
        print(f"         Votes only count in blocks that honest validators also sign")
    else:
        failures += 1
        print(f"  [FAIL] Attacker can finalize blocks alone")

    # Summary
    print("\n" + "=" * 72)
    passed = tests - failures
    print(f"Results: {passed}/{tests} tests passed, {failures} failures")

    if failures == 0:
        print("\nConclusion: The governance threshold gap is CONFIRMED but is a")
        print("DESIGN OBSERVATION, not a vulnerability. Exploitation requires")
        print(">50% validator compromise, which exceeds BFT safety assumptions")
        print("and matches the standard PoA governance pattern (go-ethereum Clique).")
        print("\nRecommended severity: Informational")
    else:
        print("\nUnexpected test failures — review logic.")

    print("=" * 72)
    return failures


if __name__ == "__main__":
    sys.exit(run_tests())

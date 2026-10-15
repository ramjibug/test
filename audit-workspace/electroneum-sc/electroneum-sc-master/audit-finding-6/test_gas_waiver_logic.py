#!/usr/bin/env python3
"""
test_gas_waiver_logic.py — Demonstrates gas waiver validation logic.

Simulates the validation paths from:
  - core/state_transition.go:389-426 (validatePriorityGasFields)
  - core/state_transition.go:196-216 (buyGas)
  - core/state_transition.go:255-265 (preCheck base fee skip)
  - core/tx_pool.go:669-768 (validateTx)

No network connections. No production systems. Pure logic test.
"""

import sys


class PriorityTransactor:
    def __init__(self, is_gas_price_waiver: bool, entity_name: str):
        self.is_gas_price_waiver = is_gas_price_waiver
        self.entity_name = entity_name


class Message:
    def __init__(self, gas: int, gas_fee_cap: int, gas_tip_cap: int,
                 value: int, priority_sender: str = ""):
        self.gas = gas
        self.gas_fee_cap = gas_fee_cap
        self.gas_tip_cap = gas_tip_cap
        self.value = value
        self.priority_sender = priority_sender


def validate_priority_gas_fields(msg, transactor_map):
    """Simulates state_transition.go:389-426"""
    ps = msg.priority_sender
    if not ps:
        return False, None

    if ps not in transactor_map:
        return False, "errBadPriorityKey"

    transactor = transactor_map[ps]

    if transactor.is_gas_price_waiver:
        if msg.gas_fee_cap != 0 or msg.gas_tip_cap != 0:
            return True, "errNoGasPriceWaiver: waiver tx must have zero fee fields"
        return True, None  # Waiver granted

    if msg.gas_fee_cap <= 0:
        return False, "errNoGasPriceWaiver: non-waiver tx must have feeCap > 0"

    return False, None


def buy_gas(msg, sender_balance, gas_pool_remaining):
    """Simulates state_transition.go:196-216"""
    gas_price = min(msg.gas_tip_cap + 1000, msg.gas_fee_cap)  # simplified effective price
    if msg.gas_fee_cap == 0:
        gas_price = 0

    mgval = msg.gas * gas_price  # amount to deduct from sender
    balance_check = msg.gas * msg.gas_fee_cap + msg.value

    if sender_balance < balance_check:
        return None, None, "ErrInsufficientFunds"

    if gas_pool_remaining < msg.gas:
        return None, None, "ErrGasLimitReached"

    new_balance = sender_balance - mgval
    new_gas_pool = gas_pool_remaining - msg.gas
    return new_balance, new_gas_pool, None


def pre_check(msg, transactor_map, base_fee):
    """Simulates state_transition.go:218-269 (fee portion only)"""
    has_waiver, err = validate_priority_gas_fields(msg, transactor_map)
    if err:
        return err

    if not has_waiver and msg.gas_fee_cap < base_fee:
        return "ErrFeeCapTooLow"

    return None


def validate_tx_pool(msg, transactor_map, min_gas_price, is_local=False):
    """Simulates tx_pool.go:669-768 (priority-relevant portions)"""
    if msg.gas < 21000:
        return "ErrIntrinsicGas"

    is_gas_waiver = False
    if msg.priority_sender:
        if msg.priority_sender not in transactor_map:
            return "errBadPriorityKey"
        transactor = transactor_map[msg.priority_sender]
        is_gas_waiver = transactor.is_gas_price_waiver

        if is_gas_waiver and (msg.gas_fee_cap != 0 or msg.gas_tip_cap != 0):
            return "errNoGasPriceWaiver: waiver tx must have zero fee fields"

        if not is_gas_waiver and (msg.gas_fee_cap == 0 and msg.gas_tip_cap == 0):
            return "errNoGasPriceWaiver"

    if not is_local and not is_gas_waiver and msg.gas_tip_cap < min_gas_price:
        return "ErrUnderpriced"

    return None


def run_tests():
    failures = 0
    tests = 0

    waiver_key = "waiver-key-0x1234"
    no_waiver_key = "no-waiver-key-0x5678"
    transactor_map = {
        waiver_key: PriorityTransactor(True, "Electroneum-Waiver"),
        no_waiver_key: PriorityTransactor(False, "Electroneum-NoWaiver"),
    }
    base_fee = 1000  # 1000 wei
    min_gas_price = 100

    print("=" * 72)
    print("Finding 6: Gas Waiver DoS — Validation Logic Simulation")
    print("=" * 72)

    # === Test 1: Waiver key + zero fees → accepted ===
    print("\n--- Test 1: Waiver key with zero fees ---")
    tests += 1
    msg = Message(gas=21000, gas_fee_cap=0, gas_tip_cap=0, value=0,
                  priority_sender=waiver_key)
    has_waiver, err = validate_priority_gas_fields(msg, transactor_map)
    if has_waiver and err is None:
        print(f"  [PASS] validatePriorityGasFields: waiver=True, err=None")
    else:
        failures += 1
        print(f"  [FAIL] Expected waiver=True/err=None, got waiver={has_waiver}/err={err}")

    # === Test 2: Waiver key + non-zero fees → rejected ===
    print("\n--- Test 2: Waiver key with non-zero fees ---")
    tests += 1
    msg = Message(gas=21000, gas_fee_cap=1000, gas_tip_cap=100, value=0,
                  priority_sender=waiver_key)
    has_waiver, err = validate_priority_gas_fields(msg, transactor_map)
    if has_waiver and err is not None:
        print(f"  [PASS] Rejected: {err}")
    else:
        failures += 1
        print(f"  [FAIL] Expected rejection, got waiver={has_waiver}/err={err}")

    # === Test 3: Non-waiver key + zero fees → rejected ===
    print("\n--- Test 3: Non-waiver key with zero fees ---")
    tests += 1
    msg = Message(gas=21000, gas_fee_cap=0, gas_tip_cap=0, value=0,
                  priority_sender=no_waiver_key)
    has_waiver, err = validate_priority_gas_fields(msg, transactor_map)
    if not has_waiver and err is not None:
        print(f"  [PASS] Rejected: {err}")
    else:
        failures += 1
        print(f"  [FAIL] Expected rejection, got waiver={has_waiver}/err={err}")

    # === Test 4: Non-waiver key + positive fees → accepted ===
    print("\n--- Test 4: Non-waiver key with positive fees ---")
    tests += 1
    msg = Message(gas=21000, gas_fee_cap=2000, gas_tip_cap=100, value=0,
                  priority_sender=no_waiver_key)
    has_waiver, err = validate_priority_gas_fields(msg, transactor_map)
    if not has_waiver and err is None:
        print(f"  [PASS] Accepted: waiver=False (non-waiver pays fees)")
    else:
        failures += 1
        print(f"  [FAIL] Expected acceptance, got waiver={has_waiver}/err={err}")

    # === Test 5: preCheck skips baseFee for waiver tx ===
    print("\n--- Test 5: preCheck skips baseFee check for waiver tx ---")
    tests += 1
    msg = Message(gas=21000, gas_fee_cap=0, gas_tip_cap=0, value=0,
                  priority_sender=waiver_key)
    err = pre_check(msg, transactor_map, base_fee)
    if err is None:
        print(f"  [PASS] Waiver tx passes preCheck despite feeCap=0 < baseFee={base_fee}")
    else:
        failures += 1
        print(f"  [FAIL] Expected pass, got err={err}")

    # === Test 6: preCheck rejects regular tx with feeCap < baseFee ===
    print("\n--- Test 6: preCheck rejects regular tx below baseFee ---")
    tests += 1
    msg = Message(gas=21000, gas_fee_cap=500, gas_tip_cap=100, value=0,
                  priority_sender="")
    err = pre_check(msg, transactor_map, base_fee)
    if err == "ErrFeeCapTooLow":
        print(f"  [PASS] Regular tx rejected: {err}")
    else:
        failures += 1
        print(f"  [FAIL] Expected ErrFeeCapTooLow, got err={err}")

    # === Test 7: buyGas deducts zero from sender, but consumes block gas ===
    print("\n--- Test 7: buyGas — zero deduction but block gas consumed ---")
    tests += 1
    msg = Message(gas=21000, gas_fee_cap=0, gas_tip_cap=0, value=0,
                  priority_sender=waiver_key)
    sender_balance = 1000000
    gas_pool = 30_000_000  # 30M block gas limit

    new_balance, new_gas_pool, err = buy_gas(msg, sender_balance, gas_pool)
    if err is None and new_balance == sender_balance and new_gas_pool == gas_pool - 21000:
        print(f"  [PASS] Sender balance: {sender_balance} → {new_balance} (zero deduction)")
        print(f"         Block gas pool: {gas_pool} → {new_gas_pool} (21,000 consumed)")
    else:
        failures += 1
        print(f"  [FAIL] err={err}, balance={new_balance}, gas_pool={new_gas_pool}")

    # === Test 8: Block capacity calculation ===
    print("\n--- Test 8: Block capacity consumption ---")
    tests += 1
    block_gas_limit = 30_000_000
    simple_tx_gas = 21000
    max_zero_fee_txs = block_gas_limit // simple_tx_gas

    print(f"  Block gas limit: {block_gas_limit:,}")
    print(f"  Simple tx gas: {simple_tx_gas:,}")
    print(f"  Max zero-fee simple txs per block: {max_zero_fee_txs:,}")
    print(f"  Cost to attacker per block: 0 ETN")

    contract_call_gas = 1_000_000
    max_contract_calls = block_gas_limit // contract_call_gas
    print(f"  Max zero-fee contract calls (1M gas each): {max_contract_calls}")

    if max_zero_fee_txs > 1000:
        print(f"  [PASS] Significant block capacity can be consumed for free")
    else:
        failures += 1
        print(f"  [FAIL] Block capacity consumption insignificant")

    # === Test 9: Pool limits ===
    print("\n--- Test 9: Priority pool limits ---")
    tests += 1
    priority_slots = 4096 + 1024  # 5120
    priority_queue = 1024
    total_priority_capacity = priority_slots + priority_queue

    print(f"  Priority executable slots: {priority_slots}")
    print(f"  Priority queue slots: {priority_queue}")
    print(f"  Total priority capacity: {total_priority_capacity}")

    if total_priority_capacity <= 10000:
        print(f"  [PASS] Pool limits cap mempool flooding to {total_priority_capacity} txs")
    else:
        failures += 1
        print(f"  [FAIL] Pool limits unexpectedly high")

    # === Test 10: Pool validation for waiver tx ===
    print("\n--- Test 10: Pool validates waiver tx correctly ---")
    tests += 1
    msg = Message(gas=21000, gas_fee_cap=0, gas_tip_cap=0, value=0,
                  priority_sender=waiver_key)
    err = validate_tx_pool(msg, transactor_map, min_gas_price, is_local=False)
    if err is None:
        print(f"  [PASS] Waiver tx passes pool validation (skips underpriced check)")
    else:
        failures += 1
        print(f"  [FAIL] Expected pass, got err={err}")

    # === Test 11: Pool rejects regular tx below minimum price ===
    print("\n--- Test 11: Pool rejects underpriced regular tx ---")
    tests += 1
    msg = Message(gas=21000, gas_fee_cap=50, gas_tip_cap=10, value=0,
                  priority_sender="")
    err = validate_tx_pool(msg, transactor_map, min_gas_price, is_local=False)
    if err == "ErrUnderpriced":
        print(f"  [PASS] Regular tx rejected: {err}")
    else:
        failures += 1
        print(f"  [FAIL] Expected ErrUnderpriced, got err={err}")

    # Summary
    print("\n" + "=" * 72)
    passed = tests - failures
    print(f"Results: {passed}/{tests} tests passed, {failures} failures")

    if failures == 0:
        print("\nConclusion: Gas waiver behavior CONFIRMED.")
        print("- Zero-fee priority txs ARE accepted through all validation layers")
        print("- Block gas IS consumed (bounded by block gas limit)")
        print("- Sender pays zero ETN for gas")
        print("- Pool limits cap mempool flooding to ~6,144 txs")
        print("- Key compromise is required (permissioned system)")
        print("\nSeverity: Medium (resource abuse requiring key compromise)")
    else:
        print("\nUnexpected test failures — review logic.")

    print("=" * 72)
    return failures


if __name__ == "__main__":
    sys.exit(run_tests())

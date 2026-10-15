# Bug Bounty Report: Governance Voting Threshold Below Consensus Quorum

## Title

Simple Majority Governance Threshold Permits Validator-Set Escalation by >50% Coalition

## CWE

CWE-863: Incorrect Authorization (threshold mismatch between governance and consensus layers)

## Severity

**Informational (Design Observation)**

This is a deliberate design choice matching the standard PoA governance pattern (go-ethereum Clique, IBFT). Exploitation requires >50% validator compromise — already far beyond BFT safety assumptions.

## Affected Version

Electroneum Smart Chain (ETN-SC) — current `master` branch.

## Summary

The validator governance voting mechanism uses a simple majority threshold (`> N/2`, i.e., `⌊N/2⌋ + 1` votes), while QBFT consensus requires a 2/3 supermajority (`ceil(2N/3)`). For validator sets of size N ≥ 5, a coalition controlling more than half the validators can add colluding validators and incrementally escalate to full consensus quorum — without ever needing 2/3 directly.

However, the starting requirement of >50% validator compromise already exceeds the BFT fault tolerance threshold (<33%) by 1.5x. This threshold pattern is standard across Clique-based PoA implementations and is a documented design tradeoff, not an oversight.

## Technical Details

### Consensus Quorum

**Source**: `consensus/istanbul/core/core.go:333-335`
```go
func (c *core) QuorumSize() int {
    return int(math.Ceil(float64(2*c.valSet.Size()) / 3))
}
```

Formula: `ceil(2*N/3)` — standard BFT 2/3 supermajority. Used for PREPARE, COMMIT, and ROUND-CHANGE quorums.

### Governance Voting Threshold

**Source**: `consensus/istanbul/backend/engine.go:708`
```go
if tally := snap.Tally[candidate]; tally.Votes > snap.ValSet.Size()/2 {
```

Formula: `> N/2` with Go integer division = `⌊N/2⌋ + 1` votes required. Used for adding/removing validators.

### Threshold Gap

| N | Consensus `ceil(2N/3)` | Governance `⌊N/2⌋+1` | Gap |
|---|---|---|---|
| 5 | 4 | 3 | 1 |
| 7 | 5 | 4 | 1 |
| 10 | 7 | 6 | 1 |
| 15 | 10 | 8 | 2 |
| 21 | 14 | 11 | 3 |

### Voting Mechanism

1. Block proposer includes a vote in the header (engine.go:676-705)
2. One vote per validator per candidate — no double voting (engine.go:685-694)
3. Votes accumulate across blocks from different proposers
4. When tally exceeds majority, the candidate is added/removed (engine.go:708-737)
5. Votes reset at epoch boundaries (engine.go:657-660)

### Theoretical Escalation (N=7, attacker has 4)

| Step | Action | Attacker/Total | Consensus Quorum | Has Quorum? |
|------|--------|----------------|-------------------|-------------|
| 0 | Initial | 4/7 (57%) | 5 | No |
| 1 | Add X | 5/8 (63%) | 6 | No |
| 2 | Add Y | 6/9 (67%) | 6 | **Yes** |

Two validator additions escalate from governance majority to consensus quorum.

## Threat Model

### Starting Requirement

The attacker must control >50% of the **permissioned** validator set. In ETN-SC's permissioned model, validators are pre-approved entities. Compromising >50% of a curated validator set is a fundamentally different threat than in a public PoS system.

### Safeguards Present

1. **Block finalization**: Each vote-carrying block requires `ceil(2N/3)` committed seals — the attacker cannot finalize blocks alone until achieving consensus quorum
2. **One vote per validator per candidate**: Prevents vote amplification
3. **Epoch-based reset**: Votes clear at epoch boundaries, limiting the attack window
4. **On-chain visibility**: All validator additions are visible in block headers
5. **Consensus requirement**: Even with governance majority, each block needs honest validator signatures to be finalized

### Why This Is Not a Vulnerability

1. **>50% exceeds BFT assumptions**: Standard BFT tolerates < 33% Byzantine nodes. An attacker with >50% has already broken the fundamental security assumption.
2. **Liveness already compromised**: >33% Byzantine nodes can halt consensus. >50% can deny liveness outright. The governance escalation path does not lower the initial compromise bar.
3. **Standard design pattern**: This threshold is inherited from go-ethereum's Clique consensus and used across IBFT/QBFT implementations. It is a deliberate tradeoff between governance agility and security.
4. **Permissioned context**: ETN-SC is a permissioned chain with known validators, making the >50% compromise assumption even harder to satisfy.

## Reproduction Steps

1. Run `python3 test_threshold_gap.py` to verify the arithmetic
2. The test confirms:
   - Governance threshold < consensus quorum for all N ≥ 5
   - Escalation from 4/7 to 6/9 (57% → 67%) is arithmetically possible
   - >50% starting requirement exceeds BFT safety threshold
   - Block finalization still requires consensus quorum (defense in depth)

## Impact

- **Theoretical**: A >50% coalition can escalate to consensus quorum via governance voting
- **Practical**: Near-zero additional impact, because >50% already implies BFT safety is broken
- **In context**: This is a permissioned chain — the >50% threshold applies to a curated, known validator set

## Remediation (Optional — Design Tradeoff)

If the team wishes to close the gap, the governance threshold could be raised to match the consensus quorum:

```go
// Current (engine.go:708):
if tally := snap.Tally[candidate]; tally.Votes > snap.ValSet.Size()/2 {

// Option: Align with consensus quorum:
if tally := snap.Tally[candidate]; tally.Votes >= (2*snap.ValSet.Size()+2)/3 {
```

**Trade-off**: This would make governance changes harder (requires 2/3 agreement instead of majority), reducing agility for legitimate validator management. Given the permissioned context, the current simple majority may be the correct design choice.

## Disclosure

This finding was identified through static code analysis under the authorized Bugcrowd bug bounty program. No production systems were tested or affected. All analysis was performed on local source code with synthetic test data.

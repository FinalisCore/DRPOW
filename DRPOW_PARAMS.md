# DRPOW Consensus Parameters (Locked)

This file defines the canonical DRPOW parameters that must match implementation constants.

Source of truth in code: `src/consensus/drpow_params.h`

Any change here is a consensus change and requires coordinated network upgrade.

## 1) Epoch and Validator Set

- `kEpochLengthRounds = 10`
- `kEpochValidatorCap = 64`
- `kEpochValidatorGrowthPerEpoch = 4`

## 2) Admission Policy

- `kAdmissionLookbackEpochs = 1`
- `kAdmissionPowRecentMinWins = 1`
- `kAdmissionIncumbentMinWins = 1`

Interpretation:
- Newcomers and incumbents are admitted from deterministic committed-history windows.
- Newcomer and incumbent minimum participation thresholds are both 1 within the configured lookback.

## 3) PoW-Recent Eligibility / Typed QC

- `kPowRecentEligibilityLookbackRounds = 10` (equal to epoch length)
- `kPowRecentVoteWeight = 1`

Typed QC denominator:

`W_total = sum(epoch validator voting power) + kPowRecentVoteWeight * |pow_recent_set(round)|`

QC pass condition (integer-safe):

`W_voted * 3 >= W_total * 2 + 1`

## 4) Difficulty/Bootstrap

- `kTargetEpochRounds = 10`
- `kGenesisBootstrapRounds = 10`
- `kTargetAdjustUpPpmLimit = 2000000`
- `kTargetAdjustDownPpmLimit = 250000`

## 5) Conformance Requirement

Implementations MUST:
- use these exact values in consensus-critical code paths,
- reject mixed configurations at runtime for the same network magic,
- version/announce parameter changes as protocol upgrades.


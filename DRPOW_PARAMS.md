# DRPOW Consensus Parameters (Locked)

This file defines the canonical DRPOW parameters that must match implementation constants.

Source of truth in code: `src/consensus/drpow_params.h`

Any change here is a consensus change and requires coordinated network upgrade.

## 1) QC Threshold

- `kMinQcVotes = 2`

## 2) Difficulty Retarget Limits

- `kTargetAdjustUpPpmLimit = 2000000`
- `kTargetAdjustDownPpmLimit = 250000`

## 3) Conformance Requirement

Implementations MUST:
- use these exact values in consensus-critical code paths,
- reject mixed configurations at runtime for the same network magic,
- version/announce parameter changes as protocol upgrades.

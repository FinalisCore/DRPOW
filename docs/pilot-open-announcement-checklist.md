# Pilot-Open Announcement Checklist

Use this checklist before publicly stating "global testnet is live".

## 1. Manifest Freeze

1. Publish [global_testnet_manifest_v1.md](./global_testnet_manifest_v1.md) with:
- final seed list (no TBD),
- release tag/commit,
- exact params/genesis values.

2. Ensure all seed operators confirm matching:
- `params_version`,
- `params_hash`,
- genesis hash.

## 2. Seed Readiness

1. At least 3 independent seeds online.
2. Different regions/ASNs.
3. Public contact/incident channel per operator.

## 3. Soak Evidence Attached

1. Wave A complete (10 nodes / 24h).
2. Publish summary using [global-testnet-soak-report-template.md](./global-testnet-soak-report-template.md).
3. Include parser output from `src/scripts/analyze_testnet_log.sh` for each seed log.

## 4. Operator Docs

1. Join/run instructions are copy-paste complete.
2. Troubleshooting section includes:
- params mismatch,
- no peers,
- sync lag,
- stale peer drops.

## 5. Announcement Guardrails

1. Label clearly as `pilot-open` (not mainnet, not economic-finality guarantee).
2. Publish compatibility window and upgrade policy.
3. Publish known risks and current tuning areas.

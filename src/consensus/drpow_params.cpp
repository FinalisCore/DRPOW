#include "drpow_params.h"

#include <stdio.h>
#include <string.h>
#include <vector>

#include "drpow/tx_codec.h"

namespace drpow {

const char* DrpowParamsVersionTag()
{
    return "drpow_params_v1";
}

bool ComputeDrpowParamsHash(Bytes32* out_hash)
{
    if (!out_hash)
        return false;
    char buf[1024];
    // Canonical serialization: fixed field order, decimal integer formatting.
    const int n = snprintf(
        buf,
        sizeof(buf),
        "%s|epoch_len=%llu|validator_cap=%llu|validator_growth=%llu|admission_lookback_epochs=%llu|admission_pow_recent_min_wins=%llu|admission_incumbent_min_wins=%llu|pow_recent_eligibility_lookback_rounds=%llu|pow_recent_vote_weight=%llu|target_epoch_rounds=%llu|genesis_bootstrap_rounds=%llu|target_adjust_up_ppm_limit=%llu|target_adjust_down_ppm_limit=%llu",
        DrpowParamsVersionTag(),
        (unsigned long long)DrpowParams::kEpochLengthRounds,
        (unsigned long long)DrpowParams::kEpochValidatorCap,
        (unsigned long long)DrpowParams::kEpochValidatorGrowthPerEpoch,
        (unsigned long long)DrpowParams::kAdmissionLookbackEpochs,
        (unsigned long long)DrpowParams::kAdmissionPowRecentMinWins,
        (unsigned long long)DrpowParams::kAdmissionIncumbentMinWins,
        (unsigned long long)DrpowParams::kPowRecentEligibilityLookbackRounds,
        (unsigned long long)DrpowParams::kPowRecentVoteWeight,
        (unsigned long long)DrpowParams::kTargetEpochRounds,
        (unsigned long long)DrpowParams::kGenesisBootstrapRounds,
        (unsigned long long)DrpowParams::kTargetAdjustUpPpmLimit,
        (unsigned long long)DrpowParams::kTargetAdjustDownPpmLimit);
    if (n <= 0 || (size_t)n >= sizeof(buf))
        return false;
    std::vector<uint8_t> bytes((const uint8_t*)buf, (const uint8_t*)buf + (size_t)n);
    return Sha256(bytes, out_hash);
}

}  // namespace drpow


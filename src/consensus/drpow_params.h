#ifndef COIN_DRPOW_PARAMS_H
#define COIN_DRPOW_PARAMS_H

#include <stddef.h>
#include <stdint.h>

namespace drpow {

// Consensus-locked DRPOW parameters.
// Any value change is a consensus change and requires coordinated upgrade.
struct DrpowParams {
    static const uint64_t kEpochLengthRounds = 10;
    static const size_t kEpochValidatorCap = 64;
    static const size_t kEpochValidatorGrowthPerEpoch = 4;

    static const uint64_t kAdmissionLookbackEpochs = 1;
    static const uint64_t kAdmissionPowRecentMinWins = 1;
    static const uint64_t kAdmissionIncumbentMinWins = 1;

    static const uint64_t kPowRecentEligibilityLookbackRounds = kEpochLengthRounds;
    static const uint64_t kPowRecentVoteWeight = 1;

    static const uint64_t kTargetEpochRounds = kEpochLengthRounds;
    static const uint64_t kGenesisBootstrapRounds = 10;
    static const uint64_t kTargetAdjustUpPpmLimit = 2000000;
    static const uint64_t kTargetAdjustDownPpmLimit = 250000;
};

}  // namespace drpow

#endif

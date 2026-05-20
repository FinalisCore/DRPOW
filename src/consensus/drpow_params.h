#ifndef COIN_DRPOW_PARAMS_H
#define COIN_DRPOW_PARAMS_H

#include <stddef.h>
#include <stdint.h>
#include <string>

namespace drpow {

struct Bytes32;

// Consensus-locked DRPOW parameters.
// Any value change is a consensus change and requires coordinated upgrade.
struct DrpowParams {
    // Minimum cumulative PoW vote-ticket weight required for QC validity.
    static const uint64_t kMinQcWeight = 2;
    static const uint64_t kTargetAdjustUpPpmLimit = 2000000;
    static const uint64_t kTargetAdjustDownPpmLimit = 250000;
};

const char* DrpowParamsVersionTag();
bool ComputeDrpowParamsHash(Bytes32* out_hash);
bool ComputeDrpowParamsHashFromSpecFile(const char* spec_file_path, Bytes32* out_hash, std::string* out_error);

}  // namespace drpow

#endif

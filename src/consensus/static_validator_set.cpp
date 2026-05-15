#include "static_validator_set.h"

namespace rpov2 {

StaticValidatorSet::StaticValidatorSet(uint64_t epoch_length, const std::vector<Validator>& validators)
    : epoch_length_(epoch_length), validators_(validators)
{
}

bool StaticValidatorSet::GetEpochForRound(uint64_t round, ValidatorEpoch* out_epoch) const
{
    if (!out_epoch || epoch_length_ == 0 || validators_.empty() || round == 0)
        return false;

    uint64_t epoch = (round - 1) / epoch_length_;
    out_epoch->epoch = epoch;
    out_epoch->round_start = epoch * epoch_length_ + 1;
    out_epoch->round_end = out_epoch->round_start + epoch_length_ - 1;
    out_epoch->validators = validators_;
    return true;
}

}  

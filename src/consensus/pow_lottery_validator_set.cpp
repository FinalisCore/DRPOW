#include "pow_lottery_validator_set.h"
#include <string.h>

namespace rpov2 {

static bool SameValidators(const std::vector<Validator>& a, const std::vector<Validator>& b)
{
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        if (memcmp(a[i].validator_id.v, b[i].validator_id.v, 32) != 0 ||
            a[i].voting_power != b[i].voting_power)
            return false;
    }
    return true;
}

PowLotteryValidatorSet::PowLotteryValidatorSet(uint64_t epoch_length)
    : epoch_length_(epoch_length)
{
}

bool PowLotteryValidatorSet::InstallEpoch(uint64_t epoch, const std::vector<Validator>& validators)
{
    if (epoch_length_ == 0 || validators.empty())
        return false;

    // Deterministic transition policy:
    // 1) epoch 0 MUST be installed first
    // 2) later epochs MUST be installed contiguously (no gaps)
    // 3) existing epoch may only be reinstalled if byte-identical (idempotent)
    std::map<uint64_t, std::vector<Validator> >::const_iterator it = epochs_.find(epoch);
    if (it != epochs_.end())
        return SameValidators(it->second, validators);

    if (epochs_.empty())
    {
        if (epoch != 0)
            return false;
    }
    else
    {
        const uint64_t last_epoch = epochs_.rbegin()->first;
        if (epoch != last_epoch + 1)
            return false;
    }

    epochs_.insert(std::make_pair(epoch, validators));
    return true;
}

bool PowLotteryValidatorSet::GetEpochForRound(uint64_t round, ValidatorEpoch* out_epoch) const
{
    if (!out_epoch || epoch_length_ == 0 || round == 0)
        return false;

    const uint64_t epoch = (round - 1) / epoch_length_;
    std::map<uint64_t, std::vector<Validator> >::const_iterator it = epochs_.find(epoch);
    if (it == epochs_.end())
        return false;

    out_epoch->epoch = epoch;
    out_epoch->round_start = epoch * epoch_length_ + 1;
    out_epoch->round_end = out_epoch->round_start + epoch_length_ - 1;
    out_epoch->validators = it->second;
    return true;
}

}  

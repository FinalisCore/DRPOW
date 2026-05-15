#ifndef COIN_POW_LOTTERY_VALIDATOR_SET_H
#define COIN_POW_LOTTERY_VALIDATOR_SET_H

#include <map>

#include "validator_set.h"

namespace rpov2 {

class PowLotteryValidatorSet : public ValidatorSet {
public:
    PowLotteryValidatorSet(uint64_t epoch_length);

    bool InstallEpoch(uint64_t epoch, const std::vector<Validator>& validators);
    virtual bool GetEpochForRound(uint64_t round, ValidatorEpoch* out_epoch) const;

private:
    uint64_t epoch_length_;
    std::map<uint64_t, std::vector<Validator> > epochs_;
};

}  

#endif

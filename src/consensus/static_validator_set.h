#ifndef COIN_STATIC_VALIDATOR_SET_H
#define COIN_STATIC_VALIDATOR_SET_H

#include "validator_set.h"

namespace drpow {

class StaticValidatorSet : public ValidatorSet {
public:
    StaticValidatorSet(uint64_t epoch_length, const std::vector<Validator>& validators);
    virtual bool GetEpochForRound(uint64_t round, ValidatorEpoch* out_epoch) const;

private:
    uint64_t epoch_length_;
    std::vector<Validator> validators_;
};

}  

#endif

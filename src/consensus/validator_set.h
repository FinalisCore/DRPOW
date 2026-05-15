#ifndef COIN_VALIDATOR_SET_H
#define COIN_VALIDATOR_SET_H

#include <stdint.h>
#include <vector>

#include "rpov2/tx_types.h"

namespace rpov2 {

struct Validator {
    Bytes32 validator_id;
    uint64_t voting_power;
};

struct ValidatorEpoch {
    uint64_t epoch;
    uint64_t round_start;
    uint64_t round_end;
    std::vector<Validator> validators;
};

class ValidatorSet {
public:
    virtual ~ValidatorSet() {}
    virtual bool GetEpochForRound(uint64_t round, ValidatorEpoch* out_epoch) const = 0;
};

}  

#endif

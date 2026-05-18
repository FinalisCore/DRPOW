#ifndef COIN_VALIDATOR_LOTTERY_H
#define COIN_VALIDATOR_LOTTERY_H

#include <cstddef>
#include <stdint.h>
#include <vector>

#include "drpow/tx_types.h"
#include "validator_set.h"

namespace drpow {

struct LotteryShare {
    Bytes32 state_hash;
    uint64_t nonce;
    Bytes32 pubkey;
    std::vector<uint8_t> signature;
    Bytes32 digest;
};

bool ComputeLotteryDigest(const LotteryShare& share, Bytes32* out_digest);
bool VerifyLotteryShare(const LotteryShare& share);
bool IsWinningShare(const LotteryShare& share, const Bytes32& target);

std::vector<Validator> SelectTopValidators(const std::vector<LotteryShare>& shares,
                                           size_t n,
                                           uint64_t voting_power_per_validator);

}  

#endif

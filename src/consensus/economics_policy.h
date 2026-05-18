#ifndef COIN_ECONOMICS_POLICY_H
#define COIN_ECONOMICS_POLICY_H

#include <cstddef>

#include "drpow/tx_types.h"

namespace drpow {

struct RoundBatch;

struct EconomicsPolicy {
    size_t max_spends_per_round;
    size_t max_mints_per_round;
    size_t max_proof_cost_per_round;
    uint64_t min_fee_per_spend;
    uint64_t max_fee_per_spend;
    Bytes32 max_target;
    Bytes32 min_target;
    uint64_t initial_subsidy;
    uint64_t subsidy_floor;
    uint64_t halving_interval_rounds;
    uint64_t initial_transfer_tax_ppm;
    uint64_t min_transfer_tax_ppm;
    uint64_t target_window_rounds;
    uint64_t target_mints_per_window;
    uint64_t target_epoch_rounds;
    uint64_t target_adjust_up_ppm_limit;
    uint64_t target_adjust_down_ppm_limit;
    uint64_t genesis_bootstrap_rounds;
};

EconomicsPolicy DefaultEconomicsPolicy();
uint64_t MintSubsidyForRound(uint64_t round, const EconomicsPolicy& policy);
uint64_t TransferTaxPpmForRound(uint64_t round, const EconomicsPolicy& policy);
bool ValidateBatchEconomics(const RoundBatch& batch, const EconomicsPolicy& policy);
bool ValidateBatchFeePolicy(const RoundBatch& batch, const EconomicsPolicy& policy);
bool NextPowTargetDeterministic(const Bytes32& prev_target,
                                uint64_t observed_mints,
                                uint64_t expected_mints,
                                uint64_t adjust_up_ppm_limit,
                                uint64_t adjust_down_ppm_limit,
                                const Bytes32& min_target,
                                const Bytes32& max_target,
                                Bytes32* out_target);

}  

#endif

#include "economics_policy.h"

#include <stdint.h>
#include <string.h>

#include "consensus_round.h"
#include "drpow_params.h"

namespace drpow {

namespace {

static int Compare32(const Bytes32& a, const Bytes32& b)
{
    return memcmp(a.v, b.v, 32);
}

static bool ScaleTargetByRatio(const Bytes32& in, uint64_t num, uint64_t den, Bytes32* out)
{
    if (!out || den == 0 || num == 0)
        return false;
    // 256-bit integer as 8 limbs, little-endian base 2^32.
    uint32_t a[8];
    for (int i = 0; i < 8; ++i)
    {
        const int b = i * 4;
        a[7 - i] = ((uint32_t)in.v[b] << 24) |
                   ((uint32_t)in.v[b + 1] << 16) |
                   ((uint32_t)in.v[b + 2] << 8) |
                   (uint32_t)in.v[b + 3];
    }

    // Multiply by num -> 9-limb product.
    uint32_t p[9];
    memset(p, 0, sizeof(p));
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i)
    {
        __uint128_t v = (__uint128_t)a[i] * (__uint128_t)num + carry;
        p[i] = (uint32_t)(v & 0xffffffffULL);
        carry = (uint64_t)(v >> 32);
    }
    p[8] = (uint32_t)carry;

    // Divide by den -> 9-limb quotient, keep low 8 limbs (clamped later).
    uint32_t q[9];
    memset(q, 0, sizeof(q));
    __uint128_t rem = 0;
    for (int i = 8; i >= 0; --i)
    {
        __uint128_t cur = (rem << 32) | p[i];
        q[i] = (uint32_t)(cur / den);
        rem = cur % den;
    }
    if (q[8] != 0)
    {
        memset(out->v, 0xff, 32);
        return true;
    }

    for (int i = 0; i < 8; ++i)
    {
        const uint32_t w = q[7 - i];
        const int b = i * 4;
        out->v[b] = (uint8_t)((w >> 24) & 0xff);
        out->v[b + 1] = (uint8_t)((w >> 16) & 0xff);
        out->v[b + 2] = (uint8_t)((w >> 8) & 0xff);
        out->v[b + 3] = (uint8_t)(w & 0xff);
    }
    return true;
}

static void Clamp32(Bytes32* v, const Bytes32& lo, const Bytes32& hi)
{
    if (!v)
        return;
    if (Compare32(*v, lo) < 0)
        *v = lo;
    if (Compare32(*v, hi) > 0)
        *v = hi;
}

}  // namespace

EconomicsPolicy DefaultEconomicsPolicy()
{
    static const uint64_t kAtomicPerCoin = 1000ULL;
    static const uint64_t kRoundSeconds = 20ULL;
    static const uint64_t kYearSeconds = 365ULL * 24ULL * 3600ULL;
    EconomicsPolicy p;
    p.max_spends_per_round = 10000;
    p.max_mints_per_round = 1;
    p.max_proof_cost_per_round = 8 * 1024 * 1024;
    p.min_fee_per_spend = 1;
    p.max_fee_per_spend = 0;
    memset(p.min_target.v, 0x00, 32);
    p.min_target.v[31] = 0x01;
    // Default network PoW target (stricter floor than 0f...):
    // 07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    memset(p.max_target.v, 0xff, 32);
    p.max_target.v[0] = 0x07;
    p.initial_subsidy = 50 * kAtomicPerCoin;
    p.subsidy_floor = 1;  // tail emission floor in atomic units
    // Era-0 duration is 2 years. Each next era doubles in duration (2y,4y,8y,...).
    p.halving_interval_rounds = (2ULL * kYearSeconds) / kRoundSeconds;
    p.initial_transfer_tax_ppm = 200000;  // 20%
    p.min_transfer_tax_ppm = 20000;       // 2%
    p.target_window_rounds = 10;
    p.target_mints_per_window = 10;
    p.target_epoch_rounds = DrpowParams::kTargetEpochRounds;
    p.target_adjust_up_ppm_limit = DrpowParams::kTargetAdjustUpPpmLimit;
    // Faster hardening when blocks are too frequent:
    // allow up to 4x harder target per retarget step.
    p.target_adjust_down_ppm_limit = DrpowParams::kTargetAdjustDownPpmLimit;
    p.genesis_bootstrap_rounds = DrpowParams::kGenesisBootstrapRounds;
    return p;
}

uint64_t MintSubsidyForRound(uint64_t round, const EconomicsPolicy& policy)
{
    if (round == 0 || policy.initial_subsidy == 0 || policy.halving_interval_rounds == 0)
        return 0;
    uint64_t era = 0;
    uint64_t remain = round - 1;
    uint64_t era_len = policy.halving_interval_rounds;
    while (remain >= era_len && era < 63)
    {
        remain -= era_len;
        if (era_len > (UINT64_MAX >> 1))
            era_len = UINT64_MAX;
        else
            era_len <<= 1;
        ++era;
    }
    if (era >= 63)
        return policy.subsidy_floor;
    uint64_t s = policy.initial_subsidy >> era;
    if (s < policy.subsidy_floor)
        s = policy.subsidy_floor;
    return s;
}

uint64_t TransferTaxPpmForRound(uint64_t round, const EconomicsPolicy& policy)
{
    if (round == 0 || policy.initial_transfer_tax_ppm == 0)
        return 0;
    uint64_t era = 0;
    uint64_t remain = round - 1;
    uint64_t era_len = policy.halving_interval_rounds == 0 ? 1 : policy.halving_interval_rounds;
    while (remain >= era_len && era < 63)
    {
        remain -= era_len;
        if (era_len > (UINT64_MAX >> 1))
            era_len = UINT64_MAX;
        else
            era_len <<= 1;
        ++era;
    }
    uint64_t ppm = (era >= 63) ? 0 : (policy.initial_transfer_tax_ppm >> era);
    if (ppm < policy.min_transfer_tax_ppm)
        ppm = policy.min_transfer_tax_ppm;
    return ppm;
}

bool ValidateBatchEconomics(const RoundBatch& batch, const EconomicsPolicy& policy)
{
    if (batch.spends.size() > policy.max_spends_per_round)
        return false;
    if (batch.mints.size() > policy.max_mints_per_round)
        return false;

    for (size_t i = 0; i < batch.mints.size(); ++i)
    {
        if (Compare32(batch.mints[i].target, policy.max_target) > 0)
            return false;
    }
    uint64_t subsidy = MintSubsidyForRound(batch.round, policy);
    uint64_t minted = 0;
    for (size_t i = 0; i < batch.mints.size(); ++i)
    {
        if (UINT64_MAX - minted < batch.mints[i].output.value)
            return false;
        minted += batch.mints[i].output.value;
    }
    if (minted > subsidy)
        return false;

    return true;
}

bool ValidateBatchFeePolicy(const RoundBatch& batch, const EconomicsPolicy& policy)
{
    for (size_t i = 0; i < batch.spends.size(); ++i)
    {
        const SpendTx& tx = batch.spends[i];
        if (tx.inputs.empty())
            return false;
        if (tx.outputs.empty())
            return false;
        if (tx.transfer_amount == 0)
            return false;

        if (tx.inputs[0].ownership_proof.size() < 32)
            return false;
        Bytes32 sender_pubkey;
        memcpy(sender_pubkey.v, &tx.inputs[0].ownership_proof[0], 32);
        for (size_t j = 1; j < tx.inputs.size(); ++j)
        {
            if (tx.inputs[j].ownership_proof.size() < 32)
                return false;
            if (memcmp(sender_pubkey.v, &tx.inputs[j].ownership_proof[0], 32) != 0)
                return false;
        }

        uint64_t external_out_sum = 0;
        for (size_t j = 0; j < tx.outputs.size(); ++j)
        {
            if (memcmp(tx.outputs[j].owner_pubkey.v, sender_pubkey.v, 32) == 0)
                continue;  // sender-owned change
            if (UINT64_MAX - external_out_sum < tx.outputs[j].value)
                return false;
            external_out_sum += tx.outputs[j].value;
        }
        if (external_out_sum != tx.transfer_amount)
            return false;

        const uint64_t tax_ppm = TransferTaxPpmForRound(batch.round, policy);
        const uint64_t expected_tax = (tx.transfer_amount * tax_ppm + 999999ULL) / 1000000ULL;
        const uint64_t fee = tx.fee;
        if (fee != expected_tax)
            return false;
        if (fee < policy.min_fee_per_spend)
            return false;
        if (policy.max_fee_per_spend > 0 && fee > policy.max_fee_per_spend)
            return false;
    }
    return true;
}

bool NextPowTargetDeterministic(const Bytes32& prev_target,
                                uint64_t observed_mints,
                                uint64_t expected_mints,
                                uint64_t adjust_up_ppm_limit,
                                uint64_t adjust_down_ppm_limit,
                                const Bytes32& min_target,
                                const Bytes32& max_target,
                                Bytes32* out_target)
{
    if (!out_target || expected_mints == 0 || adjust_up_ppm_limit == 0 || adjust_down_ppm_limit == 0)
        return false;

    uint64_t obs = observed_mints;
    if (obs == 0)
        obs = 1;

    // ratio_ppm ~= expected/observed; observed>expected => lower target (harder)
    const uint64_t ratio_ppm = (expected_mints > UINT64_MAX / 1000000ULL)
                                   ? UINT64_MAX
                                   : (expected_mints * 1000000ULL) / obs;
    uint64_t bounded_ppm = ratio_ppm;
    if (bounded_ppm > adjust_up_ppm_limit)
        bounded_ppm = adjust_up_ppm_limit;
    if (bounded_ppm < adjust_down_ppm_limit)
        bounded_ppm = adjust_down_ppm_limit;
    if (!ScaleTargetByRatio(prev_target, bounded_ppm, 1000000ULL, out_target))
        return false;
    Clamp32(out_target, min_target, max_target);
    return true;
}

}  

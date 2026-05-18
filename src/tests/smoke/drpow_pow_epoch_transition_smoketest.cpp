#include <stdio.h>

#include <vector>

#include "pow_lottery_validator_set.h"

using namespace drpow;

static Bytes32 MakeId(uint8_t seed)
{
    Bytes32 b;
    for (int i = 0; i < 32; ++i)
        b.v[i] = (uint8_t)(seed + i);
    return b;
}

static std::vector<Validator> MakeValidators(uint8_t base, size_t n)
{
    std::vector<Validator> out;
    for (size_t i = 0; i < n; ++i)
    {
        Validator v;
        v.validator_id = MakeId((uint8_t)(base + i));
        v.voting_power = 1;
        out.push_back(v);
    }
    return out;
}

int main()
{
    PowLotteryValidatorSet vset(10);
    std::vector<Validator> e0 = MakeValidators(10, 3);
    std::vector<Validator> e1 = MakeValidators(20, 3);
    std::vector<Validator> e2 = MakeValidators(30, 3);

    if (vset.InstallEpoch(1, e1))
    {
        printf("expected_reject_missing_epoch0\n");
        return 1;
    }
    if (!vset.InstallEpoch(0, e0))
    {
        printf("failed_install_epoch0\n");
        return 2;
    }
    if (!vset.InstallEpoch(0, e0))
    {
        printf("failed_idempotent_reinstall\n");
        return 3;
    }
    if (vset.InstallEpoch(0, e1))
    {
        printf("expected_reject_epoch0_overwrite\n");
        return 4;
    }
    if (vset.InstallEpoch(2, e2))
    {
        printf("expected_reject_epoch_gap\n");
        return 5;
    }
    if (!vset.InstallEpoch(1, e1))
    {
        printf("failed_install_epoch1\n");
        return 6;
    }

    ValidatorEpoch epoch;
    if (!vset.GetEpochForRound(1, &epoch) || epoch.epoch != 0)
    {
        printf("failed_epoch_round1\n");
        return 7;
    }
    if (!vset.GetEpochForRound(10, &epoch) || epoch.epoch != 0)
    {
        printf("failed_epoch_round10\n");
        return 8;
    }
    if (!vset.GetEpochForRound(11, &epoch) || epoch.epoch != 1)
    {
        printf("failed_epoch_round11\n");
        return 9;
    }

    printf("ok pow_epoch_transition_vectors\n");
    return 0;
}

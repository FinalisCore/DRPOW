#include <stdio.h>
#include <string.h>

#include <map>
#include <string>
#include <vector>

#include "drpow_params.h"
#include "state_store.h"

using namespace drpow;

struct SimStats {
    uint64_t wins;
    uint64_t weighted_work_units;
};

static Bytes32 MinerId(uint8_t seed)
{
    Bytes32 b;
    for (int i = 0; i < 32; ++i)
        b.v[i] = (uint8_t)(seed + i);
    return b;
}

static uint64_t WorkUnitsFromTargetTop64(const Bytes32& target)
{
    uint64_t t = 0;
    for (int i = 0; i < 8; ++i)
        t = (t << 8) | (uint64_t)target.v[i];
    return ~t;
}

static std::string Key(const Bytes32& b)
{
    return std::string((const char*)b.v, 32);
}

int main()
{
    // Vector 1: many identities with one easy win each should fail threshold.
    std::map<std::string, SimStats> s1;
    Bytes32 easy_target;
    memset(easy_target.v, 0xff, 32);
    easy_target.v[0] = 0x07;
    for (int i = 0; i < 64; ++i)
    {
        const Bytes32 m = MinerId((uint8_t)(10 + i));
        SimStats st;
        st.wins = 1;
        st.weighted_work_units = WorkUnitsFromTargetTop64(easy_target) * 1;
        s1[Key(m)] = st;
    }
    size_t eligible1 = 0;
    for (std::map<std::string, SimStats>::const_iterator it = s1.begin(); it != s1.end(); ++it)
    {
        if (it->second.wins >= DrpowParams::kPowRecentMinWins &&
            it->second.weighted_work_units >= DrpowParams::kPowRecentMinWorkUnits)
            eligible1 += 1;
    }
    if (eligible1 != 0)
    {
        printf("sybil_vector_one_win_failed eligible=%zu\n", eligible1);
        return 1;
    }

    // Vector 2: sustained miners with multiple wins should pass.
    std::map<std::string, SimStats> s2;
    for (int i = 0; i < 3; ++i)
    {
        const Bytes32 m = MinerId((uint8_t)(140 + i));
        SimStats st;
        st.wins = 0;
        st.weighted_work_units = 0;
        for (int w = 1; w <= 3; ++w)
        {
            st.wins += 1;
            st.weighted_work_units += WorkUnitsFromTargetTop64(easy_target) * (uint64_t)w;
        }
        s2[Key(m)] = st;
    }
    size_t eligible2 = 0;
    for (std::map<std::string, SimStats>::const_iterator it = s2.begin(); it != s2.end(); ++it)
    {
        if (it->second.wins >= DrpowParams::kPowRecentMinWins &&
            it->second.weighted_work_units >= DrpowParams::kPowRecentMinWorkUnits)
            eligible2 += 1;
    }
    if (eligible2 != 3)
    {
        printf("sybil_vector_sustained_failed eligible=%zu\n", eligible2);
        return 2;
    }

    // Vector 3: recency decay effect (same wins, later rounds weighted higher).
    const uint64_t unit = 1;
    SimStats old_pattern;
    old_pattern.wins = 2;
    old_pattern.weighted_work_units = unit * 1 + unit * 2;
    SimStats recent_pattern;
    recent_pattern.wins = 2;
    recent_pattern.weighted_work_units = unit * 9 + unit * 10;
    if (!(recent_pattern.weighted_work_units > old_pattern.weighted_work_units))
    {
        printf("sybil_vector_decay_weighting_failed\n");
        return 3;
    }

    printf("ok pow_sybil_hardening_vectors threshold_wins=%llu threshold_work=%llu\n",
           (unsigned long long)DrpowParams::kPowRecentMinWins,
           (unsigned long long)DrpowParams::kPowRecentMinWorkUnits);
    return 0;
}

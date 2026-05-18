#include "validator_lottery.h"

#include <algorithm>
#include <map>
#include <string>
#include <string.h>

#include "drpow/tx_codec.h"

namespace drpow {

struct ShareLess {
    bool operator()(const LotteryShare& a, const LotteryShare& b) const
    {
        for (int i = 0; i < 32; ++i)
        {
            if (a.digest.v[i] < b.digest.v[i])
                return true;
            if (a.digest.v[i] > b.digest.v[i])
                return false;
        }
        for (int i = 0; i < 32; ++i)
        {
            if (a.pubkey.v[i] < b.pubkey.v[i])
                return true;
            if (a.pubkey.v[i] > b.pubkey.v[i])
                return false;
        }
        return a.nonce < b.nonce;
    }
};

static int Compare32(const Bytes32& a, const Bytes32& b)
{
    for (int i = 0; i < 32; ++i)
    {
        if (a.v[i] < b.v[i])
            return -1;
        if (a.v[i] > b.v[i])
            return 1;
    }
    return 0;
}

bool ComputeLotteryDigest(const LotteryShare& share, Bytes32* out_digest)
{
    if (!out_digest)
        return false;
    std::vector<uint8_t> m;
    WriteBytes32(&m, share.state_hash);
    WriteU64LE(&m, share.nonce);
    WriteBytes32(&m, share.pubkey);
    return Sha256(m, out_digest);
}

bool VerifyLotteryShare(const LotteryShare& share)
{
    if (share.signature.size() != 32)
        return false;
    Bytes32 d;
    if (!ComputeLotteryDigest(share, &d))
        return false;
    std::vector<uint8_t> m;
    m.insert(m.end(), d.v, d.v + 32);
    m.insert(m.end(), share.pubkey.v, share.pubkey.v + 32);
    Bytes32 sig_expected;
    if (!Sha256(m, &sig_expected))
        return false;
    return memcmp(&share.signature[0], sig_expected.v, 32) == 0;
}

bool IsWinningShare(const LotteryShare& share, const Bytes32& target)
{
    Bytes32 d;
    if (!ComputeLotteryDigest(share, &d))
        return false;
    return Compare32(d, target) <= 0;
}

std::vector<Validator> SelectTopValidators(const std::vector<LotteryShare>& shares,
                                           size_t n,
                                           uint64_t voting_power_per_validator)
{
    std::vector<LotteryShare> valid;
    valid.reserve(shares.size());

    for (size_t i = 0; i < shares.size(); ++i)
    {
        LotteryShare s = shares[i];
        if (!VerifyLotteryShare(s))
            continue;
        if (!ComputeLotteryDigest(s, &s.digest))
            continue;
        valid.push_back(s);
    }

    std::sort(valid.begin(), valid.end(), ShareLess());

    std::map<std::string, bool> seen;
    std::vector<Validator> out;
    out.reserve(n);

    for (size_t i = 0; i < valid.size() && out.size() < n; ++i)
    {
        std::string k((const char*)valid[i].pubkey.v, 32);
        if (seen.count(k))
            continue;
        seen[k] = true;

        Validator v;
        v.validator_id = valid[i].pubkey;
        v.voting_power = voting_power_per_validator;
        out.push_back(v);
    }

    return out;
}

}  

#include "finality_qc.h"

#include <string>
#include <string.h>
#include <vector>

#include "drpow/tx_codec.h"

namespace drpow {

bool HasSupermajority(size_t total_validators, size_t votes_count)
{
    if (total_validators == 0)
        return false;
    return votes_count >= ((2 * total_validators) / 3 + 1);
}

bool VoteEligibilityTypeValid(uint8_t t)
{
    return t == VOTE_ELIGIBILITY_VALIDATOR_SET || t == VOTE_ELIGIBILITY_POW_RECENT;
}

uint64_t TotalVotingPower(const ValidatorEpoch& epoch)
{
    uint64_t total = 0;
    for (size_t i = 0; i < epoch.validators.size(); ++i)
        total += epoch.validators[i].voting_power;
    return total;
}

uint64_t VotedPower(const ValidatorEpoch& epoch, const QuorumCertificate& qc)
{
    uint64_t voted = 0;
    std::set<std::string> seen;
    for (size_t i = 0; i < qc.votes.size(); ++i)
    {
        const Vote& v = qc.votes[i];
        std::string id((const char*)v.validator_id.v, 32);
        if (seen.count(id))
            continue;
        for (size_t j = 0; j < epoch.validators.size(); ++j)
        {
            const Validator& val = epoch.validators[j];
            if (memcmp(val.validator_id.v, v.validator_id.v, 32) == 0)
            {
                voted += val.voting_power;
                seen.insert(id);
                break;
            }
        }
    }
    return voted;
}

bool HasSupermajorityPower(const ValidatorEpoch& epoch, const QuorumCertificate& qc)
{
    const uint64_t total = TotalVotingPower(epoch);
    if (total == 0)
        return false;
    const uint64_t voted = VotedPower(epoch, qc);
    return voted * 3 >= total * 2 + 1;
}

uint64_t VotedPowerTyped(const ValidatorEpoch& epoch,
                         const QuorumCertificate& qc,
                         const std::set<std::string>& pow_recent_ids,
                         uint64_t pow_recent_vote_weight)
{
    uint64_t voted = 0;
    std::set<std::string> seen;
    for (size_t i = 0; i < qc.votes.size(); ++i)
    {
        const Vote& v = qc.votes[i];
        const std::string id((const char*)v.validator_id.v, 32);
        if (seen.count(id))
            continue;

        bool in_validator_set = false;
        uint64_t validator_weight = 0;
        for (size_t j = 0; j < epoch.validators.size(); ++j)
        {
            const Validator& val = epoch.validators[j];
            if (memcmp(val.validator_id.v, v.validator_id.v, 32) == 0)
            {
                in_validator_set = true;
                validator_weight = val.voting_power;
                break;
            }
        }

        if (in_validator_set)
        {
            if (v.eligibility_type != VOTE_ELIGIBILITY_VALIDATOR_SET)
                continue;
            voted += validator_weight;
            seen.insert(id);
            continue;
        }

        if (v.eligibility_type != VOTE_ELIGIBILITY_POW_RECENT)
            continue;
        if (!pow_recent_ids.count(id))
            continue;
        voted += pow_recent_vote_weight;
        seen.insert(id);
    }
    return voted;
}

bool HasSupermajorityPowerTyped(const ValidatorEpoch& epoch,
                                const QuorumCertificate& qc,
                                const std::set<std::string>& pow_recent_ids,
                                uint64_t pow_recent_vote_weight)
{
    if (pow_recent_vote_weight == 0)
        return false;
    const uint64_t validator_total = TotalVotingPower(epoch);
    const uint64_t pow_total = (uint64_t)pow_recent_ids.size() * pow_recent_vote_weight;
    const uint64_t total = validator_total + pow_total;
    if (total == 0)
        return false;
    const uint64_t voted = VotedPowerTyped(epoch, qc, pow_recent_ids, pow_recent_vote_weight);
    return voted * 3 >= total * 2 + 1;
}

bool BasicVoteVerifier::VerifyVote(const Vote& vote) const
{
    if (!crypto_backend_ || vote.round == 0 || vote.signature.empty() || !VoteEligibilityTypeValid(vote.eligibility_type))
        return false;
    std::vector<uint8_t> m;
    WriteU64LE(&m, vote.round);
    m.insert(m.end(), vote.batch_hash.v, vote.batch_hash.v + 32);
    m.insert(m.end(), vote.validator_id.v, vote.validator_id.v + 32);
    m.push_back(vote.eligibility_type);
    return crypto_backend_->VerifyEd25519(vote.validator_id.v,
                                          m.empty() ? NULL : &m[0],
                                          m.size(),
                                          vote.signature.empty() ? NULL : &vote.signature[0],
                                          vote.signature.size());
}

bool VerifyQuorumCertificate(const ValidatorEpoch& epoch,
                             const QuorumCertificate& qc,
                             uint64_t expected_round,
                             const Bytes32& expected_batch_hash,
                             const VoteVerifier& verifier)
{
    if (qc.round != expected_round)
        return false;
    if (memcmp(qc.batch_hash.v, expected_batch_hash.v, 32) != 0)
        return false;
    if (!HasSupermajorityPower(epoch, qc))
        return false;

    std::set<std::string> seen;
    for (size_t i = 0; i < qc.votes.size(); ++i)
    {
        const Vote& v = qc.votes[i];
        if (v.round != expected_round)
            return false;
        if (memcmp(v.batch_hash.v, expected_batch_hash.v, 32) != 0)
            return false;
        if (!VoteEligibilityTypeValid(v.eligibility_type))
            return false;
        std::string id((const char*)v.validator_id.v, 32);
        if (seen.count(id))
            return false;
        seen.insert(id);
        if (!verifier.VerifyVote(v))
            return false;
    }
    return true;
}

bool VerifyQuorumCertificateTyped(const ValidatorEpoch& epoch,
                                  const QuorumCertificate& qc,
                                  uint64_t expected_round,
                                  const Bytes32& expected_batch_hash,
                                  const std::set<std::string>& pow_recent_ids,
                                  uint64_t pow_recent_vote_weight,
                                  const VoteVerifier& verifier)
{
    if (qc.round != expected_round)
        return false;
    if (memcmp(qc.batch_hash.v, expected_batch_hash.v, 32) != 0)
        return false;
    if (!HasSupermajorityPowerTyped(epoch, qc, pow_recent_ids, pow_recent_vote_weight))
        return false;

    std::set<std::string> seen;
    for (size_t i = 0; i < qc.votes.size(); ++i)
    {
        const Vote& v = qc.votes[i];
        if (v.round != expected_round)
            return false;
        if (memcmp(v.batch_hash.v, expected_batch_hash.v, 32) != 0)
            return false;
        if (!VoteEligibilityTypeValid(v.eligibility_type))
            return false;

        const std::string id((const char*)v.validator_id.v, 32);
        if (seen.count(id))
            return false;
        seen.insert(id);

        bool in_validator_set = false;
        for (size_t j = 0; j < epoch.validators.size(); ++j)
        {
            if (memcmp(epoch.validators[j].validator_id.v, v.validator_id.v, 32) == 0)
            {
                in_validator_set = true;
                break;
            }
        }
        if (in_validator_set)
        {
            if (v.eligibility_type != VOTE_ELIGIBILITY_VALIDATOR_SET)
                return false;
        }
        else
        {
            if (v.eligibility_type != VOTE_ELIGIBILITY_POW_RECENT)
                return false;
            if (!pow_recent_ids.count(id))
                return false;
        }

        if (!verifier.VerifyVote(v))
            return false;
    }
    return true;
}

std::vector<uint8_t> SerializeQuorumCertificate(const QuorumCertificate& qc)
{
    std::vector<uint8_t> out;
    WriteU64LE(&out, qc.round);
    out.insert(out.end(), qc.batch_hash.v, qc.batch_hash.v + 32);
    WriteU64LE(&out, (uint64_t)qc.votes.size());
    for (size_t i = 0; i < qc.votes.size(); ++i)
    {
        const Vote& v = qc.votes[i];
        WriteU64LE(&out, v.round);
        out.insert(out.end(), v.batch_hash.v, v.batch_hash.v + 32);
        out.insert(out.end(), v.validator_id.v, v.validator_id.v + 32);
        out.push_back(v.eligibility_type);
        WriteU64LE(&out, (uint64_t)v.signature.size());
        out.insert(out.end(), v.signature.begin(), v.signature.end());
    }
    return out;
}

std::vector<Bytes32> FindEquivocatingValidators(const QuorumCertificate& a, const QuorumCertificate& b)
{
    std::vector<Bytes32> out;
    if (a.round != b.round)
        return out;
    if (memcmp(a.batch_hash.v, b.batch_hash.v, 32) == 0)
        return out;

    std::set<std::string> va;
    for (size_t i = 0; i < a.votes.size(); ++i)
        va.insert(std::string((const char*)a.votes[i].validator_id.v, 32));

    std::set<std::string> seen;
    for (size_t i = 0; i < b.votes.size(); ++i)
    {
        std::string id((const char*)b.votes[i].validator_id.v, 32);
        if (!va.count(id) || seen.count(id))
            continue;
        seen.insert(id);
        Bytes32 v;
        memcpy(v.v, b.votes[i].validator_id.v, 32);
        out.push_back(v);
    }
    return out;
}

}  

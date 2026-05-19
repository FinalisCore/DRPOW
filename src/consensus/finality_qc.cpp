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

bool VotePowHashMeetsTarget(const Bytes32& pow_hash, const Bytes32& pow_target)
{
    return memcmp(pow_hash.v, pow_target.v, 32) <= 0;
}

void BuildVoteSigningMessageV1(const Vote& vote, std::vector<uint8_t>* out)
{
    if (!out)
        return;
    out->clear();
    WriteU64LE(out, vote.round);
    out->insert(out->end(), vote.batch_hash.v, vote.batch_hash.v + 32);
    out->insert(out->end(), vote.validator_id.v, vote.validator_id.v + 32);
    out->push_back(vote.eligibility_type);
}

static void BuildVotePowPreimage(const Vote& vote, std::vector<uint8_t>* out)
{
    if (!out)
        return;
    out->clear();
    // Domain-separate vote PoW from block PoW and any future PoW objects.
    out->push_back('V');
    out->push_back('P');
    out->push_back('O');
    out->push_back('W');
    WriteU64LE(out, vote.round);
    out->insert(out->end(), vote.batch_hash.v, vote.batch_hash.v + 32);
    out->insert(out->end(), vote.validator_id.v, vote.validator_id.v + 32);
    out->push_back(vote.eligibility_type);
    WriteU64LE(out, vote.pow_nonce);
    out->insert(out->end(), vote.pow_target.v, vote.pow_target.v + 32);
}

void BuildVoteSigningMessageV2(const Vote& vote, std::vector<uint8_t>* out)
{
    if (!out)
        return;
    BuildVoteSigningMessageV1(vote, out);
    out->push_back(vote.pow_proof_present ? 1u : 0u);
    if (vote.pow_proof_present)
    {
        WriteU64LE(out, vote.pow_nonce);
        out->insert(out->end(), vote.pow_target.v, vote.pow_target.v + 32);
        out->insert(out->end(), vote.pow_hash.v, vote.pow_hash.v + 32);
    }
}

bool VerifyVotePowFields(const Vote& vote, std::string* reason)
{
    if (!vote.pow_proof_present)
    {
        if (reason)
            *reason = "absent";
        return true;
    }
    bool target_all_zero = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (vote.pow_target.v[i] != 0)
        {
            target_all_zero = false;
            break;
        }
    }
    if (target_all_zero)
    {
        if (reason)
            *reason = "target_zero";
        return false;
    }
    std::vector<uint8_t> preimage;
    BuildVotePowPreimage(vote, &preimage);
    Bytes32 computed;
    if (!Sha256(preimage, &computed))
    {
        if (reason)
            *reason = "hash_failed";
        return false;
    }
    if (memcmp(computed.v, vote.pow_hash.v, 32) != 0)
    {
        if (reason)
            *reason = "hash_mismatch";
        return false;
    }
    if (!VotePowHashMeetsTarget(vote.pow_hash, vote.pow_target))
    {
        if (reason)
            *reason = "hash_above_target";
        return false;
    }
    if (reason)
        *reason = "ok";
    return true;
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
    // Prevent denominator inflation: identities already in the validator set
    // must not be counted again in the PoW-recent bucket.
    uint64_t overlap_count = 0;
    for (size_t i = 0; i < epoch.validators.size(); ++i)
    {
        const std::string id((const char*)epoch.validators[i].validator_id.v, 32);
        if (pow_recent_ids.count(id))
            overlap_count += 1;
    }
    const uint64_t pow_unique_count =
        ((uint64_t)pow_recent_ids.size() > overlap_count)
            ? ((uint64_t)pow_recent_ids.size() - overlap_count)
            : 0;
    const uint64_t pow_total = pow_unique_count * pow_recent_vote_weight;
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
    std::vector<uint8_t> m_v2;
    BuildVoteSigningMessageV2(vote, &m_v2);
    if (crypto_backend_->VerifyEd25519(vote.validator_id.v,
                                       m_v2.empty() ? NULL : &m_v2[0],
                                       m_v2.size(),
                                       vote.signature.empty() ? NULL : &vote.signature[0],
                                       vote.signature.size()))
    {
        return true;
    }
    // Backward compatibility for legacy signatures that did not include PoW fields.
    std::vector<uint8_t> m_v1;
    BuildVoteSigningMessageV1(vote, &m_v1);
    return crypto_backend_->VerifyEd25519(vote.validator_id.v,
                                          m_v1.empty() ? NULL : &m_v1[0],
                                          m_v1.size(),
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
        out.push_back(v.pow_proof_present ? 1u : 0u);
        WriteU64LE(&out, v.pow_nonce);
        out.insert(out.end(), v.pow_target.v, v.pow_target.v + 32);
        out.insert(out.end(), v.pow_hash.v, v.pow_hash.v + 32);
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

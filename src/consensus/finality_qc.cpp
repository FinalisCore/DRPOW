#include "finality_qc.h"

#include <string>
#include <string.h>
#include <vector>

#include "drpow/tx_codec.h"

namespace drpow {

bool VoteEligibilityTypeValid(uint8_t t)
{
    return t == VOTE_ELIGIBILITY_POW_RECENT;
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
    out->push_back('V');
    out->push_back('O');
    out->push_back('T');
    out->push_back('E');
    WriteU64LE(out, vote.round);
    out->insert(out->end(), vote.batch_hash.v, vote.batch_hash.v + 32);
    out->insert(out->end(), vote.validator_id.v, vote.validator_id.v + 32);
    WriteU64LE(out, vote.pow_nonce);
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
    if (reason)
        *reason = "ok";
    return true;
}

bool VerifyVotePowAgainstTarget(const Vote& vote, const Bytes32& target_round, std::string* reason)
{
    std::string local_reason;
    if (!VerifyVotePowFields(vote, &local_reason))
    {
        if (reason)
            *reason = local_reason;
        return false;
    }
    if (!vote.pow_proof_present)
    {
        if (reason)
            *reason = "missing_pow";
        return false;
    }
    if (!VotePowHashMeetsTarget(vote.pow_hash, target_round))
    {
        if (reason)
            *reason = "hash_above_target";
        return false;
    }
    if (reason)
        *reason = "ok";
    return true;
}

uint64_t VotePowWeight(const Vote& vote)
{
    if (!vote.pow_proof_present)
        return 0;
    // Deterministic inverse-hash weight over the high 64 bits of pow_hash:
    // w = floor((2^64 - 1) / (hi64(pow_hash)+1)).
    // Lower hash -> higher weight; bounded and cheap for consensus paths.
    uint64_t hi = 0;
    for (int i = 0; i < 8; ++i)
        hi = (hi << 8) | (uint64_t)vote.pow_hash.v[i];
    const uint64_t denom = hi + 1ULL;
    return UINT64_MAX / denom;
}

bool VerifyQuorumCertificatePow(const QuorumCertificate& qc,
                                uint64_t expected_round,
                                const Bytes32& expected_batch_hash,
                                const Bytes32& target_round,
                                uint64_t min_weight,
                                const VoteVerifier& verifier)
{
    if (qc.round != expected_round)
        return false;
    if (memcmp(qc.batch_hash.v, expected_batch_hash.v, 32) != 0)
        return false;
    if (qc.votes.empty())
        return false;
    std::set<std::string> seen;
    size_t valid_votes = 0;
    uint64_t weight_sum = 0;
    for (size_t i = 0; i < qc.votes.size(); ++i)
    {
        const Vote& v = qc.votes[i];
        if (v.round != expected_round)
            return false;
        if (memcmp(v.batch_hash.v, expected_batch_hash.v, 32) != 0)
            return false;
        const std::string id((const char*)v.validator_id.v, 32);
        if (seen.count(id))
            return false;
        seen.insert(id);
        if (!verifier.VerifyVote(v))
            return false;
        if (!VerifyVotePowAgainstTarget(v, target_round, NULL))
            return false;
        const uint64_t w = VotePowWeight(v);
        if (UINT64_MAX - weight_sum < w)
            weight_sum = UINT64_MAX;
        else
            weight_sum += w;
        valid_votes += 1;
    }
    return valid_votes > 0 && weight_sum >= min_weight;
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

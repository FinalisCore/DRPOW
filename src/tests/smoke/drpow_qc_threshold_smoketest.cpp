#include <stdio.h>
#include <string.h>

#include <vector>

#include "finality_qc.h"
#include "drpow/tx_codec.h"

using namespace drpow;

namespace {

static Bytes32 All(uint8_t v)
{
    Bytes32 b;
    memset(b.v, v, sizeof(b.v));
    return b;
}

static Vote MakeVote(uint64_t round, const Bytes32& batch_hash, const Bytes32& validator_id)
{
    Vote v;
    v.round = round;
    v.batch_hash = batch_hash;
    v.validator_id = validator_id;
    v.eligibility_type = VOTE_ELIGIBILITY_POW_RECENT;
    v.pow_proof_present = 1;
    v.pow_nonce = 12345ULL + (uint64_t)validator_id.v[31];
    v.pow_target = All(0xff);

    std::vector<uint8_t> preimage;
    preimage.push_back('V');
    preimage.push_back('O');
    preimage.push_back('T');
    preimage.push_back('E');
    WriteU64LE(&preimage, v.round);
    preimage.insert(preimage.end(), v.batch_hash.v, v.batch_hash.v + 32);
    preimage.insert(preimage.end(), v.validator_id.v, v.validator_id.v + 32);
    WriteU64LE(&preimage, v.pow_nonce);
    if (!Sha256(preimage, &v.pow_hash))
        v.pow_hash = Bytes32();
    return v;
}

class AcceptAllVoteVerifier : public VoteVerifier {
public:
    virtual ~AcceptAllVoteVerifier() {}
    virtual bool VerifyVote(const Vote& vote) const
    {
        (void)vote;
        return true;
    }
};

}  // namespace

int main()
{
    const uint64_t round = 7;
    const Bytes32 batch_hash = All(0x42);
    const Bytes32 target_round = All(0xff);

    Bytes32 v1_id = All(0x11);
    Bytes32 v2_id = All(0x22);

    Vote v1 = MakeVote(round, batch_hash, v1_id);
    Vote v2 = MakeVote(round, batch_hash, v2_id);
    const uint64_t min_weight = VotePowWeight(v1) + VotePowWeight(v2);

    AcceptAllVoteVerifier verifier;

    QuorumCertificate qc_one;
    qc_one.round = round;
    qc_one.batch_hash = batch_hash;
    qc_one.votes.push_back(v1);
    if (VerifyQuorumCertificatePow(qc_one, round, batch_hash, target_round, min_weight, verifier))
    {
        printf("qc_one_vote_unexpected_pass\n");
        return 1;
    }

    QuorumCertificate qc_two = qc_one;
    qc_two.votes.push_back(v2);
    if (!VerifyQuorumCertificatePow(qc_two, round, batch_hash, target_round, min_weight, verifier))
    {
        printf("qc_two_votes_expected_pass\n");
        return 2;
    }

    QuorumCertificate qc_dup = qc_one;
    qc_dup.votes.push_back(v1);
    if (VerifyQuorumCertificatePow(qc_dup, round, batch_hash, target_round, min_weight, verifier))
    {
        printf("qc_duplicate_voter_unexpected_pass\n");
        return 3;
    }

    printf("ok qc_threshold_enforced\n");
    return 0;
}

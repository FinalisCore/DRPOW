#ifndef COIN_FINALITY_QC_H
#define COIN_FINALITY_QC_H

#include <cstddef>
#include <stdint.h>
#include <set>
#include <vector>

#include "drpow/tx_types.h"
#include "validator_set.h"
#include "crypto_backend.h"

namespace drpow {

enum VoteEligibilityType : uint8_t {
    VOTE_ELIGIBILITY_VALIDATOR_SET = 0,
    VOTE_ELIGIBILITY_POW_RECENT = 1
};

struct Vote {
    uint64_t round = 0;
    Bytes32 batch_hash = Bytes32();
    Bytes32 validator_id = Bytes32();
    uint8_t eligibility_type = VOTE_ELIGIBILITY_VALIDATOR_SET;
    // Optional PoW proof metadata for vote diagnostics and future admission rules.
    uint8_t pow_proof_present = 0;
    uint64_t pow_nonce = 0;
    Bytes32 pow_target = Bytes32();
    Bytes32 pow_hash = Bytes32();
    std::vector<uint8_t> signature;
};

struct QuorumCertificate {
    uint64_t round;
    Bytes32 batch_hash;
    std::vector<Vote> votes;
};

bool HasSupermajority(size_t total_validators, size_t votes_count);
uint64_t TotalVotingPower(const ValidatorEpoch& epoch);
uint64_t VotedPower(const ValidatorEpoch& epoch, const QuorumCertificate& qc);
bool HasSupermajorityPower(const ValidatorEpoch& epoch, const QuorumCertificate& qc);
bool VoteEligibilityTypeValid(uint8_t t);
uint64_t VotedPowerTyped(const ValidatorEpoch& epoch,
                         const QuorumCertificate& qc,
                         const std::set<std::string>& pow_recent_ids,
                         uint64_t pow_recent_vote_weight);
bool HasSupermajorityPowerTyped(const ValidatorEpoch& epoch,
                                const QuorumCertificate& qc,
                                const std::set<std::string>& pow_recent_ids,
                                uint64_t pow_recent_vote_weight);
void BuildVoteSigningMessageV1(const Vote& vote, std::vector<uint8_t>* out);
void BuildVoteSigningMessageV2(const Vote& vote, std::vector<uint8_t>* out);
bool VerifyVotePowFields(const Vote& vote, std::string* reason);
bool VotePowHashMeetsTarget(const Bytes32& pow_hash, const Bytes32& pow_target);

class VoteVerifier {
public:
    virtual ~VoteVerifier() {}
    virtual bool VerifyVote(const Vote& vote) const = 0;
};

class BasicVoteVerifier : public VoteVerifier {
public:
    explicit BasicVoteVerifier(const CryptoBackend* crypto_backend) : crypto_backend_(crypto_backend) {}
    virtual bool VerifyVote(const Vote& vote) const;
private:
    const CryptoBackend* crypto_backend_;
};

bool VerifyQuorumCertificate(const ValidatorEpoch& epoch,
                             const QuorumCertificate& qc,
                             uint64_t expected_round,
                             const Bytes32& expected_batch_hash,
                             const VoteVerifier& verifier);
bool VerifyQuorumCertificateTyped(const ValidatorEpoch& epoch,
                                  const QuorumCertificate& qc,
                                  uint64_t expected_round,
                                  const Bytes32& expected_batch_hash,
                                  const std::set<std::string>& pow_recent_ids,
                                  uint64_t pow_recent_vote_weight,
                                  const VoteVerifier& verifier);
std::vector<uint8_t> SerializeQuorumCertificate(const QuorumCertificate& qc);
std::vector<Bytes32> FindEquivocatingValidators(const QuorumCertificate& a, const QuorumCertificate& b);

}  

#endif

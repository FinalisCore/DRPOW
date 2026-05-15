#ifndef COIN_FINALITY_QC_H
#define COIN_FINALITY_QC_H

#include <cstddef>
#include <stdint.h>
#include <set>
#include <vector>

#include "rpov2/tx_types.h"
#include "validator_set.h"
#include "crypto_backend.h"

namespace rpov2 {

struct Vote {
    uint64_t round;
    Bytes32 batch_hash;
    Bytes32 validator_id;
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
std::vector<uint8_t> SerializeQuorumCertificate(const QuorumCertificate& qc);
std::vector<Bytes32> FindEquivocatingValidators(const QuorumCertificate& a, const QuorumCertificate& b);

}  

#endif

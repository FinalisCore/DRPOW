#ifndef COIN_CONSENSUS_ROUND_H
#define COIN_CONSENSUS_ROUND_H

#include <stdint.h>
#include <string>
#include <vector>

#include "finality_qc.h"
#include "economics_policy.h"
#include "proof_verifier.h"
#include "state_store.h"
#include "rpov2/tx_types.h"
#include "validator_set.h"

namespace rpov2 {

enum ConsensusRejectCode {
    REJECT_NONE = 0,
    REJECT_NULL_STATE_STORE,
    REJECT_ZERO_ROUND,
    REJECT_BATCH_STATELESS_INVALID,
    REJECT_BATCH_HASH_MISMATCH,
    REJECT_QC_ROUND_MISMATCH,
    REJECT_VALIDATOR_EPOCH_UNAVAILABLE,
    REJECT_QC_SUPERMAJORITY_MISSING,
    REJECT_QC_INVALID,
    REJECT_STORE_BEGIN_FAILED,
    REJECT_SPEND_PROOF_INVALID,
    REJECT_SPEND_APPLY_FAILED,
    REJECT_MINT_PROOF_INVALID,
    REJECT_MINT_APPLY_FAILED,
    REJECT_STATE_ROOT_READ_FAILED,
    REJECT_COMMIT_RECORD_WRITE_FAILED,
    REJECT_STORE_COMMIT_FAILED,
    REJECT_EQUIVOCATION_NONE,
    REJECT_EQUIVOCATION_WRITE_FAILED,
    REJECT_ECONOMICS_INVALID,
    REJECT_PROOF_BUDGET_EXCEEDED,
    REJECT_POW_ELIGIBILITY_INVALID,
    REJECT_POW_TARGET_INVALID,
    REJECT_POW_AUTH_MISSING,
    REJECT_POW_AUTH_INVALID,
    REJECT_FEE_POLICY_INVALID
};

struct RoundBatch {
    uint64_t round;
    std::vector<SpendTx> spends;
    std::vector<MintTx> mints;
    Bytes32 batch_hash;
};

class ConsensusRoundEngine {
public:
    ConsensusRoundEngine(StateStore* state_store,
                         const ValidatorSet* validator_set,
                         const VoteVerifier* vote_verifier,
                         const ProofVerifier* proof_verifier,
                         const EconomicsPolicy* economics_policy = NULL);

    bool Propose(const RoundBatch& batch);
    bool ValidateAndVote(const RoundBatch& batch, Vote* out_vote) const;
    bool Commit(const RoundBatch& batch, const QuorumCertificate& qc);
    bool RecordEquivocationEvidence(const QuorumCertificate& qc_a, const QuorumCertificate& qc_b);
    ConsensusRejectCode last_reject_code() const { return last_reject_code_; }
    const std::string& last_reject_message() const { return last_reject_message_; }

private:
    bool Fail(ConsensusRejectCode code, const char* message);
    StateStore* state_store_;
    const ValidatorSet* validator_set_;
    const VoteVerifier* vote_verifier_;
    const ProofVerifier* proof_verifier_;
    EconomicsPolicy economics_policy_;
    ConsensusRejectCode last_reject_code_;
    std::string last_reject_message_;
};

}  

#endif

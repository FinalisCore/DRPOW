#include "consensus_round.h"
#include "drpow/tx_codec.h"

#include <set>
#include <string>
#include <string.h>

namespace drpow {

static bool ComputeBatchHashCanonical(const RoundBatch& batch, Bytes32* out)
{
    if (!out)
        return false;

    std::vector<uint8_t> encoded;
    WriteU64LE(&encoded, batch.round);

    WriteU64LE(&encoded, (uint64_t)batch.spends.size());
    for (size_t i = 0; i < batch.spends.size(); ++i)
        SerializeSpendTxCanonical(batch.spends[i], &encoded);

    WriteU64LE(&encoded, (uint64_t)batch.mints.size());
    for (size_t i = 0; i < batch.mints.size(); ++i)
        SerializeMintTxCanonical(batch.mints[i], &encoded);

    return Sha256(encoded, out);
}

static bool ValidateBatchStateless(const RoundBatch& batch)
{
    std::set<std::string> seen_spend_txids;
    std::set<std::string> seen_mint_txids;
    std::set<std::string> seen_input_coin_ids;

    for (size_t i = 0; i < batch.spends.size(); ++i)
    {
        Bytes32 txid;
        if (!ComputeSpendTxId(batch.spends[i], &txid))
            return false;
        std::string txid_key((const char*)txid.v, 32);
        if (seen_spend_txids.count(txid_key))
            return false;
        seen_spend_txids.insert(txid_key);

        for (size_t j = 0; j < batch.spends[i].inputs.size(); ++j)
        {
            const Bytes32& coin_id = batch.spends[i].inputs[j].coin_id;
            std::string coin_key((const char*)coin_id.v, 32);
            if (seen_input_coin_ids.count(coin_key))
                return false;
            seen_input_coin_ids.insert(coin_key);
        }
    }

    for (size_t i = 0; i < batch.mints.size(); ++i)
    {
        Bytes32 txid;
        if (!ComputeMintTxId(batch.mints[i], &txid))
            return false;
        std::string txid_key((const char*)txid.v, 32);
        if (seen_mint_txids.count(txid_key) || seen_spend_txids.count(txid_key))
            return false;
        seen_mint_txids.insert(txid_key);
    }

    return true;
}

static bool HasPowAuthorization(const RoundBatch& batch, const ProofVerifier* proof_verifier)
{
    (void)proof_verifier;
    if (batch.mints.empty())
        return false;
    // Pure PoW mode: any miner is authorized if its canonical batch hash
    // meets the declared target. This removes signature-gated mint auth.
    Bytes32 h;
    if (!ComputeBatchHashCanonical(batch, &h))
        return false;
    return memcmp(h.v, batch.mints[0].target.v, 32) <= 0;
}

static bool IsMinerEligibleForRound(const RoundBatch& batch,
                                    const ValidatorSet* validator_set,
                                    const EconomicsPolicy& policy)
{
    (void)validator_set;
    (void)policy;
    // Open PoW mining: miner does not need pre-existing validator membership.
    // Authorization + target checks enforce real work validity.
    if (batch.mints.empty())
        return false;
    return true;
}

static bool ComputeExpectedTargetForRound(const StateStore* state_store,
                                          uint64_t round,
                                          const EconomicsPolicy& policy,
                                          Bytes32* out_target)
{
    if (!state_store || !out_target || round == 0)
        return false;
    const uint64_t epoch_len = policy.target_epoch_rounds == 0 ? 1 : policy.target_epoch_rounds;
    const bool epoch_start = (round == 1) || (((round - 1) % epoch_len) == 0);
    if (round == 1)
    {
        *out_target = policy.max_target;
        return true;
    }

    if (!epoch_start)
    {
        std::vector<RoundCommitRecord> prev;
        if (!state_store->ExportVerifiedCommitRecordsFromRound(round - 1, 1, &prev))
            return false;
        if (prev.size() != 1)
            return false;
        MintTx mint;
        size_t off = 0;
        if (!ParseMintTxCanonical(prev[0].consensus_proof.empty() ? NULL : &prev[0].consensus_proof[0],
                                  prev[0].consensus_proof.size(),
                                  &off,
                                  &mint) ||
            off != prev[0].consensus_proof.size())
        {
            return false;
        }
        *out_target = mint.target;
        return true;
    }

    // Epoch boundary retarget: derive one target commitment from previous epoch only.
    std::vector<RoundCommitRecord> recs;
    const uint64_t from_round = round - epoch_len;
    if (!state_store->ExportVerifiedCommitRecordsFromRound(from_round, (size_t)epoch_len, &recs))
        return false;
    if (recs.size() == 0)
        return false;

    Bytes32 prev_target = policy.max_target;
    uint64_t observed_mints = 0;
    for (size_t i = 0; i < recs.size(); ++i)
    {
        MintTx mint;
        size_t off = 0;
        if (!ParseMintTxCanonical(recs[i].consensus_proof.empty() ? NULL : &recs[i].consensus_proof[0],
                                  recs[i].consensus_proof.size(),
                                  &off,
                                  &mint) ||
            off != recs[i].consensus_proof.size())
        {
            return false;
        }
        prev_target = mint.target;
        observed_mints += 1;
    }
    const uint64_t expected_mints = policy.target_mints_per_window == 0 ? epoch_len : policy.target_mints_per_window;
    return NextPowTargetDeterministic(prev_target,
                                      observed_mints,
                                      expected_mints,
                                      policy.target_adjust_up_ppm_limit,
                                      policy.target_adjust_down_ppm_limit,
                                      policy.min_target,
                                      policy.max_target,
                                      out_target);
}

static bool BatchMatchesExpectedTarget(const RoundBatch& batch, const Bytes32& expected_target)
{
    if (batch.mints.empty())
        return false;
    for (size_t i = 0; i < batch.mints.size(); ++i)
    {
        if (memcmp(batch.mints[i].target.v, expected_target.v, 32) != 0)
            return false;
    }
    return true;
}

static uint64_t BatchProofCostUnits(const RoundBatch& batch)
{
    uint64_t cost = 0;
    for (size_t i = 0; i < batch.spends.size(); ++i)
    {
        const SpendTx& tx = batch.spends[i];
        cost += tx.sum_proof.size();
        for (size_t j = 0; j < tx.inputs.size(); ++j)
            cost += tx.inputs[j].ownership_proof.size();
        for (size_t j = 0; j < tx.signatures.size(); ++j)
            cost += tx.signatures[j].size();
        cost += tx.outputs.size() * (size_t)64;
    }
    for (size_t i = 0; i < batch.mints.size(); ++i)
    {
        cost += batch.mints[i].signature.size();
        cost += 64;
    }
    return cost;
}

ConsensusRoundEngine::ConsensusRoundEngine(StateStore* state_store,
                                           const ValidatorSet* validator_set,
                                           const VoteVerifier* vote_verifier,
                                           const ProofVerifier* proof_verifier,
                                           const EconomicsPolicy* economics_policy)
    : state_store_(state_store),
      validator_set_(validator_set),
      vote_verifier_(vote_verifier),
      proof_verifier_(proof_verifier),
      economics_policy_(economics_policy ? *economics_policy : DefaultEconomicsPolicy()),
      last_reject_code_(REJECT_NONE),
      last_reject_message_("")
{
}

bool ConsensusRoundEngine::Fail(ConsensusRejectCode code, const char* message)
{
    last_reject_code_ = code;
    last_reject_message_ = message ? message : "";
    return false;
}

bool ConsensusRoundEngine::Propose(const RoundBatch& batch)
{
    if (batch.round == 0)
        return Fail(REJECT_ZERO_ROUND, "zero round");
    if (!ValidateBatchStateless(batch))
        return Fail(REJECT_BATCH_STATELESS_INVALID, "stateless batch invalid");
    if (!ValidateBatchEconomics(batch, economics_policy_))
        return Fail(REJECT_ECONOMICS_INVALID, "economics invalid");
    if (!ValidateBatchFeePolicy(batch, economics_policy_))
        return Fail(REJECT_FEE_POLICY_INVALID, "fee policy invalid");
    if (BatchProofCostUnits(batch) > economics_policy_.max_proof_cost_per_round)
        return Fail(REJECT_PROOF_BUDGET_EXCEEDED, "proof budget exceeded");
    if (!IsMinerEligibleForRound(batch, validator_set_, economics_policy_))
        return Fail(REJECT_POW_ELIGIBILITY_INVALID, "pow eligibility invalid");
    if (!HasPowAuthorization(batch, proof_verifier_))
        return Fail(REJECT_POW_TARGET_INVALID, "pow target not met");
    Bytes32 expected_target;
    if (!ComputeExpectedTargetForRound(state_store_, batch.round, economics_policy_, &expected_target))
        return Fail(REJECT_POW_TARGET_INVALID, "pow target derive failed");
    if (!BatchMatchesExpectedTarget(batch, expected_target))
        return Fail(REJECT_POW_TARGET_INVALID, "pow target invalid");
    Bytes32 h;
    if (!ComputeBatchHashCanonical(batch, &h))
        return Fail(REJECT_BATCH_HASH_MISMATCH, "batch hash compute failed");
    for (int i = 0; i < 32; ++i)
        if (h.v[i] != batch.batch_hash.v[i])
            return Fail(REJECT_BATCH_HASH_MISMATCH, "batch hash mismatch");
    last_reject_code_ = REJECT_NONE;
    last_reject_message_.clear();
    return true;
}

bool ConsensusRoundEngine::ValidateAndVote(const RoundBatch& batch, Vote* out_vote) const
{
    if (!out_vote)
        return false;
    if (!ValidateBatchStateless(batch))
        return false;
    if (!ValidateBatchEconomics(batch, economics_policy_))
        return false;
    if (!ValidateBatchFeePolicy(batch, economics_policy_))
        return false;
    if (BatchProofCostUnits(batch) > economics_policy_.max_proof_cost_per_round)
        return false;
    if (!IsMinerEligibleForRound(batch, validator_set_, economics_policy_))
        return false;
    if (!HasPowAuthorization(batch, proof_verifier_))
        return false;
    Bytes32 expected_target;
    if (!ComputeExpectedTargetForRound(state_store_, batch.round, economics_policy_, &expected_target))
        return false;
    if (!BatchMatchesExpectedTarget(batch, expected_target))
        return false;
    Bytes32 h;
    if (!ComputeBatchHashCanonical(batch, &h))
        return false;
    for (int i = 0; i < 32; ++i)
        if (h.v[i] != batch.batch_hash.v[i])
            return false;
    out_vote->round = batch.round;
    out_vote->batch_hash = batch.batch_hash;
    out_vote->eligibility_type = VOTE_ELIGIBILITY_VALIDATOR_SET;
    return true;
}

bool ConsensusRoundEngine::Commit(const RoundBatch& batch, const QuorumCertificate& qc)
{
    (void)qc;
    if (!state_store_)
        return Fail(REJECT_NULL_STATE_STORE, "null state store");
    if (!ValidateBatchStateless(batch))
        return Fail(REJECT_BATCH_STATELESS_INVALID, "stateless batch invalid");
    if (!ValidateBatchEconomics(batch, economics_policy_))
        return Fail(REJECT_ECONOMICS_INVALID, "economics invalid");
    if (!ValidateBatchFeePolicy(batch, economics_policy_))
        return Fail(REJECT_FEE_POLICY_INVALID, "fee policy invalid");
    if (BatchProofCostUnits(batch) > economics_policy_.max_proof_cost_per_round)
        return Fail(REJECT_PROOF_BUDGET_EXCEEDED, "proof budget exceeded");
    if (!IsMinerEligibleForRound(batch, validator_set_, economics_policy_))
        return Fail(REJECT_POW_ELIGIBILITY_INVALID, "pow eligibility invalid");
    Bytes32 expected_target;
    if (!ComputeExpectedTargetForRound(state_store_, batch.round, economics_policy_, &expected_target))
        return Fail(REJECT_POW_TARGET_INVALID, "pow target derive failed");
    if (!BatchMatchesExpectedTarget(batch, expected_target))
        return Fail(REJECT_POW_TARGET_INVALID, "pow target invalid");
    if (batch.mints.empty())
        return Fail(REJECT_POW_AUTH_MISSING, "pow auth missing");
    if (!HasPowAuthorization(batch, proof_verifier_))
        return Fail(REJECT_POW_TARGET_INVALID, "pow target not met");

    if (!state_store_->Begin())
        return Fail(REJECT_STORE_BEGIN_FAILED, "store begin failed");

    for (size_t i = 0; i < batch.spends.size(); ++i)
    {
        if (!proof_verifier_ || !proof_verifier_->VerifySpendTx(batch.spends[i]))
        {
            state_store_->Rollback();
            return Fail(REJECT_SPEND_PROOF_INVALID, "spend proof invalid");
        }
        if (!state_store_->Spend(batch.spends[i]))
        {
            state_store_->Rollback();
            return Fail(REJECT_SPEND_APPLY_FAILED, "spend apply failed");
        }
    }

    for (size_t i = 0; i < batch.mints.size(); ++i)
    {
        if (!proof_verifier_ || !proof_verifier_->VerifyMintTx(batch.mints[i]))
        {
            state_store_->Rollback();
            return Fail(REJECT_MINT_PROOF_INVALID, "mint proof invalid");
        }
        if (!state_store_->Mint(batch.mints[i]))
        {
            state_store_->Rollback();
            return Fail(REJECT_MINT_APPLY_FAILED, "mint apply failed");
        }
    }

    RoundCommitRecord rec;
    rec.round = batch.round;
    rec.batch_hash = batch.batch_hash;
    rec.consensus_proof.clear();
    SerializeMintTxCanonical(batch.mints[0], &rec.consensus_proof);
    if (!state_store_->ReadStateRoot(&rec.state_root))
    {
        state_store_->Rollback();
        return Fail(REJECT_STATE_ROOT_READ_FAILED, "state root read failed");
    }
    if (!state_store_->WriteRoundCommit(rec))
    {
        state_store_->Rollback();
        return Fail(REJECT_COMMIT_RECORD_WRITE_FAILED, "commit record write failed");
    }

    if (!state_store_->Commit())
    {
        state_store_->Rollback();
        return Fail(REJECT_STORE_COMMIT_FAILED, "store commit failed");
    }

    last_reject_code_ = REJECT_NONE;
    last_reject_message_.clear();
    return true;
}

bool ConsensusRoundEngine::RecordEquivocationEvidence(const QuorumCertificate& qc_a, const QuorumCertificate& qc_b)
{
    if (!state_store_)
        return Fail(REJECT_NULL_STATE_STORE, "null state store");
    std::vector<Bytes32> bad = FindEquivocatingValidators(qc_a, qc_b);
    if (bad.empty())
        return Fail(REJECT_EQUIVOCATION_NONE, "no equivocation");

    std::vector<uint8_t> ser_a = SerializeQuorumCertificate(qc_a);
    std::vector<uint8_t> ser_b = SerializeQuorumCertificate(qc_b);
    for (size_t i = 0; i < bad.size(); ++i)
    {
        EquivocationEvidenceRecord rec;
        rec.round = qc_a.round;
        rec.validator_id = bad[i];
        rec.batch_hash_a = qc_a.batch_hash;
        rec.batch_hash_b = qc_b.batch_hash;
        rec.qc_a = ser_a;
        rec.qc_b = ser_b;
        if (!state_store_->WriteEquivocationEvidence(rec))
            return Fail(REJECT_EQUIVOCATION_WRITE_FAILED, "evidence write failed");
    }
    last_reject_code_ = REJECT_NONE;
    last_reject_message_.clear();
    return true;
}

}  

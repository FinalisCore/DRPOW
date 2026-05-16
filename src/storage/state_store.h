#ifndef COIN_STATE_STORE_H
#define COIN_STATE_STORE_H

#include <stdint.h>
#include <string>
#include <vector>

#include "rpov2/tx_types.h"

namespace rpov2 {

struct RoundCommitRecord {
    uint16_t record_version;
    uint16_t hash_alg_id;
    uint16_t sig_alg_id;
    uint64_t round;
    Bytes32 batch_hash;
    std::vector<uint8_t> consensus_proof;
    Bytes32 state_root;
    Bytes32 record_hash;
    Bytes32 record_signer_id;
    std::vector<uint8_t> record_signature;
};

struct EquivocationEvidenceRecord {
    uint64_t round;
    Bytes32 validator_id;
    Bytes32 batch_hash_a;
    Bytes32 batch_hash_b;
    std::vector<uint8_t> qc_a;
    std::vector<uint8_t> qc_b;
};

class StateStore {
public:
    virtual ~StateStore() {}

    virtual bool Begin() = 0;
    virtual bool Commit() = 0;
    virtual void Rollback() = 0;

    virtual bool Spend(const SpendTx& tx) = 0;
    virtual bool Mint(const MintTx& tx) = 0;

    virtual bool WriteRoundCommit(const RoundCommitRecord& record) = 0;
    virtual bool WriteEquivocationEvidence(const EquivocationEvidenceRecord& record) = 0;
    virtual bool ReadStateRoot(Bytes32* out_root) const = 0;
    virtual bool ReadMintBudget(uint64_t* out_budget) const
    {
        (void)out_budget;
        return false;
    }
    virtual bool ExportVerifiedCommitRecordsFromRound(uint64_t from_round,
                                                      size_t max_records,
                                                      std::vector<RoundCommitRecord>* out) const
    {
        (void)from_round;
        (void)max_records;
        (void)out;
        return false;
    }
};

}  

#endif

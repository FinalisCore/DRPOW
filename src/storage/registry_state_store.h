#ifndef COIN_REGISTRY_STATE_STORE_H
#define COIN_REGISTRY_STATE_STORE_H

#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include "crypto_backend.h"
#include "proof_verifier.h"
#include "state_store.h"

namespace rpov2 {

class RegistryStateStore : public StateStore {
public:
    enum CommitLogVerifyError {
        COMMITLOG_VERIFY_OK = 0,
        COMMITLOG_VERIFY_IO_ERROR,
        COMMITLOG_VERIFY_FORMAT_ERROR,
        COMMITLOG_VERIFY_UNSUPPORTED_UPGRADE,
        COMMITLOG_VERIFY_ORDER_INVALID,
        COMMITLOG_VERIFY_HASH_MISMATCH,
        COMMITLOG_VERIFY_SIGNER_MISMATCH,
        COMMITLOG_VERIFY_SIGNATURE_INVALID
    };

    RegistryStateStore(const std::string& registry_file,
                       const std::string& commit_log_file,
                       const std::string& evidence_log_file,
                       const ProofVerifier* proof_verifier,
                       const CryptoBackend* crypto_backend,
                       const uint8_t commit_signer_privkey[32],
                       const Bytes32* commit_signer_id);

    virtual bool Begin();
    virtual bool Commit();
    virtual void Rollback();

    virtual bool Spend(const SpendTx& tx);
    virtual bool Mint(const MintTx& tx);

    virtual bool WriteRoundCommit(const RoundCommitRecord& record);
    virtual bool WriteEquivocationEvidence(const EquivocationEvidenceRecord& record);
    virtual bool ReadStateRoot(Bytes32* out_root) const;
    virtual bool ReadMintBudget(uint64_t* out_budget) const;
    uint64_t LastVerifiedCommitRound() const { return verified_last_round_; }
    virtual bool ExportVerifiedCommitRecordsFromRound(uint64_t from_round, size_t max_records, std::vector<RoundCommitRecord>* out) const;
    CommitLogVerifyError commit_log_verify_error() const { return commit_log_verify_error_; }
    const std::string& commit_log_verify_error_message() const { return commit_log_verify_error_message_; }

private:
    struct LedgerTotals {
        uint64_t total_supply;
        uint64_t total_minted;
        uint64_t total_fees_burned;
    };

    struct UtxoRecord {
        Bytes32 coin_id;
        UtxoOutput output;
        Bytes32 mint_nonce;
        Bytes32 mint_signature;
        Bytes32 reserved;
    };

    std::string registry_file_;
    std::string ledger_file_;
    std::string commit_log_file_;
    std::string evidence_log_file_;
    const ProofVerifier* proof_verifier_;
    const CryptoBackend* crypto_backend_;
    uint8_t commit_signer_privkey_[32];
    Bytes32 commit_signer_id_;
    bool has_commit_signer_;

    bool in_txn_;
    bool commit_log_ok_;
    mutable uint64_t verified_last_round_;
    mutable CommitLogVerifyError commit_log_verify_error_;
    mutable std::string commit_log_verify_error_message_;
    std::map<std::string, UtxoRecord> live_;
    std::map<std::string, UtxoRecord> staged_;
    LedgerTotals live_totals_;
    LedgerTotals staged_totals_;
    uint64_t genesis_supply_;
    std::vector<RoundCommitRecord> pending_commits_;

    static std::string Key(const Bytes32& id);
    static void Zero32(Bytes32* v);
    static bool IsZero32(const Bytes32& v);
    static bool ComputeCoinId(const UtxoOutput& out, uint64_t nonce_hint, Bytes32* coin_id);

    bool LoadRegistry();
    bool FlushRegistry(const std::map<std::string, UtxoRecord>& src) const;
    bool LoadLedgerTotals();
    bool FlushLedgerTotals(const LedgerTotals& totals) const;
    bool AppendCommitLog(const RoundCommitRecord& record) const;
    bool VerifyCommitLog() const;
    bool AppendEvidenceLog(const EquivocationEvidenceRecord& record) const;
    bool CurrentStateRoot(const std::map<std::string, UtxoRecord>& src, Bytes32* out_root) const;
    bool ComputeSupply(const std::map<std::string, UtxoRecord>& src, uint64_t* out_supply) const;
};

}  

#endif

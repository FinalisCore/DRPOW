#ifndef COIN_PROOF_VERIFIER_H
#define COIN_PROOF_VERIFIER_H

#include <cstddef>

#include "rpov2/tx_types.h"
#include "crypto_backend.h"

namespace rpov2 {

struct ProofPolicy {
    size_t max_inputs_per_spend;
    size_t max_outputs_per_spend;
    size_t max_signature_bytes;
    size_t max_total_signature_bytes_per_spend;
    size_t max_ownership_proof_bytes;
    size_t max_sum_proof_bytes;
    uint8_t spend_ownership_proof_format_version;
    uint8_t spend_ownership_proof_next_format_version;
    uint8_t spend_sum_proof_format_version;
    uint8_t spend_sum_proof_next_format_version;
};

ProofPolicy DefaultProofPolicy();

class ProofVerifier {
public:
    virtual ~ProofVerifier() {}
    virtual bool VerifySpendTx(const SpendTx& tx) const = 0;
    virtual bool VerifyMintTx(const MintTx& tx) const = 0;
};

class BasicProofVerifier : public ProofVerifier {
public:
    explicit BasicProofVerifier(const CryptoBackend* crypto_backend, const ProofPolicy* policy = NULL);
    virtual bool VerifySpendTx(const SpendTx& tx) const;
    virtual bool VerifyMintTx(const MintTx& tx) const;
private:
    const CryptoBackend* crypto_backend_;
    ProofPolicy policy_;
};

}  

#endif

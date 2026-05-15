#include "proof_verifier.h"

#include <string.h>
#include <vector>

#include "rpov2/tx_codec.h"

namespace rpov2 {

namespace {

static bool IsAllowedFormatVersion(uint8_t v, uint8_t cur, uint8_t next)
{
    if (v == cur)
        return true;
    return next != 0 && v == next;
}

}  // namespace

ProofPolicy DefaultProofPolicy()
{
    ProofPolicy p;
    p.max_inputs_per_spend = 64;
    p.max_outputs_per_spend = 64;
    p.max_signature_bytes = 32 * 1024;
    p.max_total_signature_bytes_per_spend = 512 * 1024;
    p.max_ownership_proof_bytes = 4 * 1024;
    p.max_sum_proof_bytes = 256 * 1024;
    p.spend_ownership_proof_format_version = 1;
    p.spend_ownership_proof_next_format_version = 0;
    p.spend_sum_proof_format_version = 1;
    p.spend_sum_proof_next_format_version = 0;
    return p;
}

BasicProofVerifier::BasicProofVerifier(const CryptoBackend* crypto_backend, const ProofPolicy* policy)
    : crypto_backend_(crypto_backend),
      policy_(policy ? *policy : DefaultProofPolicy())
{
}

bool BasicProofVerifier::VerifySpendTx(const SpendTx& tx) const
{
    if (!crypto_backend_)
        return false;
    if (tx.inputs.empty() || tx.outputs.empty())
        return false;
    if (tx.inputs.size() > policy_.max_inputs_per_spend || tx.outputs.size() > policy_.max_outputs_per_spend)
        return false;
    if (tx.sum_proof.empty() || tx.sum_proof.size() > policy_.max_sum_proof_bytes)
        return false;
    if (!IsAllowedFormatVersion(tx.sum_proof[0],
                                policy_.spend_sum_proof_format_version,
                                policy_.spend_sum_proof_next_format_version))
        return false;
    if (tx.signatures.size() < tx.inputs.size())
        return false;

    SpendTx tx_core = tx;
    tx_core.signatures.clear();
    std::vector<uint8_t> core;
    SerializeSpendTxCanonical(tx_core, &core);
    Bytes32 core_hash;
    if (!Sha256(core, &core_hash))
        return false;

    size_t total_sig_bytes = 0;
    for (size_t i = 0; i < tx.inputs.size(); ++i)
    {
        if (tx.inputs[i].ownership_proof.empty())
            return false;
        if (tx.inputs[i].ownership_proof.size() < 33 ||
            tx.inputs[i].ownership_proof.size() > policy_.max_ownership_proof_bytes)
            return false;
        if (!IsAllowedFormatVersion(tx.inputs[i].ownership_proof[0],
                                    policy_.spend_ownership_proof_format_version,
                                    policy_.spend_ownership_proof_next_format_version))
            return false;
        if (tx.signatures[i].empty())
            return false;
        if (tx.signatures[i].size() > policy_.max_signature_bytes)
            return false;
        total_sig_bytes += tx.signatures[i].size();
        if (total_sig_bytes > policy_.max_total_signature_bytes_per_spend)
            return false;
        std::vector<uint8_t> m;
        m.insert(m.end(), core_hash.v, core_hash.v + 32);
        m.insert(m.end(), tx.inputs[i].coin_id.v, tx.inputs[i].coin_id.v + 32);
        const uint8_t* pub = &tx.inputs[i].ownership_proof[1];
        if (!crypto_backend_->VerifyEd25519(pub,
                                            m.empty() ? NULL : &m[0],
                                            m.size(),
                                            tx.signatures[i].empty() ? NULL : &tx.signatures[i][0],
                                            tx.signatures[i].size()))
            return false;
    }

    for (size_t i = 0; i < tx.outputs.size(); ++i)
    {
        bool all_zero = true;
        for (int j = 0; j < 64; ++j)
            if (tx.outputs[i].range_proof.v[j] != 0)
            {
                all_zero = false;
                break;
            }
        if (all_zero)
            return false;
    }

    return true;
}

bool BasicProofVerifier::VerifyMintTx(const MintTx& tx) const
{
    if (!crypto_backend_ || tx.signature.empty())
        return false;
    if (tx.signature.size() > policy_.max_signature_bytes)
        return false;
    std::vector<uint8_t> m;
    WriteU64LE(&m, tx.output.value);
    WriteBytes32(&m, tx.output.commitment);
    WriteBytes32(&m, tx.output.owner_pubkey);
    WriteBytes64(&m, tx.output.range_proof);
    WriteU64LE(&m, tx.mint_nonce);
    WriteBytes32(&m, tx.target);
    WriteBytes32(&m, tx.miner_pubkey);
    if (!crypto_backend_->VerifyEd25519(tx.miner_pubkey.v,
                                        m.empty() ? NULL : &m[0],
                                        m.size(),
                                        tx.signature.empty() ? NULL : &tx.signature[0],
                                        tx.signature.size()))
        return false;

    std::vector<uint8_t> pow_msg;
    WriteBytes32(&pow_msg, tx.output.commitment);
    WriteU64LE(&pow_msg, tx.mint_nonce);
    WriteBytes32(&pow_msg, tx.miner_pubkey);
    Bytes32 pow_hash;
    if (!Sha256(pow_msg, &pow_hash))
        return false;
    return memcmp(pow_hash.v, tx.target.v, 32) <= 0;
}

}  

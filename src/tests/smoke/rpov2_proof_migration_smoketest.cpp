#include <stdio.h>

#include <memory>
#include <vector>

#include "crypto_backend.h"
#include "proof_verifier.h"
#include "rpov2/tx_codec.h"

using namespace rpov2;

static void Fill32(Bytes32* b, uint8_t seed)
{
    for (int i = 0; i < 32; ++i)
        b->v[i] = (uint8_t)(seed + i);
}

static void Fill64(Bytes64* b, uint8_t seed)
{
    for (int i = 0; i < 64; ++i)
        b->v[i] = (uint8_t)(seed + i);
}

static std::vector<uint8_t> BuildSpendSig(const CryptoBackend& cb, const uint8_t priv[32], const SpendTx& tx, size_t idx)
{
    SpendTx tx_core = tx;
    tx_core.signatures.clear();
    std::vector<uint8_t> core;
    SerializeSpendTxCanonical(tx_core, &core);
    Bytes32 h;
    Sha256(core, &h);

    std::vector<uint8_t> m;
    m.insert(m.end(), h.v, h.v + 32);
    m.insert(m.end(), tx.inputs[idx].coin_id.v, tx.inputs[idx].coin_id.v + 32);
    std::vector<uint8_t> sig;
    cb.SignEd25519(priv, m.empty() ? NULL : &m[0], m.size(), &sig);
    return sig;
}

static SpendTx BuildSpendTemplate(const Bytes32& owner_pub)
{
    SpendTx tx;
    tx.timestamp = 1;
    tx.fee = 1;

    SpendInput in;
    Fill32(&in.coin_id, 7);
    in.ownership_proof.push_back(1);
    in.ownership_proof.insert(in.ownership_proof.end(), owner_pub.v, owner_pub.v + 32);
    tx.inputs.push_back(in);

    UtxoOutput out;
    out.value = 1;
    Fill32(&out.commitment, 3);
    out.owner_pubkey = owner_pub;
    Fill64(&out.range_proof, 9);
    tx.outputs.push_back(out);

    tx.sum_proof.push_back(1);
    tx.sum_proof.push_back(0xaa);
    return tx;
}

int main()
{
    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed\n");
        return 10;
    }

    uint8_t owner_priv[32];
    for (int i = 0; i < 32; ++i)
        owner_priv[i] = (uint8_t)(70 + i);
    Bytes32 owner_pub;
    crypto->PublicFromPrivateEd25519(owner_priv, owner_pub.v);

    SpendTx v1 = BuildSpendTemplate(owner_pub);
    v1.signatures.push_back(BuildSpendSig(*crypto, owner_priv, v1, 0));

    SpendTx v2 = v1;
    v2.inputs[0].ownership_proof[0] = 2;
    v2.sum_proof[0] = 2;
    v2.signatures[0] = BuildSpendSig(*crypto, owner_priv, v2, 0);

    ProofPolicy p = DefaultProofPolicy();
    p.max_signature_bytes = 64 * 1024;
    p.max_total_signature_bytes_per_spend = 64 * 1024;
    p.max_ownership_proof_bytes = 1024;

    // Matrix A: strict v1 only.
    p.spend_ownership_proof_format_version = 1;
    p.spend_ownership_proof_next_format_version = 0;
    p.spend_sum_proof_format_version = 1;
    p.spend_sum_proof_next_format_version = 0;
    BasicProofVerifier v1_only(crypto.get(), &p);

    if (!v1_only.VerifySpendTx(v1))
    {
        printf("matrix_a_v1_should_pass\n");
        return 1;
    }
    if (v1_only.VerifySpendTx(v2))
    {
        printf("matrix_a_v2_should_fail\n");
        return 2;
    }

    // Matrix B: migration window v1+v2 accepted.
    p.spend_ownership_proof_next_format_version = 2;
    p.spend_sum_proof_next_format_version = 2;
    BasicProofVerifier v1_v2(crypto.get(), &p);

    if (!v1_v2.VerifySpendTx(v1))
    {
        printf("matrix_b_v1_should_pass\n");
        return 3;
    }
    if (!v1_v2.VerifySpendTx(v2))
    {
        printf("matrix_b_v2_should_pass\n");
        return 4;
    }

    // Matrix C: post-migration strict v2 only.
    p.spend_ownership_proof_format_version = 2;
    p.spend_ownership_proof_next_format_version = 0;
    p.spend_sum_proof_format_version = 2;
    p.spend_sum_proof_next_format_version = 0;
    BasicProofVerifier v2_only(crypto.get(), &p);

    if (v2_only.VerifySpendTx(v1))
    {
        printf("matrix_c_v1_should_fail\n");
        return 5;
    }
    if (!v2_only.VerifySpendTx(v2))
    {
        printf("matrix_c_v2_should_pass\n");
        return 6;
    }

    printf("ok proof_migration_vectors\n");
    return 0;
}

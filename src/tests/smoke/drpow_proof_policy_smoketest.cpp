#include <stdio.h>
#include <string.h>

#include <memory>
#include <vector>

#include "crypto_backend.h"
#include "proof_verifier.h"
#include "drpow/tx_codec.h"

using namespace drpow;

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

int main()
{
    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed\n");
        return 10;
    }

    ProofPolicy p = DefaultProofPolicy();
    p.max_signature_bytes = 64 * 1024;
    p.max_total_signature_bytes_per_spend = 64 * 1024;
    p.max_ownership_proof_bytes = 64;
    BasicProofVerifier verifier(crypto.get(), &p);

    uint8_t owner_priv[32];
    for (int i = 0; i < 32; ++i)
        owner_priv[i] = (uint8_t)(40 + i);
    Bytes32 owner_pub;
    crypto->PublicFromPrivateEd25519(owner_priv, owner_pub.v);

    SpendTx ok;
    ok.timestamp = 1;
    ok.fee = 1;
    ok.sum_proof.push_back(1);
    ok.sum_proof.push_back(0xaa);

    SpendInput in;
    Fill32(&in.coin_id, 7);
    in.ownership_proof.push_back(1);
    in.ownership_proof.insert(in.ownership_proof.end(), owner_pub.v, owner_pub.v + 32);
    ok.inputs.push_back(in);

    UtxoOutput out;
    out.value = 1;
    Fill32(&out.commitment, 3);
    out.owner_pubkey = owner_pub;
    Fill64(&out.range_proof, 9);
    ok.outputs.push_back(out);

    ok.signatures.push_back(BuildSpendSig(*crypto, owner_priv, ok, 0));

    if (!verifier.VerifySpendTx(ok))
    {
        printf("verify_spend_ok_failed\n");
        return 1;
    }

    SpendTx bad_sum_ver = ok;
    bad_sum_ver.sum_proof[0] = 2;
    if (verifier.VerifySpendTx(bad_sum_ver))
    {
        printf("bad_sum_ver_unexpected_pass\n");
        return 2;
    }

    SpendTx bad_owner_ver = ok;
    bad_owner_ver.inputs[0].ownership_proof[0] = 2;
    if (verifier.VerifySpendTx(bad_owner_ver))
    {
        printf("bad_owner_ver_unexpected_pass\n");
        return 3;
    }

    SpendTx too_big_sig = ok;
    too_big_sig.signatures[0].assign(100 * 1024, 0x42);
    if (verifier.VerifySpendTx(too_big_sig))
    {
        printf("too_big_sig_unexpected_pass\n");
        return 4;
    }

    printf("ok proof_policy_vectors\n");
    return 0;
}

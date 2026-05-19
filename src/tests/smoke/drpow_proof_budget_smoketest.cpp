#include <stdio.h>

#include <memory>
#include <vector>

#include "consensus_round.h"
#include "crypto_backend.h"
#include "drpow_params.h"
#include "proof_verifier.h"
#include "registry_state_store.h"
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

static bool BuildBatchHash(const RoundBatch& batch, Bytes32* out)
{
    if (!out)
        return false;
    std::vector<uint8_t> encoded;
    WriteU64LE(&encoded, batch.round);
    WriteBytes32(&encoded, batch.params_hash);
    WriteU64LE(&encoded, (uint64_t)batch.spends.size());
    for (size_t i = 0; i < batch.spends.size(); ++i)
        SerializeSpendTxCanonical(batch.spends[i], &encoded);
    WriteU64LE(&encoded, (uint64_t)batch.mints.size());
    for (size_t i = 0; i < batch.mints.size(); ++i)
        SerializeMintTxCanonical(batch.mints[i], &encoded);
    return Sha256(encoded, out);
}

static std::vector<uint8_t> BuildMintSig(const CryptoBackend& cb, const uint8_t privkey[32], const MintTx& tx)
{
    std::vector<uint8_t> m;
    WriteU64LE(&m, tx.output.value);
    WriteBytes32(&m, tx.output.commitment);
    WriteBytes32(&m, tx.output.owner_pubkey);
    WriteBytes64(&m, tx.output.range_proof);
    WriteU64LE(&m, tx.mint_nonce);
    WriteBytes32(&m, tx.target);
    WriteBytes32(&m, tx.miner_pubkey);
    std::vector<uint8_t> sig;
    cb.SignEd25519(privkey, m.empty() ? NULL : &m[0], m.size(), &sig);
    return sig;
}

int main()
{
    remove("/tmp/drpow_budget_registry.bin");
    remove("/tmp/drpow_budget_registry.bin.ledger");
    remove("/tmp/drpow_budget_commit.log");
    remove("/tmp/drpow_budget_evidence.log");

    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed\n");
        return 10;
    }

    ProofPolicy proof_policy = DefaultProofPolicy();
    BasicProofVerifier proof_verifier(crypto.get(), &proof_policy);
    BasicVoteVerifier vote_verifier(crypto.get());

    uint8_t signer_priv[32];
    for (int i = 0; i < 32; ++i)
        signer_priv[i] = (uint8_t)(210 + i);
    Bytes32 signer_id;
    crypto->PublicFromPrivateEd25519(signer_priv, signer_id.v);

    RegistryStateStore store("/tmp/drpow_budget_registry.bin",
                             "/tmp/drpow_budget_commit.log",
                             "/tmp/drpow_budget_evidence.log",
                             &proof_verifier,
                             crypto.get(),
                             signer_priv,
                             &signer_id);

    MintTx mint;
    mint.output.value = 1;
    Fill32(&mint.output.commitment, 1);
    Fill32(&mint.output.owner_pubkey, 2);
    Fill64(&mint.output.range_proof, 3);
    mint.mint_nonce = 42;
    for (int i = 0; i < 32; ++i)
        mint.target.v[i] = 0xff;
    mint.miner_pubkey = signer_id;
    mint.signature = BuildMintSig(*crypto, signer_priv, mint);

    RoundBatch batch;
    batch.round = 1;
    if (!ComputeDrpowParamsHash(&batch.params_hash))
    {
        printf("params_hash_failed\n");
        return 11;
    }
    batch.mints.push_back(mint);

    SpendTx heavy;
    heavy.timestamp = 1;
    heavy.fee = 1;
    heavy.sum_proof.assign(4096, 0x5a);
    heavy.sum_proof[0] = 1;
    SpendInput in;
    Fill32(&in.coin_id, 9);
    in.ownership_proof.push_back(1);
    in.ownership_proof.insert(in.ownership_proof.end(), signer_id.v, signer_id.v + 32);
    heavy.inputs.push_back(in);
    UtxoOutput out;
    out.value = 1;
    Fill32(&out.commitment, 4);
    out.owner_pubkey = signer_id;
    Fill64(&out.range_proof, 7);
    heavy.outputs.push_back(out);
    heavy.signatures.assign(1, std::vector<uint8_t>(1024, 0x42));
    batch.spends.push_back(heavy);

    BuildBatchHash(batch, &batch.batch_hash);

    EconomicsPolicy low_budget = DefaultEconomicsPolicy();
    low_budget.max_proof_cost_per_round = 1024;
    ConsensusRoundEngine low_engine(&store, &vote_verifier, &proof_verifier, &low_budget);
    if (low_engine.Propose(batch))
    {
        printf("budget_reject_missing\n");
        return 1;
    }
    if (low_engine.last_reject_code() != REJECT_PROOF_BUDGET_EXCEEDED)
    {
        printf("budget_reject_code_mismatch code=%d\n", (int)low_engine.last_reject_code());
        return 2;
    }

    EconomicsPolicy high_budget = DefaultEconomicsPolicy();
    high_budget.max_proof_cost_per_round = 64 * 1024;
    ConsensusRoundEngine high_engine(&store, &vote_verifier, &proof_verifier, &high_budget);
    if (!high_engine.Propose(batch))
    {
        printf("budget_accept_failed code=%d\n", (int)high_engine.last_reject_code());
        return 3;
    }

    printf("ok proof_budget_vectors\n");
    return 0;
}

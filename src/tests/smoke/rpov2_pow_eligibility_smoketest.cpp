#include <stdio.h>

#include <memory>
#include <vector>

#include "consensus_round.h"
#include "crypto_backend.h"
#include "proof_verifier.h"
#include "registry_state_store.h"
#include "static_validator_set.h"
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

static bool BuildBatchHash(const RoundBatch& batch, Bytes32* out)
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
    remove("/tmp/rpov2_elig_registry.bin");
    remove("/tmp/rpov2_elig_registry.bin.ledger");
    remove("/tmp/rpov2_elig_commit.log");
    remove("/tmp/rpov2_elig_evidence.log");

    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed\n");
        return 10;
    }

    ProofPolicy pp = DefaultProofPolicy();
    BasicProofVerifier proof_verifier(crypto.get(), &pp);
    BasicVoteVerifier vote_verifier(crypto.get());

    uint8_t signer_priv[32];
    for (int i = 0; i < 32; ++i)
        signer_priv[i] = (uint8_t)(170 + i);
    Bytes32 signer_id;
    crypto->PublicFromPrivateEd25519(signer_priv, signer_id.v);

    uint8_t other_priv[32];
    for (int i = 0; i < 32; ++i)
        other_priv[i] = (uint8_t)(90 + i);
    Bytes32 other_id;
    crypto->PublicFromPrivateEd25519(other_priv, other_id.v);

    std::vector<Validator> vals(1);
    vals[0].validator_id = signer_id;
    vals[0].voting_power = 1;
    StaticValidatorSet vset(1000, vals);

    RegistryStateStore store("/tmp/rpov2_elig_registry.bin",
                             "/tmp/rpov2_elig_commit.log",
                             "/tmp/rpov2_elig_evidence.log",
                             &proof_verifier,
                             crypto.get(),
                             signer_priv,
                             &signer_id);
    ConsensusRoundEngine engine(&store, &vset, &vote_verifier, &proof_verifier);

    MintTx mint;
    mint.output.value = 1;
    Fill32(&mint.output.commitment, 1);
    Fill32(&mint.output.owner_pubkey, 2);
    Fill64(&mint.output.range_proof, 3);
    mint.mint_nonce = 42;
    for (int i = 0; i < 32; ++i)
        mint.target.v[i] = 0xff;

    RoundBatch bad;
    bad.round = 1;
    mint.miner_pubkey = other_id;
    mint.signature = BuildMintSig(*crypto, other_priv, mint);
    bad.mints.push_back(mint);
    BuildBatchHash(bad, &bad.batch_hash);

    if (engine.Propose(bad))
    {
        printf("bad_eligibility_unexpected_pass\n");
        return 1;
    }
    if (engine.last_reject_code() != REJECT_POW_ELIGIBILITY_INVALID)
    {
        printf("bad_eligibility_wrong_code=%d\n", (int)engine.last_reject_code());
        return 2;
    }

    RoundBatch good;
    good.round = 1;
    mint.miner_pubkey = signer_id;
    mint.signature = BuildMintSig(*crypto, signer_priv, mint);
    good.mints.clear();
    good.mints.push_back(mint);
    BuildBatchHash(good, &good.batch_hash);

    if (!engine.Propose(good))
    {
        printf("good_eligibility_rejected code=%d\n", (int)engine.last_reject_code());
        return 3;
    }

    printf("ok pow_eligibility_vectors\n");
    return 0;
}

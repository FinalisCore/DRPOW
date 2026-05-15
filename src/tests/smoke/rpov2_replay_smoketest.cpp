#include <stdio.h>
#include <string.h>

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

static std::vector<uint8_t> BuildVoteSig(const CryptoBackend& cb, const uint8_t privkey[32], uint64_t round, const Bytes32& batch_hash, const Bytes32& validator_id)
{
    std::vector<uint8_t> m;
    WriteU64LE(&m, round);
    m.insert(m.end(), batch_hash.v, batch_hash.v + 32);
    m.insert(m.end(), validator_id.v, validator_id.v + 32);
    std::vector<uint8_t> sig;
    cb.SignEd25519(privkey, m.empty() ? NULL : &m[0], m.size(), &sig);
    return sig;
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
    const char* reg = "/tmp/rpov2_replay_registry.bin";
    const char* log = "/tmp/rpov2_replay_commit.log";
    const char* evd = "/tmp/rpov2_replay_evidence.log";
    remove(reg);
    remove("/tmp/rpov2_replay_registry.bin.ledger");
    remove(log);
    remove(evd);

    std::unique_ptr<CryptoBackend> crypto_backend = CreateCryptoBackendFromEnv();
    if (!crypto_backend.get())
    {
        printf("crypto_backend_select_failed\n");
        return 10;
    }
    BasicProofVerifier proof_verifier(crypto_backend.get());
    BasicVoteVerifier vote_verifier(crypto_backend.get());
    uint8_t commit_signer_priv[32];
    for (int i = 0; i < 32; ++i)
        commit_signer_priv[i] = (uint8_t)(230 + i);
    Bytes32 commit_signer_id;
    crypto_backend->PublicFromPrivateEd25519(commit_signer_priv, commit_signer_id.v);

    std::vector<Validator> vals(4);
    std::vector< std::vector<uint8_t> > validator_privs(vals.size(), std::vector<uint8_t>(32, 0));
    for (size_t i = 0; i < vals.size(); ++i)
    {
        for (int j = 0; j < 32; ++j)
            validator_privs[i][j] = (uint8_t)(70 + i + j);
        crypto_backend->PublicFromPrivateEd25519(&validator_privs[i][0], vals[i].validator_id.v);
        vals[i].voting_power = 1;
    }
    StaticValidatorSet vset(1000, vals);

    {
        RegistryStateStore store(reg, log, evd, &proof_verifier, crypto_backend.get(), commit_signer_priv, &commit_signer_id);
        ConsensusRoundEngine engine(&store, &vset, &vote_verifier, &proof_verifier);

        MintTx mint;
        mint.output.value = 50;
        Fill32(&mint.output.commitment, 11);
        Fill32(&mint.output.owner_pubkey, 12);
        Fill64(&mint.output.range_proof, 13);
        mint.mint_nonce = 999;
        for (int i = 0; i < 32; ++i)
            mint.target.v[i] = 0xff;
        mint.miner_pubkey = vals[0].validator_id;
        mint.signature = BuildMintSig(*crypto_backend, &validator_privs[0][0], mint);

        RoundBatch batch;
        batch.round = 1;
        batch.mints.push_back(mint);
        BuildBatchHash(batch, &batch.batch_hash);

        QuorumCertificate qc;
        qc.round = 1;
        qc.batch_hash = batch.batch_hash;
        for (size_t i = 0; i < vals.size(); ++i)
        {
            Vote v;
            v.round = 1;
            v.batch_hash = batch.batch_hash;
            v.validator_id = vals[i].validator_id;
            v.signature = BuildVoteSig(*crypto_backend, &validator_privs[i][0], v.round, v.batch_hash, v.validator_id);
            qc.votes.push_back(v);
        }

        if (!engine.Commit(batch, qc))
        {
            printf("replay_commit_failed code=%d msg=%s\n", (int)engine.last_reject_code(), engine.last_reject_message().c_str());
            return 1;
        }

        Bytes32 root1;
        if (!store.ReadStateRoot(&root1))
        {
            printf("replay_read_root1_failed\n");
            return 2;
        }

        RegistryStateStore store2(reg, log, evd, &proof_verifier, crypto_backend.get(), commit_signer_priv, &commit_signer_id);
        Bytes32 root2;
        if (!store2.ReadStateRoot(&root2))
        {
            printf("replay_read_root2_failed\n");
            return 3;
        }

        if (memcmp(root1.v, root2.v, 32) != 0)
        {
            printf("replay_root_mismatch\n");
            return 4;
        }

        printf("ok replay_root=%02x%02x%02x%02x\n", root2.v[0], root2.v[1], root2.v[2], root2.v[3]);
    }

    return 0;
}

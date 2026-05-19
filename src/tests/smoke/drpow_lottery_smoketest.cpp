#include <stdio.h>

#include <vector>

#include "consensus_round.h"
#include "crypto_backend.h"
#include "drpow_params.h"
#include "pow_lottery_validator_set.h"
#include "proof_verifier.h"
#include "registry_state_store.h"
#include "drpow/tx_codec.h"
#include "validator_lottery.h"

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

static std::vector<uint8_t> BuildLotterySig(const LotteryShare& s)
{
    Bytes32 d;
    ComputeLotteryDigest(s, &d);
    std::vector<uint8_t> m;
    m.insert(m.end(), d.v, d.v + 32);
    m.insert(m.end(), s.pubkey.v, s.pubkey.v + 32);
    Bytes32 h;
    Sha256(m, &h);
    return std::vector<uint8_t>(h.v, h.v + 32);
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

static std::vector<uint8_t> BuildVoteSig(const CryptoBackend& cb, const uint8_t privkey[32], uint64_t round, const Bytes32& batch_hash, const Bytes32& validator_id, uint8_t eligibility_type)
{
    std::vector<uint8_t> m;
    WriteU64LE(&m, round);
    m.insert(m.end(), batch_hash.v, batch_hash.v + 32);
    m.insert(m.end(), validator_id.v, validator_id.v + 32);
    m.push_back(eligibility_type);
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
    remove("/tmp/drpow_lottery_registry.bin");
    remove("/tmp/drpow_lottery_registry.bin.ledger");
    remove("/tmp/drpow_lottery_commit.log");
    remove("/tmp/drpow_lottery_evidence.log");

    Bytes32 state_hash;
    Fill32(&state_hash, 9);

    std::vector<LotteryShare> shares;
    for (int i = 0; i < 8; ++i)
    {
        LotteryShare s;
        s.state_hash = state_hash;
        s.nonce = (uint64_t)(100 + i);
        Fill32(&s.pubkey, (uint8_t)(30 + i));
        s.signature = BuildLotterySig(s);
        shares.push_back(s);
    }

    std::vector<Validator> epoch_validators = SelectTopValidators(shares, 4, 1);
    if (epoch_validators.size() != 4)
    {
        printf("lottery_select_failed\n");
        return 1;
    }

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
        commit_signer_priv[i] = (uint8_t)(220 + i);
    Bytes32 commit_signer_id;
    crypto_backend->PublicFromPrivateEd25519(commit_signer_priv, commit_signer_id.v);
    RegistryStateStore store("/tmp/drpow_lottery_registry.bin",
                             "/tmp/drpow_lottery_commit.log",
                             "/tmp/drpow_lottery_evidence.log",
                             &proof_verifier,
                             crypto_backend.get(),
                             commit_signer_priv,
                             &commit_signer_id);

    MintTx mint;
    mint.output.value = 50;
    Fill32(&mint.output.commitment, 1);
    Fill32(&mint.output.owner_pubkey, 2);
    Fill64(&mint.output.range_proof, 3);
    mint.mint_nonce = 77;
    for (int i = 0; i < 32; ++i)
        mint.target.v[i] = 0xff;
    RoundBatch batch;
    batch.round = 1;
    if (!ComputeDrpowParamsHash(&batch.params_hash))
    {
        printf("params_hash_failed\n");
        return 11;
    }

    std::vector< std::vector<uint8_t> > validator_privs(epoch_validators.size(), std::vector<uint8_t>(32, 0));
    for (size_t i = 0; i < epoch_validators.size(); ++i)
    {
        for (int j = 0; j < 32; ++j)
            validator_privs[i][j] = (uint8_t)(150 + i + j);
        crypto_backend->PublicFromPrivateEd25519(&validator_privs[i][0], epoch_validators[i].validator_id.v);
    }
    mint.miner_pubkey = epoch_validators[0].validator_id;
    mint.signature = BuildMintSig(*crypto_backend, &validator_privs[0][0], mint);
    batch.mints.push_back(mint);
    BuildBatchHash(batch, &batch.batch_hash);

    PowLotteryValidatorSet vset(1000);
    if (!vset.InstallEpoch(0, epoch_validators))
    {
        printf("epoch_install_failed\n");
        return 2;
    }
    ConsensusRoundEngine engine(&store, &vset, &vote_verifier, &proof_verifier);

    QuorumCertificate qc;
    qc.round = 1;
    qc.batch_hash = batch.batch_hash;
    for (size_t i = 0; i < epoch_validators.size(); ++i)
    {
        Vote v;
        v.round = 1;
        v.batch_hash = batch.batch_hash;
        v.validator_id = epoch_validators[i].validator_id;
        v.eligibility_type = VOTE_ELIGIBILITY_VALIDATOR_SET;
        v.signature = BuildVoteSig(*crypto_backend, &validator_privs[i][0], v.round, v.batch_hash, v.validator_id, v.eligibility_type);
        qc.votes.push_back(v);
    }

    if (!engine.Commit(batch, qc))
    {
        printf("lottery_commit_failed\n");
        return 3;
    }

    Bytes32 root;
    if (!store.ReadStateRoot(&root))
    {
        printf("lottery_root_failed\n");
        return 4;
    }

    printf("ok lottery_root=%02x%02x%02x%02x\n", root.v[0], root.v[1], root.v[2], root.v[3]);
    return 0;
}

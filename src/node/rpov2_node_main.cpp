#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <set>
#include <string>
#include <vector>
#include <functional>
#include <fstream>
#include <algorithm>
#include <sstream>

#include "consensus_round.h"
#include "crypto_backend.h"
#include "rpov2/node_config.h"
#include "p2p_wire.h"
#include "p2p_reactor.h"
#include "proof_verifier.h"
#include "pow_lottery_validator_set.h"
#include "registry_state_store.h"
#include "rpov2/tx_codec.h"

using namespace rpov2;

static bool HexTo32(const std::string& s, uint8_t out[32])
{
    if (s.size() != 64)
        return false;
    for (int i = 0; i < 32; ++i)
    {
        char a = s[i * 2];
        char b = s[i * 2 + 1];
        int hi = (a >= '0' && a <= '9') ? (a - '0') : (a >= 'a' && a <= 'f') ? (10 + a - 'a') : (a >= 'A' && a <= 'F') ? (10 + a - 'A') : -1;
        int lo = (b >= '0' && b <= '9') ? (b - '0') : (b >= 'a' && b <= 'f') ? (10 + b - 'a') : (b >= 'A' && b <= 'F') ? (10 + b - 'A') : -1;
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool EnsureDir(const std::string& d)
{
    if (mkdir(d.c_str(), 0755) == 0)
        return true;
    return errno == EEXIST;
}

static bool EnsureOwnerOnlyFile(const std::string& path)
{
    return chmod(path.c_str(), S_IRUSR | S_IWUSR) == 0;
}

static std::string Bytes32Key(const Bytes32& b)
{
    return std::string((const char*)b.v, 32);
}

static std::string Hex32(const Bytes32& b)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(64);
    for (int i = 0; i < 32; ++i)
    {
        out[i * 2] = kHex[(b.v[i] >> 4) & 0x0f];
        out[i * 2 + 1] = kHex[b.v[i] & 0x0f];
    }
    return out;
}

static std::string HexBytes(const uint8_t* p, size_t n)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        out[i * 2] = kHex[(p[i] >> 4) & 0x0f];
        out[i * 2 + 1] = kHex[p[i] & 0x0f];
    }
    return out;
}

static bool FillRandom(uint8_t* out, size_t n)
{
    if (!out || n == 0)
        return false;
    std::ifstream in("/dev/urandom", std::ios::binary);
    if (!in.good())
        return false;
    in.read((char*)out, (std::streamsize)n);
    return in.good();
}

static bool LoadPeerFile(const std::string& path, std::vector<std::string>* out)
{
    if (!out)
        return false;
    out->clear();
    std::ifstream in(path.c_str());
    if (!in.good())
        return true;
    std::string line;
    while (std::getline(in, line))
    {
        if (!line.empty())
            out->push_back(line);
    }
    return true;
}

static bool SavePeerFile(const std::string& path, const std::vector<std::string>& peers)
{
    std::ofstream out(path.c_str(), std::ios::trunc);
    if (!out.good())
        return false;
    for (size_t i = 0; i < peers.size(); ++i)
        out << peers[i] << "\n";
    return out.good();
}

static bool IsValidEndpoint(const std::string& ep)
{
    size_t c = ep.rfind(':');
    if (c == std::string::npos || c == 0 || c + 1 >= ep.size())
        return false;
    int port = atoi(ep.substr(c + 1).c_str());
    return port > 0 && port <= 65535;
}

static void CanonicalizePeerList(std::vector<std::string>* peers)
{
    if (!peers)
        return;
    std::sort(peers->begin(), peers->end());
    peers->erase(std::unique(peers->begin(), peers->end()), peers->end());
}

static bool BuildPeerListSignBytes(uint64_t advertised_round,
                                   const Bytes32& advertiser_id,
                                   const std::vector<std::string>& peers,
                                   std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    const char* tag = "RPOV2:peer_list:v1";
    while (*tag)
        out->push_back((uint8_t)*tag++);
    WriteU64LE(out, advertised_round);
    WriteBytes32(out, advertiser_id);
    WriteU64LE(out, (uint64_t)peers.size());
    for (size_t i = 0; i < peers.size(); ++i)
    {
        WriteU64LE(out, (uint64_t)peers[i].size());
        out->insert(out->end(), peers[i].begin(), peers[i].end());
    }
    return true;
}

static bool ComputeExpectedTargetForRoundNode(const RegistryStateStore& store,
                                              uint64_t round,
                                              const EconomicsPolicy& policy,
                                              Bytes32* out_target)
{
    if (!out_target || round == 0)
        return false;
    Bytes32 prev_target = policy.max_target;
    uint64_t observed_mints = 0;
    if (round > 1)
    {
        const uint64_t window = policy.target_window_rounds == 0 ? 1 : policy.target_window_rounds;
        const uint64_t from_round = (round > window) ? (round - window) : 1;
        std::vector<RoundCommitRecord> recs;
        if (!store.ExportVerifiedCommitRecordsFromRound(from_round, (size_t)window, &recs))
            return false;
        for (size_t i = 0; i < recs.size(); ++i)
        {
            MintTx mint;
            size_t off = 0;
            if (!ParseMintTxCanonical(recs[i].consensus_proof.empty() ? NULL : &recs[i].consensus_proof[0],
                                      recs[i].consensus_proof.size(),
                                      &off,
                                      &mint) ||
                off != recs[i].consensus_proof.size())
            {
                return false;
            }
            prev_target = mint.target;
            observed_mints += 1;
        }
    }
    const uint64_t expected_mints = policy.target_mints_per_window == 0 ? 1 : policy.target_mints_per_window;
    return NextPowTargetDeterministic(prev_target,
                                      observed_mints,
                                      expected_mints,
                                      policy.target_adjust_up_ppm_limit,
                                      policy.target_adjust_down_ppm_limit,
                                      policy.min_target,
                                      policy.max_target,
                                      out_target);
}

static std::vector<Validator> DeriveEpochValidatorsDeterministic(const std::vector<Validator>& base, const Bytes32& seed, uint64_t epoch)
{
    std::vector<Validator> out = base;
    if (out.empty())
        return out;
    std::vector<uint8_t> d;
    d.insert(d.end(), seed.v, seed.v + 32);
    WriteU64LE(&d, epoch);
    Bytes32 h;
    if (!Sha256(d, &h))
        return out;
    const size_t n = out.size();
    const size_t rot = (size_t)(h.v[0] % (uint8_t)n);
    std::rotate(out.begin(), out.begin() + rot, out.end());
    return out;
}

struct MinerCountEntry {
    Bytes32 miner;
    uint64_t count;
};

static bool MinerCountEntryLess(const MinerCountEntry& a, const MinerCountEntry& b)
{
    if (a.count != b.count)
        return a.count > b.count;
    return memcmp(a.miner.v, b.miner.v, 32) < 0;
}

static std::vector<Validator> DeriveEpochValidatorsFromPowHistory(const RegistryStateStore& store,
                                                                  const ValidatorEpoch* prev_epoch,
                                                                  uint64_t epoch,
                                                                  uint64_t epoch_length,
                                                                  size_t max_validators)
{
    std::vector<Validator> out;
    if (epoch == 0 || epoch_length == 0 || max_validators == 0)
        return out;

    const uint64_t prev_start = (epoch - 1) * epoch_length + 1;
    std::vector<RoundCommitRecord> recs;
    if (!store.ExportVerifiedCommitRecordsFromRound(prev_start, (size_t)epoch_length, &recs))
    {
        if (prev_epoch)
            return prev_epoch->validators;
        return out;
    }

    std::map<std::string, uint64_t> counts;
    for (size_t i = 0; i < recs.size(); ++i)
    {
        MintTx mint;
        size_t off = 0;
        if (!ParseMintTxCanonical(recs[i].consensus_proof.empty() ? NULL : &recs[i].consensus_proof[0],
                                  recs[i].consensus_proof.size(),
                                  &off,
                                  &mint) ||
            off != recs[i].consensus_proof.size())
        {
            continue;
        }
        std::string k((const char*)mint.miner_pubkey.v, 32);
        counts[k] += 1;
    }

    std::vector<MinerCountEntry> ranked;
    ranked.reserve(counts.size());
    for (std::map<std::string, uint64_t>::const_iterator it = counts.begin(); it != counts.end(); ++it)
    {
        MinerCountEntry e;
        memset(e.miner.v, 0, 32);
        memcpy(e.miner.v, it->first.data(), 32);
        e.count = it->second;
        ranked.push_back(e);
    }
    std::sort(ranked.begin(), ranked.end(), MinerCountEntryLess);

    for (size_t i = 0; i < ranked.size() && out.size() < max_validators; ++i)
    {
        Validator v;
        v.validator_id = ranked[i].miner;
        v.voting_power = 1;
        out.push_back(v);
    }

    if (out.empty() && prev_epoch && !prev_epoch->validators.empty())
        return prev_epoch->validators;
    return out;
}

static bool ComputeRecordHashV1Local(const RoundCommitRecord& record, Bytes32* out)
{
    if (!out)
        return false;
    std::vector<uint8_t> m;
    const char* tag = "RPOV2:commit_record:v1";
    while (*tag)
        m.push_back((uint8_t)*tag++);
    m.push_back((uint8_t)(record.record_version & 0xff));
    m.push_back((uint8_t)((record.record_version >> 8) & 0xff));
    m.push_back((uint8_t)(record.hash_alg_id & 0xff));
    m.push_back((uint8_t)((record.hash_alg_id >> 8) & 0xff));
    m.push_back((uint8_t)(record.sig_alg_id & 0xff));
    m.push_back((uint8_t)((record.sig_alg_id >> 8) & 0xff));
    WriteU64LE(&m, record.round);
    WriteBytes32(&m, record.batch_hash);
    WriteBytes32(&m, record.state_root);
    WriteU64LE(&m, (uint64_t)record.consensus_proof.size());
    m.insert(m.end(), record.consensus_proof.begin(), record.consensus_proof.end());
    return Sha256(m, out);
}

static bool BuildBatchHashLocal(const RoundBatch& batch, Bytes32* out)
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

static std::vector<uint8_t> BuildMintSigLocal(const CryptoBackend& cb, const uint8_t privkey[32], const MintTx& tx)
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

static bool LoadSyncedTipFile(const std::string& tip_file, uint64_t* out_round, Bytes32* out_root)
{
    if (!out_round || !out_root)
        return false;
    std::ifstream in(tip_file.c_str(), std::ios::binary);
    if (!in.good())
        return false;
    in.read((char*)out_round, sizeof(*out_round));
    in.read((char*)out_root->v, 32);
    return in.good();
}

static bool SaveSyncedTipFile(const std::string& tip_file, uint64_t round, const Bytes32& root)
{
    std::ofstream out(tip_file.c_str(), std::ios::binary | std::ios::trunc);
    if (!out.good())
        return false;
    out.write((const char*)&round, sizeof(round));
    out.write((const char*)root.v, 32);
    return out.good();
}

static bool LoadAndVerifySyncedCommitLog(const std::string& sync_log_file,
                                         const CryptoBackend* crypto,
                                         uint64_t* out_last_round,
                                         Bytes32* out_last_root)
{
    if (!crypto || !out_last_round || !out_last_root)
        return false;
    *out_last_round = 0;
    memset(out_last_root->v, 0, 32);

    std::ifstream in(sync_log_file.c_str(), std::ios::binary);
    if (!in.good())
        return true;

    uint64_t last_round = 0;
    Bytes32 last_root;
    memset(last_root.v, 0, 32);
    while (true)
    {
        RoundCommitRecord rec;
        uint64_t proof_size = 0;
        uint64_t sig_size = 0;
        in.read((char*)&rec.record_version, sizeof(rec.record_version));
        if (in.eof())
            break;
        if (!in.good())
            return false;
        in.read((char*)&rec.hash_alg_id, sizeof(rec.hash_alg_id));
        in.read((char*)&rec.sig_alg_id, sizeof(rec.sig_alg_id));
        in.read((char*)&rec.round, sizeof(rec.round));
        in.read((char*)rec.batch_hash.v, 32);
        in.read((char*)rec.state_root.v, 32);
        in.read((char*)&proof_size, sizeof(proof_size));
        if (!in.good() || proof_size > (16 * 1024 * 1024))
            return false;
        rec.consensus_proof.assign((size_t)proof_size, 0);
        if (proof_size > 0)
            in.read((char*)&rec.consensus_proof[0], (std::streamsize)proof_size);
        in.read((char*)rec.record_hash.v, 32);
        in.read((char*)rec.record_signer_id.v, 32);
        in.read((char*)&sig_size, sizeof(sig_size));
        if (!in.good() || sig_size > (16 * 1024 * 1024))
            return false;
        rec.record_signature.assign((size_t)sig_size, 0);
        if (sig_size > 0)
            in.read((char*)&rec.record_signature[0], (std::streamsize)sig_size);
        if (!in.good())
            return false;

        if (rec.round == 0 || rec.round <= last_round)
            return false;
        Bytes32 h;
        if (!ComputeRecordHashV1Local(rec, &h) || memcmp(h.v, rec.record_hash.v, 32) != 0)
            return false;
        if (!crypto->VerifyEd25519(rec.record_signer_id.v,
                                   rec.record_hash.v,
                                   32,
                                   rec.record_signature.empty() ? NULL : &rec.record_signature[0],
                                   rec.record_signature.size()))
            return false;
        last_round = rec.round;
        last_root = rec.state_root;
    }

    *out_last_round = last_round;
    *out_last_root = last_root;
    return true;
}

static bool AppendCommitPayloadCache(const std::string& cache_file, const std::vector<uint8_t>& payload)
{
    std::ofstream out(cache_file.c_str(), std::ios::binary | std::ios::app);
    if (!out.good())
        return false;
    uint32_t n = (uint32_t)payload.size();
    out.write((const char*)&n, sizeof(n));
    if (n > 0)
        out.write((const char*)&payload[0], (std::streamsize)n);
    return out.good();
}

static bool LoadCommitPayloadCache(const std::string& cache_file, std::vector< std::vector<uint8_t> >* out_payloads);

static bool PayloadContainsRoundHash(const std::vector<uint8_t>& payload, uint64_t* out_round, Bytes32* out_batch_hash)
{
    if (!out_round || !out_batch_hash)
        return false;
    RoundBatch b;
    QuorumCertificate q;
    if (!ParseCommitPayload(payload, &b, &q))
        return false;
    *out_round = b.round;
    *out_batch_hash = b.batch_hash;
    return true;
}

static bool AppendCommitPayloadCacheDedup(const std::string& cache_file, const std::vector<uint8_t>& payload)
{
    uint64_t new_round = 0;
    Bytes32 new_hash;
    if (!PayloadContainsRoundHash(payload, &new_round, &new_hash))
        return false;

    std::vector< std::vector<uint8_t> > existing;
    if (!LoadCommitPayloadCache(cache_file, &existing))
        return false;
    for (size_t i = 0; i < existing.size(); ++i)
    {
        uint64_t r = 0;
        Bytes32 h;
        if (!PayloadContainsRoundHash(existing[i], &r, &h))
            continue;
        if (r == new_round && memcmp(h.v, new_hash.v, 32) == 0)
            return true;
    }
    return AppendCommitPayloadCache(cache_file, payload);
}

static bool LoadCommitPayloadCache(const std::string& cache_file, std::vector< std::vector<uint8_t> >* out_payloads)
{
    if (!out_payloads)
        return false;
    out_payloads->clear();
    std::ifstream in(cache_file.c_str(), std::ios::binary);
    if (!in.good())
        return true;
    while (true)
    {
        uint32_t n = 0;
        in.read((char*)&n, sizeof(n));
        if (in.eof())
            return true;
        if (!in.good())
            return false;
        if (n > (16 * 1024 * 1024))
            return false;
        std::vector<uint8_t> p(n);
        if (n > 0)
            in.read((char*)&p[0], (std::streamsize)n);
        if (!in.good())
            return false;
        out_payloads->push_back(p);
    }
}

static size_t CountCommitPayloadCacheEntries(const std::string& cache_file)
{
    std::vector< std::vector<uint8_t> > payloads;
    if (!LoadCommitPayloadCache(cache_file, &payloads))
        return 0;
    return payloads.size();
}

static bool RewriteCommitPayloadCache(const std::string& cache_file, const std::vector< std::vector<uint8_t> >& payloads)
{
    std::ofstream out(cache_file.c_str(), std::ios::binary | std::ios::trunc);
    if (!out.good())
        return false;
    for (size_t i = 0; i < payloads.size(); ++i)
    {
        uint32_t n = (uint32_t)payloads[i].size();
        out.write((const char*)&n, sizeof(n));
        if (n > 0)
            out.write((const char*)&payloads[i][0], (std::streamsize)n);
    }
    return out.good();
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("usage: %s <node.conf>\n", argv[0]);
        return 1;
    }

    NodeConfig cfg;
    std::string err;
    if (!LoadNodeConfig(argv[1], &cfg, &err))
    {
        printf("config_error: %s\n", err.c_str());
        return 2;
    }
    if (!WireSetMagic(cfg.network_magic))
    {
        printf("config_error: invalid network_magic\n");
        return 2;
    }

    if (!EnsureDir(cfg.data_dir))
    {
        printf("data_dir_error\n");
        return 3;
    }

    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed\n");
        return 4;
    }

    const std::string signer_key_file = cfg.data_dir + "/signer_privkey.hex";
    uint8_t signer_priv[32];
    bool have_signer = false;
    if (!cfg.signer_privkey_hex.empty())
        have_signer = HexTo32(cfg.signer_privkey_hex, signer_priv);
    if (!have_signer)
    {
        std::ifstream kin(signer_key_file.c_str());
        std::string line;
        if (kin.good() && std::getline(kin, line))
        {
            have_signer = HexTo32(line, signer_priv);
            (void)EnsureOwnerOnlyFile(signer_key_file);
        }
    }
    if (!have_signer)
    {
        if (!FillRandom(signer_priv, sizeof(signer_priv)))
        {
            printf("signer_key_generate_failed\n");
            return 5;
        }
        std::ofstream kout(signer_key_file.c_str(), std::ios::trunc);
        if (!kout.good())
        {
            printf("signer_key_persist_failed\n");
            return 5;
        }
        kout << HexBytes(signer_priv, sizeof(signer_priv)) << "\n";
        if (!kout.good())
        {
            printf("signer_key_persist_failed\n");
            return 5;
        }
        if (!EnsureOwnerOnlyFile(signer_key_file))
        {
            printf("signer_key_permission_failed\n");
            return 5;
        }
        printf("signer_key_generated file=%s\n", signer_key_file.c_str());
    }
    Bytes32 signer_id;
    if (!crypto->PublicFromPrivateEd25519(signer_priv, signer_id.v))
    {
        printf("signer_pubkey_derive_failed\n");
        return 6;
    }
    printf("signer_id=%s\n", Hex32(signer_id).c_str());

    ProofPolicy proof_policy = DefaultProofPolicy();
    BasicProofVerifier proof_verifier(crypto.get(), &proof_policy);
    BasicVoteVerifier vote_verifier(crypto.get());

    const std::string validators_file = cfg.data_dir + "/validator_pubkeys.hex";
    std::vector<std::string> validator_hex = cfg.validator_pubkeys_hex;
    if (validator_hex.empty())
    {
        std::ifstream vin(validators_file.c_str());
        std::string line;
        if (vin.good() && std::getline(vin, line))
        {
            std::stringstream ss(line);
            std::string p;
            while (std::getline(ss, p, ','))
                if (!p.empty())
                    validator_hex.push_back(p);
        }
    }

    std::vector<Validator> vals;
    if (!validator_hex.empty())
    {
        vals.resize(validator_hex.size());
        for (size_t i = 0; i < validator_hex.size(); ++i)
        {
            if (!HexTo32(validator_hex[i], vals[i].validator_id.v))
            {
                printf("invalid validator_pubkeys_hex at index=%zu\n", i);
                return 6;
            }
            vals[i].voting_power = 1;
        }
    }
    else
    {
        vals.resize(1);
        vals[0].validator_id = signer_id;
        vals[0].voting_power = 1;
        std::ofstream vout(validators_file.c_str(), std::ios::trunc);
        if (vout.good())
        {
            vout << Hex32(signer_id) << "\n";
            printf("validator_pubkeys_generated file=%s\n", validators_file.c_str());
        }
    }
    EconomicsPolicy economics_policy = DefaultEconomicsPolicy();
    const uint64_t kRuntimeEpochLength = 10;
    const size_t kEpochValidatorCap = 64;
    PowLotteryValidatorSet vset(kRuntimeEpochLength);
    if (!vset.InstallEpoch(0, vals))
    {
        printf("epoch_install_error epoch=0\n");
        return 6;
    }

    std::string registry = cfg.data_dir + "/registry.bin";
    std::string commitlog = cfg.data_dir + "/commit.log";
    std::string evidlog = cfg.data_dir + "/evidence.log";

    RegistryStateStore store(registry, commitlog, evidlog, &proof_verifier, crypto.get(), signer_priv, &signer_id);
    ConsensusRoundEngine engine(&store, &vset, &vote_verifier, &proof_verifier, &economics_policy);
    std::map<std::string, RoundBatch> known_batches;
    std::map<std::string, std::vector<Vote> > known_votes;
    std::map<std::string, std::set<std::string> > known_vote_ids;
    uint64_t last_committed_round = store.LastVerifiedCommitRound();
    std::map<int, uint64_t> peer_last_round;
    const std::string sync_cache = cfg.data_dir + "/sync_commit.log";
    const std::string sync_tip_file = cfg.data_dir + "/sync_tip.dat";
    const std::string commit_payload_cache = cfg.data_dir + "/commit_payload_cache.bin";
    uint64_t synced_last_round = 0;
    Bytes32 synced_state_root;
    memset(synced_state_root.v, 0, 32);

    uint64_t cached_tip_round = 0;
    Bytes32 cached_tip_root;
    memset(cached_tip_root.v, 0, 32);
    if (LoadSyncedTipFile(sync_tip_file, &cached_tip_round, &cached_tip_root))
    {
        synced_last_round = cached_tip_round;
        synced_state_root = cached_tip_root;
    }
    uint64_t log_tip_round = 0;
    Bytes32 log_tip_root;
    memset(log_tip_root.v, 0, 32);
    if (LoadAndVerifySyncedCommitLog(sync_cache, crypto.get(), &log_tip_round, &log_tip_root))
    {
        if (log_tip_round > synced_last_round)
        {
            synced_last_round = log_tip_round;
            synced_state_root = log_tip_root;
            (void)SaveSyncedTipFile(sync_tip_file, synced_last_round, synced_state_root);
        }
    }

    std::function<void()> CompactCommitPayloadCache = [&]() {
        const size_t before_count = CountCommitPayloadCacheEntries(commit_payload_cache);
        std::vector< std::vector<uint8_t> > payloads;
        if (!LoadCommitPayloadCache(commit_payload_cache, &payloads))
            return;
        struct Entry {
            uint64_t round;
            Bytes32 hash;
            std::vector<uint8_t> payload;
        };
        std::vector<Entry> entries;
        entries.reserve(payloads.size());
        for (size_t i = 0; i < payloads.size(); ++i)
        {
            uint64_t r = 0;
            Bytes32 h;
            if (!PayloadContainsRoundHash(payloads[i], &r, &h))
                continue;
            Entry e;
            e.round = r;
            e.hash = h;
            e.payload = payloads[i];
            entries.push_back(e);
        }
        std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
            if (a.round != b.round)
                return a.round < b.round;
            return memcmp(a.hash.v, b.hash.v, 32) < 0;
        });

        std::set<std::string> seen;
        std::vector< std::vector<uint8_t> > compacted;
        const uint64_t low = last_committed_round + 1;
        uint64_t high = synced_last_round;
        const uint64_t kWindow = 4096;
        if (high > low + kWindow)
            high = low + kWindow;

        for (size_t i = 0; i < entries.size(); ++i)
        {
            if (entries[i].round < low || entries[i].round > high)
                continue;
            std::string k((const char*)&entries[i].round, sizeof(entries[i].round));
            k.append((const char*)entries[i].hash.v, 32);
            if (seen.count(k))
                continue;
            seen.insert(k);
            compacted.push_back(entries[i].payload);
        }
        (void)RewriteCommitPayloadCache(commit_payload_cache, compacted);
        const size_t after_count = compacted.size();
        printf("sync_cache_compact before=%zu after=%zu low=%llu high=%llu\n",
               before_count,
               after_count,
               (unsigned long long)low,
               (unsigned long long)high);
    };
    CompactCommitPayloadCache();

    std::function<void(uint64_t)> EnsureEpochTransitionForRound = [&](uint64_t round) {
        if (round == 0)
            return;
        ValidatorEpoch existing;
        if (vset.GetEpochForRound(round, &existing))
            return;
        const uint64_t epoch = (round - 1) / kRuntimeEpochLength;
        ValidatorEpoch prev_epoch;
        bool have_prev_epoch = (epoch > 0) && vset.GetEpochForRound((epoch - 1) * kRuntimeEpochLength + 1, &prev_epoch);
        std::vector<Validator> next_vals;
        if (epoch == 0)
        {
            next_vals = vals;
        }
        else
        {
            next_vals = DeriveEpochValidatorsFromPowHistory(store,
                                                            have_prev_epoch ? &prev_epoch : NULL,
                                                            epoch,
                                                            kRuntimeEpochLength,
                                                            kEpochValidatorCap);
        }
        if (next_vals.empty())
            return;
        if (!vset.InstallEpoch(epoch, next_vals))
            return;
        Bytes32 next_target;
        if (!ComputeExpectedTargetForRoundNode(store, round, economics_policy, &next_target))
            memset(next_target.v, 0, 32);
        Bytes32 seed_root;
        if (!store.ReadStateRoot(&seed_root))
            memset(seed_root.v, 0, 32);
        printf("epoch_transition epoch=%llu round_start=%llu validators=%zu target=%s seed_root=%s\n",
               (unsigned long long)epoch,
               (unsigned long long)(epoch * kRuntimeEpochLength + 1),
               next_vals.size(),
               Hex32(next_target).c_str(),
               Hex32(seed_root).c_str());
    };

    std::function<void()> TryCatchUpFromCache = [&]() {
        if (last_committed_round >= synced_last_round)
            return;
        const uint64_t lag_before = synced_last_round - last_committed_round;
        std::vector< std::vector<uint8_t> > payloads;
        if (!LoadCommitPayloadCache(commit_payload_cache, &payloads))
            return;
        struct Item {
            RoundBatch batch;
            QuorumCertificate qc;
        };
        std::vector<Item> items;
        for (size_t i = 0; i < payloads.size(); ++i)
        {
            RoundBatch b;
            QuorumCertificate q;
            if (!ParseCommitPayload(payloads[i], &b, &q))
                continue;
            Item it;
            it.batch = b;
            it.qc = q;
            items.push_back(it);
        }
        std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) { return a.batch.round < b.batch.round; });
        size_t applied = 0;
        for (size_t i = 0; i < items.size(); ++i)
        {
            const RoundBatch& batch = items[i].batch;
            const QuorumCertificate& qc = items[i].qc;
            if (batch.round <= last_committed_round)
                continue;
            if (batch.round > synced_last_round)
                continue;
            if (batch.round != last_committed_round + 1)
            {
                printf("catchup_break_noncontiguous expected=%llu got=%llu\n",
                       (unsigned long long)(last_committed_round + 1),
                       (unsigned long long)batch.round);
                break;
            }
            if (qc.round != batch.round || memcmp(qc.batch_hash.v, batch.batch_hash.v, 32) != 0)
            {
                printf("catchup_break_qc_batch_mismatch round=%llu qc_round=%llu\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)qc.round);
                break;
            }
            EnsureEpochTransitionForRound(batch.round);
            if (batch.round > economics_policy.genesis_bootstrap_rounds)
            {
                ValidatorEpoch epoch;
                if (!vset.GetEpochForRound(batch.round, &epoch))
                {
                    printf("catchup_break_epoch_missing round=%llu\n", (unsigned long long)batch.round);
                    break;
                }
                if (!VerifyQuorumCertificate(epoch, qc, batch.round, batch.batch_hash, vote_verifier))
                {
                    printf("catchup_break_qc_invalid round=%llu votes=%zu\n",
                           (unsigned long long)batch.round,
                           qc.votes.size());
                    break;
                }
            }
            if (!engine.Commit(batch, qc))
            {
                printf("catchup_break_commit_reject round=%llu code=%d\n",
                       (unsigned long long)batch.round,
                       (int)engine.last_reject_code());
                break;
            }
            last_committed_round = batch.round;
            applied++;
            printf("catchup commit ok round=%llu\n", (unsigned long long)batch.round);
        }
        const uint64_t lag_after = (synced_last_round > last_committed_round) ? (synced_last_round - last_committed_round) : 0;
        printf("sync_catchup applied=%zu lag_before=%llu lag_after=%llu cache_entries=%zu\n",
               applied,
               (unsigned long long)lag_before,
               (unsigned long long)lag_after,
               CountCommitPayloadCacheEntries(commit_payload_cache));
        CompactCommitPayloadCache();
    };
    TryCatchUpFromCache();

    std::function<bool(uint64_t)> HasPendingRound = [&](uint64_t round) {
        for (std::map<std::string, RoundBatch>::const_iterator it = known_batches.begin(); it != known_batches.end(); ++it)
            if (it->second.round == round)
                return true;
        return false;
    };
    std::function<bool(uint64_t, RoundBatch*)> GetPendingRound = [&](uint64_t round, RoundBatch* out) {
        if (!out)
            return false;
        for (std::map<std::string, RoundBatch>::const_iterator it = known_batches.begin(); it != known_batches.end(); ++it)
        {
            if (it->second.round == round)
            {
                *out = it->second;
                return true;
            }
        }
        return false;
    };

    const std::string discovered_peers_file = cfg.data_dir + "/discovered_peers.txt";
    std::vector<std::string> persisted_peers;
    (void)LoadPeerFile(discovered_peers_file, &persisted_peers);
    std::set<std::string> bootstrap_peers(cfg.peers.begin(), cfg.peers.end());
    for (size_t i = 0; i < persisted_peers.size(); ++i)
        if (IsValidEndpoint(persisted_peers[i]))
            bootstrap_peers.insert(persisted_peers[i]);
    std::vector<std::string> all_bootstrap(bootstrap_peers.begin(), bootstrap_peers.end());
    P2PReactor reactor(cfg.bind_port, all_bootstrap, signer_id);

    std::function<void()> PersistKnownPeers = [&]() {
        std::vector<std::string> peers = reactor.KnownPeers();
        std::vector<std::string> clean;
        for (size_t i = 0; i < peers.size(); ++i)
        {
            if (!IsValidEndpoint(peers[i]))
                continue;
            if (!cfg.public_endpoint.empty() && peers[i] == cfg.public_endpoint)
                continue;
            clean.push_back(peers[i]);
        }
        std::sort(clean.begin(), clean.end());
        clean.erase(std::unique(clean.begin(), clean.end()), clean.end());
        (void)SavePeerFile(discovered_peers_file, clean);
    };
    std::function<void()> BroadcastSyncStatus = [&]() {
        Bytes32 root;
        if (!store.ReadStateRoot(&root))
            return;
        std::vector<uint8_t> payload;
        if (!SerializeSyncStatusPayload(last_committed_round, root, &payload))
            return;
        WireEnvelope out;
        out.magic = WireMagicMainnet();
        out.version = 1;
        out.msg_type = WIRE_MSG_SYNC_STATUS;
        out.payload_len = (uint32_t)payload.size();
        out.unix_ms = 0;
        out.payload_hash = Bytes32();
        out.payload.swap(payload);
        (void)reactor.Broadcast(out);
    };
    reactor.SetMessageHandler([&](int peer_fd, const WireEnvelope& env) {
        if (env.msg_type == WIRE_MSG_HELLO)
        {
            std::string ep = reactor.PeerEndpoint(peer_fd);
            if (IsValidEndpoint(ep))
                reactor.AddPeer(ep);
            PersistKnownPeers();
            BroadcastSyncStatus();
            std::vector<std::string> advertise = reactor.KnownPeers();
            if (!cfg.public_endpoint.empty())
                advertise.push_back(cfg.public_endpoint);
            CanonicalizePeerList(&advertise);
            std::vector<uint8_t> sign_msg;
            if (!BuildPeerListSignBytes(last_committed_round, signer_id, advertise, &sign_msg))
                return;
            std::vector<uint8_t> sig;
            if (!crypto->SignEd25519(signer_priv,
                                     sign_msg.empty() ? NULL : &sign_msg[0],
                                     sign_msg.size(),
                                     &sig))
            {
                return;
            }
            std::vector<uint8_t> p;
            if (SerializePeerListPayload(last_committed_round, signer_id, advertise, sig, &p))
            {
                WireEnvelope out;
                out.magic = WireMagicMainnet();
                out.version = 1;
                out.msg_type = WIRE_MSG_PEER_LIST;
                out.payload_len = (uint32_t)p.size();
                out.unix_ms = 0;
                out.payload_hash = Bytes32();
                out.payload.swap(p);
                (void)reactor.SendTo(peer_fd, out);
            }
            return;
        }
        if (env.msg_type == WIRE_MSG_PEER_LIST)
        {
            uint64_t advertised_round = 0;
            Bytes32 advertiser_id;
            std::vector<std::string> peers;
            std::vector<uint8_t> signature;
            if (!ParsePeerListPayload(env.payload, &advertised_round, &advertiser_id, &peers, &signature))
            {
                printf("drop peer_list parse_failed\n");
                return;
            }
            if (advertised_round > last_committed_round + 1)
            {
                printf("drop peer_list future_round adv=%llu local=%llu\n",
                       (unsigned long long)advertised_round,
                       (unsigned long long)last_committed_round);
                return;
            }
            CanonicalizePeerList(&peers);
            std::vector<uint8_t> sign_msg;
            if (!BuildPeerListSignBytes(advertised_round, advertiser_id, peers, &sign_msg))
            {
                printf("drop peer_list sign_msg_failed\n");
                return;
            }
            if (!crypto->VerifyEd25519(advertiser_id.v,
                                       sign_msg.empty() ? NULL : &sign_msg[0],
                                       sign_msg.size(),
                                       signature.empty() ? NULL : &signature[0],
                                       signature.size()))
            {
                printf("drop peer_list sig_invalid\n");
                return;
            }
            const uint64_t auth_round = (last_committed_round == 0) ? 1 : last_committed_round;
            if (auth_round > economics_policy.genesis_bootstrap_rounds)
            {
                ValidatorEpoch auth_epoch;
                if (!vset.GetEpochForRound(auth_round, &auth_epoch))
                {
                    printf("drop peer_list auth_epoch_missing round=%llu\n", (unsigned long long)auth_round);
                    return;
                }
                bool authorized = false;
                for (size_t i = 0; i < auth_epoch.validators.size(); ++i)
                {
                    if (memcmp(auth_epoch.validators[i].validator_id.v, advertiser_id.v, 32) == 0)
                    {
                        authorized = true;
                        break;
                    }
                }
                if (!authorized)
                {
                    printf("drop peer_list unauthorized advertiser=%s\n", Hex32(advertiser_id).c_str());
                    return;
                }
            }
            size_t added = 0;
            for (size_t i = 0; i < peers.size(); ++i)
            {
                if (!IsValidEndpoint(peers[i]))
                    continue;
                if (!cfg.public_endpoint.empty() && peers[i] == cfg.public_endpoint)
                    continue;
                reactor.AddPeer(peers[i]);
                added++;
            }
            if (added > 0)
            {
                PersistKnownPeers();
                printf("peer_discovery added=%zu total=%zu\n", added, reactor.KnownPeers().size());
            }
            return;
        }
        if (env.msg_type == WIRE_MSG_SYNC_STATUS)
        {
            uint64_t peer_round = 0;
            Bytes32 peer_root;
            if (!ParseSyncStatusPayload(env.payload, &peer_round, &peer_root))
            {
                printf("drop sync_status parse_failed\n");
                return;
            }
            if (peer_round < last_committed_round)
            {
                printf("ignore peer=%d lower_round=%llu local=%llu\n",
                       peer_fd,
                       (unsigned long long)peer_round,
                       (unsigned long long)last_committed_round);
                return;
            }
            peer_last_round[peer_fd] = peer_round;
            if (peer_round > last_committed_round)
            {
                printf("sync_needed peer=%d peer_round=%llu local=%llu\n",
                       peer_fd,
                       (unsigned long long)peer_round,
                       (unsigned long long)last_committed_round);
                std::vector<uint8_t> req_payload;
                if (SerializeSyncRequestPayload(last_committed_round + 1, 64, &req_payload))
                {
                    WireEnvelope req;
                    req.magic = WireMagicMainnet();
                    req.version = 1;
                    req.msg_type = WIRE_MSG_SYNC_REQUEST;
                    req.payload_len = (uint32_t)req_payload.size();
                    req.unix_ms = 0;
                    req.payload_hash = Bytes32();
                    req.payload.swap(req_payload);
                    (void)reactor.Broadcast(req);
                }
                return;
            }
            Bytes32 local_root;
            if (store.ReadStateRoot(&local_root) && memcmp(local_root.v, peer_root.v, 32) != 0)
                printf("sync_warning peer=%d same_round_root_mismatch=%llu\n", peer_fd, (unsigned long long)peer_round);
            return;
        }
        std::map<int, uint64_t>::const_iterator it_peer_round = peer_last_round.find(peer_fd);
        if (it_peer_round != peer_last_round.end() &&
            it_peer_round->second < last_committed_round &&
            (env.msg_type == WIRE_MSG_PROPOSE || env.msg_type == WIRE_MSG_VOTE || env.msg_type == WIRE_MSG_COMMIT))
        {
            printf("drop from_stale_peer peer=%d peer_round=%llu local=%llu\n",
                   peer_fd,
                   (unsigned long long)it_peer_round->second,
                   (unsigned long long)last_committed_round);
            return;
        }
        if (last_committed_round < synced_last_round &&
            (env.msg_type == WIRE_MSG_PROPOSE || env.msg_type == WIRE_MSG_VOTE || env.msg_type == WIRE_MSG_COMMIT))
        {
            printf("drop catchup_required local_round=%llu synced_round=%llu\n",
                   (unsigned long long)last_committed_round,
                   (unsigned long long)synced_last_round);
            return;
        }
        if (env.msg_type == WIRE_MSG_SYNC_REQUEST)
        {
            uint64_t from_round = 0;
            uint32_t max_records = 0;
            if (!ParseSyncRequestPayload(env.payload, &from_round, &max_records))
            {
                printf("drop sync_request parse_failed\n");
                return;
            }
            if (max_records == 0 || max_records > 256)
                max_records = 256;
            std::vector< std::vector<uint8_t> > all_payloads;
            std::vector< std::vector<uint8_t> > selected_payloads;
            if (!LoadCommitPayloadCache(commit_payload_cache, &all_payloads))
            {
                printf("drop sync_request cache_load_failed\n");
                return;
            }
            for (size_t i = 0; i < all_payloads.size(); ++i)
            {
                uint64_t round = 0;
                Bytes32 bh;
                if (!PayloadContainsRoundHash(all_payloads[i], &round, &bh))
                    continue;
                if (round < from_round)
                    continue;
                selected_payloads.push_back(all_payloads[i]);
            }
            std::sort(selected_payloads.begin(), selected_payloads.end(),
                      [&](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
                          uint64_t ra = 0, rb = 0;
                          Bytes32 ha, hb;
                          (void)PayloadContainsRoundHash(a, &ra, &ha);
                          (void)PayloadContainsRoundHash(b, &rb, &hb);
                          if (ra != rb)
                              return ra < rb;
                          return memcmp(ha.v, hb.v, 32) < 0;
                      });
            if (selected_payloads.size() > max_records)
                selected_payloads.resize(max_records);
            std::vector<uint8_t> rsp_payload;
            if (!SerializeSyncResponsePayload(from_round, selected_payloads, &rsp_payload))
            {
                printf("drop sync_request serialize_failed\n");
                return;
            }
            WireEnvelope rsp;
            rsp.magic = WireMagicMainnet();
            rsp.version = 1;
            rsp.msg_type = WIRE_MSG_SYNC_RESPONSE;
            rsp.payload_len = (uint32_t)rsp_payload.size();
            rsp.unix_ms = 0;
            rsp.payload_hash = Bytes32();
            rsp.payload.swap(rsp_payload);
            (void)reactor.SendTo(peer_fd, rsp);
            return;
        }
        if (env.msg_type == WIRE_MSG_SYNC_RESPONSE)
        {
            uint64_t from_round = 0;
            std::vector< std::vector<uint8_t> > payloads;
            if (!ParseSyncResponsePayload(env.payload, &from_round, &payloads))
            {
                printf("drop sync_response parse_failed\n");
                return;
            }
            size_t accepted = 0;
            uint64_t max_round = 0;
            for (size_t i = 0; i < payloads.size(); ++i)
            {
                uint64_t round = 0;
                Bytes32 batch_hash;
                if (!PayloadContainsRoundHash(payloads[i], &round, &batch_hash))
                    continue;
                if (round < from_round || round <= last_committed_round)
                    continue;
                if (!AppendCommitPayloadCacheDedup(commit_payload_cache, payloads[i]))
                    continue;
                accepted++;
                if (round > max_round)
                    max_round = round;
            }
            if (accepted == 0)
                return;
            if (max_round > synced_last_round)
            {
                synced_last_round = max_round;
                (void)SaveSyncedTipFile(sync_tip_file, synced_last_round, synced_state_root);
                printf("sync_tip updated round=%llu\n", (unsigned long long)synced_last_round);
                printf("sync_lag local_round=%llu synced_round=%llu lag=%llu\n",
                       (unsigned long long)last_committed_round,
                       (unsigned long long)synced_last_round,
                       (unsigned long long)(synced_last_round - last_committed_round));
            }
            printf("sync_received payloads=%zu from_round=%llu to_round=%llu\n",
                   accepted,
                   (unsigned long long)from_round,
                   (unsigned long long)max_round);
            TryCatchUpFromCache();
            return;
        }
        if (env.msg_type == WIRE_MSG_PROPOSE)
        {
            RoundBatch batch;
            if (!ParseRoundBatchPayload(env.payload, &batch))
            {
                printf("drop propose parse_failed\n");
                return;
            }
            if (batch.round <= last_committed_round)
            {
                printf("drop propose stale round=%llu last=%llu\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)last_committed_round);
                return;
            }
            EnsureEpochTransitionForRound(batch.round);
            if (!engine.Propose(batch))
            {
                printf("drop propose invalid code=%d\n", (int)engine.last_reject_code());
                return;
            }
            const std::string batch_key = Bytes32Key(batch.batch_hash);
            if (!known_batches.count(batch_key))
                known_batches[batch_key] = batch;
            Vote vote;
            if (!engine.ValidateAndVote(batch, &vote))
            {
                printf("drop propose vote_build_failed\n");
                return;
            }
            vote.validator_id = signer_id;
            std::vector<uint8_t> m;
            WriteU64LE(&m, vote.round);
            m.insert(m.end(), vote.batch_hash.v, vote.batch_hash.v + 32);
            m.insert(m.end(), vote.validator_id.v, vote.validator_id.v + 32);
            if (!crypto->SignEd25519(signer_priv, m.empty() ? NULL : &m[0], m.size(), &vote.signature))
            {
                printf("drop propose vote_sign_failed\n");
                return;
            }
            std::vector<uint8_t> vote_payload;
            if (!SerializeVotePayload(vote, &vote_payload))
                return;
            WireEnvelope out;
            out.magic = WireMagicMainnet();
            out.version = 1;
            out.msg_type = WIRE_MSG_VOTE;
            out.payload_len = (uint32_t)vote_payload.size();
            out.unix_ms = 0;
            out.payload_hash = Bytes32();
            out.payload.swap(vote_payload);
            if (!reactor.Broadcast(out))
                printf("drop vote send_failed\n");
            return;
        }
        if (env.msg_type == WIRE_MSG_VOTE)
        {
            Vote vote;
            if (!ParseVotePayload(env.payload, &vote))
            {
                printf("drop vote parse_failed\n");
                return;
            }
            if (vote.round <= last_committed_round)
            {
                printf("drop vote stale round=%llu last=%llu\n",
                       (unsigned long long)vote.round,
                       (unsigned long long)last_committed_round);
                return;
            }
            EnsureEpochTransitionForRound(vote.round);
            if (!vote_verifier.VerifyVote(vote))
            {
                printf("drop vote bad_sig\n");
                return;
            }
            const std::string k = Bytes32Key(vote.batch_hash);
            std::map<std::string, RoundBatch>::const_iterator itb = known_batches.find(k);
            if (itb == known_batches.end())
            {
                printf("drop vote unknown_batch\n");
                return;
            }
            if (vote.round != itb->second.round)
            {
                printf("drop vote round_mismatch vote=%llu batch=%llu\n",
                       (unsigned long long)vote.round,
                       (unsigned long long)itb->second.round);
                return;
            }
            const std::string voter_key((const char*)vote.validator_id.v, 32);
            if (known_vote_ids[k].count(voter_key))
                return;
            known_vote_ids[k].insert(voter_key);
            known_votes[k].push_back(vote);
            QuorumCertificate qc;
            qc.round = itb->second.round;
            qc.batch_hash = itb->second.batch_hash;
            qc.votes = known_votes[k];
            if (itb->second.round > economics_policy.genesis_bootstrap_rounds)
            {
                ValidatorEpoch epoch;
                if (!vset.GetEpochForRound(itb->second.round, &epoch))
                    return;
                if (!HasSupermajorityPower(epoch, qc))
                    return;
            }
            std::vector<uint8_t> commit_payload;
            if (!SerializeCommitPayload(itb->second, qc, &commit_payload))
                return;
            WireEnvelope out;
            out.magic = WireMagicMainnet();
            out.version = 1;
            out.msg_type = WIRE_MSG_COMMIT;
            out.payload_len = (uint32_t)commit_payload.size();
            out.unix_ms = 0;
            out.payload_hash = Bytes32();
            out.payload.swap(commit_payload);
            if (!reactor.Broadcast(out))
                printf("drop commit send_failed\n");
            return;
        }
        if (env.msg_type == WIRE_MSG_COMMIT)
        {
            RoundBatch batch;
            QuorumCertificate qc;
            if (!ParseCommitPayload(env.payload, &batch, &qc))
            {
                printf("drop commit parse_failed\n");
                return;
            }
            if (batch.round <= last_committed_round)
            {
                printf("drop commit stale round=%llu last=%llu\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)last_committed_round);
                return;
            }
            EnsureEpochTransitionForRound(batch.round);
            if (qc.round != batch.round || memcmp(qc.batch_hash.v, batch.batch_hash.v, 32) != 0)
            {
                printf("drop commit qc_batch_mismatch\n");
                return;
            }
            if (batch.round > economics_policy.genesis_bootstrap_rounds)
            {
                ValidatorEpoch epoch;
                if (!vset.GetEpochForRound(batch.round, &epoch))
                {
                    printf("drop commit epoch_missing\n");
                    return;
                }
                if (!VerifyQuorumCertificate(epoch, qc, batch.round, batch.batch_hash, vote_verifier))
                {
                    printf("drop commit qc_invalid\n");
                    return;
                }
            }
            if (!engine.Commit(batch, qc))
            {
                printf("drop commit invalid code=%d\n", (int)engine.last_reject_code());
                return;
            }
            (void)AppendCommitPayloadCacheDedup(commit_payload_cache, env.payload);
            last_committed_round = batch.round;
            known_batches.erase(Bytes32Key(batch.batch_hash));
            known_votes.erase(Bytes32Key(batch.batch_hash));
            known_vote_ids.erase(Bytes32Key(batch.batch_hash));
            printf("commit ok round=%llu\n", (unsigned long long)batch.round);
            BroadcastSyncStatus();
        }
    });
    if (!reactor.Start(&err))
    {
        printf("p2p_start_error: %s\n", err.c_str());
        return 7;
    }

    printf("node_started port=%u data_dir=%s peers=%zu duration_sec=%d\n",
           (unsigned)cfg.bind_port,
           cfg.data_dir.c_str(),
           cfg.peers.size(),
           cfg.duration_sec);
    printf("network_magic=0x%08x\n", (unsigned)cfg.network_magic);
    printf("validator_set size=%zu\n", vals.size());
    printf("autopropose enabled=%d interval_sec=%d\n", cfg.autopropose, cfg.autopropose_interval_sec);
    printf("commit_recovery last_round=%llu\n", (unsigned long long)last_committed_round);
    printf("sync_tip round=%llu\n", (unsigned long long)synced_last_round);
    printf("sync_lag local_round=%llu synced_round=%llu lag=%llu cache_entries=%zu\n",
           (unsigned long long)last_committed_round,
           (unsigned long long)synced_last_round,
           (unsigned long long)((synced_last_round > last_committed_round) ? (synced_last_round - last_committed_round) : 0),
           CountCommitPayloadCacheEntries(commit_payload_cache));
    BroadcastSyncStatus();

    time_t start = time(NULL);
    time_t last_sync_tick = start;
    time_t last_autopropose_tick = start;
    while (true)
    {
        reactor.PollOnce();
        if (cfg.autopropose != 0 &&
            last_committed_round >= synced_last_round &&
            (time(NULL) - last_autopropose_tick) >= cfg.autopropose_interval_sec)
        {
            RoundBatch batch;
            const uint64_t target_round = last_committed_round + 1;
            EnsureEpochTransitionForRound(target_round);
            bool have_pending = GetPendingRound(target_round, &batch);
            if (!have_pending)
            {
                batch.round = target_round;
                MintTx mint;
                mint.output.value = 1;
                for (int i = 0; i < 32; ++i)
                {
                    mint.output.commitment.v[i] = (uint8_t)(signer_id.v[i] ^ (uint8_t)(batch.round + i));
                    mint.output.owner_pubkey.v[i] = signer_id.v[i];
                }
                Bytes32 expected_target;
                if (!ComputeExpectedTargetForRoundNode(store, batch.round, economics_policy, &expected_target))
                {
                    last_autopropose_tick = time(NULL);
                    continue;
                }
                mint.target = expected_target;
                memset(mint.output.range_proof.v, 0, 64);
                mint.mint_nonce = (uint64_t)time(NULL);
                mint.miner_pubkey = signer_id;
                mint.signature = BuildMintSigLocal(*crypto, signer_priv, mint);
                batch.mints.push_back(mint);
                if (!(BuildBatchHashLocal(batch, &batch.batch_hash) && engine.Propose(batch)))
                {
                    last_autopropose_tick = time(NULL);
                    continue;
                }
                known_batches[Bytes32Key(batch.batch_hash)] = batch;
            }
            if (HasPendingRound(target_round))
            {
                std::vector<uint8_t> propose_payload;
                if (SerializeRoundBatchPayload(batch, &propose_payload))
                {
                    WireEnvelope outp;
                    outp.magic = WireMagicMainnet();
                    outp.version = 1;
                    outp.msg_type = WIRE_MSG_PROPOSE;
                    outp.payload_len = (uint32_t)propose_payload.size();
                    outp.unix_ms = 0;
                    outp.payload_hash = Bytes32();
                    outp.payload.swap(propose_payload);
                    if (!reactor.Broadcast(outp))
                        printf("drop autopropose send_failed\n");
                }

                Vote vote;
                if (engine.ValidateAndVote(batch, &vote))
                {
                    vote.validator_id = signer_id;
                    std::vector<uint8_t> m;
                    WriteU64LE(&m, vote.round);
                    m.insert(m.end(), vote.batch_hash.v, vote.batch_hash.v + 32);
                    m.insert(m.end(), vote.validator_id.v, vote.validator_id.v + 32);
                    if (crypto->SignEd25519(signer_priv, m.empty() ? NULL : &m[0], m.size(), &vote.signature))
                    {
                        const std::string k = Bytes32Key(vote.batch_hash);
                        const std::string voter_key((const char*)vote.validator_id.v, 32);
                        if (!known_vote_ids[k].count(voter_key))
                        {
                            known_vote_ids[k].insert(voter_key);
                            known_votes[k].push_back(vote);
                        }
                        std::vector<uint8_t> vote_payload;
                        if (SerializeVotePayload(vote, &vote_payload))
                        {
                            WireEnvelope outv;
                            outv.magic = WireMagicMainnet();
                            outv.version = 1;
                            outv.msg_type = WIRE_MSG_VOTE;
                            outv.payload_len = (uint32_t)vote_payload.size();
                            outv.unix_ms = 0;
                            outv.payload_hash = Bytes32();
                            outv.payload.swap(vote_payload);
                            if (!reactor.Broadcast(outv))
                                printf("drop autopropose_vote send_failed\n");
                        }
                    }
                }
                printf("autopropose round=%llu\n", (unsigned long long)batch.round);
            }
            last_autopropose_tick = time(NULL);
        }
        if ((time(NULL) - last_sync_tick) >= 5)
        {
            BroadcastSyncStatus();
            TryCatchUpFromCache();
            PersistKnownPeers();
            printf("sync_tick local_round=%llu synced_round=%llu lag=%llu cache_entries=%zu\n",
                   (unsigned long long)last_committed_round,
                   (unsigned long long)synced_last_round,
                   (unsigned long long)((synced_last_round > last_committed_round) ? (synced_last_round - last_committed_round) : 0),
                   CountCommitPayloadCacheEntries(commit_payload_cache));
            last_sync_tick = time(NULL);
        }
        if (cfg.duration_sec > 0 && (int)(time(NULL) - start) >= cfg.duration_sec)
            break;
    }

    reactor.Stop();
    PersistKnownPeers();
    Bytes32 final_root;
    if (store.ReadStateRoot(&final_root))
        printf("final_status round=%llu state_root=%s\n",
               (unsigned long long)last_committed_round,
               Hex32(final_root).c_str());
    printf("node_stopped\n");
    return 0;
}

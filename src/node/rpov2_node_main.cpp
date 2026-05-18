#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
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
#include <stdarg.h>

#include "consensus_round.h"
#include "crypto_backend.h"
#include "rpov2/mempool.h"
#include "rpov2/node_config.h"
#include "p2p_wire.h"
#include "p2p_reactor.h"
#include "proof_verifier.h"
#include "pow_lottery_validator_set.h"
#include "registry_state_store.h"
#include "rpov2/tx_codec.h"

using namespace rpov2;

enum {
    LOG_QUIET = 0,
    LOG_NORMAL = 1,
    LOG_DEBUG = 2
};

static int g_log_level = LOG_NORMAL;

static bool LogEnabled(int level)
{
    return level <= g_log_level;
}

static void Logf(int level, const char* fmt, ...)
{
    if (!LogEnabled(level))
        return;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static uint64_t NowMonotonicMs()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

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

struct PeerCacheRecord {
    std::string endpoint;
    uint64_t last_seen_round;
};

static bool ParsePeerCacheLine(const std::string& line, PeerCacheRecord* out)
{
    if (!out || line.empty())
        return false;
    out->endpoint.clear();
    out->last_seen_round = 0;
    std::istringstream iss(line);
    std::string ep;
    if (!(iss >> ep))
        return false;
    std::string rs;
    if (iss >> rs)
        out->last_seen_round = (uint64_t)strtoull(rs.c_str(), NULL, 10);
    out->endpoint = ep;
    return true;
}

static bool LoadPeerCacheRecords(const std::string& path, std::vector<PeerCacheRecord>* out)
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
        PeerCacheRecord r;
        if (!ParsePeerCacheLine(line, &r))
            continue;
        if (r.endpoint.empty())
            continue;
        out->push_back(r);
    }
    return true;
}

static bool SavePeerCacheRecords(const std::string& path, const std::vector<PeerCacheRecord>& records)
{
    std::ofstream out(path.c_str(), std::ios::trunc);
    if (!out.good())
        return false;
    for (size_t i = 0; i < records.size(); ++i)
        out << records[i].endpoint << " " << (unsigned long long)records[i].last_seen_round << "\n";
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

static void CompactPeerCacheRecords(std::vector<PeerCacheRecord>* records, uint64_t local_round, uint64_t keep_window_rounds)
{
    if (!records)
        return;
    std::map<std::string, uint64_t> best;
    for (size_t i = 0; i < records->size(); ++i)
    {
        const PeerCacheRecord& r = (*records)[i];
        if (!IsValidEndpoint(r.endpoint))
            continue;
        std::map<std::string, uint64_t>::iterator it = best.find(r.endpoint);
        if (it == best.end() || r.last_seen_round > it->second)
            best[r.endpoint] = r.last_seen_round;
    }
    records->clear();
    uint64_t cutoff = 0;
    bool use_cutoff = false;
    if (local_round >= keep_window_rounds)
    {
        cutoff = local_round - keep_window_rounds;
        use_cutoff = true;
    }
    for (std::map<std::string, uint64_t>::const_iterator it = best.begin(); it != best.end(); ++it)
    {
        if (use_cutoff && it->second < cutoff)
            continue;
        PeerCacheRecord r;
        r.endpoint = it->first;
        r.last_seen_round = it->second;
        records->push_back(r);
    }
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
    const uint64_t epoch_len = policy.target_epoch_rounds == 0 ? 1 : policy.target_epoch_rounds;
    const bool epoch_start = (round == 1) || (((round - 1) % epoch_len) == 0);
    if (round == 1)
    {
        *out_target = policy.max_target;
        return true;
    }
    if (!epoch_start)
    {
        std::vector<RoundCommitRecord> prev;
        if (!store.ExportVerifiedCommitRecordsFromRound(round - 1, 1, &prev))
            return false;
        if (prev.size() != 1)
            return false;
        MintTx mint;
        size_t off = 0;
        if (!ParseMintTxCanonical(prev[0].consensus_proof.empty() ? NULL : &prev[0].consensus_proof[0],
                                  prev[0].consensus_proof.size(),
                                  &off,
                                  &mint) ||
            off != prev[0].consensus_proof.size())
        {
            return false;
        }
        *out_target = mint.target;
        return true;
    }

    Bytes32 prev_target = policy.max_target;
    uint64_t observed_mints = 0;
    std::vector<RoundCommitRecord> recs;
    const uint64_t from_round = round - epoch_len;
    if (!store.ExportVerifiedCommitRecordsFromRound(from_round, (size_t)epoch_len, &recs))
        return false;
    if (recs.size() == 0)
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
    const uint64_t expected_mints = policy.target_mints_per_window == 0 ? epoch_len : policy.target_mints_per_window;
    return NextPowTargetDeterministic(prev_target,
                                      observed_mints,
                                      expected_mints,
                                      policy.target_adjust_up_ppm_limit,
                                      policy.target_adjust_down_ppm_limit,
                                      policy.min_target,
                                      policy.max_target,
                                      out_target);
}

static uint64_t SumBatchMintValue(const RoundBatch& batch)
{
    uint64_t s = 0;
    for (size_t i = 0; i < batch.mints.size(); ++i)
        s += batch.mints[i].output.value;
    return s;
}

static uint64_t SumBatchFees(const RoundBatch& batch)
{
    uint64_t s = 0;
    for (size_t i = 0; i < batch.spends.size(); ++i)
        s += batch.spends[i].fee;
    return s;
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
    Bytes32 work_score;
    uint64_t wins;
    uint64_t wins_recent;
    bool incumbent;
};

static int CompareBytes32(const Bytes32& a, const Bytes32& b)
{
    return memcmp(a.v, b.v, 32);
}

static bool MinerCountEntryLess(const MinerCountEntry& a, const MinerCountEntry& b)
{
    const int c = CompareBytes32(a.work_score, b.work_score);
    if (c != 0)
        return c > 0;
    if (a.wins != b.wins)
        return a.wins > b.wins;
    return memcmp(a.miner.v, b.miner.v, 32) < 0;
}

static bool SameValidatorSetOrdered(const std::vector<Validator>& a, const std::vector<Validator>& b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
    {
        if (memcmp(a[i].validator_id.v, b[i].validator_id.v, 32) != 0)
            return false;
        if (a[i].voting_power != b[i].voting_power)
            return false;
    }
    return true;
}

static void AddBytes32Saturating(Bytes32* acc, const Bytes32& delta)
{
    uint16_t carry = 0;
    for (int i = 31; i >= 0; --i)
    {
        const uint16_t s = (uint16_t)acc->v[i] + (uint16_t)delta.v[i] + carry;
        acc->v[i] = (uint8_t)(s & 0xff);
        carry = (uint16_t)(s >> 8);
    }
    if (carry != 0)
        memset(acc->v, 0xff, 32);
}

static Bytes32 WorkScoreFromTarget256(const Bytes32& target)
{
    // Full-256 deterministic monotone proxy:
    // contribution = (2^256 - 1) - target
    // Smaller target => larger contribution.
    Bytes32 out;
    for (int i = 0; i < 32; ++i)
        out.v[i] = (uint8_t)~target.v[i];
    return out;
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

    // Open competition mode: emphasize freshest work so active miners
    // can enter validator set quickly.
    const uint64_t kAdmissionLookbackEpochs = 1;
    const uint64_t latest_epoch = epoch - 1;
    struct MinerStats {
        uint64_t wins;
        uint64_t wins_recent;
        Bytes32 work_score;
    };
    std::map<std::string, MinerStats> stats;
    for (uint64_t off = 0; off < kAdmissionLookbackEpochs; ++off)
    {
        if (latest_epoch < off)
            break;
        const uint64_t src_epoch = latest_epoch - off;
        const uint64_t from_round = src_epoch * epoch_length + 1;
        std::vector<RoundCommitRecord> recs;
        if (!store.ExportVerifiedCommitRecordsFromRound(from_round, (size_t)epoch_length, &recs))
        {
            continue;
        }

        // More recent eras get more weight.
        const uint64_t era_weight = (kAdmissionLookbackEpochs - off);
        for (size_t i = 0; i < recs.size(); ++i)
        {
            MintTx mint;
            size_t p = 0;
            if (!ParseMintTxCanonical(recs[i].consensus_proof.empty() ? NULL : &recs[i].consensus_proof[0],
                                      recs[i].consensus_proof.size(),
                                      &p,
                                      &mint) ||
                p != recs[i].consensus_proof.size())
            {
                continue;
            }
            std::string k((const char*)mint.miner_pubkey.v, 32);
            MinerStats s = stats[k];
            if (s.wins < UINT64_MAX)
                s.wins += 1;
            if (off == 0 && s.wins_recent < UINT64_MAX)
                s.wins_recent += 1;
            const Bytes32 w = WorkScoreFromTarget256(mint.target);
            for (uint64_t n = 0; n < era_weight; ++n)
                AddBytes32Saturating(&s.work_score, w);
            stats[k] = s;
        }
    }

    std::set<std::string> incumbent_ids;
    if (prev_epoch)
    {
        for (size_t i = 0; i < prev_epoch->validators.size(); ++i)
            incumbent_ids.insert(std::string((const char*)prev_epoch->validators[i].validator_id.v, 32));
    }

    std::vector<MinerCountEntry> ranked;
    ranked.reserve(stats.size());
    for (std::map<std::string, MinerStats>::const_iterator it = stats.begin(); it != stats.end(); ++it)
    {
        MinerCountEntry e;
        memset(e.miner.v, 0, 32);
        memcpy(e.miner.v, it->first.data(), 32);
        e.work_score = it->second.work_score;
        e.wins = it->second.wins;
        e.wins_recent = it->second.wins_recent;
        e.incumbent = incumbent_ids.count(it->first) != 0;
        ranked.push_back(e);
    }
    std::sort(ranked.begin(), ranked.end(), MinerCountEntryLess);

    size_t target_size = max_validators;
    if (prev_epoch && !prev_epoch->validators.empty())
    {
        target_size = prev_epoch->validators.size();
        // Open growth: expand faster (+4/epoch) until max_validators.
        if (target_size < max_validators)
        {
            const size_t grow = 4;
            target_size = std::min(max_validators, target_size + grow);
        }
    }
    if (target_size > max_validators)
        target_size = max_validators;
    if (target_size == 0)
        target_size = 1;

    // Open competition admission:
    // - allow full newcomer turnover when fresh miners are active
    // - require only one recent win to qualify
    size_t max_newcomers = target_size;
    if (max_newcomers > target_size)
        max_newcomers = target_size;
    const uint64_t newcomer_min_wins_recent = 1;
    const uint64_t incumbent_min_wins_total = 1;

    size_t newcomers_added = 0;
    for (size_t i = 0; i < ranked.size() && out.size() < target_size; ++i)
    {
        if (!ranked[i].incumbent)
        {
            if (newcomers_added >= max_newcomers)
                continue;
            if (ranked[i].wins_recent < newcomer_min_wins_recent)
                continue;
        }
        else if (ranked[i].wins < incumbent_min_wins_total)
        {
            // Incumbents must also show sustained participation over lookback window.
            continue;
        }
        Validator v;
        v.validator_id = ranked[i].miner;
        v.voting_power = 1;
        out.push_back(v);
        if (!ranked[i].incumbent)
            newcomers_added += 1;
    }

    // Strict era-local PoW admission:
    // do NOT auto-carry validators that produced no PoW in the source era window.
    // This keeps validator rights coupled to recent work.
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

static bool LoadVerifiedCommitLogRecordsGeneric(const std::string& log_file,
                                                const CryptoBackend* crypto,
                                                std::vector<RoundCommitRecord>* out_records)
{
    if (!crypto || !out_records)
        return false;
    out_records->clear();
    std::ifstream in(log_file.c_str(), std::ios::binary);
    if (!in.good())
        return true;
    uint64_t last_round = 0;
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
        out_records->push_back(rec);
    }
    return true;
}

static bool WriteCommitRecordBinary(std::ofstream* out, const RoundCommitRecord& rec)
{
    if (!out || !out->good())
        return false;
    out->write((const char*)&rec.record_version, sizeof(rec.record_version));
    out->write((const char*)&rec.hash_alg_id, sizeof(rec.hash_alg_id));
    out->write((const char*)&rec.sig_alg_id, sizeof(rec.sig_alg_id));
    out->write((const char*)&rec.round, sizeof(rec.round));
    out->write((const char*)rec.batch_hash.v, 32);
    out->write((const char*)rec.state_root.v, 32);
    const uint64_t proof_size = (uint64_t)rec.consensus_proof.size();
    out->write((const char*)&proof_size, sizeof(proof_size));
    if (proof_size > 0)
        out->write((const char*)&rec.consensus_proof[0], (std::streamsize)proof_size);
    out->write((const char*)rec.record_hash.v, 32);
    out->write((const char*)rec.record_signer_id.v, 32);
    const uint64_t sig_size = (uint64_t)rec.record_signature.size();
    out->write((const char*)&sig_size, sizeof(sig_size));
    if (sig_size > 0)
        out->write((const char*)&rec.record_signature[0], (std::streamsize)sig_size);
    return out->good();
}

static bool RewriteCommitLogGeneric(const std::string& path, const std::vector<RoundCommitRecord>& records)
{
    std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
    if (!out.good())
        return false;
    for (size_t i = 0; i < records.size(); ++i)
        if (!WriteCommitRecordBinary(&out, records[i]))
            return false;
    return out.good();
}

static bool WriteCheckpointSnapshot(const std::string& checkpoint_file, const RoundCommitRecord& rec)
{
    std::ofstream out(checkpoint_file.c_str(), std::ios::binary | std::ios::trunc);
    if (!out.good())
        return false;
    return WriteCommitRecordBinary(&out, rec);
}

static bool RotateCommitLogWithCheckpoint(const std::string& log_file,
                                          const std::string& checkpoint_file,
                                          const CryptoBackend* crypto,
                                          uint64_t keep_from_round)
{
    std::vector<RoundCommitRecord> all;
    if (!LoadVerifiedCommitLogRecordsGeneric(log_file, crypto, &all))
        return false;
    if (all.empty())
        return true;
    size_t first_keep = 0;
    while (first_keep < all.size() && all[first_keep].round < keep_from_round)
        ++first_keep;
    if (first_keep == 0)
        return true;
    const RoundCommitRecord boundary = all[first_keep - 1];
    std::vector<RoundCommitRecord> kept;
    kept.reserve(all.size() - first_keep);
    for (size_t i = first_keep; i < all.size(); ++i)
        kept.push_back(all[i]);
    if (!RewriteCommitLogGeneric(log_file, kept))
        return false;
    return WriteCheckpointSnapshot(checkpoint_file, boundary);
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

static uint64_t FileSizeBytes(const std::string& path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0)
        return 0;
    if (st.st_size < 0)
        return 0;
    return (uint64_t)st.st_size;
}

static bool ReadFileBytes(const std::string& path, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in.good())
        return false;
    in.seekg(0, std::ios::end);
    const std::streamoff n = in.tellg();
    if (n < 0)
        return false;
    in.seekg(0, std::ios::beg);
    out->resize((size_t)n);
    if (n > 0)
        in.read((char*)&(*out)[0], n);
    return in.good();
}

static bool VerifyGenesisHashLocked(const std::string& data_dir, const std::string& expected_hex, std::string* out_actual_hex)
{
    const std::string genesis_file = data_dir + "/genesis_epoch0.bin";
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(genesis_file, &bytes))
        return false;
    Bytes32 h;
    if (!Sha256(bytes, &h))
        return false;
    const std::string actual = Hex32(h);
    if (out_actual_hex)
        *out_actual_hex = actual;
    return actual == expected_hex;
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
    if (cfg.log_level == "quiet")
        g_log_level = LOG_QUIET;
    else if (cfg.log_level == "debug")
        g_log_level = LOG_DEBUG;
    else
        g_log_level = LOG_NORMAL;

    std::string actual_genesis_hash;
    if (!VerifyGenesisHashLocked(cfg.data_dir, cfg.genesis_hash_hex, &actual_genesis_hash))
    {
        printf("genesis_hash_mismatch data_dir=%s expected=%s actual=%s file=%s/genesis_epoch0.bin\n",
               cfg.data_dir.c_str(),
               cfg.genesis_hash_hex.c_str(),
               actual_genesis_hash.empty() ? "<unavailable>" : actual_genesis_hash.c_str(),
               cfg.data_dir.c_str());
        return 2;
    }
    printf("genesis_hash_ok hash=%s\n", cfg.genesis_hash_hex.c_str());

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
    const bool config_provided_signer = !cfg.signer_privkey_hex.empty();
    if (!cfg.signer_privkey_hex.empty())
        have_signer = HexTo32(cfg.signer_privkey_hex, signer_priv);
    if (!have_signer && !config_provided_signer)
    {
        std::ifstream kin(signer_key_file.c_str());
        std::string line;
        if (kin.good() && std::getline(kin, line))
        {
            have_signer = HexTo32(line, signer_priv);
            (void)EnsureOwnerOnlyFile(signer_key_file);
        }
    }
    if (!have_signer && !config_provided_signer)
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
    Mempool mempool;
    std::map<std::string, RoundBatch> known_batches;
    std::map<std::string, std::vector<Vote> > known_votes;
    std::map<std::string, std::set<std::string> > known_vote_ids;
    uint64_t last_committed_round = store.LastVerifiedCommitRound();
    const uint64_t startup_registry_bytes = FileSizeBytes(registry);
    const uint64_t startup_commitlog_bytes = FileSizeBytes(commitlog);
    if (last_committed_round == 0 && (startup_registry_bytes > 0 || startup_commitlog_bytes > 0))
    {
        printf("startup_state_inconsistent data_dir=%s last_round=0 registry_bytes=%llu commitlog_bytes=%llu\n",
               cfg.data_dir.c_str(),
               (unsigned long long)startup_registry_bytes,
               (unsigned long long)startup_commitlog_bytes);
        printf("startup_hint: clear node state dir or restore matching signer key before restart\n");
        return 7;
    }
    std::map<int, uint64_t> peer_last_round;
    std::map<int, uint64_t> peer_last_lower_round_log_local;
    time_t last_progress_time = time(NULL);
    uint64_t last_progress_round = last_committed_round;
    const std::string sync_cache = cfg.data_dir + "/sync_commit.log";
    const std::string sync_cache_checkpoint = cfg.data_dir + "/sync_commit.checkpoint";
    const std::string sync_tip_file = cfg.data_dir + "/sync_tip.dat";
    const std::string commit_payload_cache = cfg.data_dir + "/commit_payload_cache.bin";
    const std::string commitlog_checkpoint = cfg.data_dir + "/commit.checkpoint";
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
        const uint64_t before_bytes = FileSizeBytes(commit_payload_cache);
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
        const uint64_t kWindow = 4096;
        uint64_t low = 1;
        uint64_t high = 0;
        if (synced_last_round > last_committed_round)
        {
            // Catch-up mode: keep forward window only.
            low = last_committed_round + 1;
            high = synced_last_round;
            if (high > low + kWindow)
                high = low + kWindow;
        }
        else
        {
            // Normal mode: retain recent committed payloads for serving peers.
            high = last_committed_round;
            if (high > kWindow)
                low = high - kWindow + 1;
        }

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

        // Hard byte cap retention: keep newest payloads within cap after round-window filtering.
        const uint64_t kCommitPayloadCacheMaxBytes = 64ULL * 1024ULL * 1024ULL;
        uint64_t kept_bytes = 0;
        std::vector< std::vector<uint8_t> > capped_rev;
        capped_rev.reserve(compacted.size());
        for (size_t i = compacted.size(); i > 0; --i)
        {
            const std::vector<uint8_t>& p = compacted[i - 1];
            const uint64_t entry_bytes = (uint64_t)p.size() + 4ULL;
            if (!capped_rev.empty() && kept_bytes + entry_bytes > kCommitPayloadCacheMaxBytes)
                break;
            kept_bytes += entry_bytes;
            capped_rev.push_back(p);
        }
        std::vector< std::vector<uint8_t> > capped;
        capped.reserve(capped_rev.size());
        for (size_t i = capped_rev.size(); i > 0; --i)
            capped.push_back(capped_rev[i - 1]);

        (void)RewriteCommitPayloadCache(commit_payload_cache, capped);
        const size_t after_count = capped.size();
        const uint64_t after_bytes = FileSizeBytes(commit_payload_cache);
        printf("sync_cache_compact before=%zu after=%zu before_bytes=%llu after_bytes=%llu low=%llu high=%llu\n",
               before_count,
               after_count,
               (unsigned long long)before_bytes,
               (unsigned long long)after_bytes,
               (unsigned long long)low,
               (unsigned long long)high);
    };
    CompactCommitPayloadCache();

    std::function<bool(uint64_t, const char*)> EnsureEpochTransitionForRound = [&](uint64_t round, const char* phase) {
        if (round == 0)
            return true;
        const uint64_t epoch = (round - 1) / kRuntimeEpochLength;
        // Ensure all intermediate epochs are installed contiguously up to target epoch.
        for (uint64_t e = 0; e <= epoch; ++e)
        {
            const uint64_t probe_round = e * kRuntimeEpochLength + 1;
            ValidatorEpoch installed;
            if (vset.GetEpochForRound(probe_round, &installed))
                continue;
            ValidatorEpoch prev_epoch;
            const bool have_prev_epoch = (e > 0) && vset.GetEpochForRound((e - 1) * kRuntimeEpochLength + 1, &prev_epoch);
            std::vector<Validator> next_vals;
            if (e == 0)
                next_vals = vals;
            else
            {
                if (!have_prev_epoch)
                {
                    printf("epoch_transition_reject phase=%s epoch=%llu reason=missing_prev_epoch\n",
                           phase ? phase : "-",
                           (unsigned long long)e);
                    return false;
                }
                next_vals = DeriveEpochValidatorsFromPowHistory(store,
                                                                &prev_epoch,
                                                                e,
                                                                kRuntimeEpochLength,
                                                                kEpochValidatorCap);
            }
            if (next_vals.empty())
            {
                printf("epoch_transition_reject phase=%s epoch=%llu reason=empty_next_set\n",
                       phase ? phase : "-",
                       (unsigned long long)e);
                return false;
            }
            if (!vset.InstallEpoch(e, next_vals))
            {
                printf("epoch_transition_reject phase=%s epoch=%llu reason=install_failed\n",
                       phase ? phase : "-",
                       (unsigned long long)e);
                return false;
            }
            if (e != epoch)
                continue;

            Bytes32 next_target;
            if (!ComputeExpectedTargetForRoundNode(store, round, economics_policy, &next_target))
                memset(next_target.v, 0, 32);
            Bytes32 seed_root;
            if (!store.ReadStateRoot(&seed_root))
                memset(seed_root.v, 0, 32);
            size_t prev_count = 0;
            size_t retained_count = 0;
            size_t newcomer_count = next_vals.size();
            if (have_prev_epoch)
            {
                prev_count = prev_epoch.validators.size();
                std::set<std::string> prev_ids;
                for (size_t i = 0; i < prev_epoch.validators.size(); ++i)
                    prev_ids.insert(std::string((const char*)prev_epoch.validators[i].validator_id.v, 32));
                for (size_t i = 0; i < next_vals.size(); ++i)
                {
                    if (prev_ids.count(std::string((const char*)next_vals[i].validator_id.v, 32)))
                        retained_count += 1;
                }
                if (retained_count <= newcomer_count)
                    newcomer_count -= retained_count;
                else
                    newcomer_count = 0;
            }
            printf("epoch_transition epoch=%llu round_start=%llu validators=%zu retained=%zu newcomers=%zu prev=%zu target=%s seed_root=%s\n",
                   (unsigned long long)e,
                   (unsigned long long)(e * kRuntimeEpochLength + 1),
                   next_vals.size(),
                   retained_count,
                   newcomer_count,
                   prev_count,
                   Hex32(next_target).c_str(),
                   Hex32(seed_root).c_str());
        }
        ValidatorEpoch existing;
        if (!vset.GetEpochForRound(round, &existing))
        {
            printf("epoch_transition_reject phase=%s epoch=%llu reason=missing_after_install\n",
                   phase ? phase : "-",
                   (unsigned long long)epoch);
            return false;
        }
        return true;
    };
    std::function<bool(const Bytes32&, uint64_t)> IsValidatorForRound = [&](const Bytes32& validator_id, uint64_t round) {
        ValidatorEpoch epoch;
        if (!vset.GetEpochForRound(round, &epoch))
            return false;
        for (size_t i = 0; i < epoch.validators.size(); ++i)
        {
            if (memcmp(epoch.validators[i].validator_id.v, validator_id.v, 32) == 0)
                return true;
        }
        return false;
    };
    std::function<bool(const Bytes32&, uint64_t)> IsPowEligibleForRound = [&](const Bytes32& validator_id, uint64_t round) {
        if (round == 0)
            return false;
        // Deterministic "eligibility proof path":
        // A node is considered PoW-eligible if it has at least one successful
        // committed mint in the most recent admission window.
        const uint64_t lookback = kRuntimeEpochLength;
        const uint64_t from_round = (round > lookback) ? (round - lookback) : 1;
        const size_t count = (size_t)(round - from_round);
        if (count == 0)
            return false;
        std::vector<RoundCommitRecord> recs;
        if (!store.ExportVerifiedCommitRecordsFromRound(from_round, count, &recs))
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
                continue;
            }
            if (memcmp(mint.miner_pubkey.v, validator_id.v, 32) == 0)
                return true;
        }
        return false;
    };
    std::function<bool(const Bytes32&, uint64_t, uint8_t*)> ResolveVoteEligibilityForRound =
        [&](const Bytes32& validator_id, uint64_t round, uint8_t* out_type) {
            if (!out_type)
                return false;
            if (IsValidatorForRound(validator_id, round))
            {
                *out_type = VOTE_ELIGIBILITY_VALIDATOR_SET;
                return true;
            }
            if (IsPowEligibleForRound(validator_id, round))
            {
                *out_type = VOTE_ELIGIBILITY_POW_RECENT;
                return true;
            }
            return false;
        };
    std::function<void(uint64_t, std::set<std::string>*)> BuildPowEligibleIdSetForRound =
        [&](uint64_t round, std::set<std::string>* out_ids) {
            if (!out_ids)
                return;
            out_ids->clear();
            if (round == 0)
                return;
            const uint64_t lookback = kRuntimeEpochLength;
            const uint64_t from_round = (round > lookback) ? (round - lookback) : 1;
            const size_t count = (size_t)(round - from_round);
            if (count == 0)
                return;
            std::vector<RoundCommitRecord> recs;
            if (!store.ExportVerifiedCommitRecordsFromRound(from_round, count, &recs))
                return;
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
                out_ids->insert(std::string((const char*)mint.miner_pubkey.v, 32));
            }
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
            if (!EnsureEpochTransitionForRound(batch.round, "catchup"))
            {
                printf("catchup_break_epoch_transition_invalid round=%llu\n",
                       (unsigned long long)batch.round);
                break;
            }
            if (batch.round > economics_policy.genesis_bootstrap_rounds)
            {
                ValidatorEpoch epoch;
                if (!vset.GetEpochForRound(batch.round, &epoch))
                {
                    printf("catchup_break_epoch_missing round=%llu\n", (unsigned long long)batch.round);
                    break;
                }
                std::set<std::string> pow_recent_ids;
                BuildPowEligibleIdSetForRound(batch.round, &pow_recent_ids);
                if (!VerifyQuorumCertificateTyped(epoch, qc, batch.round, batch.batch_hash, pow_recent_ids, 1, vote_verifier))
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
            last_progress_round = last_committed_round;
            last_progress_time = time(NULL);
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
    const uint64_t kPeerCacheKeepRounds = 20;
    std::vector<PeerCacheRecord> persisted_records;
    (void)LoadPeerCacheRecords(discovered_peers_file, &persisted_records);
    const size_t peer_cache_before_startup = persisted_records.size();
    CompactPeerCacheRecords(&persisted_records, last_committed_round, kPeerCacheKeepRounds);
    const size_t peer_cache_after_startup = persisted_records.size();
    const uint64_t peer_cache_cutoff_startup =
        (last_committed_round >= kPeerCacheKeepRounds) ? (last_committed_round - kPeerCacheKeepRounds) : 0;
    printf("peer_cache_compact before=%zu after=%zu cutoff_round=%llu\n",
           peer_cache_before_startup,
           peer_cache_after_startup,
           (unsigned long long)peer_cache_cutoff_startup);
    (void)SavePeerCacheRecords(discovered_peers_file, persisted_records);
    std::set<std::string> bootstrap_peers(cfg.peers.begin(), cfg.peers.end());
    std::map<std::string, uint64_t> peer_last_seen_round;
    for (size_t i = 0; i < persisted_records.size(); ++i)
    {
        if (!IsValidEndpoint(persisted_records[i].endpoint))
            continue;
        bootstrap_peers.insert(persisted_records[i].endpoint);
        peer_last_seen_round[persisted_records[i].endpoint] = persisted_records[i].last_seen_round;
    }
    std::vector<std::string> all_bootstrap(bootstrap_peers.begin(), bootstrap_peers.end());
    P2PReactor reactor(cfg.bind_port, all_bootstrap, signer_id);

    std::function<void()> PersistKnownPeers = [&]() {
        std::vector<std::string> peers = reactor.KnownPeers();
        std::vector<PeerCacheRecord> clean;
        for (size_t i = 0; i < peers.size(); ++i)
        {
            if (!IsValidEndpoint(peers[i]))
                continue;
            if (!cfg.public_endpoint.empty() && peers[i] == cfg.public_endpoint)
                continue;
            PeerCacheRecord r;
            r.endpoint = peers[i];
            r.last_seen_round = last_committed_round;
            std::map<std::string, uint64_t>::const_iterator it = peer_last_seen_round.find(peers[i]);
            if (it != peer_last_seen_round.end() && it->second > r.last_seen_round)
                r.last_seen_round = it->second;
            clean.push_back(r);
        }
        const size_t before = clean.size();
        CompactPeerCacheRecords(&clean, last_committed_round, kPeerCacheKeepRounds);
        const size_t after = clean.size();
        const uint64_t cutoff =
            (last_committed_round >= kPeerCacheKeepRounds) ? (last_committed_round - kPeerCacheKeepRounds) : 0;
        printf("peer_cache_compact before=%zu after=%zu cutoff_round=%llu\n",
               before,
               after,
               (unsigned long long)cutoff);
        (void)SavePeerCacheRecords(discovered_peers_file, clean);
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
    struct PeerRateState {
        double tokens_sync;
        double tokens_tx;
        double tokens_consensus;
        uint64_t last_ms;
        int ban_score;
        uint64_t quarantine_until_ms;
    };
    std::map<int, PeerRateState> peer_rate;
    std::map<int, Bytes32> peer_node_id_by_fd;
    std::map<std::string, int> peer_fd_by_node_id;
    std::map<int, Bytes32> peer_pending_node_id_by_fd;
    std::map<int, Bytes32> peer_challenge_by_fd;
    std::map<std::string, uint64_t> duplicate_node_cooldown_until_ms;
    std::map<std::string, uint64_t> duplicate_endpoint_cooldown_until_ms;
    struct PeerPenaltyPersist {
        double score;
        uint64_t last_ms;
        uint64_t quarantine_until_ms;
    };
    std::map<std::string, PeerPenaltyPersist> persist_penalty_by_node;
    std::map<std::string, PeerPenaltyPersist> persist_penalty_by_endpoint;
    auto now_ms = [&]() -> uint64_t { return (uint64_t)time(NULL) * 1000ULL; };
    auto decay_persist = [&](PeerPenaltyPersist* p) {
        if (!p)
            return;
        const uint64_t n = now_ms();
        if (p->last_ms == 0 || n <= p->last_ms)
        {
            p->last_ms = n;
            return;
        }
        const double dt = (double)(n - p->last_ms) / 1000.0;
        const double decay_units_per_sec = 0.2;
        p->score = std::max(0.0, p->score - dt * decay_units_per_sec);
        p->last_ms = n;
    };
    auto build_auth_sign_bytes = [&](const Bytes32& challenge, const Bytes32& node_id, std::vector<uint8_t>* out) {
        if (!out)
            return false;
        out->clear();
        const char* tag = "RPOV2:hello_auth:v1";
        while (*tag)
            out->push_back((uint8_t)*tag++);
        out->insert(out->end(), challenge.v, challenge.v + 32);
        out->insert(out->end(), node_id.v, node_id.v + 32);
        return true;
    };
    auto get_rate = [&](int fd) -> PeerRateState& {
        PeerRateState& rs = peer_rate[fd];
        if (rs.last_ms == 0)
        {
            rs.tokens_sync = 20.0;
            rs.tokens_tx = 20.0;
            rs.tokens_consensus = 40.0;
            rs.last_ms = now_ms();
            rs.ban_score = 0;
            rs.quarantine_until_ms = 0;
        }
        return rs;
    };
    auto penalize_peer = [&](int fd, int delta, const char* reason) {
        PeerRateState& rs = get_rate(fd);
        rs.ban_score += delta;
        std::map<int, Bytes32>::const_iterator it_node = peer_node_id_by_fd.find(fd);
        if (it_node == peer_node_id_by_fd.end())
            it_node = peer_pending_node_id_by_fd.find(fd);
        if (it_node != peer_node_id_by_fd.end())
        {
            const std::string node_key((const char*)it_node->second.v, 32);
            PeerPenaltyPersist& ps = persist_penalty_by_node[node_key];
            decay_persist(&ps);
            ps.score += (double)delta;
            ps.last_ms = now_ms();
        }
        const std::string ep = reactor.PeerEndpoint(fd);
        if (!ep.empty())
        {
            PeerPenaltyPersist& pe = persist_penalty_by_endpoint[ep];
            decay_persist(&pe);
            pe.score += (double)delta;
            pe.last_ms = now_ms();
        }
        if (rs.ban_score >= 40)
        {
            std::map<int, Bytes32>::iterator itid = peer_node_id_by_fd.find(fd);
            if (itid != peer_node_id_by_fd.end())
            {
                peer_fd_by_node_id.erase(std::string((const char*)itid->second.v, 32));
                peer_node_id_by_fd.erase(itid);
            }
            std::map<int, Bytes32>::iterator itp = peer_pending_node_id_by_fd.find(fd);
            if (itp != peer_pending_node_id_by_fd.end())
                peer_pending_node_id_by_fd.erase(itp);
            peer_challenge_by_fd.erase(fd);
            rs.quarantine_until_ms = now_ms() + 60000ULL;
            if (it_node != peer_node_id_by_fd.end())
            {
                const std::string node_key((const char*)it_node->second.v, 32);
                PeerPenaltyPersist& ps = persist_penalty_by_node[node_key];
                ps.quarantine_until_ms = rs.quarantine_until_ms;
            }
            if (!ep.empty())
            {
                PeerPenaltyPersist& pe = persist_penalty_by_endpoint[ep];
                pe.quarantine_until_ms = rs.quarantine_until_ms;
            }
            printf("peer_quarantine fd=%d ms=%llu reason=%s score=%d\n",
                   fd,
                   (unsigned long long)60000ULL,
                   reason ? reason : "-",
                   rs.ban_score);
            reactor.Disconnect(fd);
        }
    };
    std::map<std::string, uint64_t> drop_counters;
    uint64_t metric_handshake_kept_leg = 0;
    uint64_t metric_handshake_dropped_leg = 0;
    uint64_t metric_handshake_cooldown_hits = 0;
    uint64_t drop_summary_last_ms = now_ms();
    auto note_drop = [&](const char* reason) {
        if (!reason)
            return;
        drop_counters[std::string(reason)] += 1;
    };
    auto flush_drop_summary = [&](bool force) {
        const uint64_t now = now_ms();
        if (!force && now > drop_summary_last_ms && (now - drop_summary_last_ms) < 30000ULL)
            return;
        if (drop_counters.empty())
        {
            drop_summary_last_ms = now;
            return;
        }
        std::string msg = "[NET] drop_summary";
        {
            char mbuf[192];
            snprintf(mbuf,
                     sizeof(mbuf),
                     " kept_leg=%llu dropped_leg=%llu cooldown_hits=%llu",
                     (unsigned long long)metric_handshake_kept_leg,
                     (unsigned long long)metric_handshake_dropped_leg,
                     (unsigned long long)metric_handshake_cooldown_hits);
            msg += mbuf;
        }
        for (std::map<std::string, uint64_t>::const_iterator it = drop_counters.begin();
             it != drop_counters.end(); ++it)
        {
            char buf[96];
            snprintf(buf, sizeof(buf), " %s=%llu", it->first.c_str(), (unsigned long long)it->second);
            msg += buf;
        }
        msg += "\n";
        Logf(LOG_NORMAL, "%s", msg.c_str());
        drop_counters.clear();
        drop_summary_last_ms = now;
    };
    auto allow_msg = [&](int fd, uint16_t msg_type) -> bool {
        PeerRateState& rs = get_rate(fd);
        const uint64_t n = now_ms();
        if (rs.quarantine_until_ms > n)
            return false;
        const double dt = (n > rs.last_ms) ? ((double)(n - rs.last_ms) / 1000.0) : 0.0;
        rs.last_ms = n;
        rs.tokens_sync = std::min(40.0, rs.tokens_sync + dt * 10.0);
        rs.tokens_tx = std::min(30.0, rs.tokens_tx + dt * 8.0);
        rs.tokens_consensus = std::min(60.0, rs.tokens_consensus + dt * 6.0);
        double* bucket = &rs.tokens_sync;
        double cost = 1.0;
        if (msg_type == WIRE_MSG_TX)
        {
            bucket = &rs.tokens_tx;
            cost = 1.0;
        }
        else if (msg_type == WIRE_MSG_PROPOSE || msg_type == WIRE_MSG_VOTE || msg_type == WIRE_MSG_COMMIT)
        {
            bucket = &rs.tokens_consensus;
            cost = (msg_type == WIRE_MSG_COMMIT) ? 4.0 : 2.0;
        }
        if (*bucket < cost)
        {
            // Rate-limit should protect resources, but by itself should not
            // escalate to quarantine. No ban-score increment here.
            return false;
        }
        *bucket -= cost;
        return true;
    };
    reactor.SetMessageHandler([&](int peer_fd, const WireEnvelope& env) {
        if (env.payload_len != env.payload.size())
        {
            printf("drop malformed payload_len_mismatch fd=%d\n", peer_fd);
            penalize_peer(peer_fd, 5, "payload_len_mismatch");
            return;
        }
        if (env.msg_type > WIRE_MSG_HELLO_AUTH)
        {
            printf("drop malformed msg_type=%u fd=%d\n", (unsigned)env.msg_type, peer_fd);
            penalize_peer(peer_fd, 5, "unknown_msg_type");
            return;
        }
        if (!allow_msg(peer_fd, env.msg_type))
        {
            note_drop("rate_limited");
            return;
        }
        if (env.msg_type == WIRE_MSG_HELLO)
        {
            if (env.payload.size() != 32)
            {
                printf("drop hello bad_size fd=%d\n", peer_fd);
                penalize_peer(peer_fd, 10, "hello_bad_size");
                reactor.Disconnect(peer_fd);
                return;
            }
            Bytes32 remote_id;
            memcpy(remote_id.v, &env.payload[0], 32);
            bool zero = true;
            for (int i = 0; i < 32; ++i)
                if (remote_id.v[i] != 0)
                    zero = false;
            if (zero || memcmp(remote_id.v, signer_id.v, 32) == 0)
            {
                printf("drop hello invalid_id fd=%d\n", peer_fd);
                penalize_peer(peer_fd, 10, "hello_invalid_id");
                reactor.Disconnect(peer_fd);
                return;
            }
            const std::string node_key((const char*)remote_id.v, 32);
            {
                std::map<std::string, uint64_t>::const_iterator it_cd = duplicate_node_cooldown_until_ms.find(node_key);
                if (it_cd != duplicate_node_cooldown_until_ms.end() && it_cd->second > now_ms())
                {
                    note_drop("hello_duplicate_cooldown");
                    metric_handshake_cooldown_hits += 1;
                    reactor.Disconnect(peer_fd);
                    return;
                }
            }
            PeerPenaltyPersist& pnode = persist_penalty_by_node[node_key];
            decay_persist(&pnode);
            if (pnode.quarantine_until_ms > now_ms())
            {
                printf("drop hello quarantined_node fd=%d\n", peer_fd);
                reactor.Disconnect(peer_fd);
                return;
            }
            std::string ep = reactor.PeerEndpoint(peer_fd);
            if (!ep.empty())
            {
                std::map<std::string, uint64_t>::const_iterator it_ep_cd = duplicate_endpoint_cooldown_until_ms.find(ep);
                if (it_ep_cd != duplicate_endpoint_cooldown_until_ms.end() && it_ep_cd->second > now_ms())
                {
                    note_drop("hello_duplicate_cooldown");
                    metric_handshake_cooldown_hits += 1;
                    reactor.Disconnect(peer_fd);
                    return;
                }
                PeerPenaltyPersist& pep = persist_penalty_by_endpoint[ep];
                decay_persist(&pep);
                if (pep.quarantine_until_ms > now_ms())
                {
                    printf("drop hello quarantined_endpoint fd=%d\n", peer_fd);
                    reactor.Disconnect(peer_fd);
                    return;
                }
            }
            std::map<std::string, int>::const_iterator it_existing = peer_fd_by_node_id.find(node_key);
            if (it_existing != peer_fd_by_node_id.end() && it_existing->second != peer_fd)
            {
                if (reactor.PeerEndpoint(it_existing->second).empty())
                {
                    peer_fd_by_node_id.erase(node_key);
                }
            }
            it_existing = peer_fd_by_node_id.find(node_key);
            if (it_existing != peer_fd_by_node_id.end() && it_existing->second != peer_fd)
            {
                note_drop("hello_peer_id_collision");
                const int existing_fd = it_existing->second;
                const std::string existing_ep = reactor.PeerEndpoint(existing_fd);
                const std::string incoming_ep = reactor.PeerEndpoint(peer_fd);

                // Deterministic tie-break for dual legs to the same peer-id:
                // prefer lexicographically smaller endpoint; tie-break on lower fd.
                // This avoids ambiguous keep/drop behavior across reconnect churn.
                bool keep_incoming = false;
                if (!incoming_ep.empty() && !existing_ep.empty())
                {
                    if (incoming_ep < existing_ep)
                        keep_incoming = true;
                    else if (incoming_ep == existing_ep && peer_fd < existing_fd)
                        keep_incoming = true;
                }
                else if (!incoming_ep.empty() && existing_ep.empty())
                {
                    keep_incoming = true;
                }
                else if (incoming_ep.empty() && existing_ep.empty() && peer_fd < existing_fd)
                {
                    keep_incoming = true;
                }

                const uint64_t hold_ms = now_ms() + 30000ULL;
                duplicate_node_cooldown_until_ms[node_key] = hold_ms;
                if (!incoming_ep.empty())
                    duplicate_endpoint_cooldown_until_ms[incoming_ep] = hold_ms;
                if (!existing_ep.empty())
                    duplicate_endpoint_cooldown_until_ms[existing_ep] = hold_ms;

                if (keep_incoming)
                {
                    metric_handshake_kept_leg += 1;
                    metric_handshake_dropped_leg += 1;
                    peer_fd_by_node_id.erase(node_key);
                    reactor.Disconnect(existing_fd);
                }
                else
                {
                    metric_handshake_dropped_leg += 1;
                    reactor.Disconnect(peer_fd);
                    return;
                }
            }
            peer_pending_node_id_by_fd[peer_fd] = remote_id;
            Bytes32 challenge;
            std::vector<uint8_t> chm;
            WriteU64LE(&chm, (uint64_t)peer_fd);
            WriteU64LE(&chm, now_ms());
            chm.insert(chm.end(), signer_id.v, signer_id.v + 32);
            chm.insert(chm.end(), remote_id.v, remote_id.v + 32);
            if (!Sha256(chm, &challenge))
            {
                reactor.Disconnect(peer_fd);
                return;
            }
            peer_challenge_by_fd[peer_fd] = challenge;
            std::vector<uint8_t> cp;
            if (!SerializeHelloChallengePayload(challenge, &cp))
                return;
            WireEnvelope out;
            out.magic = WireMagicMainnet();
            out.version = 1;
            out.msg_type = WIRE_MSG_HELLO_CHALLENGE;
            out.payload_len = (uint32_t)cp.size();
            out.unix_ms = 0;
            out.payload_hash = Bytes32();
            out.payload.swap(cp);
            (void)reactor.SendTo(peer_fd, out);
            return;
        }
        if (env.msg_type == WIRE_MSG_HELLO_CHALLENGE)
        {
            Bytes32 challenge;
            if (!ParseHelloChallengePayload(env.payload, &challenge))
            {
                penalize_peer(peer_fd, 8, "hello_challenge_parse_failed");
                reactor.Disconnect(peer_fd);
                return;
            }
            std::vector<uint8_t> m;
            if (!build_auth_sign_bytes(challenge, signer_id, &m))
                return;
            std::vector<uint8_t> sig;
            if (!crypto->SignEd25519(signer_priv, m.empty() ? NULL : &m[0], m.size(), &sig))
                return;
            std::vector<uint8_t> ap;
            if (!SerializeHelloAuthPayload(signer_id, challenge, sig, &ap))
                return;
            WireEnvelope out;
            out.magic = WireMagicMainnet();
            out.version = 1;
            out.msg_type = WIRE_MSG_HELLO_AUTH;
            out.payload_len = (uint32_t)ap.size();
            out.unix_ms = 0;
            out.payload_hash = Bytes32();
            out.payload.swap(ap);
            (void)reactor.SendTo(peer_fd, out);
            return;
        }
        if (env.msg_type == WIRE_MSG_HELLO_AUTH)
        {
            Bytes32 node_id;
            Bytes32 challenge;
            std::vector<uint8_t> sig;
            if (!ParseHelloAuthPayload(env.payload, &node_id, &challenge, &sig))
            {
                penalize_peer(peer_fd, 10, "hello_auth_parse_failed");
                reactor.Disconnect(peer_fd);
                return;
            }
            std::map<int, Bytes32>::const_iterator itp = peer_pending_node_id_by_fd.find(peer_fd);
            std::map<int, Bytes32>::const_iterator itc = peer_challenge_by_fd.find(peer_fd);
            if (itp == peer_pending_node_id_by_fd.end() || itc == peer_challenge_by_fd.end())
            {
                penalize_peer(peer_fd, 10, "hello_auth_unexpected");
                reactor.Disconnect(peer_fd);
                return;
            }
            if (memcmp(itp->second.v, node_id.v, 32) != 0 || memcmp(itc->second.v, challenge.v, 32) != 0)
            {
                penalize_peer(peer_fd, 10, "hello_auth_mismatch");
                reactor.Disconnect(peer_fd);
                return;
            }
            std::vector<uint8_t> m;
            if (!build_auth_sign_bytes(challenge, node_id, &m))
            {
                reactor.Disconnect(peer_fd);
                return;
            }
            if (!crypto->VerifyEd25519(node_id.v,
                                       m.empty() ? NULL : &m[0],
                                       m.size(),
                                       sig.empty() ? NULL : &sig[0],
                                       sig.size()))
            {
                penalize_peer(peer_fd, 12, "hello_auth_bad_sig");
                reactor.Disconnect(peer_fd);
                return;
            }
            peer_pending_node_id_by_fd.erase(peer_fd);
            peer_challenge_by_fd.erase(peer_fd);
            peer_node_id_by_fd[peer_fd] = node_id;
            peer_fd_by_node_id[std::string((const char*)node_id.v, 32)] = peer_fd;
            std::string ep = reactor.PeerEndpoint(peer_fd);
            if (IsValidEndpoint(ep))
            {
                reactor.AddPeer(ep);
                peer_last_seen_round[ep] = last_committed_round;
            }
            PersistKnownPeers();
            BroadcastSyncStatus();
            std::vector<std::string> advertise = reactor.KnownPeers();
            if (!cfg.public_endpoint.empty())
                advertise.push_back(cfg.public_endpoint);
            CanonicalizePeerList(&advertise);
            std::vector<uint8_t> sign_msg;
            if (!BuildPeerListSignBytes(last_committed_round, signer_id, advertise, &sign_msg))
                return;
            std::vector<uint8_t> psig;
            if (!crypto->SignEd25519(signer_priv,
                                     sign_msg.empty() ? NULL : &sign_msg[0],
                                     sign_msg.size(),
                                     &psig))
            {
                return;
            }
            std::vector<uint8_t> p;
            if (SerializePeerListPayload(last_committed_round, signer_id, advertise, psig, &p))
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
        if (!peer_node_id_by_fd.count(peer_fd))
        {
            if (env.msg_type == WIRE_MSG_SYNC_STATUS)
            {
                // Joiners may emit sync status during handshake churn; ignore until authenticated.
                return;
            }
            note_drop("unauthenticated_message");
            // Close unauthenticated noisy leg without score escalation.
            reactor.Disconnect(peer_fd);
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
                std::map<std::string, uint64_t>::iterator it_seen = peer_last_seen_round.find(peers[i]);
                if (it_seen == peer_last_seen_round.end() || advertised_round > it_seen->second)
                    peer_last_seen_round[peers[i]] = advertised_round;
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
                std::map<int, uint64_t>::iterator it_log = peer_last_lower_round_log_local.find(peer_fd);
                bool should_log = (it_log == peer_last_lower_round_log_local.end());
                if (!should_log)
                {
                    const uint64_t prev_local = it_log->second;
                    // Rate limit repeated lower-round logs from same peer.
                    should_log = (last_committed_round >= prev_local + 10);
                }
                if (should_log)
                {
                    printf("ignore peer=%d lower_round=%llu local=%llu\n",
                           peer_fd,
                           (unsigned long long)peer_round,
                           (unsigned long long)last_committed_round);
                    peer_last_lower_round_log_local[peer_fd] = last_committed_round;
                }
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
        if (env.msg_type == WIRE_MSG_TX)
        {
            SpendTx tx;
            if (!ParseSpendTxSubmitPayload(env.payload, &tx))
            {
                printf("drop tx parse_failed\n");
                return;
            }
            std::string mem_err;
            if (!mempool.AddSpend(tx, &mem_err))
            {
                printf("drop tx add_failed reason=%s\n", mem_err.c_str());
                return;
            }
            printf("tx accepted spends_mempool=%zu\n", mempool.SpendCount());
            // Gossip accepted tx; duplicates are dropped by mempool txid dedup.
            (void)reactor.Broadcast(env);
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
            if (!EnsureEpochTransitionForRound(batch.round, "propose"))
            {
                printf("drop propose epoch_transition_invalid round=%llu\n",
                       (unsigned long long)batch.round);
                return;
            }
            if (last_committed_round == 0 &&
                !cfg.peers.empty() &&
                batch.round <= economics_policy.genesis_bootstrap_rounds &&
                !batch.mints.empty() &&
                !IsValidatorForRound(batch.mints[0].miner_pubkey, batch.round))
            {
                std::vector<Validator> bootstrap_vals(1);
                bootstrap_vals[0].validator_id = batch.mints[0].miner_pubkey;
                bootstrap_vals[0].voting_power = 1;
                PowLotteryValidatorSet bootstrap_set(kRuntimeEpochLength);
                if (bootstrap_set.InstallEpoch(0, bootstrap_vals))
                {
                    vset = bootstrap_set;
                    printf("bootstrap_validator_set_adopted proposer=%s round=%llu\n",
                           Hex32(batch.mints[0].miner_pubkey).c_str(),
                           (unsigned long long)batch.round);
                }
            }
            if (batch.mints.empty())
            {
                printf("drop propose unauthorized_proposer round=%llu\n",
                       (unsigned long long)batch.round);
                return;
            }
            if (!engine.Propose(batch))
            {
                printf("drop propose invalid code=%d msg=%s\n",
                       (int)engine.last_reject_code(),
                       engine.last_reject_message().c_str());
                return;
            }
            if (!IsValidatorForRound(batch.mints[0].miner_pubkey, batch.round))
            {
                printf("pow_candidate_accepted miner=%s round=%llu batch=%s\n",
                       Hex32(batch.mints[0].miner_pubkey).c_str(),
                       (unsigned long long)batch.round,
                       Hex32(batch.batch_hash).c_str());
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
            uint8_t local_vote_type = 0;
            if (!ResolveVoteEligibilityForRound(signer_id, batch.round, &local_vote_type))
            {
                printf("sync_only skip_vote round=%llu\n",
                       (unsigned long long)batch.round);
                return;
            }
            vote.validator_id = signer_id;
            vote.eligibility_type = local_vote_type;
            std::vector<uint8_t> m;
            WriteU64LE(&m, vote.round);
            m.insert(m.end(), vote.batch_hash.v, vote.batch_hash.v + 32);
            m.insert(m.end(), vote.validator_id.v, vote.validator_id.v + 32);
            m.push_back(vote.eligibility_type);
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
            if (!EnsureEpochTransitionForRound(vote.round, "vote"))
            {
                printf("drop vote epoch_transition_invalid round=%llu\n",
                       (unsigned long long)vote.round);
                return;
            }
            uint8_t expected_vote_type = 0;
            if (!ResolveVoteEligibilityForRound(vote.validator_id, vote.round, &expected_vote_type))
            {
                printf("drop vote unauthorized_voter round=%llu\n",
                       (unsigned long long)vote.round);
                return;
            }
            if (vote.eligibility_type != expected_vote_type)
            {
                printf("drop vote eligibility_mismatch round=%llu got=%u expected=%u\n",
                       (unsigned long long)vote.round,
                       (unsigned)vote.eligibility_type,
                       (unsigned)expected_vote_type);
                return;
            }
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
                std::set<std::string> pow_recent_ids;
                BuildPowEligibleIdSetForRound(itb->second.round, &pow_recent_ids);
                if (!HasSupermajorityPowerTyped(epoch, qc, pow_recent_ids, 1))
                    return;
            }
            if (!(IsValidatorForRound(signer_id, itb->second.round) || IsPowEligibleForRound(signer_id, itb->second.round)))
            {
                printf("sync_only skip_commit_broadcast round=%llu\n",
                       (unsigned long long)itb->second.round);
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
            if (!EnsureEpochTransitionForRound(batch.round, "commit"))
            {
                printf("drop commit epoch_transition_invalid round=%llu\n",
                       (unsigned long long)batch.round);
                return;
            }
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
                std::set<std::string> pow_recent_ids;
                BuildPowEligibleIdSetForRound(batch.round, &pow_recent_ids);
                if (!VerifyQuorumCertificateTyped(epoch, qc, batch.round, batch.batch_hash, pow_recent_ids, 1, vote_verifier))
                {
                    printf("drop commit qc_invalid\n");
                    return;
                }
            }
            if (!engine.Commit(batch, qc))
            {
                printf("drop commit invalid code=%d msg=%s\n",
                       (int)engine.last_reject_code(),
                       engine.last_reject_message().c_str());
                return;
            }
            if (!AppendCommitPayloadCacheDedup(commit_payload_cache, env.payload))
                printf("cache_append_failed source=wire_commit round=%llu\n", (unsigned long long)batch.round);
            last_committed_round = batch.round;
            last_progress_round = last_committed_round;
            last_progress_time = time(NULL);
            known_batches.erase(Bytes32Key(batch.batch_hash));
            known_votes.erase(Bytes32Key(batch.batch_hash));
            known_vote_ids.erase(Bytes32Key(batch.batch_hash));
            const uint64_t minted = SumBatchMintValue(batch);
            const uint64_t fees = SumBatchFees(batch);
            const uint64_t subsidy = MintSubsidyForRound(batch.round, economics_policy);
            const std::string miner_hex = batch.mints.empty() ? "-" : Hex32(batch.mints[0].miner_pubkey);
            const std::string target_hex = batch.mints.empty() ? "-" : Hex32(batch.mints[0].target);
            printf("commit ok round=%llu spends=%zu mints=%zu minted=%llu fees=%llu subsidy=%llu miner=%s target=%s\n",
                   (unsigned long long)batch.round,
                   batch.spends.size(),
                   batch.mints.size(),
                   (unsigned long long)minted,
                   (unsigned long long)fees,
                   (unsigned long long)subsidy,
                   miner_hex.c_str(),
                   target_hex.c_str());
            BroadcastSyncStatus();
        }
    });
    if (!reactor.Start(&err))
    {
        printf("p2p_start_error: %s\n", err.c_str());
        return 7;
    }

    Logf(LOG_NORMAL, "[BOOT] node_started port=%u data_dir=%s peers=%zu duration_sec=%d\n",
           (unsigned)cfg.bind_port,
           cfg.data_dir.c_str(),
           cfg.peers.size(),
           cfg.duration_sec);
    Logf(LOG_NORMAL, "[BOOT] network_magic=0x%08x\n", (unsigned)cfg.network_magic);
    Logf(LOG_NORMAL, "[BOOT] validator_set size=%zu\n", vals.size());
    Logf(LOG_NORMAL, "[BOOT] autopropose enabled=%d interval_sec=%d\n", cfg.autopropose, cfg.autopropose_interval_sec);
    Logf(LOG_NORMAL, "[BOOT] joiner_mode=%d\n", cfg.joiner_mode);
    Logf(LOG_NORMAL, "[BOOT] log_level=%s\n", cfg.log_level.c_str());
    Logf(LOG_NORMAL, "[BOOT] commit_recovery last_round=%llu\n", (unsigned long long)last_committed_round);
    Logf(LOG_NORMAL, "[BOOT] sync_tip round=%llu\n", (unsigned long long)synced_last_round);
    Logf(LOG_NORMAL, "[BOOT] sync_lag local=%llu synced=%llu lag=%llu cache_entries=%zu\n",
           (unsigned long long)last_committed_round,
           (unsigned long long)synced_last_round,
           (unsigned long long)((synced_last_round > last_committed_round) ? (synced_last_round - last_committed_round) : 0),
           CountCommitPayloadCacheEntries(commit_payload_cache));
    BroadcastSyncStatus();

    time_t start = time(NULL);
    time_t last_sync_tick = start;
    time_t last_autopropose_tick = start;
    time_t last_log_rotate_tick = start;
    int dynamic_autopropose_interval_sec = cfg.autopropose_interval_sec > 0 ? cfg.autopropose_interval_sec : 1;
    size_t dynamic_max_spends_per_round = economics_policy.max_spends_per_round;
    while (true)
    {
        reactor.PollOnce();
        const int base_interval_sec = cfg.autopropose_interval_sec > 0 ? cfg.autopropose_interval_sec : 1;
        const uint64_t lag_now = (synced_last_round > last_committed_round) ? (synced_last_round - last_committed_round) : 0;
        const time_t now = time(NULL);
        const int no_progress_sec = (int)(now - last_progress_time);
        int target_interval_sec = base_interval_sec;
        if (peer_last_round.size() > 8)
            target_interval_sec += base_interval_sec / 2;
        if (peer_last_round.size() > 64)
            target_interval_sec += base_interval_sec;
        if (lag_now > 0)
            target_interval_sec += 1;
        if (no_progress_sec > (base_interval_sec * 3))
        {
            int backoff = no_progress_sec / base_interval_sec;
            if (backoff < 1)
                backoff = 1;
            target_interval_sec += backoff;
        }
        const int max_interval_sec = base_interval_sec * 6;
        if (target_interval_sec > max_interval_sec)
            target_interval_sec = max_interval_sec;
        if (target_interval_sec < 1)
            target_interval_sec = 1;
        if (target_interval_sec != dynamic_autopropose_interval_sec)
        {
            dynamic_autopropose_interval_sec = target_interval_sec;
            Logf(LOG_NORMAL, "[CTRL] round_interval now=%d base=%d peers=%zu lag=%llu no_progress_sec=%d last_progress_round=%llu\n",
                   dynamic_autopropose_interval_sec,
                   base_interval_sec,
                   peer_last_round.size(),
                   (unsigned long long)lag_now,
                   no_progress_sec,
                   (unsigned long long)last_progress_round);
        }

        size_t target_max_spends = economics_policy.max_spends_per_round;
        if (peer_last_round.size() > 8)
            target_max_spends = (target_max_spends * 3) / 4;
        if (peer_last_round.size() > 64)
            target_max_spends = target_max_spends / 2;
        if (lag_now > 0)
            target_max_spends = (target_max_spends * 3) / 4;
        if (no_progress_sec > (base_interval_sec * 3))
            target_max_spends = target_max_spends / 2;
        const size_t kMinDynamicSpends = 16;
        if (target_max_spends < kMinDynamicSpends)
            target_max_spends = kMinDynamicSpends;
        if (target_max_spends > economics_policy.max_spends_per_round)
            target_max_spends = economics_policy.max_spends_per_round;
        if (target_max_spends != dynamic_max_spends_per_round)
        {
            dynamic_max_spends_per_round = target_max_spends;
            Logf(LOG_NORMAL, "[CTRL] payload_limit max_spends=%zu base=%zu peers=%zu lag=%llu no_progress_sec=%d\n",
                   dynamic_max_spends_per_round,
                   economics_policy.max_spends_per_round,
                   peer_last_round.size(),
                   (unsigned long long)lag_now,
                   no_progress_sec);
        }

        const bool have_peers = !peer_last_round.empty();
        const bool is_synced_or_standalone =
            (last_committed_round >= synced_last_round) &&
            (!have_peers || synced_last_round > 0);
        const uint64_t target_round = last_committed_round + 1;
        const bool proposer_eligible =
            IsValidatorForRound(signer_id, target_round) ||
            IsPowEligibleForRound(signer_id, target_round);
        const bool joiner_admission_ok = (cfg.joiner_mode == 0) || proposer_eligible;
        if (cfg.autopropose != 0 && !joiner_admission_ok)
            Logf(LOG_DEBUG, "joiner_gate skip_autopropose round=%llu eligible=%d synced=%llu local=%llu\n",
                 (unsigned long long)target_round,
                 proposer_eligible ? 1 : 0,
                 (unsigned long long)synced_last_round,
                 (unsigned long long)last_committed_round);
        if (cfg.autopropose != 0 &&
            is_synced_or_standalone &&
            joiner_admission_ok &&
            (time(NULL) - last_autopropose_tick) >= dynamic_autopropose_interval_sec)
        {
            RoundBatch batch;
            if (!EnsureEpochTransitionForRound(target_round, "autopropose"))
            {
                printf("drop autopropose epoch_transition_invalid round=%llu\n",
                       (unsigned long long)target_round);
                continue;
            }
            bool have_pending = GetPendingRound(target_round, &batch);
            if (!have_pending)
            {
                batch.round = target_round;
                std::vector<SpendTx> drained_spends = mempool.DrainSpends(dynamic_max_spends_per_round);
                batch.spends = drained_spends;
                MintTx mint;
                const uint64_t subsidy = MintSubsidyForRound(batch.round, economics_policy);
                uint64_t mint_budget = subsidy;
                uint64_t reserve_budget = 0;
                if (store.ReadMintBudget(&reserve_budget))
                {
                    if (mint_budget > reserve_budget)
                        mint_budget = reserve_budget;
                }
                mint.output.value = mint_budget;
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
                mint.miner_pubkey = signer_id;
                batch.mints.push_back(mint);
                Logf(LOG_NORMAL, "[AUTO] prepare round=%llu subsidy=%llu tax_ppm=%llu burn_refill=%llu reserve=%llu mint=%llu target=%s miner=%s\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)subsidy,
                       (unsigned long long)TransferTaxPpmForRound(batch.round, economics_policy),
                       (unsigned long long)SumBatchFees(batch),
                       (unsigned long long)reserve_budget,
                       (unsigned long long)mint.output.value,
                       Hex32(mint.target).c_str(),
                       Hex32(mint.miner_pubkey).c_str());

                // Bitcoin-like loop: try many nonces each interval, stop when target is met
                // or when we hit bounded CPU/work limits for this tick.
                const uint64_t pow_start_ms = NowMonotonicMs();
                const uint64_t pow_time_budget_ms = 1500; // keep node responsive
                const uint64_t pow_max_attempts = 200000; // hard cap per interval
                uint64_t pow_attempts = 0;
                bool pow_found = false;
                uint64_t nonce_cursor = ((uint64_t)time(NULL) << 32) ^ ((uint64_t)getpid() << 16) ^ batch.round;
                while (pow_attempts < pow_max_attempts)
                {
                    const uint64_t now_ms = NowMonotonicMs();
                    if (now_ms > pow_start_ms && (now_ms - pow_start_ms) >= pow_time_budget_ms)
                        break;

                    MintTx& work_mint = batch.mints[0];
                    work_mint.mint_nonce = nonce_cursor++;
                    work_mint.signature = BuildMintSigLocal(*crypto, signer_priv, work_mint);
                    if (!BuildBatchHashLocal(batch, &batch.batch_hash))
                    {
                        Logf(LOG_NORMAL, "[AUTO][REJECT] round=%llu stage=batch_hash reason=build_batch_hash_failed\n",
                               (unsigned long long)batch.round);
                        break;
                    }
                    ++pow_attempts;
                    if (memcmp(batch.batch_hash.v, work_mint.target.v, 32) <= 0)
                    {
                        pow_found = true;
                        break;
                    }
                }
                const uint64_t pow_elapsed_ms = (NowMonotonicMs() >= pow_start_ms) ? (NowMonotonicMs() - pow_start_ms) : 0;
                const uint64_t pow_hps = (pow_elapsed_ms > 0) ? ((pow_attempts * 1000ULL) / pow_elapsed_ms) : 0;
                if (!pow_found)
                {
                    Logf(LOG_NORMAL, "[POW] round=%llu status=not_found attempts=%llu elapsed_ms=%llu rate_hps=%llu\n",
                           (unsigned long long)batch.round,
                           (unsigned long long)pow_attempts,
                           (unsigned long long)pow_elapsed_ms,
                           (unsigned long long)pow_hps);
                    for (size_t i = 0; i < drained_spends.size(); ++i)
                    {
                        std::string readd_err;
                        (void)mempool.AddSpend(drained_spends[i], &readd_err);
                    }
                    last_autopropose_tick = time(NULL);
                    continue;
                }
                Logf(LOG_NORMAL, "[POW] round=%llu status=found attempts=%llu elapsed_ms=%llu rate_hps=%llu nonce=%llu hash=%s\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)pow_attempts,
                       (unsigned long long)pow_elapsed_ms,
                       (unsigned long long)pow_hps,
                       (unsigned long long)batch.mints[0].mint_nonce,
                       Hex32(batch.batch_hash).c_str());
                if (!engine.Propose(batch))
                {
                    Logf(LOG_NORMAL, "[AUTO][REJECT] round=%llu stage=propose code=%d reason=%s\n",
                           (unsigned long long)batch.round,
                           (int)engine.last_reject_code(),
                           engine.last_reject_message().c_str());
                    for (size_t i = 0; i < drained_spends.size(); ++i)
                    {
                        std::string readd_err;
                        (void)mempool.AddSpend(drained_spends[i], &readd_err);
                    }
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
                    uint8_t local_vote_type = 0;
                    if (!ResolveVoteEligibilityForRound(signer_id, batch.round, &local_vote_type))
                    {
                        printf("sync_only skip_vote round=%llu\n",
                               (unsigned long long)batch.round);
                    }
                    else
                    {
                        vote.validator_id = signer_id;
                        vote.eligibility_type = local_vote_type;
                        std::vector<uint8_t> m;
                        WriteU64LE(&m, vote.round);
                        m.insert(m.end(), vote.batch_hash.v, vote.batch_hash.v + 32);
                        m.insert(m.end(), vote.validator_id.v, vote.validator_id.v + 32);
                        m.push_back(vote.eligibility_type);
                        if (crypto->SignEd25519(signer_priv, m.empty() ? NULL : &m[0], m.size(), &vote.signature))
                        {
                            const std::string k = Bytes32Key(vote.batch_hash);
                            const std::string voter_key((const char*)vote.validator_id.v, 32);
                            if (!known_vote_ids[k].count(voter_key))
                            {
                                known_vote_ids[k].insert(voter_key);
                                known_votes[k].push_back(vote);
                            }
                            QuorumCertificate local_qc;
                            local_qc.round = batch.round;
                            local_qc.batch_hash = batch.batch_hash;
                            local_qc.votes = known_votes[k];
                            bool local_supermajority = true;
                            if (batch.round > economics_policy.genesis_bootstrap_rounds)
                            {
                                ValidatorEpoch epoch;
                                if (!vset.GetEpochForRound(batch.round, &epoch))
                                    local_supermajority = false;
                                else
                                {
                                    std::set<std::string> pow_recent_ids;
                                    BuildPowEligibleIdSetForRound(batch.round, &pow_recent_ids);
                                    local_supermajority = HasSupermajorityPowerTyped(epoch, local_qc, pow_recent_ids, 1);
                                }
                            }
                            if (local_supermajority && batch.round > last_committed_round)
                            {
                                if (engine.Commit(batch, local_qc))
                                {
                                    std::vector<uint8_t> local_commit_payload;
                                    if (!SerializeCommitPayload(batch, local_qc, &local_commit_payload))
                                    {
                                        printf("cache_serialize_failed source=local_commit round=%llu\n",
                                               (unsigned long long)batch.round);
                                    }
                                    else if (!AppendCommitPayloadCacheDedup(commit_payload_cache, local_commit_payload))
                                    {
                                        printf("cache_append_failed source=local_commit round=%llu\n",
                                               (unsigned long long)batch.round);
                                    }
                                    last_committed_round = batch.round;
                                    last_progress_round = last_committed_round;
                                    last_progress_time = time(NULL);
                                    known_batches.erase(Bytes32Key(batch.batch_hash));
                                    known_votes.erase(Bytes32Key(batch.batch_hash));
                                    known_vote_ids.erase(Bytes32Key(batch.batch_hash));
                                    const uint64_t minted = SumBatchMintValue(batch);
                                    const uint64_t fees = SumBatchFees(batch);
                                    const uint64_t subsidy = MintSubsidyForRound(batch.round, economics_policy);
                                    const std::string miner_hex = batch.mints.empty() ? "-" : Hex32(batch.mints[0].miner_pubkey);
                                    const std::string target_hex = batch.mints.empty() ? "-" : Hex32(batch.mints[0].target);
                                    Logf(LOG_NORMAL, "[COMMIT] ok round=%llu spends=%zu mints=%zu minted=%llu fees=%llu subsidy=%llu miner=%s target=%s\n",
                                           (unsigned long long)batch.round,
                                           batch.spends.size(),
                                           batch.mints.size(),
                                           (unsigned long long)minted,
                                           (unsigned long long)fees,
                                           (unsigned long long)subsidy,
                                           miner_hex.c_str(),
                                           target_hex.c_str());
                                    BroadcastSyncStatus();
                                }
                                else
                                {
                                    Logf(LOG_NORMAL, "[COMMIT][REJECT] round=%llu code=%d reason=%s\n",
                                           (unsigned long long)batch.round,
                                           (int)engine.last_reject_code(),
                                           engine.last_reject_message().c_str());
                                    // Prevent endless rebroadcast of a poisoned pending batch.
                                    known_batches.erase(Bytes32Key(batch.batch_hash));
                                    known_votes.erase(Bytes32Key(batch.batch_hash));
                                    known_vote_ids.erase(Bytes32Key(batch.batch_hash));
                                }
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
                }
                else
                {
                    Logf(LOG_DEBUG, "[AUTO] vote_skip round=%llu reason=validate_and_vote_failed\n",
                           (unsigned long long)batch.round);
                }
                Logf(LOG_DEBUG, "[AUTO] broadcast round=%llu spends=%zu mints=%zu fees=%llu minted=%llu\n",
                       (unsigned long long)batch.round,
                       batch.spends.size(),
                       batch.mints.size(),
                       (unsigned long long)SumBatchFees(batch),
                       (unsigned long long)SumBatchMintValue(batch));
            }
            last_autopropose_tick = time(NULL);
        }
        const int sync_period_sec = (synced_last_round > last_committed_round) ? 1 : 5;
        if ((time(NULL) - last_sync_tick) >= sync_period_sec)
        {
            flush_drop_summary(false);
            BroadcastSyncStatus();
            TryCatchUpFromCache();
            PersistKnownPeers();
            const uint64_t reg_sz = FileSizeBytes(registry);
            const uint64_t log_sz = FileSizeBytes(commitlog);
            const uint64_t cache_sz = FileSizeBytes(commit_payload_cache);
            const uint64_t synclog_sz = FileSizeBytes(sync_cache);
            const uint64_t utxo_est = reg_sz / 264ULL;
            Logf(LOG_DEBUG, "[SYNC] tick local=%llu synced=%llu lag=%llu cache_entries=%zu\n",
                   (unsigned long long)last_committed_round,
                   (unsigned long long)synced_last_round,
                   (unsigned long long)((synced_last_round > last_committed_round) ? (synced_last_round - last_committed_round) : 0),
                   CountCommitPayloadCacheEntries(commit_payload_cache));
            Logf(LOG_DEBUG, "[DISK] registry=%llu commitlog=%llu cache=%llu sync_log=%llu utxo_est=%llu\n",
                   (unsigned long long)reg_sz,
                   (unsigned long long)log_sz,
                   (unsigned long long)cache_sz,
                   (unsigned long long)synclog_sz,
                   (unsigned long long)utxo_est);
            last_sync_tick = time(NULL);
        }
        if ((time(NULL) - last_log_rotate_tick) >= 60)
        {
            const uint64_t commitlog_sz = FileSizeBytes(commitlog);
            const uint64_t synclog_sz = FileSizeBytes(sync_cache);
            const uint64_t kCommitLogMaxBytes = 256ULL * 1024ULL * 1024ULL;
            const uint64_t kSyncLogMaxBytes = 128ULL * 1024ULL * 1024ULL;
            const uint64_t keep_commit_rounds = 200000ULL;
            const uint64_t keep_sync_rounds = 100000ULL;
            if (commitlog_sz > kCommitLogMaxBytes)
            {
                const uint64_t keep_from = (last_committed_round > keep_commit_rounds) ? (last_committed_round - keep_commit_rounds + 1) : 1;
                if (RotateCommitLogWithCheckpoint(commitlog, commitlog_checkpoint, crypto.get(), keep_from))
                    printf("log_rotate_ok file=%s keep_from_round=%llu new_bytes=%llu checkpoint=%s\n",
                           commitlog.c_str(),
                           (unsigned long long)keep_from,
                           (unsigned long long)FileSizeBytes(commitlog),
                           commitlog_checkpoint.c_str());
                else
                    printf("log_rotate_failed file=%s\n", commitlog.c_str());
            }
            if (synclog_sz > kSyncLogMaxBytes)
            {
                const uint64_t keep_from = (synced_last_round > keep_sync_rounds) ? (synced_last_round - keep_sync_rounds + 1) : 1;
                if (RotateCommitLogWithCheckpoint(sync_cache, sync_cache_checkpoint, crypto.get(), keep_from))
                    printf("log_rotate_ok file=%s keep_from_round=%llu new_bytes=%llu checkpoint=%s\n",
                           sync_cache.c_str(),
                           (unsigned long long)keep_from,
                           (unsigned long long)FileSizeBytes(sync_cache),
                           sync_cache_checkpoint.c_str());
                else
                    printf("log_rotate_failed file=%s\n", sync_cache.c_str());
            }
            last_log_rotate_tick = time(NULL);
        }
        if (cfg.duration_sec > 0 && (int)(time(NULL) - start) >= cfg.duration_sec)
            break;
    }

    flush_drop_summary(true);
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

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
#include <stdlib.h>

#include "consensus_round.h"
#include "crypto_backend.h"
#include "drpow/mempool.h"
#include "drpow/node_config.h"
#include "p2p_wire.h"
#include "p2p_reactor.h"
#include "proof_verifier.h"
#include "drpow_params.h"
#include "registry_state_store.h"
#include "drpow/tx_codec.h"

using namespace drpow;

#ifndef DRPOW_BUILD_ID
#define DRPOW_BUILD_ID "unknown"
#endif

enum {
    LOG_QUIET = 0,
    LOG_NORMAL = 1,
    LOG_DEBUG = 2
};

enum {
    ROUND_MODE_MINING = 0,
    ROUND_MODE_VERIFY_VOTE = 1,
    ROUND_MODE_VOTED_LOCKED = 2
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

static uint64_t ParseEnvU64Clamped(const char* name, uint64_t def, uint64_t min_v, uint64_t max_v)
{
    const char* s = getenv(name);
    if (!s || !*s)
        return def;
    char* end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (end == s || (end && *end != '\0'))
        return def;
    uint64_t out = (uint64_t)v;
    if (out < min_v)
        out = min_v;
    if (out > max_v)
        out = max_v;
    return out;
}

static std::string FormatAtomic8(uint64_t units)
{
    static const uint64_t kAtomicPerCoin = 100000000ULL;
    char buf[64];
    const unsigned long long whole = (unsigned long long)(units / kAtomicPerCoin);
    const unsigned long long frac = (unsigned long long)(units % kAtomicPerCoin);
    snprintf(buf, sizeof(buf), "%llu.%08llu", whole, frac);
    return std::string(buf);
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

static bool IsLoopbackEndpoint(const std::string& ep)
{
    return ep.find("127.0.0.1:") == 0 ||
           ep.find("::1:") == 0 ||
           ep.find("[::1]:") == 0;
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
    const char* tag = "DRPOW:peer_list:v1";
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
    if (round == 1)
    {
        *out_target = policy.max_target;
        return true;
    }
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

static uint64_t SumBatchMintValue(const RoundBatch& batch)
{
    uint64_t s = 0;
    for (size_t i = 0; i < batch.mints.size(); ++i)
        s += batch.mints[i].output.value;
    return s;
}

static uint64_t ExpectedMintBudgetForRound(const RegistryStateStore& store,
                                           uint64_t round,
                                           const EconomicsPolicy& economics_policy)
{
    uint64_t expected = MintSubsidyForRound(round, economics_policy);
    uint64_t reserve_budget = 0;
    if (store.ReadMintBudget(&reserve_budget) && reserve_budget < expected)
        expected = reserve_budget;
    return expected;
}

static uint64_t SumBatchFees(const RoundBatch& batch)
{
    uint64_t s = 0;
    for (size_t i = 0; i < batch.spends.size(); ++i)
        s += batch.spends[i].fee;
    return s;
}

static bool ComputeRecordHashV1Local(const RoundCommitRecord& record, Bytes32* out)
{
    if (!out)
        return false;
    std::vector<uint8_t> m;
    const char* tag = "DRPOW:commit_record:v1";
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
    WriteBytes32(&encoded, batch.params_hash);
    WriteU64LE(&encoded, (uint64_t)batch.spends.size());
    for (size_t i = 0; i < batch.spends.size(); ++i)
        SerializeSpendTxCanonical(batch.spends[i], &encoded);
    WriteU64LE(&encoded, (uint64_t)batch.mints.size());
    for (size_t i = 0; i < batch.mints.size(); ++i)
        SerializeMintTxCanonical(batch.mints[i], &encoded);
    return Sha256(encoded, out);
}

static void HalveTargetLocal(const Bytes32& in, Bytes32* out)
{
    if (!out)
        return;
    *out = in;
    uint16_t carry = 0;
    for (int i = 0; i < 32; ++i)
    {
        const uint16_t cur = (uint16_t)(carry * 256u + out->v[i]);
        out->v[i] = (uint8_t)(cur / 2u);
        carry = (uint16_t)(cur % 2u);
    }
}

static bool ComputeProposerPowHashLocal(const RoundBatch& batch,
                                        const Bytes32& parent_root,
                                        Bytes32* out_hash)
{
    if (!out_hash || batch.mints.empty())
        return false;
    std::vector<uint8_t> preimage;
    WriteU64LE(&preimage, batch.round);
    WriteBytes32(&preimage, parent_root);
    WriteBytes32(&preimage, batch.batch_hash);
    WriteBytes32(&preimage, batch.mints[0].miner_pubkey);
    WriteU64LE(&preimage, batch.mints[0].mint_nonce);
    return Sha256(preimage, out_hash);
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

static bool TruncateFilePath(const std::string& path)
{
    std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
    return out.good();
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
    const std::string local_build_id = DRPOW_BUILD_ID;
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
        printf("crypto_backend_select_failed reason=liboqs_required backend=ml_dsa_65 build_hint=USE_LIBOQS=1\n");
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
    Bytes32 params_hash;
    if (!ComputeDrpowParamsHash(&params_hash))
    {
        printf("params_hash_compute_failed\n");
        return 5;
    }
    std::string params_spec_file;
    if (const char* env_spec = getenv("DRPOW_PARAMS_FILE"))
        params_spec_file = env_spec;
    if (params_spec_file.empty())
    {
        if (access("DRPOW_PARAMS.md", R_OK) == 0)
            params_spec_file = "DRPOW_PARAMS.md";
        else if (access("../DRPOW_PARAMS.md", R_OK) == 0)
            params_spec_file = "../DRPOW_PARAMS.md";
    }
    if (params_spec_file.empty())
    {
        printf("params_spec_missing file=DRPOW_PARAMS.md\n");
        return 5;
    }
    Bytes32 params_hash_from_spec;
    std::string params_spec_err;
    if (!ComputeDrpowParamsHashFromSpecFile(params_spec_file.c_str(), &params_hash_from_spec, &params_spec_err))
    {
        printf("params_spec_parse_failed file=%s err=%s\n",
               params_spec_file.c_str(),
               params_spec_err.empty() ? "-" : params_spec_err.c_str());
        return 5;
    }
    if (memcmp(params_hash_from_spec.v, params_hash.v, 32) != 0)
    {
        printf("params_spec_hash_mismatch file=%s spec_hash=%s code_hash=%s\n",
               params_spec_file.c_str(),
               Hex32(params_hash_from_spec).c_str(),
               Hex32(params_hash).c_str());
        return 5;
    }
    Bytes32 signer_id;
    if (!crypto->PublicFromPrivateEd25519(signer_priv, signer_id.v))
    {
        printf("signer_pubkey_derive_failed\n");
        return 6;
    }
    printf("signer_id=%s\n", Hex32(signer_id).c_str());

    Logf(LOG_NORMAL, "[BOOT] consensus_mode=pow_open\n");

    ProofPolicy proof_policy = DefaultProofPolicy();
    BasicProofVerifier proof_verifier(crypto.get(), &proof_policy);
    BasicVoteVerifier vote_verifier(crypto.get());

    EconomicsPolicy economics_policy = DefaultEconomicsPolicy();
    if (cfg.pow_target_prefix_bytes >= 0)
    {
        // Operator override for testnet tuning: set N leading zero bytes in max_target,
        // keep remaining bytes at 0xff (e.g. N=1 => 00ff.., N=2 => 0000ff..).
        memset(economics_policy.max_target.v, 0xff, 32);
        for (int i = 0; i < cfg.pow_target_prefix_bytes; ++i)
            economics_policy.max_target.v[i] = 0x00;
    }

    std::string registry = cfg.data_dir + "/registry.bin";
    std::string commitlog = cfg.data_dir + "/commit.log";
    std::string evidlog = cfg.data_dir + "/evidence.log";

    RegistryStateStore store(registry, commitlog, evidlog, &proof_verifier, crypto.get(), signer_priv, &signer_id);
    ConsensusRoundEngine engine(&store, &vote_verifier, &proof_verifier, &economics_policy);
    Mempool mempool;
    std::map<std::string, RoundBatch> known_batches;
    std::map<std::string, std::vector<Vote> > known_votes;
    std::map<std::string, std::set<std::string> > known_vote_ids;
    std::map<std::string, uint64_t> known_vote_weight_sum;
    std::map<std::string, size_t> qc_gate_last_votes;
    std::map<uint64_t, Bytes32> local_vote_by_round;
    std::map<std::string, Bytes32> remote_vote_target_by_round_voter;
    std::map<uint64_t, Bytes32> committed_batch_by_round;
    std::map<uint64_t, std::string> round_best_batch_key;
    std::map<uint64_t, Bytes32> round_best_batch_score;
    std::map<uint64_t, uint64_t> round_best_batch_vote_weight;
    std::map<uint64_t, uint64_t> round_first_seen_ms;
    std::map<uint64_t, uint64_t> round_last_activity_ms;
    std::map<uint64_t, std::set<std::string> > round_candidate_keys;
    std::map<uint64_t, std::set<std::string> > round_vote_batch_keys;
    std::map<uint64_t, std::map<std::string, TimeoutVote> > timeout_votes_by_round;
    std::set<uint64_t> timeout_qc_rounds;
    std::set<uint64_t> timeout_vote_sent_rounds;
    std::map<int, uint64_t> peer_last_sync_req_sent_ms;
    std::map<int, uint64_t> peer_last_sync_req_from_round;
    double rtt_ewma_ms = 0.0;
    uint64_t rtt_sample_count = 0;
    uint64_t adaptive_proposal_window_ms = 3000ULL;
    uint64_t adaptive_round_timeout_ms = 45000ULL;
    uint64_t finality_depth_rounds = ParseEnvU64Clamped("FINALITY_DEPTH_ROUNDS", 6ULL, 1ULL, 1000000ULL);
    uint64_t reorg_replay_window_rounds = ParseEnvU64Clamped("REORG_REPLAY_WINDOW_ROUNDS", 128ULL, 1ULL, 1000000ULL);
    std::map<uint64_t, int> round_mode_state;
    std::map<uint64_t, std::set<std::string> > branch_candidates_by_round;
    std::map<uint64_t, std::map<std::string, uint64_t> > branch_vote_weight_by_round_batch;
    uint64_t last_committed_round = store.LastVerifiedCommitRound();
    const uint64_t startup_registry_bytes = FileSizeBytes(registry);
    const uint64_t startup_ledger_bytes = FileSizeBytes(registry + ".ledger");
    const uint64_t startup_commitlog_bytes = FileSizeBytes(commitlog);
    bool startup_store_begin_ok = store.Begin();
    if (startup_store_begin_ok)
        store.Rollback();
    const bool startup_store_unhealthy = !startup_store_begin_ok;
    const bool startup_has_persisted_state =
        (startup_registry_bytes > 0 || startup_ledger_bytes > 0 || startup_commitlog_bytes > 0);
    if (last_committed_round == 0 && startup_has_persisted_state &&
        startup_store_unhealthy)
    {
        printf("startup_state_inconsistent data_dir=%s last_round=0 registry_bytes=%llu ledger_bytes=%llu commitlog_bytes=%llu store_begin_ok=%d\n",
               cfg.data_dir.c_str(),
               (unsigned long long)startup_registry_bytes,
               (unsigned long long)startup_ledger_bytes,
               (unsigned long long)startup_commitlog_bytes,
               startup_store_begin_ok ? 1 : 0);
        printf("startup_recovery: resetting local state files and continuing with sync/catchup\n");
        bool reset_ok = true;
        reset_ok = TruncateFilePath(registry) && reset_ok;
        reset_ok = TruncateFilePath(registry + ".ledger") && reset_ok;
        reset_ok = TruncateFilePath(commitlog) && reset_ok;
        reset_ok = TruncateFilePath(evidlog) && reset_ok;
        if (!reset_ok || !store.ReloadFromDisk())
        {
            printf("startup_recovery_failed data_dir=%s\n", cfg.data_dir.c_str());
            printf("startup_hint: clear node state dir or restore matching signer key before restart\n");
            return 7;
        }
        last_committed_round = store.LastVerifiedCommitRound();
        printf("startup_recovery_ok data_dir=%s last_round=%llu\n",
               cfg.data_dir.c_str(),
               (unsigned long long)last_committed_round);
    }
    std::map<int, uint64_t> peer_last_round;
    std::map<int, uint64_t> peer_last_lower_round_log_local;
    std::map<int, uint64_t> peer_last_sync_needed_log_ms;
    time_t last_progress_time = time(NULL);
    uint64_t last_progress_round = last_committed_round;
    const std::string sync_cache = cfg.data_dir + "/sync_commit.log";
    const std::string sync_cache_checkpoint = cfg.data_dir + "/sync_commit.checkpoint";
    const std::string sync_tip_file = cfg.data_dir + "/sync_tip.dat";
    const std::string commit_payload_cache = cfg.data_dir + "/commit_payload_cache.bin";
    const std::string commitlog_checkpoint = cfg.data_dir + "/commit.checkpoint";
    const std::string reorg_snapshot_dir = cfg.data_dir + "/reorg_snapshot";
    const std::string reorg_tmp_dir = cfg.data_dir + "/reorg_tmp";
    uint64_t catchup_target_unavail_round = 0;
    uint64_t catchup_target_unavail_repeats = 0;
    uint64_t force_sync_from_round = 0;
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
    std::function<void(uint64_t)> AdvanceSyncedTipFromCommit = [&](uint64_t committed_round) {
        if (committed_round > synced_last_round)
            synced_last_round = committed_round;
        Bytes32 root;
        if (store.ReadStateRoot(&root))
            synced_state_root = root;
        (void)SaveSyncedTipFile(sync_tip_file, synced_last_round, synced_state_root);
    };
    auto FinalizedRound = [&]() -> uint64_t {
        if (last_committed_round <= finality_depth_rounds)
            return 0;
        return last_committed_round - finality_depth_rounds;
    };
    auto InReplayWindow = [&](uint64_t round) -> bool {
        const uint64_t finalized = FinalizedRound();
        if (round <= finalized)
            return false;
        const uint64_t low = finalized + 1;
        const uint64_t high = finalized + reorg_replay_window_rounds;
        return round >= low && round <= high;
    };

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

    std::function<bool(const Vote&, const Bytes32&, uint64_t*, Bytes32*)> BuildVotePowProof =
        [&](const Vote& vote_base, const Bytes32& target_round, uint64_t* out_nonce, Bytes32* out_hash) {
            if (!out_nonce || !out_hash)
                return false;
            Vote v = vote_base;
            uint64_t nonce = ((uint64_t)time(NULL) << 32) ^ ((uint64_t)getpid() << 16) ^ vote_base.round;
            for (uint64_t i = 0; i < 200000ULL; ++i)
            {
                v.pow_nonce = nonce++;
                std::vector<uint8_t> preimage;
                preimage.push_back('V');
                preimage.push_back('O');
                preimage.push_back('T');
                preimage.push_back('E');
                WriteU64LE(&preimage, v.round);
                preimage.insert(preimage.end(), v.batch_hash.v, v.batch_hash.v + 32);
                preimage.insert(preimage.end(), v.validator_id.v, v.validator_id.v + 32);
                WriteU64LE(&preimage, v.pow_nonce);
                Bytes32 h;
                if (!Sha256(preimage, &h))
                    return false;
                if (memcmp(h.v, target_round.v, 32) <= 0)
                {
                    *out_nonce = v.pow_nonce;
                    *out_hash = h;
                    return true;
                }
            }
            return false;
        };
    std::function<void(uint64_t)> PurgeCommittedPending = [&](uint64_t committed_round) {
        std::vector<std::string> stale_keys;
        stale_keys.reserve(known_batches.size());
        for (std::map<std::string, RoundBatch>::const_iterator it = known_batches.begin(); it != known_batches.end(); ++it)
        {
            if (it->second.round <= committed_round)
                stale_keys.push_back(it->first);
        }
        for (size_t i = 0; i < stale_keys.size(); ++i)
        {
            const std::string& k = stale_keys[i];
            known_batches.erase(k);
            known_votes.erase(k);
            known_vote_ids.erase(k);
            known_vote_weight_sum.erase(k);
            qc_gate_last_votes.erase(k);
        }
        std::vector<uint64_t> stale_rounds;
        for (std::map<uint64_t, std::string>::const_iterator it = round_best_batch_key.begin(); it != round_best_batch_key.end(); ++it)
            if (it->first <= committed_round)
                stale_rounds.push_back(it->first);
        for (size_t i = 0; i < stale_rounds.size(); ++i)
        {
            const uint64_t r = stale_rounds[i];
            round_best_batch_key.erase(r);
            round_best_batch_score.erase(r);
            round_best_batch_vote_weight.erase(r);
            round_first_seen_ms.erase(r);
            round_last_activity_ms.erase(r);
            round_candidate_keys.erase(r);
            round_vote_batch_keys.erase(r);
            timeout_votes_by_round.erase(r);
            timeout_qc_rounds.erase(r);
            timeout_vote_sent_rounds.erase(r);
            local_vote_by_round.erase(r);
            round_mode_state.erase(r);
            branch_candidates_by_round.erase(r);
            branch_vote_weight_by_round_batch.erase(r);
        }
    };
    auto SetRoundMode = [&](uint64_t round, int mode, const char* reason) {
        if (round == 0)
            return;
        round_last_activity_ms[round] = NowMonotonicMs();
        std::map<uint64_t, int>::const_iterator it = round_mode_state.find(round);
        if (it != round_mode_state.end() && it->second == mode)
            return;
        round_mode_state[round] = mode;
        const char* mode_s = "unknown";
        if (mode == ROUND_MODE_MINING)
            mode_s = "mining";
        else if (mode == ROUND_MODE_VERIFY_VOTE)
            mode_s = "verify_vote";
        else if (mode == ROUND_MODE_VOTED_LOCKED)
            mode_s = "voted_locked";
        Logf(LOG_NORMAL, "[ROUND_MODE] round=%llu mode=%s reason=%s\n",
             (unsigned long long)round,
             mode_s,
             reason ? reason : "-");
    };
    auto RoundVoterKey = [&](uint64_t round, const Bytes32& voter) {
        std::string key((const char*)&round, sizeof(round));
        key.append((const char*)voter.v, 32);
        return key;
    };
    auto DynamicMinVotes = [&]() -> size_t {
        return 2;
    };
    auto BuildTimeoutSignMessage = [&](const TimeoutVote& tv, std::vector<uint8_t>* out) -> bool {
        if (!out)
            return false;
        out->clear();
        const char* tag = "DRPOW:timeout_vote:v1";
        while (*tag)
            out->push_back((uint8_t)*tag++);
        WriteU64LE(out, tv.round);
        WriteBytes32(out, tv.validator_id);
        WriteBytes32(out, tv.lock_batch_hash);
        return true;
    };
    auto EnsureLocalVoteForRound = [&](uint64_t round, const Bytes32& batch_hash) -> bool {
        std::map<uint64_t, Bytes32>::const_iterator it = local_vote_by_round.find(round);
        if (it == local_vote_by_round.end())
        {
            local_vote_by_round[round] = batch_hash;
            round_last_activity_ms[round] = NowMonotonicMs();
            SetRoundMode(round, ROUND_MODE_VOTED_LOCKED, "local_vote_emitted");
            return true;
        }
        return memcmp(it->second.v, batch_hash.v, 32) == 0;
    };
    auto RecordRemoteVoteTarget = [&](uint64_t round, const Bytes32& voter, const Bytes32& batch_hash) -> bool {
        const std::string key = RoundVoterKey(round, voter);
        std::map<std::string, Bytes32>::const_iterator it = remote_vote_target_by_round_voter.find(key);
        if (it == remote_vote_target_by_round_voter.end())
        {
            remote_vote_target_by_round_voter[key] = batch_hash;
            return true;
        }
        return memcmp(it->second.v, batch_hash.v, 32) == 0;
    };
    auto IsCommitConflict = [&](uint64_t round, const Bytes32& batch_hash) -> bool {
        std::map<uint64_t, Bytes32>::const_iterator it = committed_batch_by_round.find(round);
        if (it == committed_batch_by_round.end())
            return false;
        return memcmp(it->second.v, batch_hash.v, 32) != 0;
    };
    auto RememberCommitTarget = [&](uint64_t round, const Bytes32& batch_hash) {
        committed_batch_by_round[round] = batch_hash;
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
                if (last_committed_round == 0 && batch.round > 1)
                {
                    // Bootstrap fast-forward for late joiners when peers only have recent
                    // cached payloads. Anchor just before the first available round and
                    // continue deterministic commit verification from there.
                    printf("catchup_fast_forward anchor_from=%llu anchor_to=%llu\n",
                           (unsigned long long)last_committed_round,
                           (unsigned long long)(batch.round - 1));
                    last_committed_round = batch.round - 1;
                    continue;
                }
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
            if (memcmp(batch.params_hash.v, params_hash.v, 32) != 0)
            {
                printf("catchup_break_params_hash_mismatch round=%llu batch=%s local=%s\n",
                       (unsigned long long)batch.round,
                       Hex32(batch.params_hash).c_str(),
                       Hex32(params_hash).c_str());
                break;
            }
            Bytes32 expected_target;
            if (!ComputeExpectedTargetForRoundNode(store, batch.round, economics_policy, &expected_target))
            {
                printf("catchup_break_target_unavailable round=%llu\n",
                       (unsigned long long)batch.round);
                if (catchup_target_unavail_round == batch.round)
                    catchup_target_unavail_repeats += 1;
                else
                {
                    catchup_target_unavail_round = batch.round;
                    catchup_target_unavail_repeats = 1;
                }
                if (catchup_target_unavail_repeats >= 8)
                {
                    const bool purge_ok =
                        TruncateFilePath(sync_cache) &&
                        TruncateFilePath(sync_cache_checkpoint) &&
                        TruncateFilePath(commit_payload_cache);
                    force_sync_from_round = (last_committed_round + 1);
                    printf("catchup_recover target_unavailable_round=%llu repeats=%llu purge_ok=%d request_from=%llu\n",
                           (unsigned long long)batch.round,
                           (unsigned long long)catchup_target_unavail_repeats,
                           purge_ok ? 1 : 0,
                           (unsigned long long)force_sync_from_round);
                    if (purge_ok)
                    {
                        synced_last_round = last_committed_round;
                        (void)SaveSyncedTipFile(sync_tip_file, synced_last_round, synced_state_root);
                    }
                    catchup_target_unavail_repeats = 0;
                }
                break;
            }
            if (!VerifyQuorumCertificatePow(qc,
                                            batch.round,
                                            batch.batch_hash,
                                            expected_target,
                                            DrpowParams::kMinQcWeight,
                                            vote_verifier))
            {
                printf("catchup_break_qc_invalid round=%llu votes=%zu\n",
                       (unsigned long long)batch.round,
                       qc.votes.size());
                break;
            }
            if (!engine.Commit(batch, qc))
            {
                printf("catchup_break_commit_reject round=%llu code=%d reason=%s\n",
                       (unsigned long long)batch.round,
                       (int)engine.last_reject_code(),
                       engine.last_reject_message().empty() ? "-" : engine.last_reject_message().c_str());
                if (engine.last_reject_code() == REJECT_STORE_BEGIN_FAILED && last_committed_round == 0)
                {
                    // Self-heal path: if local chain is still at genesis and store cannot
                    // open a txn, reset local files and reload once, then retry on next loop.
                    const bool cleared =
                        TruncateFilePath(registry) &&
                        TruncateFilePath(registry + ".ledger") &&
                        TruncateFilePath(commitlog) &&
                        TruncateFilePath(evidlog);
                    const bool reloaded = cleared && store.ReloadFromDisk();
                    printf("catchup_store_recover local_round=%llu cleared=%d reloaded=%d\n",
                           (unsigned long long)last_committed_round,
                           cleared ? 1 : 0,
                           reloaded ? 1 : 0);
                }
                break;
            }
            last_committed_round = batch.round;
            last_progress_round = last_committed_round;
            last_progress_time = time(NULL);
            round_last_activity_ms[batch.round] = NowMonotonicMs();
            RememberCommitTarget(batch.round, batch.batch_hash);
            AdvanceSyncedTipFromCommit(last_committed_round);
            PurgeCommittedPending(last_committed_round);
            catchup_target_unavail_repeats = 0;
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

    std::function<bool()> TryReplayReorgWindow = [&]() -> bool {
        if (branch_candidates_by_round.empty())
            return false;
        if (!EnsureDir(reorg_snapshot_dir) || !EnsureDir(reorg_tmp_dir))
            return false;

        std::vector< std::vector<uint8_t> > payloads;
        if (!LoadCommitPayloadCache(commit_payload_cache, &payloads) || payloads.empty())
            return false;

        struct ReplayItem {
            RoundBatch batch;
            QuorumCertificate qc;
            uint64_t weight;
            std::vector<uint8_t> payload;
        };
        std::map<uint64_t, ReplayItem> best_by_round;
        uint64_t max_round_seen = 0;
        for (size_t i = 0; i < payloads.size(); ++i)
        {
            ReplayItem it;
            if (!ParseCommitPayload(payloads[i], &it.batch, &it.qc))
                continue;
            if (it.batch.round == 0)
                continue;
            it.payload = payloads[i];
            uint64_t w = 0;
            for (size_t j = 0; j < it.qc.votes.size(); ++j)
            {
                const uint64_t vw = VotePowWeight(it.qc.votes[j]);
                if (UINT64_MAX - w < vw)
                {
                    w = UINT64_MAX;
                    break;
                }
                w += vw;
            }
            it.weight = w;
            std::map<uint64_t, ReplayItem>::iterator prev = best_by_round.find(it.batch.round);
            if (prev == best_by_round.end() ||
                it.weight > prev->second.weight ||
                (it.weight == prev->second.weight &&
                 Bytes32Key(it.batch.batch_hash) < Bytes32Key(prev->second.batch.batch_hash)))
            {
                best_by_round[it.batch.round] = it;
            }
            if (it.batch.round > max_round_seen)
                max_round_seen = it.batch.round;
        }
        if (best_by_round.empty() || max_round_seen == 0)
            return false;

        const uint64_t finalized = FinalizedRound();
        if (max_round_seen <= last_committed_round)
            return false;
        if (max_round_seen <= finalized)
            return false;
        if (!InReplayWindow(max_round_seen))
            return false;

        // Require a fully contiguous replay sequence from round 1..target.
        for (uint64_t r = 1; r <= max_round_seen; ++r)
        {
            if (!best_by_round.count(r))
                return false;
        }

        const std::string tmp_registry = reorg_tmp_dir + "/registry.bin";
        const std::string tmp_commit = reorg_tmp_dir + "/commit.log";
        const std::string tmp_evd = reorg_tmp_dir + "/evidence.log";
        remove(tmp_registry.c_str());
        remove((tmp_registry + ".ledger").c_str());
        remove(tmp_commit.c_str());
        remove(tmp_evd.c_str());

        RegistryStateStore replay_store(tmp_registry,
                                        tmp_commit,
                                        tmp_evd,
                                        &proof_verifier,
                                        crypto.get(),
                                        signer_priv,
                                        &signer_id);
        ConsensusRoundEngine replay_engine(&replay_store, &vote_verifier, &proof_verifier, &economics_policy);

        for (uint64_t r = 1; r <= max_round_seen; ++r)
        {
            const ReplayItem& it = best_by_round[r];
            if (!replay_engine.Commit(it.batch, it.qc))
            {
                Logf(LOG_NORMAL,
                     "reorg_replay_reject round=%llu code=%d reason=%s\n",
                     (unsigned long long)r,
                     (int)replay_engine.last_reject_code(),
                     replay_engine.last_reject_message().c_str());
                return false;
            }
        }

        if (!store.SaveSnapshot(reorg_snapshot_dir))
            return false;
        if (!replay_store.SaveSnapshot(reorg_tmp_dir))
            return false;
        if (!store.RestoreSnapshot(reorg_tmp_dir))
        {
            (void)store.RestoreSnapshot(reorg_snapshot_dir);
            return false;
        }

        last_committed_round = store.LastVerifiedCommitRound();
        last_progress_round = last_committed_round;
        last_progress_time = time(NULL);
        round_last_activity_ms[last_committed_round] = NowMonotonicMs();
        AdvanceSyncedTipFromCommit(last_committed_round);
        PurgeCommittedPending(last_committed_round);
        branch_candidates_by_round.clear();
        branch_vote_weight_by_round_batch.clear();
        printf("reorg_replay_applied tip=%llu finalized=%llu\n",
               (unsigned long long)last_committed_round,
               (unsigned long long)FinalizedRound());
        return true;
    };

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

    // Strict fixed-peer mode: only configured/bootstrap peers are used.
    // Disable runtime peer discovery to avoid endpoint churn from ephemeral ports.
    const bool kFixedPeerMode = true;
    const std::string discovered_peers_file = cfg.data_dir + "/discovered_peers.txt";
    const uint64_t kPeerCacheKeepRounds = 20;
    std::vector<PeerCacheRecord> persisted_records;
    if (!kFixedPeerMode)
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
    if (!kFixedPeerMode)
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
        if (kFixedPeerMode)
            return;
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
    auto build_auth_sign_bytes = [&](const Bytes32& challenge,
                                     const Bytes32& node_id,
                                     const char* remote_params_version,
                                     const Bytes32& remote_params_hash,
                                     const char* remote_build_id,
                                     std::vector<uint8_t>* out) {
        if (!out)
            return false;
        out->clear();
        const char* tag = "DRPOW:hello_auth:v2";
        while (*tag)
            out->push_back((uint8_t)*tag++);
        out->insert(out->end(), challenge.v, challenge.v + 32);
        out->insert(out->end(), node_id.v, node_id.v + 32);
        const char* pv = remote_params_version ? remote_params_version : "";
        const size_t pv_n = strlen(pv);
        WriteU64LE(out, (uint64_t)pv_n);
        out->insert(out->end(), pv, pv + pv_n);
        out->insert(out->end(), remote_params_hash.v, remote_params_hash.v + 32);
        const char* bid = remote_build_id ? remote_build_id : "";
        const size_t bid_n = strlen(bid);
        WriteU64LE(out, (uint64_t)bid_n);
        out->insert(out->end(), bid, bid + bid_n);
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
    std::map<std::string, uint64_t> reject_counters_total;
    std::map<std::string, uint64_t> reject_counters_window;
    uint64_t metric_handshake_kept_leg = 0;
    uint64_t metric_handshake_dropped_leg = 0;
    uint64_t metric_handshake_cooldown_hits = 0;
    uint64_t metric_qc_seen = 0;
    uint64_t metric_qc_pow_votes = 0;
    uint64_t metric_qc_unknown_votes = 0;
    uint64_t metric_commit_accepts = 0;
    uint64_t metric_commit_rejects = 0;
    uint64_t metric_vote_accepts = 0;
    uint64_t metric_vote_rejects = 0;
    uint64_t metric_propose_accepts = 0;
    uint64_t metric_propose_rejects = 0;
    uint64_t metric_unsafe_mode_flips = 0;
    uint64_t metric_pow_preempt_rounds = 0;
    uint64_t metric_pow_preempt_remote_commit_within_window = 0;
    uint64_t metric_pow_preempt_remote_commit_after_window = 0;
    uint64_t metric_pow_preempt_committed_by_local = 0;
    uint64_t metric_p2p_send_fail_propose = 0;
    uint64_t metric_p2p_send_fail_commit = 0;
    uint64_t metric_p2p_send_retry_ok_propose = 0;
    uint64_t metric_p2p_send_retry_ok_commit = 0;
    const uint64_t kPreemptCommitWindowSec = 90ULL;
    std::map<uint64_t, uint64_t> preempt_round_time_sec;
    uint64_t drop_summary_last_ms = now_ms();
    bool unsafe_mode = false;
    auto note_drop = [&](const char* reason) {
        if (!reason)
            return;
        drop_counters[std::string(reason)] += 1;
    };
    auto note_reject = [&](const char* reason) {
        if (!reason)
            return;
        reject_counters_total[std::string(reason)] += 1;
        reject_counters_window[std::string(reason)] += 1;
    };
    auto observe_preempt_commit_outcome = [&](uint64_t round, const Bytes32& miner_pubkey) {
        std::map<uint64_t, uint64_t>::iterator it = preempt_round_time_sec.find(round);
        if (it == preempt_round_time_sec.end())
            return;
        const uint64_t now_sec = (uint64_t)time(NULL);
        const uint64_t elapsed_sec = (now_sec >= it->second) ? (now_sec - it->second) : 0ULL;
        const bool committed_by_local = (memcmp(miner_pubkey.v, signer_id.v, 32) == 0);
        if (committed_by_local)
        {
            metric_pow_preempt_committed_by_local += 1;
            Logf(LOG_NORMAL,
                 "[ASSERT][PREEMPT] round=%llu committed_by=local elapsed_sec=%llu window_sec=%llu\n",
                 (unsigned long long)round,
                 (unsigned long long)elapsed_sec,
                 (unsigned long long)kPreemptCommitWindowSec);
        }
        else if (elapsed_sec <= kPreemptCommitWindowSec)
        {
            metric_pow_preempt_remote_commit_within_window += 1;
            Logf(LOG_NORMAL,
                 "[ASSERT][PREEMPT] round=%llu committed_by=remote elapsed_sec=%llu window_sec=%llu status=ok\n",
                 (unsigned long long)round,
                 (unsigned long long)elapsed_sec,
                 (unsigned long long)kPreemptCommitWindowSec);
        }
        else
        {
            metric_pow_preempt_remote_commit_after_window += 1;
            Logf(LOG_NORMAL,
                 "[ASSERT][PREEMPT] round=%llu committed_by=remote elapsed_sec=%llu window_sec=%llu status=slow\n",
                 (unsigned long long)round,
                 (unsigned long long)elapsed_sec,
                 (unsigned long long)kPreemptCommitWindowSec);
        }
        preempt_round_time_sec.erase(it);
    };
    auto broadcast_with_retry = [&](WireEnvelope& env, const char* tag, uint64_t* fail_metric, uint64_t* retry_ok_metric) -> bool {
        if (reactor.Broadcast(env))
            return true;
        if (fail_metric)
            *fail_metric += 1;
        if (reactor.Broadcast(env))
        {
            if (retry_ok_metric)
                *retry_ok_metric += 1;
            Logf(LOG_NORMAL, "p2p_send_retry_ok type=%u tag=%s\n",
                 (unsigned)env.msg_type,
                 tag ? tag : "-");
            return true;
        }
        Logf(LOG_NORMAL, "drop %s send_failed type=%u\n",
             tag ? tag : "broadcast",
             (unsigned)env.msg_type);
        return false;
    };
    auto send_sync_request_to_peer = [&](int fd, uint64_t from_round, uint32_t max_records) -> bool {
        if (from_round == 0)
            from_round = 1;
        if (max_records == 0 || max_records > 256)
            max_records = 64;
        const uint64_t nowm = NowMonotonicMs();
        const uint64_t kSyncReqDebounceMs = 1500ULL;
        std::map<int, uint64_t>::const_iterator it_sent = peer_last_sync_req_sent_ms.find(fd);
        if (it_sent != peer_last_sync_req_sent_ms.end() && nowm >= it_sent->second)
        {
            const uint64_t elapsed = nowm - it_sent->second;
            if (elapsed < kSyncReqDebounceMs)
                return false;
        }
        std::map<int, uint64_t>::const_iterator it_from = peer_last_sync_req_from_round.find(fd);
        if (it_from != peer_last_sync_req_from_round.end() && it_from->second == from_round)
        {
            std::map<int, uint64_t>::const_iterator it_sent2 = peer_last_sync_req_sent_ms.find(fd);
            if (it_sent2 != peer_last_sync_req_sent_ms.end() && nowm >= it_sent2->second &&
                (nowm - it_sent2->second) < (kSyncReqDebounceMs * 2ULL))
                return false;
        }
        std::vector<uint8_t> req_payload;
        if (!SerializeSyncRequestPayload(from_round, max_records, &req_payload))
            return false;
        peer_last_sync_req_sent_ms[fd] = nowm;
        peer_last_sync_req_from_round[fd] = from_round;
        WireEnvelope req;
        req.magic = WireMagicMainnet();
        req.version = 1;
        req.msg_type = WIRE_MSG_SYNC_REQUEST;
        req.payload_len = (uint32_t)req_payload.size();
        req.unix_ms = 0;
        req.payload_hash = Bytes32();
        req.payload.swap(req_payload);
        (void)reactor.SendTo(fd, req);
        return true;
    };
    auto observe_qc = [&](const QuorumCertificate& qc) {
        metric_qc_seen += 1;
        for (size_t i = 0; i < qc.votes.size(); ++i)
        {
            if (qc.votes[i].eligibility_type == VOTE_ELIGIBILITY_POW_RECENT)
                metric_qc_pow_votes += 1;
            else
                metric_qc_unknown_votes += 1;
        }
    };
    auto proposal_score_for_batch = [&](const RoundBatch& batch, Bytes32* out_score) {
        if (!out_score)
            return false;
        Bytes32 parent_root;
        bool have_parent_root = false;
        if (batch.round <= 1)
        {
            have_parent_root = store.ReadStateRoot(&parent_root);
        }
        else
        {
            std::vector<RoundCommitRecord> prev;
            if (store.ExportVerifiedCommitRecordsFromRound(batch.round - 1, 1, &prev) &&
                prev.size() == 1)
            {
                parent_root = prev[0].state_root;
                have_parent_root = true;
            }
        }
        if (have_parent_root && ComputeProposerPowHashLocal(batch, parent_root, out_score))
            return true;
        *out_score = batch.batch_hash;
        return true;
    };
    auto register_proposal_candidate = [&](const RoundBatch& batch) {
        const uint64_t round = batch.round;
        if (round <= last_committed_round)
            return;
        const std::string batch_key = Bytes32Key(batch.batch_hash);
        if (!known_batches.count(batch_key))
            known_batches[batch_key] = batch;
        branch_candidates_by_round[round].insert(batch_key);
        if (!branch_vote_weight_by_round_batch[round].count(batch_key))
            branch_vote_weight_by_round_batch[round][batch_key] = known_vote_weight_sum[batch_key];
        round_candidate_keys[round].insert(batch_key);
        std::map<uint64_t, int>::const_iterator it_mode = round_mode_state.find(round);
        if (it_mode != round_mode_state.end() && it_mode->second == ROUND_MODE_VOTED_LOCKED)
        {
            Logf(LOG_NORMAL,
                 "candidate_ignored round=%llu reason=voted_locked batch=%s\n",
                 (unsigned long long)round,
                 Hex32(batch.batch_hash).c_str());
            return;
        }
        SetRoundMode(round, ROUND_MODE_VERIFY_VOTE, "proposal_seen");
        uint64_t now_round_ms = NowMonotonicMs();
        if (!round_first_seen_ms.count(round))
            round_first_seen_ms[round] = now_round_ms;
        round_last_activity_ms[round] = now_round_ms;
        Bytes32 score;
        (void)proposal_score_for_batch(batch, &score);
        std::map<uint64_t, std::string>::const_iterator it_key = round_best_batch_key.find(round);
        if (it_key == round_best_batch_key.end())
        {
            round_best_batch_key[round] = batch_key;
            round_best_batch_score[round] = score;
            round_best_batch_vote_weight[round] = known_vote_weight_sum[batch_key];
            Logf(LOG_NORMAL, "[ROUND_MODE] round=%llu mode=verify_vote reason=proposal_seen best_batch=%s\n",
                 (unsigned long long)round,
                 Hex32(batch.batch_hash).c_str());
            return;
        }
        const Bytes32& best = round_best_batch_score[round];
        const int cmp = memcmp(score.v, best.v, 32);
        if (cmp < 0 || (cmp == 0 && batch_key < it_key->second))
        {
            round_best_batch_key[round] = batch_key;
            round_best_batch_score[round] = score;
            round_best_batch_vote_weight[round] = known_vote_weight_sum[batch_key];
            Logf(LOG_NORMAL, "[ROUND_MODE] round=%llu mode=verify_vote reason=proposal_better best_batch=%s\n",
                 (unsigned long long)round,
                 Hex32(batch.batch_hash).c_str());
        }
    };
    auto refresh_round_best_by_vote_weight = [&](uint64_t round) {
        std::map<uint64_t, std::set<std::string> >::const_iterator it_candidates = round_candidate_keys.find(round);
        if (it_candidates == round_candidate_keys.end() || it_candidates->second.empty())
            return;
        bool have = false;
        std::string best_key;
        uint64_t best_weight = 0;
        for (std::set<std::string>::const_iterator it = it_candidates->second.begin(); it != it_candidates->second.end(); ++it)
        {
            const std::string& k = *it;
            const uint64_t w = known_vote_weight_sum.count(k) ? known_vote_weight_sum[k] : 0ULL;
            if (!have || w > best_weight || (w == best_weight && k < best_key))
            {
                have = true;
                best_key = k;
                best_weight = w;
            }
        }
        if (!have)
            return;
        std::map<uint64_t, std::string>::const_iterator it_prev = round_best_batch_key.find(round);
        if (it_prev != round_best_batch_key.end() && it_prev->second == best_key)
            return;
        round_best_batch_key[round] = best_key;
        round_best_batch_vote_weight[round] = best_weight;
        branch_vote_weight_by_round_batch[round][best_key] = best_weight;
        std::map<std::string, RoundBatch>::const_iterator it_batch = known_batches.find(best_key);
        if (it_batch != known_batches.end())
        {
            Logf(LOG_NORMAL,
                 "[ROUND_MODE] round=%llu mode=verify_vote reason=vote_weight_best best_batch=%s weight=%llu\n",
                 (unsigned long long)round,
                 Hex32(it_batch->second.batch_hash).c_str(),
                 (unsigned long long)best_weight);
        }
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

        bool next_unsafe_mode = false;
        std::string unsafe_reasons;
        const uint64_t params_mismatch_window =
            reject_counters_window["commit_params_hash_mismatch"] +
            reject_counters_window["propose_params_hash_mismatch"] +
            drop_counters["hello_params_mismatch"];
        const uint64_t unauth_window = drop_counters["unauthenticated_message"];
        const uint64_t collision_window = drop_counters["hello_peer_id_collision"];
        if (params_mismatch_window > 0)
        {
            next_unsafe_mode = true;
            unsafe_reasons += "params_mismatch ";
        }
        if (unauth_window >= 20)
        {
            next_unsafe_mode = true;
            unsafe_reasons += "unauth_spike ";
        }
        if (collision_window >= 20)
        {
            next_unsafe_mode = true;
            unsafe_reasons += "collision_spike ";
        }
        if (next_unsafe_mode != unsafe_mode)
        {
            unsafe_mode = next_unsafe_mode;
            metric_unsafe_mode_flips += 1;
            Logf(LOG_NORMAL, "[ALERT] unsafe_mode=%d reasons=%s flips=%llu\n",
                 unsafe_mode ? 1 : 0,
                 unsafe_reasons.empty() ? "-" : unsafe_reasons.c_str(),
                 (unsigned long long)metric_unsafe_mode_flips);
        }
        const double preempt_fast_rate =
            (metric_pow_preempt_rounds == 0)
                ? 0.0
                : ((double)metric_pow_preempt_remote_commit_within_window /
                   (double)metric_pow_preempt_rounds);
        Logf(LOG_NORMAL,
             "[OBS] unsafe_mode=%d propose_ok=%llu propose_reject=%llu vote_ok=%llu vote_reject=%llu commit_ok=%llu commit_reject=%llu qc_seen=%llu qc_pow_votes=%llu qc_unknown_votes=%llu rej_commit_qc_invalid=%llu rej_params_mismatch=%llu pow_preempt_rounds=%llu pow_preempt_remote_commit_fast=%llu pow_preempt_remote_commit_slow=%llu pow_preempt_commit_local=%llu p2p_send_fail_propose=%llu p2p_send_fail_commit=%llu p2p_send_retry_ok_propose=%llu p2p_send_retry_ok_commit=%llu preempt_fast_rate=%.4f\n",
             unsafe_mode ? 1 : 0,
             (unsigned long long)metric_propose_accepts,
             (unsigned long long)metric_propose_rejects,
             (unsigned long long)metric_vote_accepts,
             (unsigned long long)metric_vote_rejects,
             (unsigned long long)metric_commit_accepts,
             (unsigned long long)metric_commit_rejects,
             (unsigned long long)metric_qc_seen,
             (unsigned long long)metric_qc_pow_votes,
             (unsigned long long)metric_qc_unknown_votes,
             (unsigned long long)reject_counters_total["commit_qc_invalid"],
             (unsigned long long)(reject_counters_total["commit_params_hash_mismatch"] + reject_counters_total["propose_params_hash_mismatch"]),
             (unsigned long long)metric_pow_preempt_rounds,
             (unsigned long long)metric_pow_preempt_remote_commit_within_window,
             (unsigned long long)metric_pow_preempt_remote_commit_after_window,
             (unsigned long long)metric_pow_preempt_committed_by_local,
             (unsigned long long)metric_p2p_send_fail_propose,
             (unsigned long long)metric_p2p_send_fail_commit,
             (unsigned long long)metric_p2p_send_retry_ok_propose,
             (unsigned long long)metric_p2p_send_retry_ok_commit,
             preempt_fast_rate);
        reject_counters_window.clear();
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
        else if (msg_type == WIRE_MSG_PROPOSE || msg_type == WIRE_MSG_VOTE || msg_type == WIRE_MSG_COMMIT || msg_type == WIRE_MSG_TIMEOUT_VOTE)
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
        if (env.msg_type > WIRE_MSG_TIMEOUT_VOTE)
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
            if (!build_auth_sign_bytes(challenge, signer_id, DrpowParamsVersionTag(), params_hash, local_build_id.c_str(), &m))
                return;
            std::vector<uint8_t> sig;
            if (!crypto->SignEd25519(signer_priv, m.empty() ? NULL : &m[0], m.size(), &sig))
                return;
            std::vector<uint8_t> ap;
            if (!SerializeHelloAuthPayload(signer_id, challenge, DrpowParamsVersionTag(), params_hash, local_build_id.c_str(), sig, &ap))
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
            Bytes32 remote_params_hash;
            std::string remote_params_version;
            std::string remote_build_id;
            std::vector<uint8_t> sig;
            if (!ParseHelloAuthPayload(env.payload, &node_id, &challenge, &remote_params_version, &remote_params_hash, &remote_build_id, &sig))
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
            if (!build_auth_sign_bytes(challenge, node_id, remote_params_version.c_str(), remote_params_hash, remote_build_id.c_str(), &m))
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
            if (remote_params_version != DrpowParamsVersionTag() ||
                memcmp(remote_params_hash.v, params_hash.v, 32) != 0)
            {
                note_drop("hello_params_mismatch");
                Logf(LOG_NORMAL,
                     "[HANDSHAKE] reject peer_id=%s endpoint=%s reason=params_mismatch remote_version=%s local_version=%s remote_hash=%s local_hash=%s\n",
                     Hex32(node_id).c_str(),
                     reactor.PeerEndpoint(peer_fd).empty() ? "<unknown>" : reactor.PeerEndpoint(peer_fd).c_str(),
                     remote_params_version.c_str(),
                     DrpowParamsVersionTag(),
                     Hex32(remote_params_hash).c_str(),
                     Hex32(params_hash).c_str());
                reactor.Disconnect(peer_fd);
                return;
            }
            peer_pending_node_id_by_fd.erase(peer_fd);
            peer_challenge_by_fd.erase(peer_fd);
            peer_node_id_by_fd[peer_fd] = node_id;
            peer_fd_by_node_id[std::string((const char*)node_id.v, 32)] = peer_fd;
            std::string ep = reactor.PeerEndpoint(peer_fd);
            if (remote_build_id != local_build_id)
            {
                Logf(LOG_NORMAL,
                     "[HANDSHAKE] warn peer_id=%s endpoint=%s reason=build_id_mismatch remote_build_id=%s local_build_id=%s\n",
                     Hex32(node_id).c_str(),
                     ep.empty() ? "<unknown>" : ep.c_str(),
                     remote_build_id.c_str(),
                     local_build_id.c_str());
            }
            Logf(LOG_NORMAL, "[HANDSHAKE] ok peer_id=%s endpoint=%s remote_build_id=%s params_version=%s params_hash=%s\n",
                 Hex32(node_id).c_str(),
                 ep.empty() ? "<unknown>" : ep.c_str(),
                 remote_build_id.c_str(),
                 DrpowParamsVersionTag(),
                 Hex32(params_hash).c_str());
            if (!kFixedPeerMode && IsValidEndpoint(ep))
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
        bool unauth_local_tx = false;
        if (!peer_node_id_by_fd.count(peer_fd) && env.msg_type == WIRE_MSG_TX)
        {
            const std::string ep = reactor.PeerEndpoint(peer_fd);
            unauth_local_tx = IsLoopbackEndpoint(ep);
        }
        if (!peer_node_id_by_fd.count(peer_fd) && !unauth_local_tx)
        {
            if (env.msg_type == WIRE_MSG_SYNC_STATUS)
            {
                // Joiners may emit sync status during handshake churn; ignore until authenticated.
                return;
            }
            note_drop("unauthenticated_message");
            printf("drop unauthenticated_message fd=%d type=%u\n", peer_fd, (unsigned)env.msg_type);
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
                if (last_committed_round == 0)
                {
                    printf("accept peer_list future_round_bootstrap adv=%llu local=%llu\n",
                           (unsigned long long)advertised_round,
                           (unsigned long long)last_committed_round);
                }
                else
                {
                    printf("drop peer_list future_round adv=%llu local=%llu\n",
                           (unsigned long long)advertised_round,
                           (unsigned long long)last_committed_round);
                    return;
                }
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
            if (kFixedPeerMode)
            {
                // Ignore dynamic peer gossip in fixed-peer mode.
                return;
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
                if (peer_round > synced_last_round)
                {
                    synced_last_round = peer_round;
                    (void)SaveSyncedTipFile(sync_tip_file, synced_last_round, synced_state_root);
                    printf("sync_tip observed round=%llu\n", (unsigned long long)synced_last_round);
                }
                const uint64_t nowm = NowMonotonicMs();
                const uint64_t kSyncNeededLogDebounceMs = 3000ULL;
                bool log_sync_needed = true;
                std::map<int, uint64_t>::iterator it_sync_log = peer_last_sync_needed_log_ms.find(peer_fd);
                if (it_sync_log != peer_last_sync_needed_log_ms.end() &&
                    nowm >= it_sync_log->second &&
                    (nowm - it_sync_log->second) < kSyncNeededLogDebounceMs)
                {
                    log_sync_needed = false;
                }
                if (log_sync_needed)
                {
                    printf("sync_needed peer=%d peer_round=%llu local=%llu\n",
                           peer_fd,
                           (unsigned long long)peer_round,
                           (unsigned long long)last_committed_round);
                    peer_last_sync_needed_log_ms[peer_fd] = nowm;
                }
                (void)send_sync_request_to_peer(peer_fd, last_committed_round + 1, 64);
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
            (env.msg_type == WIRE_MSG_PROPOSE || env.msg_type == WIRE_MSG_VOTE || env.msg_type == WIRE_MSG_COMMIT || env.msg_type == WIRE_MSG_TIMEOUT_VOTE))
        {
            printf("drop from_stale_peer peer=%d peer_round=%llu local=%llu\n",
                   peer_fd,
                   (unsigned long long)it_peer_round->second,
                   (unsigned long long)last_committed_round);
            return;
        }
        if (last_committed_round < synced_last_round &&
            (env.msg_type == WIRE_MSG_PROPOSE || env.msg_type == WIRE_MSG_VOTE || env.msg_type == WIRE_MSG_COMMIT || env.msg_type == WIRE_MSG_TIMEOUT_VOTE))
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
            {
                std::map<int, uint64_t>::iterator it_req_ms = peer_last_sync_req_sent_ms.find(peer_fd);
                if (it_req_ms != peer_last_sync_req_sent_ms.end())
                {
                    const uint64_t now_ms = NowMonotonicMs();
                    if (now_ms >= it_req_ms->second)
                    {
                        const uint64_t rtt_sample_ms = now_ms - it_req_ms->second;
                        if (rtt_sample_ms >= 1 && rtt_sample_ms <= 300000)
                        {
                            if (rtt_sample_count == 0)
                                rtt_ewma_ms = (double)rtt_sample_ms;
                            else
                                rtt_ewma_ms = (0.85 * rtt_ewma_ms) + (0.15 * (double)rtt_sample_ms);
                            rtt_sample_count++;
                        }
                    }
                    peer_last_sync_req_sent_ms.erase(it_req_ms);
                    peer_last_sync_req_from_round.erase(peer_fd);
                }
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
            {
                // Fallback for late-syncing peers: if a full-history request from round 1
                // returns empty, ask for a recent window near observed tip.
                if (last_committed_round == 0 && from_round == 1 && synced_last_round > 1)
                {
                    uint64_t retry_from = (synced_last_round > 63) ? (synced_last_round - 63) : 1;
                    if (retry_from > 1)
                    {
                        printf("sync_retry_window from=%llu observed_tip=%llu\n",
                               (unsigned long long)retry_from,
                               (unsigned long long)synced_last_round);
                        (void)send_sync_request_to_peer(peer_fd, retry_from, 64);
                    }
                }
                return;
            }
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
            const std::string tx_ep = reactor.PeerEndpoint(peer_fd);
            printf("tx_submit_received fd=%d endpoint=%s payload_bytes=%zu\n",
                   peer_fd,
                   tx_ep.empty() ? "<unknown>" : tx_ep.c_str(),
                   env.payload.size());
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
                metric_propose_rejects += 1;
                note_reject("propose_parse_failed");
                printf("drop propose parse_failed\n");
                return;
            }
            if (memcmp(batch.params_hash.v, params_hash.v, 32) != 0)
            {
                metric_propose_rejects += 1;
                note_reject("propose_params_hash_mismatch");
                printf("drop propose params_hash_mismatch round=%llu batch=%s local=%s\n",
                       (unsigned long long)batch.round,
                       Hex32(batch.params_hash).c_str(),
                       Hex32(params_hash).c_str());
                return;
            }
            if (batch.round <= last_committed_round)
            {
                if (!InReplayWindow(batch.round))
                {
                    metric_propose_rejects += 1;
                    note_reject("propose_stale");
                    printf("drop propose stale round=%llu last=%llu\n",
                           (unsigned long long)batch.round,
                           (unsigned long long)last_committed_round);
                    return;
                }
            }
            if (batch.round <= FinalizedRound())
            {
                metric_propose_rejects += 1;
                note_reject("propose_finalized_immutable");
                printf("drop propose finalized_immutable round=%llu finalized=%llu\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)FinalizedRound());
                return;
            }
            const std::string incoming_batch_key = Bytes32Key(batch.batch_hash);
            if (known_batches.count(incoming_batch_key))
            {
                // Duplicate proposal payload; ignore.
                return;
            }
            if (IsCommitConflict(batch.round, batch.batch_hash))
            {
                if (!InReplayWindow(batch.round))
                {
                    metric_propose_rejects += 1;
                    note_reject("propose_round_conflict");
                    printf("drop propose round_conflict round=%llu\n",
                           (unsigned long long)batch.round);
                    return;
                }
                const std::string ckey = Bytes32Key(batch.batch_hash);
                branch_candidates_by_round[batch.round].insert(ckey);
                if (!branch_vote_weight_by_round_batch[batch.round].count(ckey))
                    branch_vote_weight_by_round_batch[batch.round][ckey] = known_vote_weight_sum[ckey];
                printf("reorg_candidate_accept kind=propose round=%llu batch=%s finalized=%llu last=%llu\n",
                       (unsigned long long)batch.round,
                       Hex32(batch.batch_hash).c_str(),
                       (unsigned long long)FinalizedRound(),
                       (unsigned long long)last_committed_round);
            }
            if (batch.mints.empty())
            {
                metric_propose_rejects += 1;
                note_reject("propose_unauthorized_proposer");
                printf("drop propose unauthorized_proposer round=%llu\n",
                       (unsigned long long)batch.round);
                return;
            }
            if (!engine.Propose(batch))
            {
                metric_propose_rejects += 1;
                note_reject("propose_engine_reject");
                printf("drop propose invalid code=%d msg=%s\n",
                       (int)engine.last_reject_code(),
                       engine.last_reject_message().c_str());
                return;
            }
            metric_propose_accepts += 1;
            printf("pow_candidate_accepted miner=%s round=%llu batch=%s\n",
                   Hex32(batch.mints[0].miner_pubkey).c_str(),
                   (unsigned long long)batch.round,
                   Hex32(batch.batch_hash).c_str());
            register_proposal_candidate(batch);
            return;
        }
        if (env.msg_type == WIRE_MSG_VOTE)
        {
            Vote vote;
            if (!ParseVotePayload(env.payload, &vote))
            {
                metric_vote_rejects += 1;
                note_reject("vote_parse_failed");
                printf("drop vote parse_failed\n");
                return;
            }
            if (vote.round <= last_committed_round)
            {
                metric_vote_rejects += 1;
                note_reject("vote_stale");
                printf("drop vote stale round=%llu last=%llu\n",
                       (unsigned long long)vote.round,
                       (unsigned long long)last_committed_round);
                return;
            }
            if (vote.round <= FinalizedRound())
            {
                metric_vote_rejects += 1;
                note_reject("vote_finalized_immutable");
                printf("drop vote finalized_immutable round=%llu finalized=%llu\n",
                       (unsigned long long)vote.round,
                       (unsigned long long)FinalizedRound());
                return;
            }
            if (!RecordRemoteVoteTarget(vote.round, vote.validator_id, vote.batch_hash))
            {
                metric_vote_rejects += 1;
                note_reject("vote_equivocation_remote");
                printf("drop vote equivocation_remote round=%llu voter=%s\n",
                       (unsigned long long)vote.round,
                       Hex32(vote.validator_id).c_str());
                return;
            }
            if (!vote_verifier.VerifyVote(vote))
            {
                metric_vote_rejects += 1;
                note_reject("vote_bad_sig");
                printf("drop vote bad_sig\n");
                return;
            }
            Bytes32 expected_vote_target;
            if (!ComputeExpectedTargetForRoundNode(store, vote.round, economics_policy, &expected_vote_target))
            {
                metric_vote_rejects += 1;
                note_reject("vote_target_unavailable");
                printf("drop vote target_unavailable round=%llu\n",
                       (unsigned long long)vote.round);
                return;
            }
            std::string vote_pow_reason;
            const bool vote_pow_ok = VerifyVotePowAgainstTarget(vote, expected_vote_target, &vote_pow_reason);
            if (!vote_pow_ok)
            {
                metric_vote_rejects += 1;
                note_reject("vote_pow_invalid");
                Logf(LOG_NORMAL,
                     "[VOTE][POW] round=%llu voter=%s status=invalid reason=%s present=%u nonce=%llu hash=%s target=%s\n",
                     (unsigned long long)vote.round,
                     Hex32(vote.validator_id).c_str(),
                     vote_pow_reason.c_str(),
                     (unsigned)vote.pow_proof_present,
                     (unsigned long long)vote.pow_nonce,
                     Hex32(vote.pow_hash).c_str(),
                     Hex32(expected_vote_target).c_str());
                return;
            }
            else if (vote.pow_proof_present)
            {
                Logf(LOG_DEBUG,
                     "[VOTE][POW] round=%llu voter=%s status=valid reason=%s nonce=%llu hash=%s target=%s\n",
                     (unsigned long long)vote.round,
                     Hex32(vote.validator_id).c_str(),
                     vote_pow_reason.c_str(),
                     (unsigned long long)vote.pow_nonce,
                     Hex32(vote.pow_hash).c_str(),
                     Hex32(expected_vote_target).c_str());
            }
            const std::string k = Bytes32Key(vote.batch_hash);
            round_vote_batch_keys[vote.round].insert(k);
            std::map<std::string, RoundBatch>::const_iterator itb = known_batches.find(k);
            if (itb == known_batches.end())
            {
                metric_vote_rejects += 1;
                note_reject("vote_unknown_batch");
                printf("drop vote unknown_batch\n");
                return;
            }
            if (vote.round != itb->second.round)
            {
                metric_vote_rejects += 1;
                note_reject("vote_round_mismatch");
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
            const uint64_t vote_w = VotePowWeight(vote);
            if (UINT64_MAX - known_vote_weight_sum[k] < vote_w)
                known_vote_weight_sum[k] = UINT64_MAX;
            else
                known_vote_weight_sum[k] += vote_w;
            refresh_round_best_by_vote_weight(vote.round);
            QuorumCertificate qc;
            qc.round = itb->second.round;
            qc.batch_hash = itb->second.batch_hash;
            qc.votes = known_votes[k];
            {
                Bytes32 expected_target;
                if (!ComputeExpectedTargetForRoundNode(store, itb->second.round, economics_policy, &expected_target))
                {
                    metric_commit_rejects += 1;
                    note_reject("commit_target_unavailable");
                    printf("drop commit target_unavailable round=%llu\n",
                           (unsigned long long)itb->second.round);
                    return;
                }
                if (!VerifyQuorumCertificatePow(qc,
                                                itb->second.round,
                                                itb->second.batch_hash,
                                                expected_target,
                                                DrpowParams::kMinQcWeight,
                                                vote_verifier))
                {
                    metric_commit_rejects += 1;
                    note_reject("commit_qc_invalid");
                    printf("drop commit qc_invalid round=%llu votes=%zu weight=%llu min_weight=%llu\n",
                           (unsigned long long)itb->second.round,
                           qc.votes.size(),
                           (unsigned long long)known_vote_weight_sum[k],
                           (unsigned long long)DrpowParams::kMinQcWeight);
                    return;
                }
            }
            qc_gate_last_votes.erase(k);
            {
                std::map<uint64_t, std::string>::const_iterator it_best = round_best_batch_key.find(itb->second.round);
                if (it_best != round_best_batch_key.end() && it_best->second != k)
                {
                    Logf(LOG_NORMAL,
                         "candidate_ignored round=%llu reason=not_best_by_weight batch=%s\n",
                         (unsigned long long)itb->second.round,
                         Hex32(itb->second.batch_hash).c_str());
                    return;
                }
            }
            observe_qc(qc);
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
            (void)broadcast_with_retry(out, "commit", &metric_p2p_send_fail_commit, &metric_p2p_send_retry_ok_commit);
            return;
        }
        if (env.msg_type == WIRE_MSG_TIMEOUT_VOTE)
        {
            TimeoutVote tv;
            if (!ParseTimeoutVotePayload(env.payload, &tv))
            {
                note_reject("timeout_vote_parse_failed");
                return;
            }
            if (tv.round <= last_committed_round)
            {
                note_reject("timeout_vote_stale");
                return;
            }
            if (tv.round <= FinalizedRound())
            {
                note_reject("timeout_vote_finalized_immutable");
                return;
            }
            std::vector<uint8_t> m;
            if (!BuildTimeoutSignMessage(tv, &m))
            {
                note_reject("timeout_vote_signmsg_failed");
                return;
            }
            if (!crypto->VerifyEd25519(tv.validator_id.v,
                                       m.empty() ? NULL : &m[0],
                                       m.size(),
                                       tv.signature.empty() ? NULL : &tv.signature[0],
                                       tv.signature.size()))
            {
                note_reject("timeout_vote_bad_sig");
                return;
            }
            const std::string voter_key((const char*)tv.validator_id.v, 32);
            timeout_votes_by_round[tv.round][voter_key] = tv;
            const size_t min_votes = DynamicMinVotes();
            const size_t have_votes = timeout_votes_by_round[tv.round].size();
            if (have_votes >= min_votes && !timeout_qc_rounds.count(tv.round))
            {
                timeout_qc_rounds.insert(tv.round);
                Logf(LOG_NORMAL,
                     "[TIMEOUT_QC] round=%llu votes=%zu min_votes=%zu status=formed\n",
                     (unsigned long long)tv.round,
                     have_votes,
                     min_votes);
            }
            return;
        }
        if (env.msg_type == WIRE_MSG_COMMIT)
        {
            RoundBatch batch;
            QuorumCertificate qc;
            if (!ParseCommitPayload(env.payload, &batch, &qc))
            {
                metric_commit_rejects += 1;
                note_reject("commit_parse_failed");
                printf("drop commit parse_failed\n");
                return;
            }
            if (memcmp(batch.params_hash.v, params_hash.v, 32) != 0)
            {
                metric_commit_rejects += 1;
                note_reject("commit_params_hash_mismatch");
                printf("drop commit params_hash_mismatch round=%llu batch=%s local=%s\n",
                       (unsigned long long)batch.round,
                       Hex32(batch.params_hash).c_str(),
                       Hex32(params_hash).c_str());
                return;
            }
            if (batch.round <= last_committed_round)
            {
                if (!InReplayWindow(batch.round))
                {
                    metric_commit_rejects += 1;
                    note_reject("commit_stale");
                    printf("drop commit stale round=%llu last=%llu\n",
                           (unsigned long long)batch.round,
                           (unsigned long long)last_committed_round);
                    return;
                }
            }
            if (batch.round <= FinalizedRound())
            {
                metric_commit_rejects += 1;
                note_reject("commit_finalized_immutable");
                printf("drop commit finalized_immutable round=%llu finalized=%llu\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)FinalizedRound());
                return;
            }
            if (IsCommitConflict(batch.round, batch.batch_hash))
            {
                if (!InReplayWindow(batch.round))
                {
                    metric_commit_rejects += 1;
                    note_reject("commit_round_conflict");
                    printf("drop commit round_conflict round=%llu\n",
                           (unsigned long long)batch.round);
                    return;
                }
                const std::string ckey = Bytes32Key(batch.batch_hash);
                branch_candidates_by_round[batch.round].insert(ckey);
                uint64_t qc_w = 0;
                for (size_t wi = 0; wi < qc.votes.size(); ++wi)
                {
                    const uint64_t w = VotePowWeight(qc.votes[wi]);
                    if (UINT64_MAX - qc_w < w)
                    {
                        qc_w = UINT64_MAX;
                        break;
                    }
                    qc_w += w;
                }
                branch_vote_weight_by_round_batch[batch.round][ckey] = qc_w;
                printf("reorg_candidate_accept kind=commit round=%llu batch=%s finalized=%llu last=%llu\n",
                       (unsigned long long)batch.round,
                       Hex32(batch.batch_hash).c_str(),
                       (unsigned long long)FinalizedRound(),
                       (unsigned long long)last_committed_round);
            }
            if (qc.round != batch.round || memcmp(qc.batch_hash.v, batch.batch_hash.v, 32) != 0)
            {
                metric_commit_rejects += 1;
                note_reject("commit_qc_batch_mismatch");
                printf("drop commit qc_batch_mismatch\n");
                return;
            }
            Bytes32 expected_target;
            if (!ComputeExpectedTargetForRoundNode(store, batch.round, economics_policy, &expected_target))
            {
                metric_commit_rejects += 1;
                note_reject("commit_target_unavailable");
                printf("drop commit target_unavailable round=%llu\n", (unsigned long long)batch.round);
                return;
            }
            if (!VerifyQuorumCertificatePow(qc,
                                            batch.round,
                                            batch.batch_hash,
                                            expected_target,
                                            DrpowParams::kMinQcWeight,
                                            vote_verifier))
            {
                metric_commit_rejects += 1;
                note_reject("commit_qc_invalid");
                printf("drop commit qc_invalid\n");
                return;
            }
            const uint64_t minted_precheck = SumBatchMintValue(batch);
            const uint64_t expected_mint_precheck = ExpectedMintBudgetForRound(store, batch.round, economics_policy);
            if (minted_precheck != expected_mint_precheck)
            {
                metric_commit_rejects += 1;
                note_reject("commit_mint_amount_mismatch");
                printf("drop commit mint_amount_mismatch round=%llu minted=%llu expected=%llu mints=%zu batch=%s\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)minted_precheck,
                       (unsigned long long)expected_mint_precheck,
                       batch.mints.size(),
                       Hex32(batch.batch_hash).c_str());
                return;
            }
            const uint64_t mint0_precheck = batch.mints.empty() ? 0 : batch.mints[0].output.value;
            if (!engine.Commit(batch, qc))
            {
                metric_commit_rejects += 1;
                note_reject("commit_engine_reject");
                printf("drop commit invalid code=%d msg=%s\n",
                       (int)engine.last_reject_code(),
                       engine.last_reject_message().c_str());
                return;
            }
            metric_commit_accepts += 1;
            observe_qc(qc);
            if (!AppendCommitPayloadCacheDedup(commit_payload_cache, env.payload))
                printf("cache_append_failed source=wire_commit round=%llu\n", (unsigned long long)batch.round);
            last_committed_round = batch.round;
            last_progress_round = last_committed_round;
            last_progress_time = time(NULL);
            round_last_activity_ms[batch.round] = NowMonotonicMs();
            RememberCommitTarget(batch.round, batch.batch_hash);
            AdvanceSyncedTipFromCommit(last_committed_round);
            PurgeCommittedPending(last_committed_round);
            const uint64_t minted = SumBatchMintValue(batch);
            const uint64_t fees = SumBatchFees(batch);
            const uint64_t subsidy = MintSubsidyForRound(batch.round, economics_policy);
            if (!batch.mints.empty())
                observe_preempt_commit_outcome(batch.round, batch.mints[0].miner_pubkey);
            if (minted != minted_precheck || (!batch.mints.empty() && batch.mints[0].output.value != mint0_precheck))
            {
                printf("fatal commit_post_batch_mutation round=%llu minted_now=%llu minted_pre=%llu mint0_now=%llu mint0_pre=%llu mints=%zu batch=%s\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)minted,
                       (unsigned long long)minted_precheck,
                       (unsigned long long)(batch.mints.empty() ? 0 : batch.mints[0].output.value),
                       (unsigned long long)mint0_precheck,
                       batch.mints.size(),
                       Hex32(batch.batch_hash).c_str());
                fflush(stdout);
                abort();
            }
            const std::string miner_hex = batch.mints.empty() ? "-" : Hex32(batch.mints[0].miner_pubkey);
            const std::string target_hex = batch.mints.empty() ? "-" : Hex32(batch.mints[0].target);
            printf("commit ok round=%llu spends=%zu mints=%zu minted=%llu minted_drpow=%s fees=%llu fees_drpow=%s subsidy=%llu subsidy_drpow=%s miner=%s target=%s\n",
                   (unsigned long long)batch.round,
                   batch.spends.size(),
                   batch.mints.size(),
                   (unsigned long long)minted,
                   FormatAtomic8(minted).c_str(),
                   (unsigned long long)fees,
                   FormatAtomic8(fees).c_str(),
                   (unsigned long long)subsidy,
                   FormatAtomic8(subsidy).c_str(),
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
    Logf(LOG_NORMAL, "[BOOT] build_id=%s\n", local_build_id.c_str());
    Logf(LOG_NORMAL, "[BOOT] params_version=%s\n", DrpowParamsVersionTag());
    Logf(LOG_NORMAL, "[BOOT] params_hash=%s\n", Hex32(params_hash).c_str());
    {
        std::string pq_db_path;
        bool pq_parent_owner_only = false;
        bool pq_file_exists = false;
        bool pq_file_owner_only = false;
        if (GetPqcKeyDbSelfCheck(&pq_db_path, &pq_parent_owner_only, &pq_file_exists, &pq_file_owner_only))
        {
            Logf(LOG_NORMAL,
                 "[BOOT] pq_key_db path=%s parent_owner_only=%d file_exists=%d file_owner_only=%d\n",
                 pq_db_path.c_str(),
                 pq_parent_owner_only ? 1 : 0,
                 pq_file_exists ? 1 : 0,
                 pq_file_owner_only ? 1 : 0);
        }
    }
    Logf(LOG_NORMAL, "[BOOT] network_magic=0x%08x\n", (unsigned)cfg.network_magic);
    Logf(LOG_NORMAL, "[BOOT] voting_mode=pow_only\n");
    Logf(LOG_NORMAL, "[BOOT] peer_mode=fixed\n");
    Logf(LOG_NORMAL,
         "[BOOT] pow_target_prefix_bytes=%d max_target=%s\n",
         cfg.pow_target_prefix_bytes,
         Hex32(economics_policy.max_target).c_str());
    const uint64_t proposal_window_ms = ParseEnvU64Clamped("PROPOSAL_WINDOW_MS", 3000ULL, 100ULL, 10000ULL);
    const uint64_t round_timeout_ms = ParseEnvU64Clamped("ROUND_TIMEOUT_MS", 45000ULL, 5000ULL, 180000ULL);
    const uint64_t adaptive_proposal_window_min_ms =
        ParseEnvU64Clamped("ADAPTIVE_PROPOSAL_WINDOW_MIN_MS", 500ULL, 100ULL, 30000ULL);
    const uint64_t adaptive_proposal_window_max_ms =
        ParseEnvU64Clamped("ADAPTIVE_PROPOSAL_WINDOW_MAX_MS", 10000ULL, 100ULL, 60000ULL);
    const uint64_t adaptive_round_timeout_min_ms =
        ParseEnvU64Clamped("ADAPTIVE_ROUND_TIMEOUT_MIN_MS", 30000ULL, 1000ULL, 300000ULL);
    const uint64_t adaptive_round_timeout_max_ms =
        ParseEnvU64Clamped("ADAPTIVE_ROUND_TIMEOUT_MAX_MS", 180000ULL, 5000ULL, 600000ULL);
    adaptive_proposal_window_ms = proposal_window_ms;
    adaptive_round_timeout_ms = round_timeout_ms;
    Logf(LOG_NORMAL, "[BOOT] autopropose enabled=%d interval_sec=%d\n", cfg.autopropose, cfg.autopropose_interval_sec);
    Logf(LOG_NORMAL, "[BOOT] proposal_window_ms=%llu\n", (unsigned long long)proposal_window_ms);
    Logf(LOG_NORMAL, "[BOOT] round_timeout_ms=%llu\n", (unsigned long long)round_timeout_ms);
    Logf(LOG_NORMAL, "[BOOT] finality_depth_rounds=%llu finalized_round=%llu\n",
         (unsigned long long)finality_depth_rounds,
         (unsigned long long)FinalizedRound());
    Logf(LOG_NORMAL, "[BOOT] reorg_replay_window_rounds=%llu replay_low=%llu replay_high=%llu\n",
         (unsigned long long)reorg_replay_window_rounds,
         (unsigned long long)(FinalizedRound() + 1),
         (unsigned long long)(FinalizedRound() + reorg_replay_window_rounds));
    Logf(LOG_NORMAL,
         "[BOOT] adaptive_timing proposal_window_min_ms=%llu proposal_window_max_ms=%llu round_timeout_min_ms=%llu round_timeout_max_ms=%llu\n",
         (unsigned long long)adaptive_proposal_window_min_ms,
         (unsigned long long)adaptive_proposal_window_max_ms,
         (unsigned long long)adaptive_round_timeout_min_ms,
         (unsigned long long)adaptive_round_timeout_max_ms);
    Logf(LOG_NORMAL, "[BOOT] sync_policy=sync_first\n");
    Logf(LOG_NORMAL, "[BOOT] log_level=%s\n", cfg.log_level.c_str());
    Logf(LOG_NORMAL, "[BOOT] commit_recovery last_round=%llu\n", (unsigned long long)last_committed_round);
    Logf(LOG_NORMAL, "[BOOT] sync_tip round=%llu\n", (unsigned long long)synced_last_round);
    Logf(LOG_NORMAL, "[BOOT] sync_lag local=%llu synced=%llu lag=%llu cache_entries=%zu\n",
           (unsigned long long)last_committed_round,
           (unsigned long long)synced_last_round,
           (unsigned long long)((synced_last_round > last_committed_round) ? (synced_last_round - last_committed_round) : 0),
           CountCommitPayloadCacheEntries(commit_payload_cache));
    BroadcastSyncStatus();
    std::function<void(uint64_t)> TryVoteCanonicalRound = [&](uint64_t round) {
        if (round <= last_committed_round)
            return;
        if (local_vote_by_round.count(round))
            return;
        std::map<uint64_t, std::string>::const_iterator it_key = round_best_batch_key.find(round);
        std::map<uint64_t, uint64_t>::const_iterator it_seen = round_first_seen_ms.find(round);
        if (it_key == round_best_batch_key.end() || it_seen == round_first_seen_ms.end())
            return;
        const uint64_t now_ms = NowMonotonicMs();
        if (now_ms < it_seen->second || (now_ms - it_seen->second) < adaptive_proposal_window_ms)
            return;
        const uint64_t proposal_elapsed_ms = now_ms - it_seen->second;
        size_t candidate_evidence = 0;
        {
            std::map<uint64_t, std::set<std::string> >::const_iterator it_candidates = round_candidate_keys.find(round);
            if (it_candidates != round_candidate_keys.end())
                candidate_evidence = it_candidates->second.size();
        }
        size_t vote_target_evidence = 0;
        {
            std::map<uint64_t, std::set<std::string> >::const_iterator it_vote_targets = round_vote_batch_keys.find(round);
            if (it_vote_targets != round_vote_batch_keys.end())
                vote_target_evidence = it_vote_targets->second.size();
        }
        const bool saw_competing_candidate = candidate_evidence > 1;
        const bool saw_competing_vote_evidence = vote_target_evidence > 1;
        const bool have_peer_context = !peer_last_round.empty();
        const bool conflict_evidence = saw_competing_candidate || saw_competing_vote_evidence;
        uint64_t solo_candidate_wait_ms = adaptive_proposal_window_ms * 4ULL;
        if (solo_candidate_wait_ms < adaptive_proposal_window_ms)
            solo_candidate_wait_ms = adaptive_proposal_window_ms;
        if (solo_candidate_wait_ms > 30000ULL)
            solo_candidate_wait_ms = 30000ULL;
        if (have_peer_context && !conflict_evidence && proposal_elapsed_ms < solo_candidate_wait_ms)
        {
            Logf(LOG_DEBUG,
                 "[VOTE_GATE] round=%llu defer=solo_view elapsed_ms=%llu wait_ms=%llu candidates=%zu vote_targets=%zu\n",
                 (unsigned long long)round,
                 (unsigned long long)proposal_elapsed_ms,
                 (unsigned long long)solo_candidate_wait_ms,
                 candidate_evidence,
                 vote_target_evidence);
            return;
        }
        Logf(LOG_DEBUG,
             "[VOTE_GATE] round=%llu candidates=%zu vote_targets=%zu competing_candidate=%d competing_vote=%d\n",
             (unsigned long long)round,
             candidate_evidence,
             vote_target_evidence,
             saw_competing_candidate ? 1 : 0,
             saw_competing_vote_evidence ? 1 : 0);
        std::map<std::string, RoundBatch>::const_iterator it_batch = known_batches.find(it_key->second);
        if (it_batch == known_batches.end())
            return;
        const RoundBatch& batch = it_batch->second;
        if (IsCommitConflict(batch.round, batch.batch_hash))
            return;
        Vote vote;
        if (!engine.ValidateAndVote(batch, &vote))
        {
            metric_vote_rejects += 1;
            note_reject("vote_build_failed");
            printf("drop vote_build_failed round=%llu code=%d msg=%s\n",
                   (unsigned long long)batch.round,
                   (int)engine.last_reject_code(),
                   engine.last_reject_message().c_str());
            return;
        }
        vote.validator_id = signer_id;
        vote.eligibility_type = VOTE_ELIGIBILITY_POW_RECENT;
        Bytes32 vote_target;
        if (!ComputeExpectedTargetForRoundNode(store, batch.round, economics_policy, &vote_target))
        {
            metric_vote_rejects += 1;
            note_reject("vote_target_unavailable");
            printf("drop vote_target_unavailable round=%llu\n",
                   (unsigned long long)batch.round);
            return;
        }
        vote.pow_proof_present = 1;
        vote.pow_target = vote_target;
        if (!BuildVotePowProof(vote, vote_target, &vote.pow_nonce, &vote.pow_hash))
        {
            metric_vote_rejects += 1;
            note_reject("vote_pow_not_found");
            printf("drop vote_pow_not_found round=%llu batch=%s signer=%s target=%s proof_type=vote_pow_recent\n",
                   (unsigned long long)batch.round,
                   Hex32(batch.batch_hash).c_str(),
                   Hex32(signer_id).c_str(),
                   Hex32(vote_target).c_str());
            return;
        }
        std::vector<uint8_t> m;
        BuildVoteSigningMessageV2(vote, &m);
        if (!crypto->SignEd25519(signer_priv, m.empty() ? NULL : &m[0], m.size(), &vote.signature))
        {
            metric_vote_rejects += 1;
            note_reject("vote_sign_failed");
            printf("drop vote_sign_failed\n");
            return;
        }
        if (!EnsureLocalVoteForRound(batch.round, batch.batch_hash))
        {
            metric_vote_rejects += 1;
            note_reject("vote_equivocation_local_blocked");
            printf("drop vote equivocation_local_blocked round=%llu\n",
                   (unsigned long long)batch.round);
            return;
        }
        metric_vote_accepts += 1;
        const std::string k = Bytes32Key(vote.batch_hash);
        round_vote_batch_keys[vote.round].insert(k);
        const std::string voter_key((const char*)vote.validator_id.v, 32);
        if (!known_vote_ids[k].count(voter_key))
        {
            known_vote_ids[k].insert(voter_key);
            known_votes[k].push_back(vote);
            const uint64_t vote_w = VotePowWeight(vote);
            if (UINT64_MAX - known_vote_weight_sum[k] < vote_w)
                known_vote_weight_sum[k] = UINT64_MAX;
            else
                known_vote_weight_sum[k] += vote_w;
        }
        refresh_round_best_by_vote_weight(vote.round);
        QuorumCertificate local_qc;
        local_qc.round = batch.round;
        local_qc.batch_hash = batch.batch_hash;
        local_qc.votes = known_votes[k];
        bool local_qc_valid = false;
        {
            Bytes32 expected_target;
            if (!ComputeExpectedTargetForRoundNode(store, batch.round, economics_policy, &expected_target))
            {
                metric_commit_rejects += 1;
                note_reject("local_commit_target_unavailable");
                Logf(LOG_NORMAL,
                     "[COMMIT][REJECT] round=%llu reason=target_unavailable\n",
                     (unsigned long long)batch.round);
                return;
            }
            local_qc_valid = VerifyQuorumCertificatePow(local_qc,
                                                        batch.round,
                                                        batch.batch_hash,
                                                        expected_target,
                                                        DrpowParams::kMinQcWeight,
                                                        vote_verifier);
            if (!local_qc_valid)
            {
                metric_commit_rejects += 1;
                note_reject("local_commit_qc_invalid");
                Logf(LOG_NORMAL,
                     "[COMMIT][REJECT] round=%llu reason=qc_invalid votes=%zu weight=%llu min_weight=%llu\n",
                     (unsigned long long)batch.round,
                     local_qc.votes.size(),
                     (unsigned long long)known_vote_weight_sum[k],
                     (unsigned long long)DrpowParams::kMinQcWeight);
                return;
            }
        }
        if (local_qc_valid && batch.round > last_committed_round)
        {
            std::map<uint64_t, std::string>::const_iterator it_best = round_best_batch_key.find(batch.round);
            if (it_best != round_best_batch_key.end() && it_best->second != k)
            {
                Logf(LOG_NORMAL,
                     "candidate_ignored round=%llu reason=not_best_by_weight batch=%s\n",
                     (unsigned long long)batch.round,
                     Hex32(batch.batch_hash).c_str());
                return;
            }
            qc_gate_last_votes.erase(k);
            const uint64_t minted_precheck = SumBatchMintValue(batch);
            const uint64_t expected_mint_precheck = ExpectedMintBudgetForRound(store, batch.round, economics_policy);
            if (minted_precheck != expected_mint_precheck)
            {
                metric_commit_rejects += 1;
                note_reject("local_commit_mint_amount_mismatch");
                Logf(LOG_NORMAL,
                     "[COMMIT][REJECT] round=%llu reason=mint_amount_mismatch minted=%llu expected=%llu mints=%zu batch=%s\n",
                     (unsigned long long)batch.round,
                     (unsigned long long)minted_precheck,
                     (unsigned long long)expected_mint_precheck,
                     batch.mints.size(),
                     Hex32(batch.batch_hash).c_str());
                return;
            }
            const uint64_t mint0_precheck = batch.mints.empty() ? 0 : batch.mints[0].output.value;
            // Commit may be followed by cache purge that erases known_batches[batch],
            // so keep a stable copy for post-commit logging/accounting.
            const RoundBatch committed_batch = batch;
            if (engine.Commit(committed_batch, local_qc))
            {
                metric_commit_accepts += 1;
                observe_qc(local_qc);
                std::vector<uint8_t> local_commit_payload;
                if (!SerializeCommitPayload(committed_batch, local_qc, &local_commit_payload))
                    printf("cache_serialize_failed source=local_commit round=%llu\n", (unsigned long long)committed_batch.round);
                else if (!AppendCommitPayloadCacheDedup(commit_payload_cache, local_commit_payload))
                    printf("cache_append_failed source=local_commit round=%llu\n", (unsigned long long)committed_batch.round);
                last_committed_round = committed_batch.round;
                last_progress_round = last_committed_round;
                last_progress_time = time(NULL);
                round_last_activity_ms[committed_batch.round] = NowMonotonicMs();
                RememberCommitTarget(committed_batch.round, committed_batch.batch_hash);
                AdvanceSyncedTipFromCommit(last_committed_round);
                PurgeCommittedPending(last_committed_round);
                const uint64_t minted = SumBatchMintValue(committed_batch);
                const uint64_t fees = SumBatchFees(committed_batch);
                const uint64_t subsidy = MintSubsidyForRound(committed_batch.round, economics_policy);
                if (!committed_batch.mints.empty())
                    observe_preempt_commit_outcome(committed_batch.round, committed_batch.mints[0].miner_pubkey);
                if (minted != minted_precheck || (!committed_batch.mints.empty() && committed_batch.mints[0].output.value != mint0_precheck))
                {
                    Logf(LOG_NORMAL,
                         "fatal commit_post_batch_mutation round=%llu minted_now=%llu minted_pre=%llu mint0_now=%llu mint0_pre=%llu mints=%zu batch=%s\n",
                         (unsigned long long)committed_batch.round,
                         (unsigned long long)minted,
                         (unsigned long long)minted_precheck,
                         (unsigned long long)(committed_batch.mints.empty() ? 0 : committed_batch.mints[0].output.value),
                         (unsigned long long)mint0_precheck,
                         committed_batch.mints.size(),
                         Hex32(committed_batch.batch_hash).c_str());
                    fflush(stdout);
                    abort();
                }
                const std::string miner_hex = committed_batch.mints.empty() ? "-" : Hex32(committed_batch.mints[0].miner_pubkey);
                const std::string target_hex = committed_batch.mints.empty() ? "-" : Hex32(committed_batch.mints[0].target);
                Logf(LOG_NORMAL, "[COMMIT] ok round=%llu spends=%zu mints=%zu minted=%llu minted_drpow=%s fees=%llu fees_drpow=%s subsidy=%llu subsidy_drpow=%s miner=%s target=%s\n",
                       (unsigned long long)committed_batch.round,
                       committed_batch.spends.size(),
                       committed_batch.mints.size(),
                       (unsigned long long)minted,
                       FormatAtomic8(minted).c_str(),
                       (unsigned long long)fees,
                       FormatAtomic8(fees).c_str(),
                       (unsigned long long)subsidy,
                       FormatAtomic8(subsidy).c_str(),
                       miner_hex.c_str(),
                       target_hex.c_str());
                BroadcastSyncStatus();
            }
            else
            {
                metric_commit_rejects += 1;
                note_reject("local_commit_engine_reject");
                Logf(LOG_NORMAL, "[COMMIT][REJECT] round=%llu code=%d reason=%s\n",
                       (unsigned long long)batch.round,
                       (int)engine.last_reject_code(),
                       engine.last_reject_message().c_str());
                known_batches.erase(Bytes32Key(batch.batch_hash));
                known_votes.erase(Bytes32Key(batch.batch_hash));
                known_vote_ids.erase(Bytes32Key(batch.batch_hash));
                qc_gate_last_votes.erase(Bytes32Key(batch.batch_hash));
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
                printf("drop vote send_failed\n");
        }
    };

    time_t start = time(NULL);
    time_t last_sync_tick = start;
    time_t last_autopropose_tick = start;
    time_t last_log_rotate_tick = start;
    int dynamic_autopropose_interval_sec = cfg.autopropose_interval_sec > 0 ? cfg.autopropose_interval_sec : 1;
    size_t dynamic_max_spends_per_round = economics_policy.max_spends_per_round;
    const uint64_t kPowBaseBudgetMs = 6000ULL;
    uint64_t dynamic_pow_time_budget_ms = kPowBaseBudgetMs;
    uint64_t last_leader_log_round = 0;
    bool sync_first_prev = false;
    while (true)
    {
        reactor.PollOnce();
        const int base_interval_sec = cfg.autopropose_interval_sec > 0 ? cfg.autopropose_interval_sec : 1;
        const uint64_t lag_now = (synced_last_round > last_committed_round) ? (synced_last_round - last_committed_round) : 0;
        const time_t now = time(NULL);
        const int no_progress_sec = (int)(now - last_progress_time);
        if (rtt_sample_count >= 3)
        {
            const uint64_t rtt_ms = (uint64_t)rtt_ewma_ms;
            uint64_t next_proposal_window_ms = (rtt_ms * 4ULL) + 300ULL;
            if (next_proposal_window_ms < adaptive_proposal_window_min_ms)
                next_proposal_window_ms = adaptive_proposal_window_min_ms;
            if (next_proposal_window_ms > adaptive_proposal_window_max_ms)
                next_proposal_window_ms = adaptive_proposal_window_max_ms;
            adaptive_proposal_window_ms = next_proposal_window_ms;

            uint64_t next_round_timeout_ms = (rtt_ms * 12ULL) + (adaptive_proposal_window_ms * 2ULL);
            if (next_round_timeout_ms < adaptive_round_timeout_min_ms)
                next_round_timeout_ms = adaptive_round_timeout_min_ms;
            if (next_round_timeout_ms > adaptive_round_timeout_max_ms)
                next_round_timeout_ms = adaptive_round_timeout_max_ms;
            adaptive_round_timeout_ms = next_round_timeout_ms;
        }
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
            Logf(LOG_NORMAL, "[CTRL] round_interval now=%d base=%d peers=%zu lag=%llu no_progress_sec=%d last_progress_round=%llu rtt_ewma_ms=%llu proposal_window_ms=%llu round_timeout_ms=%llu\n",
                   dynamic_autopropose_interval_sec,
                   base_interval_sec,
                   peer_last_round.size(),
                   (unsigned long long)lag_now,
                   no_progress_sec,
                   (unsigned long long)last_progress_round,
                   (unsigned long long)rtt_ewma_ms,
                   (unsigned long long)adaptive_proposal_window_ms,
                   (unsigned long long)adaptive_round_timeout_ms);
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
        bool any_peer_progress = false;
        for (std::map<int, uint64_t>::const_iterator it = peer_last_round.begin(); it != peer_last_round.end(); ++it)
        {
            if (it->second > 0)
            {
                any_peer_progress = true;
                break;
            }
        }
        const bool is_synced_or_standalone =
            (last_committed_round >= synced_last_round) &&
            (!have_peers || synced_last_round > 0 || !any_peer_progress);
        // Sync-first policy: fully (or near-fully) catch up before mining.
        // This keeps late arrivals deterministic and avoids wasting work on stale rounds.
        const uint64_t kSyncFirstLag = 3;
        const uint64_t lag_to_sync = (synced_last_round > last_committed_round)
                                         ? (synced_last_round - last_committed_round)
                                         : 0;
        const bool sync_first =
            ((last_committed_round == 0 && synced_last_round > 0) || (lag_to_sync > kSyncFirstLag));
        if (sync_first != sync_first_prev)
        {
            Logf(LOG_NORMAL, "[SYNC] mode=%s local=%llu synced=%llu lag=%llu threshold=%llu\n",
                   sync_first ? "sync_first" : "open_mining",
                   (unsigned long long)last_committed_round,
                   (unsigned long long)synced_last_round,
                   (unsigned long long)lag_to_sync,
                   (unsigned long long)kSyncFirstLag);
            sync_first_prev = sync_first;
        }
        const bool autopropose_sync_gate_ok = is_synced_or_standalone && !sync_first;
        const uint64_t target_round = last_committed_round + 1;
        bool round_timeout_elapsed = false;
        {
            const uint64_t nowm = NowMonotonicMs();
            std::map<uint64_t, uint64_t>::const_iterator it_act = round_last_activity_ms.find(target_round);
            const uint64_t last_act = (it_act == round_last_activity_ms.end()) ? nowm : it_act->second;
            round_timeout_elapsed = (nowm >= last_act) && ((nowm - last_act) >= adaptive_round_timeout_ms);
        }
        if (cfg.autopropose != 0 && autopropose_sync_gate_ok && have_peers &&
            round_timeout_elapsed &&
            !timeout_vote_sent_rounds.count(target_round) &&
            !timeout_qc_rounds.count(target_round) &&
            round_best_batch_key.count(target_round) &&
            !HasPendingRound(target_round) &&
            !local_vote_by_round.count(target_round))
        {
            TimeoutVote tv;
            tv.round = target_round;
            tv.validator_id = signer_id;
            std::map<uint64_t, std::string>::const_iterator it_best = round_best_batch_key.find(target_round);
            if (it_best != round_best_batch_key.end() && it_best->second.size() == 32)
                memcpy(tv.lock_batch_hash.v, it_best->second.data(), 32);
            std::vector<uint8_t> m;
            if (BuildTimeoutSignMessage(tv, &m) &&
                crypto->SignEd25519(signer_priv, m.empty() ? NULL : &m[0], m.size(), &tv.signature))
            {
                timeout_votes_by_round[target_round][std::string((const char*)signer_id.v, 32)] = tv;
                timeout_vote_sent_rounds.insert(target_round);
                std::vector<uint8_t> payload;
                if (SerializeTimeoutVotePayload(tv, &payload))
                {
                    WireEnvelope outt;
                    outt.magic = WireMagicMainnet();
                    outt.version = 1;
                    outt.msg_type = WIRE_MSG_TIMEOUT_VOTE;
                    outt.payload_len = (uint32_t)payload.size();
                    outt.unix_ms = 0;
                    outt.payload_hash = Bytes32();
                    outt.payload.swap(payload);
                    (void)reactor.Broadcast(outt);
                    Logf(LOG_NORMAL,
                         "[TIMEOUT] emit round=%llu no_progress_sec=%d min_votes=%zu\n",
                         (unsigned long long)target_round,
                         no_progress_sec,
                         DynamicMinVotes());
                }
            }
        }
        auto IsLocalRoundLeader = [&](uint64_t round, Bytes32* out_winner, size_t* out_n) -> bool {
            (void)round;
            if (out_winner)
                *out_winner = signer_id;
            if (out_n)
                *out_n = 0;
            return true;
        };
        if (cfg.autopropose != 0 &&
            autopropose_sync_gate_ok &&
            (time(NULL) - last_autopropose_tick) >= dynamic_autopropose_interval_sec)
        {
            RoundBatch batch;
            bool have_pending = GetPendingRound(target_round, &batch);
            if (!have_pending)
            {
                Bytes32 leader_id;
                const bool local_leader = IsLocalRoundLeader(target_round, &leader_id, NULL);
                if (last_leader_log_round != target_round)
                {
                    last_leader_log_round = target_round;
                    Logf(LOG_NORMAL, "[LEADER] round=%llu role_set=open participants=unbounded winner=%s local=%d\n",
                           (unsigned long long)target_round,
                           Hex32(leader_id).c_str(),
                           local_leader ? 1 : 0);
                }
                if (!local_leader)
                {
                    last_autopropose_tick = time(NULL);
                    continue;
                }
                batch.round = target_round;
                SetRoundMode(target_round, ROUND_MODE_MINING, "autopropose_start");
                batch.params_hash = params_hash;
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
                Logf(LOG_NORMAL, "[AUTO] prepare round=%llu subsidy=%llu subsidy_drpow=%s tax_ppm=%llu burn_refill=%llu burn_refill_drpow=%s reserve=%llu reserve_drpow=%s mint=%llu mint_drpow=%s target=%s miner=%s\n",
                       (unsigned long long)batch.round,
                       (unsigned long long)subsidy,
                       FormatAtomic8(subsidy).c_str(),
                       (unsigned long long)TransferTaxPpmForRound(batch.round, economics_policy),
                       (unsigned long long)SumBatchFees(batch),
                       FormatAtomic8(SumBatchFees(batch)).c_str(),
                       (unsigned long long)reserve_budget,
                       FormatAtomic8(reserve_budget).c_str(),
                       (unsigned long long)mint.output.value,
                       FormatAtomic8(mint.output.value).c_str(),
                       Hex32(mint.target).c_str(),
                       Hex32(mint.miner_pubkey).c_str());

                // Bitcoin-like loop: try many nonces each interval, stop when target is met
                // or when we hit bounded CPU/work limits for this tick.
                const uint64_t pow_start_ms = NowMonotonicMs();
                // Adaptive budget:
                // base=6000ms, on not_found => double, on found => reset to base.
                const uint64_t pow_time_budget_ms = dynamic_pow_time_budget_ms;
                uint64_t pow_attempts = 0;
                bool pow_found = false;
                bool pow_preempted = false;
                uint64_t nonce_cursor = ((uint64_t)time(NULL) << 32) ^ ((uint64_t)getpid() << 16) ^ batch.round;
                Bytes32 parent_root;
                if (!store.ReadStateRoot(&parent_root))
                {
                    Logf(LOG_NORMAL, "[AUTO][REJECT] round=%llu stage=parent_root reason=read_state_root_failed\n",
                           (unsigned long long)batch.round);
                    for (size_t i = 0; i < drained_spends.size(); ++i)
                    {
                        std::string readd_err;
                        (void)mempool.AddSpend(drained_spends[i], &readd_err);
                    }
                    last_autopropose_tick = time(NULL);
                    continue;
                }
                Bytes32 proposer_target_half;
                HalveTargetLocal(expected_target, &proposer_target_half);
                Bytes32 proposer_pow_hash;
                while (true)
                {
                    if ((pow_attempts & 2047ULL) == 0ULL)
                    {
                        reactor.PollOnce();
                        if (last_committed_round >= batch.round)
                        {
                            pow_preempted = true;
                            break;
                        }
                    }
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
                    if (!ComputeProposerPowHashLocal(batch, parent_root, &proposer_pow_hash))
                    {
                        Logf(LOG_NORMAL, "[AUTO][REJECT] round=%llu stage=pow_hash reason=compute_failed\n",
                               (unsigned long long)batch.round);
                        break;
                    }
                    ++pow_attempts;
                    {
                        const std::string local_batch_key = Bytes32Key(batch.batch_hash);
                        std::map<uint64_t, std::string>::const_iterator it_best_live = round_best_batch_key.find(batch.round);
                        if (it_best_live != round_best_batch_key.end() &&
                            !it_best_live->second.empty() &&
                            it_best_live->second != local_batch_key)
                        {
                            pow_preempted = true;
                            break;
                        }
                    }
                    if (memcmp(proposer_pow_hash.v, proposer_target_half.v, 32) <= 0)
                    {
                        pow_found = true;
                        break;
                    }
                }
                const uint64_t pow_elapsed_ms = (NowMonotonicMs() >= pow_start_ms) ? (NowMonotonicMs() - pow_start_ms) : 0;
                const uint64_t pow_hps = (pow_elapsed_ms > 0) ? ((pow_attempts * 1000ULL) / pow_elapsed_ms) : 0;
                if (pow_preempted)
                {
                    metric_pow_preempt_rounds += 1;
                    preempt_round_time_sec[batch.round] = (uint64_t)time(NULL);
                    Logf(LOG_NORMAL, "[POW] round=%llu status=preempted attempts=%llu elapsed_ms=%llu rate_hps=%llu\n",
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
                if (!pow_found)
                {
                    Logf(LOG_NORMAL, "[POW] round=%llu status=not_found attempts=%llu elapsed_ms=%llu rate_hps=%llu\n",
                           (unsigned long long)batch.round,
                           (unsigned long long)pow_attempts,
                           (unsigned long long)pow_elapsed_ms,
                           (unsigned long long)pow_hps);
                    if (dynamic_pow_time_budget_ms <= (UINT64_MAX / 2ULL))
                        dynamic_pow_time_budget_ms *= 2ULL;
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
                       Hex32(proposer_pow_hash).c_str());
                dynamic_pow_time_budget_ms = kPowBaseBudgetMs;
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
                register_proposal_candidate(batch);
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
                    (void)broadcast_with_retry(outp, "autopropose", &metric_p2p_send_fail_propose, &metric_p2p_send_retry_ok_propose);
                }

                TryVoteCanonicalRound(target_round);
                Logf(LOG_DEBUG, "[AUTO] broadcast round=%llu spends=%zu mints=%zu fees=%llu minted=%llu\n",
                       (unsigned long long)batch.round,
                       batch.spends.size(),
                       batch.mints.size(),
                       (unsigned long long)SumBatchFees(batch),
                       (unsigned long long)SumBatchMintValue(batch));
            }
            last_autopropose_tick = time(NULL);
        }
        if (cfg.autopropose != 0 && autopropose_sync_gate_ok)
            TryVoteCanonicalRound(target_round);
        const int sync_period_sec = (synced_last_round > last_committed_round) ? 1 : 5;
        if ((time(NULL) - last_sync_tick) >= sync_period_sec)
        {
            flush_drop_summary(false);
            BroadcastSyncStatus();
            TryCatchUpFromCache();
            if (force_sync_from_round > 0)
            {
                size_t req_sent = 0;
                for (std::map<int, uint64_t>::const_iterator itp = peer_last_round.begin();
                     itp != peer_last_round.end();
                     ++itp)
                {
                    if (itp->second >= force_sync_from_round)
                    {
                        if (send_sync_request_to_peer(itp->first, force_sync_from_round, 64))
                            req_sent += 1;
                    }
                }
                printf("catchup_recover_request from_round=%llu peers=%zu\n",
                       (unsigned long long)force_sync_from_round,
                       req_sent);
                if (req_sent > 0)
                    force_sync_from_round = 0;
            }
            (void)TryReplayReorgWindow();
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

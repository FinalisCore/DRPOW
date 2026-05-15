#include "p2p_wire.h"

#include <string.h>
#include <vector>

#include "rpov2/tx_codec.h"

namespace rpov2 {

static uint32_t g_wire_magic = 0x52504f57u;  // 'RPOW'

uint32_t WireMagicMainnet()
{
    return g_wire_magic;
}

bool WireSetMagic(uint32_t magic)
{
    if (magic == 0)
        return false;
    g_wire_magic = magic;
    return true;
}

size_t WireMaxPayloadBytes()
{
    return 1024 * 1024;
}

static void WriteU32LELocal(std::vector<uint8_t>* out, uint32_t v)
{
    out->push_back((uint8_t)(v & 0xff));
    out->push_back((uint8_t)((v >> 8) & 0xff));
    out->push_back((uint8_t)((v >> 16) & 0xff));
    out->push_back((uint8_t)((v >> 24) & 0xff));
}

static void WriteU16LELocal(std::vector<uint8_t>* out, uint16_t v)
{
    out->push_back((uint8_t)(v & 0xff));
    out->push_back((uint8_t)((v >> 8) & 0xff));
}

static void WriteU32LEVecLocal(std::vector<uint8_t>* out, uint32_t v)
{
    out->push_back((uint8_t)(v & 0xff));
    out->push_back((uint8_t)((v >> 8) & 0xff));
    out->push_back((uint8_t)((v >> 16) & 0xff));
    out->push_back((uint8_t)((v >> 24) & 0xff));
}

static bool ReadU32LELocal(const uint8_t* in, size_t n, size_t* off, uint32_t* out)
{
    if (!in || !off || !out || *off + 4 > n)
        return false;
    const size_t i = *off;
    *out = ((uint32_t)in[i]) | ((uint32_t)in[i + 1] << 8) | ((uint32_t)in[i + 2] << 16) | ((uint32_t)in[i + 3] << 24);
    *off += 4;
    return true;
}

static bool ReadU16LELocal(const uint8_t* in, size_t n, size_t* off, uint16_t* out)
{
    if (!in || !off || !out || *off + 2 > n)
        return false;
    const size_t i = *off;
    *out = (uint16_t)(((uint16_t)in[i]) | ((uint16_t)in[i + 1] << 8));
    *off += 2;
    return true;
}

static bool ReadU64LELocal(const uint8_t* in, size_t n, size_t* off, uint64_t* out)
{
    if (!in || !off || !out || *off + 8 > n)
        return false;
    const size_t i = *off;
    *out = ((uint64_t)in[i]) |
           ((uint64_t)in[i + 1] << 8) |
           ((uint64_t)in[i + 2] << 16) |
           ((uint64_t)in[i + 3] << 24) |
           ((uint64_t)in[i + 4] << 32) |
           ((uint64_t)in[i + 5] << 40) |
           ((uint64_t)in[i + 6] << 48) |
           ((uint64_t)in[i + 7] << 56);
    *off += 8;
    return true;
}

static bool ReadBytesLocal(const uint8_t* in, size_t n, size_t* off, uint8_t* out, size_t bytes)
{
    if (!in || !off || !out || *off + bytes > n)
        return false;
    memcpy(out, in + *off, bytes);
    *off += bytes;
    return true;
}

static bool ReadVecLocal(const uint8_t* in, size_t n, size_t* off, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    uint64_t sz = 0;
    if (!ReadU64LELocal(in, n, off, &sz))
        return false;
    if (sz > n || *off + (size_t)sz > n)
        return false;
    out->assign(in + *off, in + *off + (size_t)sz);
    *off += (size_t)sz;
    return true;
}

bool SerializeWireEnvelope(const WireEnvelope& env, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    if (env.payload.size() > WireMaxPayloadBytes())
        return false;

    Bytes32 h;
    if (!Sha256(env.payload, &h))
        return false;

    out->clear();
    out->reserve(4 + 2 + 2 + 4 + 8 + 32 + env.payload.size());
    WriteU32LELocal(out, env.magic);
    WriteU16LELocal(out, env.version);
    WriteU16LELocal(out, env.msg_type);
    WriteU32LELocal(out, (uint32_t)env.payload.size());
    WriteU64LE(out, env.unix_ms);
    out->insert(out->end(), h.v, h.v + 32);
    out->insert(out->end(), env.payload.begin(), env.payload.end());
    return true;
}

bool ParseWireEnvelope(const std::vector<uint8_t>& in, WireEnvelope* out)
{
    if (!out)
        return false;
    if (in.size() < 4 + 2 + 2 + 4 + 8 + 32)
        return false;

    size_t off = 0;
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t msg_type = 0;
    uint32_t payload_len = 0;
    uint64_t unix_ms = 0;
    Bytes32 declared_hash;

    if (!ReadU32LELocal(&in[0], in.size(), &off, &magic))
        return false;
    if (!ReadU16LELocal(&in[0], in.size(), &off, &version))
        return false;
    if (!ReadU16LELocal(&in[0], in.size(), &off, &msg_type))
        return false;
    if (!ReadU32LELocal(&in[0], in.size(), &off, &payload_len))
        return false;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &unix_ms))
        return false;

    if (payload_len > WireMaxPayloadBytes())
        return false;
    if (off + 32 + payload_len != in.size())
        return false;

    memcpy(declared_hash.v, &in[off], 32);
    off += 32;

    std::vector<uint8_t> payload(payload_len);
    if (payload_len > 0)
        memcpy(&payload[0], &in[off], payload_len);

    Bytes32 actual_hash;
    if (!Sha256(payload, &actual_hash))
        return false;
    if (memcmp(actual_hash.v, declared_hash.v, 32) != 0)
        return false;

    out->magic = magic;
    out->version = version;
    out->msg_type = msg_type;
    out->payload_len = payload_len;
    out->unix_ms = unix_ms;
    out->payload_hash = declared_hash;
    out->payload.swap(payload);
    return true;
}

bool SerializeRoundBatchPayload(const RoundBatch& batch, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    WriteU64LE(out, batch.round);
    WriteBytes32(out, batch.batch_hash);
    WriteU64LE(out, (uint64_t)batch.spends.size());
    for (size_t i = 0; i < batch.spends.size(); ++i)
        SerializeSpendTxCanonical(batch.spends[i], out);
    WriteU64LE(out, (uint64_t)batch.mints.size());
    for (size_t i = 0; i < batch.mints.size(); ++i)
        SerializeMintTxCanonical(batch.mints[i], out);
    return true;
}

bool ParseRoundBatchPayload(const std::vector<uint8_t>& in, RoundBatch* out)
{
    if (!out || in.empty())
        return false;
    size_t off = 0;
    RoundBatch batch;
    uint64_t spends_n = 0, mints_n = 0;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &batch.round))
        return false;
    if (!ReadBytesLocal(&in[0], in.size(), &off, batch.batch_hash.v, 32))
        return false;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &spends_n))
        return false;
    if (spends_n > 1000000ULL)
        return false;
    batch.spends.resize((size_t)spends_n);
    for (size_t i = 0; i < batch.spends.size(); ++i)
        if (!ParseSpendTxCanonical(&in[0], in.size(), &off, &batch.spends[i]))
            return false;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &mints_n))
        return false;
    if (mints_n > 1000000ULL)
        return false;
    batch.mints.resize((size_t)mints_n);
    for (size_t i = 0; i < batch.mints.size(); ++i)
        if (!ParseMintTxCanonical(&in[0], in.size(), &off, &batch.mints[i]))
            return false;
    if (off != in.size())
        return false;
    *out = batch;
    return true;
}

bool SerializeVotePayload(const Vote& vote, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    WriteU64LE(out, vote.round);
    WriteBytes32(out, vote.batch_hash);
    WriteBytes32(out, vote.validator_id);
    WriteU64LE(out, (uint64_t)vote.signature.size());
    out->insert(out->end(), vote.signature.begin(), vote.signature.end());
    return true;
}

bool ParseVotePayload(const std::vector<uint8_t>& in, Vote* out)
{
    if (!out || in.empty())
        return false;
    size_t off = 0;
    Vote v;
    uint64_t sig_n = 0;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &v.round))
        return false;
    if (!ReadBytesLocal(&in[0], in.size(), &off, v.batch_hash.v, 32))
        return false;
    if (!ReadBytesLocal(&in[0], in.size(), &off, v.validator_id.v, 32))
        return false;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &sig_n))
        return false;
    if (sig_n > in.size() || off + (size_t)sig_n != in.size())
        return false;
    v.signature.assign(in.begin() + off, in.end());
    *out = v;
    return true;
}

static bool SerializeQcLocal(const QuorumCertificate& qc, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    WriteU64LE(out, qc.round);
    WriteBytes32(out, qc.batch_hash);
    WriteU64LE(out, (uint64_t)qc.votes.size());
    for (size_t i = 0; i < qc.votes.size(); ++i)
    {
        const Vote& v = qc.votes[i];
        WriteU64LE(out, v.round);
        WriteBytes32(out, v.batch_hash);
        WriteBytes32(out, v.validator_id);
        WriteU64LE(out, (uint64_t)v.signature.size());
        out->insert(out->end(), v.signature.begin(), v.signature.end());
    }
    return true;
}

static bool ParseQcLocal(const uint8_t* data, size_t n, size_t* off, QuorumCertificate* out)
{
    if (!data || !off || !out)
        return false;
    QuorumCertificate qc;
    uint64_t votes_n = 0;
    if (!ReadU64LELocal(data, n, off, &qc.round))
        return false;
    if (!ReadBytesLocal(data, n, off, qc.batch_hash.v, 32))
        return false;
    if (!ReadU64LELocal(data, n, off, &votes_n))
        return false;
    if (votes_n > 1000000ULL)
        return false;
    qc.votes.resize((size_t)votes_n);
    for (size_t i = 0; i < qc.votes.size(); ++i)
    {
        std::vector<uint8_t> sig;
        if (!ReadU64LELocal(data, n, off, &qc.votes[i].round))
            return false;
        if (!ReadBytesLocal(data, n, off, qc.votes[i].batch_hash.v, 32))
            return false;
        if (!ReadBytesLocal(data, n, off, qc.votes[i].validator_id.v, 32))
            return false;
        if (!ReadVecLocal(data, n, off, &sig))
            return false;
        qc.votes[i].signature.swap(sig);
    }
    *out = qc;
    return true;
}

bool SerializeCommitPayload(const RoundBatch& batch, const QuorumCertificate& qc, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    if (!SerializeRoundBatchPayload(batch, out))
        return false;
    std::vector<uint8_t> qc_bytes;
    if (!SerializeQcLocal(qc, &qc_bytes))
        return false;
    WriteU64LE(out, (uint64_t)qc_bytes.size());
    out->insert(out->end(), qc_bytes.begin(), qc_bytes.end());
    return true;
}

bool ParseCommitPayload(const std::vector<uint8_t>& in, RoundBatch* batch, QuorumCertificate* qc)
{
    if (!batch || !qc || in.empty())
        return false;

    RoundBatch b;
    size_t off = 0;
    uint64_t spends_n = 0, mints_n = 0, qc_sz = 0;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &b.round))
        return false;
    if (!ReadBytesLocal(&in[0], in.size(), &off, b.batch_hash.v, 32))
        return false;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &spends_n))
        return false;
    if (spends_n > 1000000ULL)
        return false;
    b.spends.resize((size_t)spends_n);
    for (size_t i = 0; i < b.spends.size(); ++i)
        if (!ParseSpendTxCanonical(&in[0], in.size(), &off, &b.spends[i]))
            return false;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &mints_n))
        return false;
    if (mints_n > 1000000ULL)
        return false;
    b.mints.resize((size_t)mints_n);
    for (size_t i = 0; i < b.mints.size(); ++i)
        if (!ParseMintTxCanonical(&in[0], in.size(), &off, &b.mints[i]))
            return false;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &qc_sz))
        return false;
    if (qc_sz > in.size() || off + (size_t)qc_sz != in.size())
        return false;
    size_t qc_off = 0;
    QuorumCertificate q;
    if (!ParseQcLocal(&in[off], (size_t)qc_sz, &qc_off, &q))
        return false;
    if (qc_off != (size_t)qc_sz)
        return false;
    *batch = b;
    *qc = q;
    return true;
}

bool SerializeSyncStatusPayload(uint64_t last_committed_round, const Bytes32& state_root, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    WriteU64LE(out, last_committed_round);
    WriteBytes32(out, state_root);
    return true;
}

bool ParseSyncStatusPayload(const std::vector<uint8_t>& in, uint64_t* last_committed_round, Bytes32* state_root)
{
    if (!last_committed_round || !state_root || in.size() != (8 + 32))
        return false;
    size_t off = 0;
    if (!ReadU64LELocal(&in[0], in.size(), &off, last_committed_round))
        return false;
    if (!ReadBytesLocal(&in[0], in.size(), &off, state_root->v, 32))
        return false;
    return off == in.size();
}

bool SerializeSyncRequestPayload(uint64_t from_round, uint32_t max_records, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    WriteU64LE(out, from_round);
    WriteU32LEVecLocal(out, max_records);
    return true;
}

bool ParseSyncRequestPayload(const std::vector<uint8_t>& in, uint64_t* from_round, uint32_t* max_records)
{
    if (!from_round || !max_records || in.size() != 12)
        return false;
    size_t off = 0;
    if (!ReadU64LELocal(&in[0], in.size(), &off, from_round))
        return false;
    if (!ReadU32LELocal(&in[0], in.size(), &off, max_records))
        return false;
    return off == in.size();
}

bool SerializeSyncResponsePayload(uint64_t from_round, const std::vector< std::vector<uint8_t> >& commit_payloads, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    WriteU64LE(out, from_round);
    WriteU32LEVecLocal(out, (uint32_t)commit_payloads.size());
    for (size_t i = 0; i < commit_payloads.size(); ++i)
    {
        WriteU64LE(out, (uint64_t)commit_payloads[i].size());
        out->insert(out->end(), commit_payloads[i].begin(), commit_payloads[i].end());
    }
    return true;
}

bool ParseSyncResponsePayload(const std::vector<uint8_t>& in, uint64_t* from_round, std::vector< std::vector<uint8_t> >* commit_payloads)
{
    if (!from_round || !commit_payloads || in.empty())
        return false;
    size_t off = 0;
    uint32_t count = 0;
    if (!ReadU64LELocal(&in[0], in.size(), &off, from_round))
        return false;
    if (!ReadU32LELocal(&in[0], in.size(), &off, &count))
        return false;
    if (count > 10000)
        return false;
    commit_payloads->clear();
    commit_payloads->reserve(count);
    for (uint32_t i = 0; i < count; ++i)
    {
        uint64_t n = 0;
        if (!ReadU64LELocal(&in[0], in.size(), &off, &n))
            return false;
        if (n > in.size() || off + (size_t)n > in.size())
            return false;
        std::vector<uint8_t> payload(in.begin() + off, in.begin() + off + (size_t)n);
        off += (size_t)n;
        commit_payloads->push_back(payload);
    }
    return off == in.size();
}

bool SerializePeerListPayload(uint64_t advertised_round,
                              const Bytes32& advertiser_id,
                              const std::vector<std::string>& peers,
                              const std::vector<uint8_t>& signature,
                              std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    WriteU64LE(out, advertised_round);
    WriteBytes32(out, advertiser_id);
    WriteU64LE(out, (uint64_t)peers.size());
    for (size_t i = 0; i < peers.size(); ++i)
    {
        WriteU64LE(out, (uint64_t)peers[i].size());
        out->insert(out->end(), peers[i].begin(), peers[i].end());
    }
    WriteU64LE(out, (uint64_t)signature.size());
    out->insert(out->end(), signature.begin(), signature.end());
    return true;
}

bool ParsePeerListPayload(const std::vector<uint8_t>& in,
                          uint64_t* advertised_round,
                          Bytes32* advertiser_id,
                          std::vector<std::string>* peers,
                          std::vector<uint8_t>* signature)
{
    if (!advertised_round || !advertiser_id || !peers || !signature || in.empty())
        return false;
    peers->clear();
    signature->clear();
    size_t off = 0;
    if (!ReadU64LELocal(&in[0], in.size(), &off, advertised_round))
        return false;
    if (!ReadBytesLocal(&in[0], in.size(), &off, advertiser_id->v, 32))
        return false;
    uint64_t n = 0;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &n))
        return false;
    if (n > 10000)
        return false;
    for (uint64_t i = 0; i < n; ++i)
    {
        uint64_t sz = 0;
        if (!ReadU64LELocal(&in[0], in.size(), &off, &sz))
            return false;
        if (sz > in.size() || off + (size_t)sz > in.size())
            return false;
        peers->push_back(std::string((const char*)&in[off], (size_t)sz));
        off += (size_t)sz;
    }
    uint64_t sig_sz = 0;
    if (!ReadU64LELocal(&in[0], in.size(), &off, &sig_sz))
        return false;
    if (sig_sz > in.size() || off + (size_t)sig_sz > in.size())
        return false;
    signature->assign(in.begin() + off, in.begin() + off + (size_t)sig_sz);
    off += (size_t)sig_sz;
    return off == in.size();
}

}  

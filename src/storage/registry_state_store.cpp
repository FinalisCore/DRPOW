#include "registry_state_store.h"

#include <algorithm>
#include <stdint.h>
#include <fstream>
#include <string.h>

#include "state_commitment.h"
#include "rpov2/tx_codec.h"

namespace rpov2 {

namespace {

static const uint16_t kCommitRecordVersion1 = 1;
static const uint16_t kHashAlgSha256 = 1;
static const uint16_t kSigAlgPqcBackend = 1;

static bool AddNoOverflow(uint64_t a, uint64_t b, uint64_t* out)
{
    if (!out)
        return false;
    if (UINT64_MAX - a < b)
        return false;
    *out = a + b;
    return true;
}

struct CommitRecordParsedV1 {
    RoundCommitRecord rec;
};

static bool ComputeRecordHashV1(const RoundCommitRecord& record, Bytes32* out)
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

static bool ParseAndVerifyCommitRecordV1(std::ifstream* in,
                                         const CryptoBackend* crypto_backend,
                                         bool has_commit_signer,
                                         const Bytes32& commit_signer_id,
                                         bool* io_verified_any_signed_record,
                                         uint64_t* out_round,
                                         RoundCommitRecord* out_record)
{
    if (!in || !io_verified_any_signed_record || !out_round)
        return false;

    CommitRecordParsedV1 p;
    RoundCommitRecord& rec = p.rec;
    rec.record_version = kCommitRecordVersion1;
    rec.hash_alg_id = kHashAlgSha256;
    rec.sig_alg_id = kSigAlgPqcBackend;

    in->read((char*)&rec.round, sizeof(rec.round));
    if (in->eof())
        return true;
    if (!in->good())
        return false;

    in->read((char*)rec.batch_hash.v, 32);
    in->read((char*)rec.state_root.v, 32);
    if (!in->good())
        return false;

    uint64_t proof_size = 0;
    in->read((char*)&proof_size, sizeof(proof_size));
    if (!in->good())
        return false;
    if (proof_size > (16 * 1024 * 1024))
        return false;
    rec.consensus_proof.assign((size_t)proof_size, 0);
    if (proof_size > 0)
        in->read((char*)&rec.consensus_proof[0], (std::streamsize)proof_size);
    if (!in->good())
        return false;

    char trailer_head[40];
    in->read(trailer_head, 40);
    if (!in->good())
    {
        // Backward compatibility: legacy records had no hash/signature trailer.
        if (in->eof())
            return true;
        return false;
    }
    memcpy(rec.record_hash.v, trailer_head, 32);
    memcpy(rec.record_signer_id.v, trailer_head + 32, 8);
    in->read((char*)rec.record_signer_id.v + 8, 24);
    if (!in->good())
        return false;

    uint64_t sig_size = 0;
    in->read((char*)&sig_size, sizeof(sig_size));
    if (!in->good())
        return false;
    if (sig_size > (16 * 1024 * 1024))
        return false;
    rec.record_signature.assign((size_t)sig_size, 0);
    if (sig_size > 0)
        in->read((char*)&rec.record_signature[0], (std::streamsize)sig_size);
    if (!in->good())
        return false;

    Bytes32 expected_hash;
    if (!ComputeRecordHashV1(rec, &expected_hash))
        return false;
    if (memcmp(expected_hash.v, rec.record_hash.v, 32) != 0)
    {
        if (!*io_verified_any_signed_record)
            return true;
        return false;
    }
    if (!crypto_backend || !has_commit_signer)
        return false;
    if (memcmp(rec.record_signer_id.v, commit_signer_id.v, 32) != 0)
        return false;
    if (!crypto_backend->VerifyEd25519(rec.record_signer_id.v,
                                       rec.record_hash.v,
                                       32,
                                       rec.record_signature.empty() ? NULL : &rec.record_signature[0],
                                       rec.record_signature.size()))
    {
        if (!*io_verified_any_signed_record)
            return true;
        return false;
    }
    *io_verified_any_signed_record = true;
    *out_round = rec.round;
    if (out_record)
        *out_record = rec;
    return true;
}

static bool ParseAndVerifyCommitRecordV2Stub(std::ifstream* in)
{
    (void)in;
    return false;
}

}  // namespace

RegistryStateStore::RegistryStateStore(const std::string& registry_file,
                                       const std::string& commit_log_file,
                                       const std::string& evidence_log_file,
                                       const ProofVerifier* proof_verifier,
                                       const CryptoBackend* crypto_backend,
                                       const uint8_t commit_signer_privkey[32],
                                       const Bytes32* commit_signer_id)
    : registry_file_(registry_file),
      ledger_file_(registry_file + ".ledger"),
      commit_log_file_(commit_log_file),
      evidence_log_file_(evidence_log_file),
      proof_verifier_(proof_verifier),
      crypto_backend_(crypto_backend),
      in_txn_(false),
      commit_log_ok_(true),
      verified_last_round_(0),
      commit_log_verify_error_(COMMITLOG_VERIFY_OK),
      commit_log_verify_error_message_(""),
      genesis_supply_(0)
{
    memset(commit_signer_privkey_, 0, sizeof(commit_signer_privkey_));
    Zero32(&commit_signer_id_);
    has_commit_signer_ = false;
    if (commit_signer_privkey && commit_signer_id)
    {
        memcpy(commit_signer_privkey_, commit_signer_privkey, 32);
        commit_signer_id_ = *commit_signer_id;
        has_commit_signer_ = true;
    }

    live_totals_.total_supply = 0;
    live_totals_.total_minted = 0;
    live_totals_.total_fees_burned = 0;
    staged_totals_ = live_totals_;
    if (LoadRegistry())
    {
        if (!LoadLedgerTotals())
            commit_log_ok_ = false;
        if (!VerifyCommitLog())
            commit_log_ok_ = false;
    }
    else
    {
        commit_log_ok_ = false;
    }
}

bool RegistryStateStore::Begin()
{
    if (in_txn_)
        return false;
    if (!commit_log_ok_)
        return false;
    staged_ = live_;
    staged_totals_ = live_totals_;
    pending_commits_.clear();
    in_txn_ = true;
    return true;
}

bool RegistryStateStore::Commit()
{
    if (!in_txn_)
        return false;

    uint64_t recomputed_supply = 0;
    if (!ComputeSupply(staged_, &recomputed_supply))
        return false;
    if (recomputed_supply != staged_totals_.total_supply)
        return false;
    uint64_t lhs = 0;
    uint64_t rhs = 0;
    if (!AddNoOverflow(staged_totals_.total_supply, staged_totals_.total_fees_burned, &lhs))
        return false;
    if (!AddNoOverflow(genesis_supply_, staged_totals_.total_minted, &rhs))
        return false;
    if (lhs != rhs)
        return false;

    if (!FlushRegistry(staged_))
        return false;
    if (!FlushLedgerTotals(staged_totals_))
        return false;

    for (size_t i = 0; i < pending_commits_.size(); ++i)
        if (!AppendCommitLog(pending_commits_[i]))
            return false;

    live_.swap(staged_);
    live_totals_ = staged_totals_;
    staged_.clear();
    pending_commits_.clear();
    in_txn_ = false;
    return true;
}

void RegistryStateStore::Rollback()
{
    staged_.clear();
    staged_totals_ = live_totals_;
    pending_commits_.clear();
    in_txn_ = false;
}

bool RegistryStateStore::Spend(const SpendTx& tx)
{
    if (!in_txn_)
        return false;
    if (!proof_verifier_ || !proof_verifier_->VerifySpendTx(tx))
        return false;

    uint64_t input_total = 0;
    for (size_t i = 0; i < tx.inputs.size(); ++i)
    {
        std::string k = Key(tx.inputs[i].coin_id);
        std::map<std::string, UtxoRecord>::const_iterator it = staged_.find(k);
        if (it == staged_.end())
            return false;
        if (tx.inputs[i].ownership_proof.size() < 32)
            return false;
        if (memcmp(it->second.output.owner_pubkey.v, &tx.inputs[i].ownership_proof[0], 32) != 0)
            return false;
        if (!AddNoOverflow(input_total, it->second.output.value, &input_total))
            return false;
    }

    uint64_t output_total = 0;
    for (size_t i = 0; i < tx.outputs.size(); ++i)
        if (!AddNoOverflow(output_total, tx.outputs[i].value, &output_total))
            return false;
    if (input_total < output_total)
        return false;
    if (input_total - output_total != tx.fee)
        return false;

    for (size_t i = 0; i < tx.inputs.size(); ++i)
        staged_.erase(Key(tx.inputs[i].coin_id));

    for (size_t i = 0; i < tx.outputs.size(); ++i)
    {
        UtxoRecord rec;
        if (!ComputeCoinId(tx.outputs[i], tx.timestamp + i, &rec.coin_id))
            return false;
        rec.output = tx.outputs[i];
        Zero32(&rec.mint_nonce);
        Zero32(&rec.mint_signature);
        Zero32(&rec.reserved);
        staged_[Key(rec.coin_id)] = rec;
    }
    if (staged_totals_.total_supply < tx.fee)
        return false;
    staged_totals_.total_supply -= tx.fee;
    if (!AddNoOverflow(staged_totals_.total_fees_burned, tx.fee, &staged_totals_.total_fees_burned))
        return false;

    return true;
}

bool RegistryStateStore::Mint(const MintTx& tx)
{
    if (!in_txn_)
        return false;
    if (!proof_verifier_ || !proof_verifier_->VerifyMintTx(tx))
        return false;

    UtxoRecord rec;
    if (!ComputeCoinId(tx.output, tx.mint_nonce, &rec.coin_id))
        return false;
    rec.output = tx.output;
    Zero32(&rec.mint_nonce);
    for (int i = 0; i < 8; ++i)
        rec.mint_nonce.v[i] = (uint8_t)((tx.mint_nonce >> (8 * i)) & 0xff);
    if (!Sha256(tx.signature, &rec.mint_signature))
        return false;
    Zero32(&rec.reserved);
    staged_[Key(rec.coin_id)] = rec;
    if (!AddNoOverflow(staged_totals_.total_supply, tx.output.value, &staged_totals_.total_supply))
        return false;
    if (!AddNoOverflow(staged_totals_.total_minted, tx.output.value, &staged_totals_.total_minted))
        return false;
    return true;
}

bool RegistryStateStore::WriteRoundCommit(const RoundCommitRecord& record)
{
    if (!in_txn_)
        return false;
    pending_commits_.push_back(record);
    return true;
}

bool RegistryStateStore::WriteEquivocationEvidence(const EquivocationEvidenceRecord& record)
{
    return AppendEvidenceLog(record);
}

bool RegistryStateStore::ReadStateRoot(Bytes32* out_root) const
{
    if (!out_root)
        return false;
    if (in_txn_)
        return CurrentStateRoot(staged_, out_root);
    return CurrentStateRoot(live_, out_root);
}

std::string RegistryStateStore::Key(const Bytes32& id)
{
    return std::string((const char*)id.v, 32);
}

void RegistryStateStore::Zero32(Bytes32* v)
{
    memset(v->v, 0, 32);
}

bool RegistryStateStore::IsZero32(const Bytes32& v)
{
    for (int i = 0; i < 32; ++i)
        if (v.v[i] != 0)
            return false;
    return true;
}

bool RegistryStateStore::ComputeCoinId(const UtxoOutput& out, uint64_t nonce_hint, Bytes32* coin_id)
{
    if (!coin_id)
        return false;
    std::vector<uint8_t> d;
    WriteU64LE(&d, out.value);
    WriteBytes32(&d, out.commitment);
    WriteBytes32(&d, out.owner_pubkey);
    WriteU64LE(&d, nonce_hint);
    return Sha256(d, coin_id);
}

bool RegistryStateStore::LoadRegistry()
{
    live_.clear();
    std::ifstream in(registry_file_.c_str(), std::ios::binary);
    if (!in.good())
        return true;
    in.seekg(0, std::ios::end);
    std::streamoff sz = in.tellg();
    size_t rec_size = 0;
    if (sz >= 0 && (sz % 264) == 0)
        rec_size = 264;
    else if (sz >= 0 && (sz % 256) == 0)
        rec_size = 256;
    else
        return false;
    in.seekg(0, std::ios::beg);

    while (in.good())
    {
        UtxoRecord rec;
        rec.output.value = 0;
        if (rec_size == 264)
        {
            uint8_t vbuf[8];
            in.read((char*)vbuf, 8);
            if (!in.good())
                return false;
            uint64_t v = 0;
            for (int i = 0; i < 8; ++i)
                v |= ((uint64_t)vbuf[i] << (8 * i));
            rec.output.value = v;
        }
        in.read((char*)rec.coin_id.v, 32);
        if (!in.good())
            break;
        in.read((char*)rec.output.commitment.v, 32);
        in.read((char*)rec.output.owner_pubkey.v, 32);
        in.read((char*)rec.output.range_proof.v, 64);
        in.read((char*)rec.mint_nonce.v, 32);
        in.read((char*)rec.mint_signature.v, 32);
        in.read((char*)rec.reserved.v, 32);
        if (!in.good())
            return false;
        if (IsZero32(rec.coin_id))
            continue;
        live_[Key(rec.coin_id)] = rec;
    }
    uint64_t supply = 0;
    if (!ComputeSupply(live_, &supply))
        return false;
    genesis_supply_ = supply;
    live_totals_.total_supply = supply;
    live_totals_.total_minted = 0;
    live_totals_.total_fees_burned = 0;
    staged_totals_ = live_totals_;
    return true;
}

bool RegistryStateStore::FlushRegistry(const std::map<std::string, UtxoRecord>& src) const
{
    std::ofstream out(registry_file_.c_str(), std::ios::binary | std::ios::trunc);
    if (!out.good())
        return false;

    for (std::map<std::string, UtxoRecord>::const_iterator it = src.begin(); it != src.end(); ++it)
    {
        const UtxoRecord& rec = it->second;
        uint8_t vbuf[8];
        for (int i = 0; i < 8; ++i)
            vbuf[i] = (uint8_t)((rec.output.value >> (8 * i)) & 0xff);
        out.write((const char*)vbuf, 8);
        out.write((const char*)rec.coin_id.v, 32);
        out.write((const char*)rec.output.commitment.v, 32);
        out.write((const char*)rec.output.owner_pubkey.v, 32);
        out.write((const char*)rec.output.range_proof.v, 64);
        out.write((const char*)rec.mint_nonce.v, 32);
        out.write((const char*)rec.mint_signature.v, 32);
        out.write((const char*)rec.reserved.v, 32);
    }

    return out.good();
}

bool RegistryStateStore::AppendCommitLog(const RoundCommitRecord& record) const
{
    std::ofstream out(commit_log_file_.c_str(), std::ios::binary | std::ios::app);
    if (!out.good())
        return false;

    RoundCommitRecord rec = record;
    rec.record_version = kCommitRecordVersion1;
    rec.hash_alg_id = kHashAlgSha256;
    rec.sig_alg_id = kSigAlgPqcBackend;
    if (!ComputeRecordHashV1(rec, &rec.record_hash))
        return false;
    if (!crypto_backend_ || !has_commit_signer_)
        return false;
    rec.record_signer_id = commit_signer_id_;
    if (!crypto_backend_->SignEd25519(commit_signer_privkey_,
                                      rec.record_hash.v,
                                      32,
                                      &rec.record_signature))
        return false;

    out.write((const char*)&rec.record_version, sizeof(rec.record_version));
    out.write((const char*)&rec.hash_alg_id, sizeof(rec.hash_alg_id));
    out.write((const char*)&rec.sig_alg_id, sizeof(rec.sig_alg_id));
    out.write((const char*)&rec.round, sizeof(rec.round));
    out.write((const char*)rec.batch_hash.v, 32);
    out.write((const char*)rec.state_root.v, 32);

    uint64_t proof_size = (uint64_t)rec.consensus_proof.size();
    out.write((const char*)&proof_size, sizeof(proof_size));
    if (proof_size > 0)
        out.write((const char*)&rec.consensus_proof[0], proof_size);
    out.write((const char*)rec.record_hash.v, 32);
    out.write((const char*)rec.record_signer_id.v, 32);
    uint64_t sig_size = (uint64_t)rec.record_signature.size();
    out.write((const char*)&sig_size, sizeof(sig_size));
    if (sig_size > 0)
        out.write((const char*)&rec.record_signature[0], sig_size);

    return out.good();
}

bool RegistryStateStore::VerifyCommitLog() const
{
    commit_log_verify_error_ = COMMITLOG_VERIFY_OK;
    commit_log_verify_error_message_.clear();
    verified_last_round_ = 0;
    const auto fail = [this](CommitLogVerifyError code, const char* msg) -> bool {
        commit_log_verify_error_ = code;
        commit_log_verify_error_message_ = msg ? msg : "";
        return false;
    };

    std::ifstream in(commit_log_file_.c_str(), std::ios::binary);
    if (!in.good())
        return true;
    bool verified_any_signed_record = false;
    uint64_t last_round = 0;

    while (true)
    {
        uint16_t record_version = 0;
        uint16_t hash_alg_id = 0;
        uint16_t sig_alg_id = 0;
        in.read((char*)&record_version, sizeof(record_version));
        if (in.eof())
            return true;
        if (!in.good())
            return fail(COMMITLOG_VERIFY_IO_ERROR, "commit log read error");
        in.read((char*)&hash_alg_id, sizeof(hash_alg_id));
        if (!in.good())
            return fail(COMMITLOG_VERIFY_IO_ERROR, "commit log read error");
        in.read((char*)&sig_alg_id, sizeof(sig_alg_id));
        if (!in.good())
            return fail(COMMITLOG_VERIFY_IO_ERROR, "commit log read error");

        if (record_version == kCommitRecordVersion1 && hash_alg_id == kHashAlgSha256 && sig_alg_id == kSigAlgPqcBackend)
        {
            uint64_t parsed_round = 0;
            if (!ParseAndVerifyCommitRecordV1(&in, crypto_backend_, has_commit_signer_, commit_signer_id_, &verified_any_signed_record, &parsed_round, NULL))
            {
                if (!verified_any_signed_record)
                    return true;
                return fail(COMMITLOG_VERIFY_FORMAT_ERROR, "commit log v1 verification failed");
            }
            if (parsed_round == 0 || parsed_round <= last_round)
                return fail(COMMITLOG_VERIFY_ORDER_INVALID, "commit log round ordering invalid");
            last_round = parsed_round;
            verified_last_round_ = last_round;
            continue;
        }
        if (record_version == 2)
        {
            if (!ParseAndVerifyCommitRecordV2Stub(&in))
                return fail(COMMITLOG_VERIFY_UNSUPPORTED_UPGRADE, "commit log v2 unsupported: upgrade required");
            continue;
        }
        return fail(COMMITLOG_VERIFY_UNSUPPORTED_UPGRADE, "unsupported commit log version/algorithm");
    }
}

bool RegistryStateStore::ExportVerifiedCommitRecordsFromRound(uint64_t from_round,
                                                              size_t max_records,
                                                              std::vector<RoundCommitRecord>* out) const
{
    if (!out || max_records == 0)
        return false;
    out->clear();
    if (!commit_log_ok_)
        return false;

    std::ifstream in(commit_log_file_.c_str(), std::ios::binary);
    if (!in.good())
        return true;

    bool verified_any_signed_record = false;
    uint64_t last_round = 0;
    while (true)
    {
        uint16_t record_version = 0;
        uint16_t hash_alg_id = 0;
        uint16_t sig_alg_id = 0;
        in.read((char*)&record_version, sizeof(record_version));
        if (in.eof())
            return true;
        if (!in.good())
            return false;
        in.read((char*)&hash_alg_id, sizeof(hash_alg_id));
        in.read((char*)&sig_alg_id, sizeof(sig_alg_id));
        if (!in.good())
            return false;

        if (record_version != kCommitRecordVersion1 || hash_alg_id != kHashAlgSha256 || sig_alg_id != kSigAlgPqcBackend)
            return false;

        uint64_t parsed_round = 0;
        RoundCommitRecord rec;
        if (!ParseAndVerifyCommitRecordV1(&in,
                                          crypto_backend_,
                                          has_commit_signer_,
                                          commit_signer_id_,
                                          &verified_any_signed_record,
                                          &parsed_round,
                                          &rec))
            return false;
        if (parsed_round == 0 || parsed_round <= last_round)
            return false;
        last_round = parsed_round;
        if (parsed_round < from_round)
            continue;
        out->push_back(rec);
        if (out->size() >= max_records)
            return true;
    }
}

bool RegistryStateStore::LoadLedgerTotals()
{
    std::ifstream in(ledger_file_.c_str(), std::ios::binary);
    if (!in.good())
        return true;

    LedgerTotals t;
    in.read((char*)&t.total_supply, sizeof(t.total_supply));
    in.read((char*)&t.total_minted, sizeof(t.total_minted));
    in.read((char*)&t.total_fees_burned, sizeof(t.total_fees_burned));
    if (!in.good())
        return false;

    uint64_t recomputed_supply = 0;
    if (!ComputeSupply(live_, &recomputed_supply))
        return false;
    if (t.total_supply != recomputed_supply)
        return false;
    if (t.total_supply < genesis_supply_)
        return false;
    if (t.total_supply < t.total_fees_burned)
        return false;
    uint64_t lhs = 0;
    uint64_t rhs = 0;
    if (!AddNoOverflow(t.total_supply, t.total_fees_burned, &lhs))
        return false;
    if (!AddNoOverflow(genesis_supply_, t.total_minted, &rhs))
        return false;
    if (lhs != rhs)
        return false;

    live_totals_ = t;
    staged_totals_ = t;
    return true;
}

bool RegistryStateStore::FlushLedgerTotals(const LedgerTotals& totals) const
{
    std::ofstream out(ledger_file_.c_str(), std::ios::binary | std::ios::trunc);
    if (!out.good())
        return false;
    out.write((const char*)&totals.total_supply, sizeof(totals.total_supply));
    out.write((const char*)&totals.total_minted, sizeof(totals.total_minted));
    out.write((const char*)&totals.total_fees_burned, sizeof(totals.total_fees_burned));
    return out.good();
}

bool RegistryStateStore::AppendEvidenceLog(const EquivocationEvidenceRecord& record) const
{
    std::ofstream out(evidence_log_file_.c_str(), std::ios::binary | std::ios::app);
    if (!out.good())
        return false;

    out.write((const char*)&record.round, sizeof(record.round));
    out.write((const char*)record.validator_id.v, 32);
    out.write((const char*)record.batch_hash_a.v, 32);
    out.write((const char*)record.batch_hash_b.v, 32);

    uint64_t a_size = (uint64_t)record.qc_a.size();
    uint64_t b_size = (uint64_t)record.qc_b.size();
    out.write((const char*)&a_size, sizeof(a_size));
    if (a_size > 0)
        out.write((const char*)&record.qc_a[0], a_size);
    out.write((const char*)&b_size, sizeof(b_size));
    if (b_size > 0)
        out.write((const char*)&record.qc_b[0], b_size);

    return out.good();
}

bool RegistryStateStore::CurrentStateRoot(const std::map<std::string, UtxoRecord>& src, Bytes32* out_root) const
{
    if (!out_root)
        return false;

    std::vector< std::vector<uint8_t> > entries;
    entries.reserve(src.size());
    for (std::map<std::string, UtxoRecord>::const_iterator it = src.begin(); it != src.end(); ++it)
    {
        const UtxoRecord& rec = it->second;
        std::vector<uint8_t> e;
        e.reserve(264);
        for (int i = 0; i < 8; ++i)
            e.push_back((uint8_t)((rec.output.value >> (8 * i)) & 0xff));
        e.insert(e.end(), rec.coin_id.v, rec.coin_id.v + 32);
        e.insert(e.end(), rec.output.commitment.v, rec.output.commitment.v + 32);
        e.insert(e.end(), rec.output.owner_pubkey.v, rec.output.owner_pubkey.v + 32);
        e.insert(e.end(), rec.output.range_proof.v, rec.output.range_proof.v + 64);
        e.insert(e.end(), rec.mint_nonce.v, rec.mint_nonce.v + 32);
        e.insert(e.end(), rec.mint_signature.v, rec.mint_signature.v + 32);
        e.insert(e.end(), rec.reserved.v, rec.reserved.v + 32);
        entries.push_back(e);
    }

    return ComputeStateRootV1(entries, out_root);
}

bool RegistryStateStore::ComputeSupply(const std::map<std::string, UtxoRecord>& src, uint64_t* out_supply) const
{
    if (!out_supply)
        return false;
    uint64_t s = 0;
    for (std::map<std::string, UtxoRecord>::const_iterator it = src.begin(); it != src.end(); ++it)
    {
        if (!AddNoOverflow(s, it->second.output.value, &s))
            return false;
    }
    *out_supply = s;
    return true;
}

}  

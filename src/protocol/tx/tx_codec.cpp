#include "tx_codec.h"

#include <openssl/sha.h>
#include <string.h>

namespace rpov2 {

void WriteU64LE(std::vector<uint8_t>* out, uint64_t v)
{
    for (int i = 0; i < 8; ++i)
        out->push_back((uint8_t)((v >> (8 * i)) & 0xff));
}

void WriteBytes32(std::vector<uint8_t>* out, const Bytes32& v)
{
    out->insert(out->end(), v.v, v.v + 32);
}

void WriteBytes64(std::vector<uint8_t>* out, const Bytes64& v)
{
    out->insert(out->end(), v.v, v.v + 64);
}

static void WriteVec(std::vector<uint8_t>* out, const std::vector<uint8_t>& v)
{
    WriteU64LE(out, (uint64_t)v.size());
    out->insert(out->end(), v.begin(), v.end());
}

static bool ReadU64LELocal(const uint8_t* data, size_t data_len, size_t* off, uint64_t* out)
{
    if (!data || !off || !out || *off + 8 > data_len)
        return false;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= ((uint64_t)data[*off + i]) << (8 * i);
    *off += 8;
    *out = v;
    return true;
}

static bool ReadBytesLocal(const uint8_t* data, size_t data_len, size_t* off, uint8_t* out, size_t n)
{
    if (!data || !off || !out || *off + n > data_len)
        return false;
    memcpy(out, data + *off, n);
    *off += n;
    return true;
}

static bool ReadVecLocal(const uint8_t* data, size_t data_len, size_t* off, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    uint64_t n = 0;
    if (!ReadU64LELocal(data, data_len, off, &n))
        return false;
    if (n > data_len || *off + (size_t)n > data_len)
        return false;
    out->assign(data + *off, data + *off + (size_t)n);
    *off += (size_t)n;
    return true;
}

void SerializeSpendTxCanonical(const SpendTx& tx, std::vector<uint8_t>* out)
{
    WriteU64LE(out, (uint64_t)tx.inputs.size());
    for (size_t i = 0; i < tx.inputs.size(); ++i)
    {
        WriteBytes32(out, tx.inputs[i].coin_id);
        WriteVec(out, tx.inputs[i].ownership_proof);
    }

    WriteU64LE(out, (uint64_t)tx.outputs.size());
    for (size_t i = 0; i < tx.outputs.size(); ++i)
    {
        WriteU64LE(out, tx.outputs[i].value);
        WriteBytes32(out, tx.outputs[i].commitment);
        WriteBytes32(out, tx.outputs[i].owner_pubkey);
        WriteBytes64(out, tx.outputs[i].range_proof);
    }

    WriteVec(out, tx.sum_proof);
    WriteU64LE(out, tx.transfer_amount);
    WriteU64LE(out, tx.timestamp);
    WriteU64LE(out, tx.fee);

    WriteU64LE(out, (uint64_t)tx.signatures.size());
    for (size_t i = 0; i < tx.signatures.size(); ++i)
        WriteVec(out, tx.signatures[i]);
}

void SerializeMintTxCanonical(const MintTx& tx, std::vector<uint8_t>* out)
{
    WriteU64LE(out, tx.output.value);
    WriteBytes32(out, tx.output.commitment);
    WriteBytes32(out, tx.output.owner_pubkey);
    WriteBytes64(out, tx.output.range_proof);
    WriteU64LE(out, tx.mint_nonce);
    WriteBytes32(out, tx.target);
    WriteBytes32(out, tx.miner_pubkey);
    WriteVec(out, tx.signature);
}

bool ParseSpendTxCanonical(const uint8_t* data, size_t data_len, size_t* off, SpendTx* out)
{
    if (!data || !off || !out)
        return false;
    SpendTx tx;
    uint64_t n_inputs = 0;
    if (!ReadU64LELocal(data, data_len, off, &n_inputs))
        return false;
    if (n_inputs > 1000000ULL)
        return false;
    tx.inputs.resize((size_t)n_inputs);
    for (size_t i = 0; i < tx.inputs.size(); ++i)
    {
        if (!ReadBytesLocal(data, data_len, off, tx.inputs[i].coin_id.v, 32))
            return false;
        if (!ReadVecLocal(data, data_len, off, &tx.inputs[i].ownership_proof))
            return false;
    }

    uint64_t n_outputs = 0;
    if (!ReadU64LELocal(data, data_len, off, &n_outputs))
        return false;
    if (n_outputs > 1000000ULL)
        return false;
    tx.outputs.resize((size_t)n_outputs);
    for (size_t i = 0; i < tx.outputs.size(); ++i)
    {
        if (!ReadU64LELocal(data, data_len, off, &tx.outputs[i].value))
            return false;
        if (!ReadBytesLocal(data, data_len, off, tx.outputs[i].commitment.v, 32))
            return false;
        if (!ReadBytesLocal(data, data_len, off, tx.outputs[i].owner_pubkey.v, 32))
            return false;
        if (!ReadBytesLocal(data, data_len, off, tx.outputs[i].range_proof.v, 64))
            return false;
    }

    if (!ReadVecLocal(data, data_len, off, &tx.sum_proof))
        return false;
    if (!ReadU64LELocal(data, data_len, off, &tx.transfer_amount))
        return false;
    if (!ReadU64LELocal(data, data_len, off, &tx.timestamp))
        return false;
    if (!ReadU64LELocal(data, data_len, off, &tx.fee))
        return false;

    uint64_t n_sigs = 0;
    if (!ReadU64LELocal(data, data_len, off, &n_sigs))
        return false;
    if (n_sigs > 1000000ULL)
        return false;
    tx.signatures.resize((size_t)n_sigs);
    for (size_t i = 0; i < tx.signatures.size(); ++i)
        if (!ReadVecLocal(data, data_len, off, &tx.signatures[i]))
            return false;

    *out = tx;
    return true;
}

bool ParseMintTxCanonical(const uint8_t* data, size_t data_len, size_t* off, MintTx* out)
{
    if (!data || !off || !out)
        return false;
    MintTx tx;
    if (!ReadU64LELocal(data, data_len, off, &tx.output.value))
        return false;
    if (!ReadBytesLocal(data, data_len, off, tx.output.commitment.v, 32))
        return false;
    if (!ReadBytesLocal(data, data_len, off, tx.output.owner_pubkey.v, 32))
        return false;
    if (!ReadBytesLocal(data, data_len, off, tx.output.range_proof.v, 64))
        return false;
    if (!ReadU64LELocal(data, data_len, off, &tx.mint_nonce))
        return false;
    if (!ReadBytesLocal(data, data_len, off, tx.target.v, 32))
        return false;
    if (!ReadBytesLocal(data, data_len, off, tx.miner_pubkey.v, 32))
        return false;
    if (!ReadVecLocal(data, data_len, off, &tx.signature))
        return false;
    *out = tx;
    return true;
}

bool Sha256(const std::vector<uint8_t>& data, Bytes32* out)
{
    if (!out)
        return false;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    if (!data.empty())
        SHA256_Update(&ctx, &data[0], data.size());
    SHA256_Final(out->v, &ctx);
    return true;
}

bool HashTwo(const Bytes32& a, const Bytes32& b, Bytes32* out)
{
    if (!out)
        return false;
    std::vector<uint8_t> d;
    d.insert(d.end(), a.v, a.v + 32);
    d.insert(d.end(), b.v, b.v + 32);
    return Sha256(d, out);
}

bool ComputeSpendTxId(const SpendTx& tx, Bytes32* out)
{
    if (!out)
        return false;
    std::vector<uint8_t> encoded;
    SerializeSpendTxCanonical(tx, &encoded);
    return Sha256(encoded, out);
}

bool ComputeMintTxId(const MintTx& tx, Bytes32* out)
{
    if (!out)
        return false;
    std::vector<uint8_t> encoded;
    SerializeMintTxCanonical(tx, &encoded);
    return Sha256(encoded, out);
}

}  

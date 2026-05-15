#ifndef COIN_TX_CODEC_H
#define COIN_TX_CODEC_H

#include <cstddef>
#include <stdint.h>
#include <vector>

#include "rpov2/tx_types.h"

namespace rpov2 {

void WriteU64LE(std::vector<uint8_t>* out, uint64_t v);
void WriteBytes32(std::vector<uint8_t>* out, const Bytes32& v);
void WriteBytes64(std::vector<uint8_t>* out, const Bytes64& v);

void SerializeSpendTxCanonical(const SpendTx& tx, std::vector<uint8_t>* out);
void SerializeMintTxCanonical(const MintTx& tx, std::vector<uint8_t>* out);
bool ParseSpendTxCanonical(const uint8_t* data, size_t data_len, size_t* off, SpendTx* out);
bool ParseMintTxCanonical(const uint8_t* data, size_t data_len, size_t* off, MintTx* out);

bool Sha256(const std::vector<uint8_t>& data, Bytes32* out);
bool HashTwo(const Bytes32& a, const Bytes32& b, Bytes32* out);
bool ComputeSpendTxId(const SpendTx& tx, Bytes32* out);
bool ComputeMintTxId(const MintTx& tx, Bytes32* out);

}  

#endif

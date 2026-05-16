#ifndef COIN_TX_TYPES_H
#define COIN_TX_TYPES_H

#include <stdint.h>
#include <vector>

namespace rpov2 {

struct Bytes32 {
    uint8_t v[32];
};

struct Bytes64 {
    uint8_t v[64];
};

struct UtxoOutput {
    uint64_t value;
    Bytes32 commitment;
    Bytes32 owner_pubkey;
    Bytes64 range_proof;
};

struct SpendInput {
    Bytes32 coin_id;
    std::vector<uint8_t> ownership_proof;
};

struct SpendTx {
    std::vector<SpendInput> inputs;
    std::vector<UtxoOutput> outputs;
    std::vector<uint8_t> sum_proof;
    uint64_t transfer_amount;
    uint64_t timestamp;
    uint64_t fee;
    std::vector< std::vector<uint8_t> > signatures;
};

struct MintTx {
    UtxoOutput output;
    uint64_t mint_nonce;
    Bytes32 target;
    Bytes32 miner_pubkey;
    std::vector<uint8_t> signature;
};

}  

#endif

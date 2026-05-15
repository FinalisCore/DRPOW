#ifndef COIN_STATE_COMMITMENT_H
#define COIN_STATE_COMMITMENT_H

#include <cstddef>
#include <vector>

#include "rpov2/tx_types.h"

namespace rpov2 {

// Canonical state commitment over sorted 256-byte UTXO entries.
// Leaf hash: H("RPOV2:leaf:v1" || entry)
// Parent hash: H("RPOV2:node:v1" || left || right)
// Odd leaf count duplicates the final leaf.
bool ComputeStateRootV1(const std::vector< std::vector<uint8_t> >& entries_256, Bytes32* out_root);

}  

#endif

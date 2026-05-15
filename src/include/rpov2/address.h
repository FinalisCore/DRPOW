#ifndef RPOV2_ADDRESS_ADDRESS_H
#define RPOV2_ADDRESS_ADDRESS_H

#include <stdint.h>
#include <string>

#include "rpov2/tx_types.h"

namespace rpov2 {

std::string AddressFromPubkey(const Bytes32& pubkey, uint32_t network_magic);
bool ParseAddress(const std::string& address, uint32_t expected_network_magic, Bytes32* out_pubkey);

}  // namespace rpov2

#endif

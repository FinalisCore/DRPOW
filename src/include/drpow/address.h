#ifndef DRPOW_ADDRESS_ADDRESS_H
#define DRPOW_ADDRESS_ADDRESS_H

#include <stdint.h>
#include <string>

#include "drpow/tx_types.h"

namespace drpow {

std::string AddressFromPubkey(const Bytes32& pubkey, uint32_t network_magic);
bool ParseAddress(const std::string& address, uint32_t expected_network_magic, Bytes32* out_pubkey);

}  // namespace drpow

#endif

#ifndef RPOV2_WALLET_WALLET_H
#define RPOV2_WALLET_WALLET_H

#include <stdint.h>
#include <string>

#include "../crypto/crypto_backend.h"
#include "rpov2/tx_types.h"

namespace rpov2 {

struct WalletIdentity {
    Bytes32 pubkey;
    std::string privkey_hex;
    std::string address;
};

bool LoadOrCreateWalletIdentity(const std::string& data_dir,
                                uint32_t network_magic,
                                CryptoBackend* crypto,
                                WalletIdentity* out,
                                std::string* err);

}  // namespace rpov2

#endif

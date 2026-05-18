#ifndef DRPOW_WALLET_WALLET_H
#define DRPOW_WALLET_WALLET_H

#include <stdint.h>
#include <string>

#include "../crypto/crypto_backend.h"
#include "drpow/tx_types.h"

namespace drpow {

struct WalletIdentity {
    Bytes32 pubkey;
    std::string privkey_hex;
    std::string address;
};

bool LoadOrCreateWalletIdentity(const std::string& data_dir,
                                uint32_t network_magic,
                                CryptoBackend* crypto,
                                bool create_if_missing,
                                WalletIdentity* out,
                                std::string* err);

}  // namespace drpow

#endif

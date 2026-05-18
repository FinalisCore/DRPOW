#ifndef COIN_CRYPTO_BACKEND_H
#define COIN_CRYPTO_BACKEND_H

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <string>
#include <vector>

namespace drpow {

class CryptoBackend {
public:
    virtual ~CryptoBackend() {}
    virtual bool VerifyEd25519(const uint8_t pubkey[32],
                               const uint8_t* msg,
                               size_t msg_len,
                               const uint8_t* sig,
                               size_t sig_len) const = 0;
    virtual bool SignEd25519(const uint8_t privkey[32],
                             const uint8_t* msg,
                             size_t msg_len,
                             std::vector<uint8_t>* out_sig) const = 0;
    virtual bool PublicFromPrivateEd25519(const uint8_t privkey[32], uint8_t out_pubkey[32]) const = 0;
};

class PqcBackendStub : public CryptoBackend {
public:
    virtual bool VerifyEd25519(const uint8_t pubkey[32],
                               const uint8_t* msg,
                               size_t msg_len,
                               const uint8_t* sig,
                               size_t sig_len) const;
    virtual bool SignEd25519(const uint8_t privkey[32],
                             const uint8_t* msg,
                             size_t msg_len,
                             std::vector<uint8_t>* out_sig) const;
    virtual bool PublicFromPrivateEd25519(const uint8_t privkey[32], uint8_t out_pubkey[32]) const;
};

std::unique_ptr<CryptoBackend> CreateCryptoBackendByName(const std::string& name);
std::unique_ptr<CryptoBackend> CreateCryptoBackendFromEnv();
bool HasStandardPqcBackend();

}  

#endif

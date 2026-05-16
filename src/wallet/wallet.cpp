#include "rpov2/wallet.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include <fstream>

#include "rpov2/address.h"

namespace rpov2 {

static bool EnsureDir(const std::string& d)
{
    if (mkdir(d.c_str(), 0755) == 0)
        return true;
    return errno == EEXIST;
}

static bool EnsureOwnerOnlyFile(const std::string& path)
{
    return chmod(path.c_str(), S_IRUSR | S_IWUSR) == 0;
}

static bool HexTo32(const std::string& s, uint8_t out[32])
{
    if (s.size() != 64)
        return false;
    for (int i = 0; i < 32; ++i)
    {
        char a = s[i * 2];
        char b = s[i * 2 + 1];
        int hi = (a >= '0' && a <= '9') ? (a - '0') : (a >= 'a' && a <= 'f') ? (10 + a - 'a') : (a >= 'A' && a <= 'F') ? (10 + a - 'A') : -1;
        int lo = (b >= '0' && b <= '9') ? (b - '0') : (b >= 'a' && b <= 'f') ? (10 + b - 'a') : (b >= 'A' && b <= 'F') ? (10 + b - 'A') : -1;
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static std::string Hex(const uint8_t* p, size_t n)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        out[i * 2] = kHex[(p[i] >> 4) & 0x0f];
        out[i * 2 + 1] = kHex[p[i] & 0x0f];
    }
    return out;
}

static bool FillRandom(uint8_t* out, size_t n)
{
    std::ifstream in("/dev/urandom", std::ios::binary);
    if (!in.good())
        return false;
    in.read((char*)out, (std::streamsize)n);
    return in.good();
}

bool LoadOrCreateWalletIdentity(const std::string& data_dir,
                                uint32_t network_magic,
                                CryptoBackend* crypto,
                                WalletIdentity* out,
                                std::string* err)
{
    if (!crypto || !out)
        return false;
    if (!EnsureDir(data_dir))
    {
        if (err)
            *err = "wallet_dir_create_failed";
        return false;
    }

    const std::string key_file = data_dir + "/signer_privkey.hex";
    uint8_t priv[32];
    bool have = false;

    std::ifstream in(key_file.c_str());
    std::string line;
    if (in.good() && std::getline(in, line))
    {
        have = HexTo32(line, priv);
        (void)EnsureOwnerOnlyFile(key_file);
    }

    if (!have)
    {
        if (!FillRandom(priv, sizeof(priv)))
        {
            if (err)
                *err = "wallet_rng_failed";
            return false;
        }
        std::ofstream outk(key_file.c_str(), std::ios::trunc);
        if (!outk.good())
        {
            if (err)
                *err = "wallet_key_persist_failed";
            return false;
        }
        outk << Hex(priv, sizeof(priv)) << "\n";
        if (!outk.good())
        {
            if (err)
                *err = "wallet_key_persist_failed";
            return false;
        }
        if (!EnsureOwnerOnlyFile(key_file))
        {
            if (err)
                *err = "wallet_key_permission_failed";
            return false;
        }
    }

    WalletIdentity id;
    if (!crypto->PublicFromPrivateEd25519(priv, id.pubkey.v))
    {
        if (err)
            *err = "wallet_pubkey_derive_failed";
        return false;
    }
    id.privkey_hex = Hex(priv, sizeof(priv));
    id.address = AddressFromPubkey(id.pubkey, network_magic);
    *out = id;
    return true;
}

}  // namespace rpov2

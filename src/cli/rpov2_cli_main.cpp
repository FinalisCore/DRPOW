#include <stdio.h>
#include <stdlib.h>

#include <string>

#include "rpov2/address.h"
#include "../crypto/crypto_backend.h"
#include "rpov2/mempool.h"
#include "rpov2/tx_types.h"
#include "rpov2/wallet.h"

using namespace rpov2;

static void Usage(const char* bin)
{
    printf("usage:\n");
    printf("  %s wallet init <data_dir> [network_magic_hex]\n", bin);
    printf("  %s wallet show <data_dir> [network_magic_hex]\n", bin);
    printf("  %s address validate <address> [network_magic_hex]\n", bin);
    printf("  %s mempool demo\n", bin);
}

static uint32_t ParseMagic(const char* s)
{
    if (!s)
        return 0x52504f57u;
    return (uint32_t)strtoul(s, NULL, 16);
}

static int WalletCmd(const char* subcmd, const char* dir, uint32_t magic)
{
    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed\n");
        return 2;
    }
    WalletIdentity id;
    std::string err;
    if (!LoadOrCreateWalletIdentity(dir, magic, crypto.get(), &id, &err))
    {
        printf("wallet_error: %s\n", err.c_str());
        return 3;
    }
    if (std::string(subcmd) == "init" || std::string(subcmd) == "show")
    {
        printf("pubkey=%s\n", AddressFromPubkey(id.pubkey, 0).substr(6, 64).c_str());
        printf("address=%s\n", id.address.c_str());
        printf("key_file=%s/signer_privkey.hex\n", dir);
        return 0;
    }
    return 1;
}

static int AddressCmd(const char* addr, uint32_t magic)
{
    Bytes32 pub;
    if (!ParseAddress(addr, magic, &pub))
    {
        printf("address_invalid\n");
        return 4;
    }
    printf("address_valid\n");
    return 0;
}

static int MempoolDemo()
{
    Mempool mp;
    SpendTx s;
    MintTx m;
    m.output.value = 1;
    m.mint_nonce = 1;

    std::string err;
    if (!mp.AddSpend(s, &err))
        printf("demo_add_spend_failed=%s\n", err.c_str());
    if (!mp.AddMint(m, &err))
        printf("demo_add_mint_failed=%s\n", err.c_str());

    printf("mempool_spends=%zu\n", mp.SpendCount());
    printf("mempool_mints=%zu\n", mp.MintCount());
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        Usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "wallet")
    {
        if (argc < 4)
        {
            Usage(argv[0]);
            return 1;
        }
        uint32_t magic = ParseMagic(argc >= 5 ? argv[4] : NULL);
        return WalletCmd(argv[2], argv[3], magic);
    }
    if (cmd == "address")
    {
        if (argc < 4 || std::string(argv[2]) != "validate")
        {
            Usage(argv[0]);
            return 1;
        }
        uint32_t magic = ParseMagic(argc >= 5 ? argv[4] : NULL);
        return AddressCmd(argv[3], magic);
    }
    if (cmd == "mempool")
    {
        if (argc >= 3 && std::string(argv[2]) == "demo")
            return MempoolDemo();
        Usage(argv[0]);
        return 1;
    }

    Usage(argv[0]);
    return 1;
}

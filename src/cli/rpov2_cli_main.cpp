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

static void WalletUsage(const char* bin)
{
    printf("wallet usage:\n");
    printf("  %s wallet init [data_dir] [network_magic_hex]\n", bin);
    printf("  %s wallet show [data_dir] [network_magic_hex]\n", bin);
}

static void AddressUsage(const char* bin)
{
    printf("address usage:\n");
    printf("  %s address validate <address> [network_magic_hex]\n", bin);
}

static void MempoolUsage(const char* bin)
{
    printf("mempool usage:\n");
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
    const char* kDefaultWalletDir = "./data_wallet";
    if (argc < 2)
    {
        Usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "wallet")
    {
        if (argc == 2)
        {
            WalletUsage(argv[0]);
            return 0;
        }
        const char* subcmd = argv[2];
        const char* dir = kDefaultWalletDir;
        const char* magic_arg = NULL;
        if (argc >= 4)
            dir = argv[3];
        if (argc >= 5)
            magic_arg = argv[4];

        if (argc == 4 && std::string(argv[3]).find('/') == std::string::npos &&
            std::string(argv[3]).find('.') == std::string::npos &&
            std::string(argv[3]).size() <= 10)
        {
            // If only one optional arg is provided and it looks like a short magic string,
            // treat it as network magic and keep the default wallet directory.
            dir = kDefaultWalletDir;
            magic_arg = argv[3];
        }

        if (std::string(subcmd) != "init" && std::string(subcmd) != "show")
        {
            WalletUsage(argv[0]);
            return 1;
        }
        uint32_t magic = ParseMagic(magic_arg);
        int rc = WalletCmd(subcmd, dir, magic);
        if (rc == 1)
            WalletUsage(argv[0]);
        return rc;
    }
    if (cmd == "address")
    {
        if (argc == 2)
        {
            AddressUsage(argv[0]);
            return 0;
        }
        if (argc < 4 || std::string(argv[2]) != "validate")
        {
            AddressUsage(argv[0]);
            return 1;
        }
        uint32_t magic = ParseMagic(argc >= 5 ? argv[4] : NULL);
        return AddressCmd(argv[3], magic);
    }
    if (cmd == "mempool")
    {
        if (argc == 2)
            return MempoolDemo();
        if (argc >= 3 && std::string(argv[2]) == "demo")
            return MempoolDemo();
        MempoolUsage(argv[0]);
        return 1;
    }

    Usage(argv[0]);
    return 1;
}

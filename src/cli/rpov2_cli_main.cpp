#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <fstream>
#include <string>
#include <vector>

#include "rpov2/address.h"
#include "../crypto/crypto_backend.h"
#include "rpov2/mempool.h"
#include "rpov2/tx_codec.h"
#include "rpov2/tx_types.h"
#include "rpov2/wallet.h"

using namespace rpov2;

static void Usage(const char* bin)
{
    printf("usage:\n");
    printf("  %s wallet init [data_dir] [network_magic_hex]\n", bin);
    printf("  %s wallet show [data_dir] [network_magic_hex]\n", bin);
    printf("  %s wallet info [data_dir] [network_magic_hex] [registry_file]\n", bin);
    printf("  %s wallet send <to_address> <amount> <fee> [data_dir] [network_magic_hex] [registry_file]\n", bin);
    printf("  %s address validate <address> [network_magic_hex]\n", bin);
    printf("  %s mempool demo\n", bin);
}

static void WalletUsage(const char* bin)
{
    printf("wallet usage:\n");
    printf("  %s wallet init [data_dir] [network_magic_hex]\n", bin);
    printf("  %s wallet show [data_dir] [network_magic_hex]\n", bin);
    printf("  %s wallet info [data_dir] [network_magic_hex] [registry_file]\n", bin);
    printf("  %s wallet send <to_address> <amount> <fee> [data_dir] [network_magic_hex] [registry_file]\n", bin);
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

static bool SaveHexFile(const std::string& path, const std::vector<uint8_t>& bytes)
{
    std::ofstream out(path.c_str(), std::ios::trunc);
    if (!out.good())
        return false;
    out << Hex(bytes.empty() ? NULL : &bytes[0], bytes.size()) << "\n";
    return out.good();
}

struct LocalUtxo {
    Bytes32 coin_id;
    uint64_t value;
    Bytes32 owner_pubkey;
};

static bool LoadWalletUtxosFromRegistry(const std::string& registry_file,
                                        const Bytes32& wallet_pubkey,
                                        std::vector<LocalUtxo>* out,
                                        uint64_t* out_balance)
{
    if (!out || !out_balance)
        return false;
    out->clear();
    *out_balance = 0;

    std::ifstream in(registry_file.c_str(), std::ios::binary);
    if (!in.good())
        return false;
    in.seekg(0, std::ios::end);
    std::streamoff sz = in.tellg();
    if (sz < 0)
        return false;

    const size_t rec_size = ((sz % 264) == 0) ? 264 : (((sz % 256) == 0) ? 256 : 0);
    if (rec_size == 0)
        return false;

    in.seekg(0, std::ios::beg);
    while (in.good())
    {
        LocalUtxo u;
        memset(&u, 0, sizeof(u));
        if (rec_size == 264)
        {
            uint8_t vbuf[8];
            in.read((char*)vbuf, 8);
            if (!in.good())
                break;
            for (int i = 0; i < 8; ++i)
                u.value |= ((uint64_t)vbuf[i] << (8 * i));
        }

        in.read((char*)u.coin_id.v, 32);
        if (!in.good())
            break;

        uint8_t commitment[32];
        uint8_t rangeproof[64];
        uint8_t mint_nonce[32];
        uint8_t mint_sig[32];
        uint8_t reserved[32];
        in.read((char*)commitment, 32);
        in.read((char*)u.owner_pubkey.v, 32);
        in.read((char*)rangeproof, 64);
        in.read((char*)mint_nonce, 32);
        in.read((char*)mint_sig, 32);
        in.read((char*)reserved, 32);
        if (!in.good())
            return false;

        bool zero_coin = true;
        for (int i = 0; i < 32; ++i)
            if (u.coin_id.v[i] != 0)
            {
                zero_coin = false;
                break;
            }
        if (zero_coin)
            continue;

        if (memcmp(u.owner_pubkey.v, wallet_pubkey.v, 32) == 0)
        {
            out->push_back(u);
            *out_balance += u.value;
        }
    }

    return true;
}

static bool LoadLedgerTotals(const std::string& ledger_file, uint64_t* supply, uint64_t* minted, uint64_t* burned)
{
    if (!supply || !minted || !burned)
        return false;
    *supply = 0;
    *minted = 0;
    *burned = 0;

    std::ifstream in(ledger_file.c_str(), std::ios::binary);
    if (!in.good())
        return false;

    in.read((char*)supply, sizeof(*supply));
    in.read((char*)minted, sizeof(*minted));
    in.read((char*)burned, sizeof(*burned));
    return in.good();
}

static int WalletIdentityCmd(const char* subcmd, const char* dir, uint32_t magic)
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

static int WalletInfoCmd(const char* dir, uint32_t magic, const char* registry_file_opt)
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

    std::string registry_file = registry_file_opt ? registry_file_opt : "";
    if (registry_file.empty())
        registry_file = std::string(dir) + "/registry.hex";

    std::vector<LocalUtxo> utxos;
    uint64_t balance = 0;
    bool have_registry = LoadWalletUtxosFromRegistry(registry_file, id.pubkey, &utxos, &balance);
    uint64_t total_supply = 0, total_minted = 0, total_fees_burned = 0;
    bool have_ledger = LoadLedgerTotals(registry_file + ".ledger", &total_supply, &total_minted, &total_fees_burned);

    printf("pubkey=%s\n", AddressFromPubkey(id.pubkey, 0).substr(6, 64).c_str());
    printf("address=%s\n", id.address.c_str());
    printf("key_file=%s/signer_privkey.hex\n", dir);
    printf("registry_file=%s\n", registry_file.c_str());
    if (!have_registry)
        printf("wallet_registry_status=unavailable\n");
    else
    {
        printf("wallet_utxos=%zu\n", utxos.size());
        printf("wallet_balance=%llu\n", (unsigned long long)balance);
    }
    if (!have_ledger)
        printf("ledger_status=unavailable\n");
    else
    {
        printf("ledger_total_supply=%llu\n", (unsigned long long)total_supply);
        printf("ledger_total_minted=%llu\n", (unsigned long long)total_minted);
        printf("ledger_total_fees_burned=%llu\n", (unsigned long long)total_fees_burned);
    }
    return 0;
}

static int WalletSendCmd(const char* to_address,
                         uint64_t amount,
                         uint64_t fee,
                         const char* dir,
                         uint32_t magic,
                         const char* registry_file_opt)
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

    Bytes32 to_pub;
    if (!ParseAddress(std::string(to_address), magic, &to_pub))
    {
        printf("send_error: invalid_to_address\n");
        return 4;
    }

    std::string registry_file = registry_file_opt ? registry_file_opt : "";
    if (registry_file.empty())
        registry_file = std::string(dir) + "/registry.hex";

    std::vector<LocalUtxo> utxos;
    uint64_t balance = 0;
    if (!LoadWalletUtxosFromRegistry(registry_file, id.pubkey, &utxos, &balance))
    {
        printf("send_error: registry_unavailable path=%s\n", registry_file.c_str());
        return 5;
    }

    uint64_t required = amount + fee;
    if (balance < required)
    {
        printf("send_error: insufficient_funds balance=%llu required=%llu\n",
               (unsigned long long)balance,
               (unsigned long long)required);
        return 6;
    }

    SpendTx tx;
    tx.timestamp = (uint64_t)time(NULL);
    tx.fee = fee;
    tx.sum_proof.push_back(1);  // prototype marker

    uint64_t selected = 0;
    for (size_t i = 0; i < utxos.size() && selected < required; ++i)
    {
        SpendInput in;
        in.coin_id = utxos[i].coin_id;
        in.ownership_proof.push_back(1);
        in.ownership_proof.insert(in.ownership_proof.end(), id.pubkey.v, id.pubkey.v + 32);
        tx.inputs.push_back(in);
        selected += utxos[i].value;
    }
    if (selected < required)
    {
        printf("send_error: coin_selection_failed selected=%llu required=%llu\n",
               (unsigned long long)selected,
               (unsigned long long)required);
        return 7;
    }

    UtxoOutput out_to;
    memset(&out_to, 0, sizeof(out_to));
    out_to.value = amount;
    out_to.owner_pubkey = to_pub;
    memset(out_to.range_proof.v, 0x11, 64);
    for (int i = 0; i < 32; ++i)
        out_to.commitment.v[i] = (uint8_t)(to_pub.v[i] ^ (uint8_t)(tx.timestamp + i));
    tx.outputs.push_back(out_to);

    const uint64_t change = selected - required;
    if (change > 0)
    {
        UtxoOutput out_change;
        memset(&out_change, 0, sizeof(out_change));
        out_change.value = change;
        out_change.owner_pubkey = id.pubkey;
        memset(out_change.range_proof.v, 0x22, 64);
        for (int i = 0; i < 32; ++i)
            out_change.commitment.v[i] = (uint8_t)(id.pubkey.v[i] ^ (uint8_t)(tx.timestamp + 17 + i));
        tx.outputs.push_back(out_change);
    }

    SpendTx tx_core = tx;
    tx_core.signatures.clear();
    std::vector<uint8_t> core;
    SerializeSpendTxCanonical(tx_core, &core);
    Bytes32 core_hash;
    if (!Sha256(core, &core_hash))
    {
        printf("send_error: core_hash_failed\n");
        return 8;
    }

    uint8_t priv[32];
    if (!HexTo32(id.privkey_hex, priv))
    {
        printf("send_error: privkey_decode_failed\n");
        return 9;
    }

    for (size_t i = 0; i < tx.inputs.size(); ++i)
    {
        std::vector<uint8_t> m;
        m.insert(m.end(), core_hash.v, core_hash.v + 32);
        m.insert(m.end(), tx.inputs[i].coin_id.v, tx.inputs[i].coin_id.v + 32);
        std::vector<uint8_t> sig;
        if (!crypto->SignEd25519(priv, m.empty() ? NULL : &m[0], m.size(), &sig))
        {
            printf("send_error: sign_failed input=%zu\n", i);
            return 10;
        }
        tx.signatures.push_back(sig);
    }

    std::vector<uint8_t> encoded;
    SerializeSpendTxCanonical(tx, &encoded);
    const std::string out_path = std::string(dir) + "/outbox_spendtx_" + std::to_string((unsigned long long)tx.timestamp) + ".hex";
    if (!SaveHexFile(out_path, encoded))
    {
        printf("send_error: outbox_write_failed path=%s\n", out_path.c_str());
        return 11;
    }

    printf("send_draft_created file=%s\n", out_path.c_str());
    printf("send_to=%s\n", to_address);
    printf("send_amount=%llu\n", (unsigned long long)amount);
    printf("send_fee=%llu\n", (unsigned long long)fee);
    printf("send_inputs=%zu\n", tx.inputs.size());
    printf("send_outputs=%zu\n", tx.outputs.size());
    printf("send_change=%llu\n", (unsigned long long)change);
    printf("send_note=prototype_draft_not_broadcast\n");
    return 0;
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

        const std::string subcmd = argv[2];
        if (subcmd == "init" || subcmd == "show")
        {
            const char* dir = (argc >= 4) ? argv[3] : kDefaultWalletDir;
            const char* magic_arg = (argc >= 5) ? argv[4] : NULL;
            int rc = WalletIdentityCmd(subcmd.c_str(), dir, ParseMagic(magic_arg));
            if (rc == 1)
                WalletUsage(argv[0]);
            return rc;
        }

        if (subcmd == "info")
        {
            const char* dir = (argc >= 4) ? argv[3] : kDefaultWalletDir;
            const char* magic_arg = (argc >= 5) ? argv[4] : NULL;
            const char* registry_file = (argc >= 6) ? argv[5] : NULL;
            return WalletInfoCmd(dir, ParseMagic(magic_arg), registry_file);
        }

        if (subcmd == "send")
        {
            if (argc < 6)
            {
                WalletUsage(argv[0]);
                return 1;
            }
            const char* to_address = argv[3];
            uint64_t amount = (uint64_t)strtoull(argv[4], NULL, 10);
            uint64_t fee = (uint64_t)strtoull(argv[5], NULL, 10);
            const char* dir = (argc >= 7) ? argv[6] : kDefaultWalletDir;
            const char* magic_arg = (argc >= 8) ? argv[7] : NULL;
            const char* registry_file = (argc >= 9) ? argv[8] : NULL;
            return WalletSendCmd(to_address, amount, fee, dir, ParseMagic(magic_arg), registry_file);
        }

        WalletUsage(argv[0]);
        return 1;
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

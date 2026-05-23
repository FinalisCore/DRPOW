#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <glob.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <fstream>
#include <string>
#include <vector>

#include "drpow/address.h"
#include "../crypto/crypto_backend.h"
#include "p2p_wire.h"
#include "drpow/mempool.h"
#include "drpow/tx_codec.h"
#include "drpow/tx_types.h"
#include "drpow/wallet.h"
#include "economics_policy.h"

using namespace drpow;
static const uint64_t kAtomicPerCoin = 100000000ULL;

static std::string DefaultPathUnderHome(const char* suffix)
{
    const char* home = getenv("HOME");
    if (!home || !home[0])
        return std::string(".") + suffix;
    return std::string(home) + "/.drpow" + suffix;
}

static std::string ExistingConfigPathUnderHome()
{
    const std::string a = DefaultPathUnderHome("/config/testnet.conf");
    {
        std::ifstream in(a.c_str());
        if (in.good())
            return a;
    }
    const std::string b = DefaultPathUnderHome("/config/mainnet.conf");
    {
        std::ifstream in(b.c_str());
        if (in.good())
            return b;
    }
    const std::string c = DefaultPathUnderHome("/config/global_testnet.conf");
    {
        std::ifstream in(c.c_str());
        if (in.good())
            return c;
    }
    return a;
}

static std::string DetectDefaultNodeDataDir()
{
    const std::string cfg = ExistingConfigPathUnderHome();
    std::ifstream in(cfg.c_str());
    if (!in.good())
        return DefaultPathUnderHome("/nodes/seed");
    std::string line;
    while (std::getline(in, line))
    {
        if (line.find("data_dir=") == 0)
        {
            const std::string v = line.substr(strlen("data_dir="));
            if (!v.empty())
                return v;
        }
    }
    return DefaultPathUnderHome("/nodes/seed");
}

static void Usage(const char* bin)
{
    printf("usage:\n");
    printf("  %s wallet init [data_dir] [network_magic_hex]\n", bin);
    printf("  %s wallet show [data_dir] [network_magic_hex]\n", bin);
    printf("  %s wallet info [data_dir] [network_magic_hex] [registry_file]\n", bin);
    printf("  %s wallet miner-info [network_magic_hex] [registry_file]\n", bin);
    printf("  %s wallet send <to_address> <amount> <fee> [data_dir] [network_magic_hex] [registry_file]\n", bin);
    printf("  %s address validate <address> [network_magic_hex]\n", bin);
    printf("  %s mempool demo\n", bin);
    printf("  %s tx submit <tx_hex_file> <node_host:port> [network_magic_hex]\n", bin);
    printf("  %s tx status <tx_hex_file> [node_data_dir]\n", bin);
    printf("  %s send --to <address> --amount <decimal> [--data-dir <dir>] [--node-data-dir <dir>] [--node <host:port>] [--magic <hex>]\n", bin);
    printf("  %s getbalance [data_dir] [network_magic_hex] [registry_file]\n", bin);
    printf("  %s getutxo [data_dir] [network_magic_hex] [registry_file]\n", bin);
}

static void WalletUsage(const char* bin)
{
    printf("wallet usage:\n");
    printf("  %s wallet init [data_dir] [network_magic_hex]\n", bin);
    printf("  %s wallet show [data_dir] [network_magic_hex]\n", bin);
    printf("  %s wallet info [data_dir] [network_magic_hex] [registry_file]\n", bin);
    printf("  %s wallet miner-info [network_magic_hex] [registry_file]\n", bin);
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

static bool FileExists(const std::string& path)
{
    std::ifstream in(path.c_str(), std::ios::binary);
    return in.good();
}

static std::string ResolveRegistryPath(const char* data_dir, const char* registry_file_opt)
{
    if (registry_file_opt && registry_file_opt[0] != '\0')
        return std::string(registry_file_opt);
    const std::string dir = data_dir ? std::string(data_dir) : std::string(".");
    const std::string bin = dir + "/registry.bin";
    if (FileExists(bin))
        return bin;
    const std::string hex = dir + "/registry.hex";
    if (FileExists(hex))
        return hex;
    // Operator-friendly fallback: if wallet-local registry is missing,
    // read the canonical node registry under ~/.drpow/nodes/seed.
    const std::string node_seed_bin = DefaultPathUnderHome("/nodes/seed/registry.bin");
    if (FileExists(node_seed_bin))
        return node_seed_bin;
    const std::string node_seed_hex = DefaultPathUnderHome("/nodes/seed/registry.hex");
    if (FileExists(node_seed_hex))
        return node_seed_hex;
    // prefer current canonical filename even if absent (for clearer error)
    return bin;
}

static bool ParseHostPort(const std::string& s, std::string* host, uint16_t* port)
{
    if (!host || !port)
        return false;
    size_t c = s.rfind(':');
    if (c == std::string::npos || c == 0 || c + 1 >= s.size())
        return false;
    *host = s.substr(0, c);
    *port = (uint16_t)atoi(s.substr(c + 1).c_str());
    return !host->empty() && *port > 0;
}

static bool DecodeHexLine(const std::string& s, std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    if (s.empty() || (s.size() % 2) != 0)
        return false;
    out->resize(s.size() / 2);
    for (size_t i = 0; i < out->size(); ++i)
    {
        char a = s[i * 2];
        char b = s[i * 2 + 1];
        int hi = (a >= '0' && a <= '9') ? (a - '0') : (a >= 'a' && a <= 'f') ? (10 + a - 'a') : (a >= 'A' && a <= 'F') ? (10 + a - 'A') : -1;
        int lo = (b >= '0' && b <= '9') ? (b - '0') : (b >= 'a' && b <= 'f') ? (10 + b - 'a') : (b >= 'A' && b <= 'F') ? (10 + b - 'A') : -1;
        if (hi < 0 || lo < 0)
            return false;
        (*out)[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

// CLI amount uses 8 decimal places: 1.23456789 coin => 123456789 atomic units.
static bool ParseAmountAtomic8(const std::string& s, uint64_t* out_units)
{
    if (!out_units || s.empty())
        return false;
    size_t dot = s.find('.');
    std::string ip = (dot == std::string::npos) ? s : s.substr(0, dot);
    std::string fp = (dot == std::string::npos) ? "" : s.substr(dot + 1);
    if (ip.empty())
        ip = "0";
    if (fp.size() > 8)
        return false;
    for (size_t i = 0; i < ip.size(); ++i)
        if (ip[i] < '0' || ip[i] > '9')
            return false;
    for (size_t i = 0; i < fp.size(); ++i)
        if (fp[i] < '0' || fp[i] > '9')
            return false;
    while (fp.size() < 8)
        fp.push_back('0');
    uint64_t i_part = (uint64_t)strtoull(ip.c_str(), NULL, 10);
    uint64_t f_part = (uint64_t)strtoull(fp.c_str(), NULL, 10);
    if (i_part > (UINT64_MAX / 100000000ULL))
        return false;
    uint64_t v = i_part * 100000000ULL;
    if (UINT64_MAX - v < f_part)
        return false;
    *out_units = v + f_part;
    return true;
}

static std::string FormatAtomic8(uint64_t units)
{
    char buf[64];
    const unsigned long long whole = (unsigned long long)(units / kAtomicPerCoin);
    const unsigned long long frac = (unsigned long long)(units % kAtomicPerCoin);
    snprintf(buf, sizeof(buf), "%llu.%08llu", whole, frac);
    return std::string(buf);
}

static bool FindLatestOutboxFile(const std::string& data_dir, std::string* out_path)
{
    if (!out_path)
        return false;
    std::string pattern = data_dir + "/outbox_spendtx_*.hex";
    glob_t g;
    memset(&g, 0, sizeof(g));
    if (glob(pattern.c_str(), 0, NULL, &g) != 0 || g.gl_pathc == 0)
    {
        globfree(&g);
        return false;
    }
    std::string best = g.gl_pathv[0];
    for (size_t i = 1; i < g.gl_pathc; ++i)
    {
        std::string p = g.gl_pathv[i];
        if (p > best)
            best = p;
    }
    globfree(&g);
    *out_path = best;
    return true;
}

static bool ReadHexKeyFile32(const std::string& key_file, uint8_t out_priv[32])
{
    std::ifstream in(key_file.c_str());
    if (!in.good())
        return false;
    std::string line;
    if (!std::getline(in, line))
        return false;
    return HexTo32(line, out_priv);
}

static bool ReadSignerHexFromConfigForDataDir(const std::string& data_dir, uint8_t out_priv[32], std::string* out_label)
{
    const std::string cfg = ExistingConfigPathUnderHome();
    std::ifstream in(cfg.c_str());
    if (!in.good())
        return false;
    std::string line;
    std::string cfg_data_dir;
    std::string signer_hex;
    while (std::getline(in, line))
    {
        if (line.find("data_dir=") == 0)
            cfg_data_dir = line.substr(strlen("data_dir="));
        else if (line.find("signer_privkey_hex=") == 0)
            signer_hex = line.substr(strlen("signer_privkey_hex="));
    }
    if (cfg_data_dir.empty() || signer_hex.empty())
        return false;
    if (cfg_data_dir != data_dir)
        return false;
    if (!HexTo32(signer_hex, out_priv))
        return false;
    if (out_label)
        *out_label = cfg + ":signer_privkey_hex";
    return true;
}

static std::string DetectNodeKeyFallbackPath(const std::string& data_dir)
{
    const std::string seed_suffix = "/nodes/seed";
    if (data_dir.size() >= seed_suffix.size() &&
        data_dir.compare(data_dir.size() - seed_suffix.size(), seed_suffix.size(), seed_suffix) == 0)
    {
        return DefaultPathUnderHome("/keys/seed_signer_privkey.hex");
    }
    const std::string joiner_tag = "/nodes/joiner_";
    const size_t p = data_dir.rfind(joiner_tag);
    if (p != std::string::npos)
    {
        const std::string port = data_dir.substr(p + joiner_tag.size());
        if (!port.empty())
            return DefaultPathUnderHome(("/keys/joiner_" + port + "_signer_privkey.hex").c_str());
    }
    return "";
}

static bool LoadWalletIdentityResolved(const char* dir,
                                       uint32_t magic,
                                       CryptoBackend* crypto,
                                       bool create_if_missing,
                                       WalletIdentity* out,
                                       std::string* err,
                                       std::string* out_key_file)
{
    if (!dir || !crypto || !out)
        return false;

    const std::string data_dir(dir);
    const std::string fallback = DetectNodeKeyFallbackPath(data_dir);
    uint8_t priv[32];
    std::string key_label;
    bool loaded = false;
    if (!fallback.empty())
    {
        loaded = ReadHexKeyFile32(fallback, priv);
        if (loaded)
            key_label = fallback;
    }
    if (!loaded)
        loaded = ReadSignerHexFromConfigForDataDir(data_dir, priv, &key_label);
    if (loaded)
    {
        WalletIdentity id;
        if (!crypto->PublicFromPrivateEd25519(priv, id.pubkey.v))
            return false;
        id.privkey_hex = Hex(priv, sizeof(priv));
        id.address = AddressFromPubkey(id.pubkey, magic);
        *out = id;
        if (out_key_file)
            *out_key_file = key_label;
        if (err)
            err->clear();
        return true;
    }

    if (LoadOrCreateWalletIdentity(dir, magic, crypto, create_if_missing, out, err))
    {
        if (out_key_file)
            *out_key_file = data_dir + "/signer_privkey.hex";
        return true;
    }
    return false;
}

struct LocalUtxo {
    Bytes32 coin_id;
    uint64_t value;
    Bytes32 owner_pubkey;
};

static int WalletSendCmd(const char* to_address,
                         uint64_t amount,
                         uint64_t fee,
                         const char* dir,
                         const char* node_data_dir,
                         uint32_t magic,
                         const char* registry_file_opt);

static int TxSubmitCmd(const char* tx_hex_file, const char* node_endpoint, uint32_t network_magic)
{
    std::ifstream in(tx_hex_file);
    if (!in.good())
    {
        printf("tx_submit_error: tx_file_open_failed\n");
        return 20;
    }
    std::string line;
    if (!std::getline(in, line))
    {
        printf("tx_submit_error: tx_file_read_failed\n");
        return 21;
    }
    std::vector<uint8_t> tx_bytes;
    if (!DecodeHexLine(line, &tx_bytes))
    {
        printf("tx_submit_error: tx_hex_decode_failed\n");
        return 22;
    }
    SpendTx tx;
    size_t off = 0;
    if (!ParseSpendTxCanonical(tx_bytes.empty() ? NULL : &tx_bytes[0], tx_bytes.size(), &off, &tx) || off != tx_bytes.size())
    {
        printf("tx_submit_error: tx_parse_failed\n");
        return 23;
    }

    std::vector<uint8_t> payload;
    if (!SerializeSpendTxSubmitPayload(tx, &payload))
    {
        printf("tx_submit_error: payload_serialize_failed\n");
        return 24;
    }
    WireEnvelope env;
    env.magic = network_magic;
    env.version = 1;
    env.msg_type = WIRE_MSG_TX;
    env.payload_len = (uint32_t)payload.size();
    env.unix_ms = (uint64_t)time(NULL) * 1000ULL;
    env.payload_hash = Bytes32();
    env.payload.swap(payload);
    std::vector<uint8_t> framed;
    if (!SerializeWireEnvelope(env, &framed))
    {
        printf("tx_submit_error: envelope_serialize_failed\n");
        return 25;
    }

    std::string host;
    uint16_t port = 0;
    if (!ParseHostPort(node_endpoint, &host, &port))
    {
        printf("tx_submit_error: endpoint_invalid\n");
        return 26;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);
    struct addrinfo* res = NULL;
    if (getaddrinfo(host.c_str(), port_s, &hints, &res) != 0 || !res)
    {
        printf("tx_submit_error: resolve_failed\n");
        return 27;
    }
    int fd = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next)
    {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
    {
        printf("tx_submit_error: connect_failed\n");
        return 28;
    }

    uint8_t hdr[4];
    const uint32_t n = (uint32_t)framed.size();
    hdr[0] = (uint8_t)(n & 0xff);
    hdr[1] = (uint8_t)((n >> 8) & 0xff);
    hdr[2] = (uint8_t)((n >> 16) & 0xff);
    hdr[3] = (uint8_t)((n >> 24) & 0xff);
    ssize_t w = send(fd, hdr, 4, 0);
    if (w != 4)
    {
        close(fd);
        printf("tx_submit_error: send_header_failed\n");
        return 29;
    }
    size_t sent = 0;
    while (sent < framed.size())
    {
        ssize_t k = send(fd, &framed[sent], framed.size() - sent, 0);
        if (k <= 0)
        {
            close(fd);
            printf("tx_submit_error: send_payload_failed\n");
            return 30;
        }
        sent += (size_t)k;
    }
    close(fd);
    printf("tx_submit_ok endpoint=%s bytes=%zu\n", node_endpoint, framed.size());
    return 0;
}

static bool LoadCommitPayloadCache(const std::string& cache_file, std::vector< std::vector<uint8_t> >* out_payloads)
{
    if (!out_payloads)
        return false;
    out_payloads->clear();
    std::ifstream in(cache_file.c_str(), std::ios::binary);
    if (!in.good())
        return true;
    while (true)
    {
        uint32_t n = 0;
        in.read((char*)&n, sizeof(n));
        if (in.eof())
            return true;
        if (!in.good())
            return false;
        if (n > (16 * 1024 * 1024))
            return false;
        std::vector<uint8_t> p(n);
        if (n > 0)
            in.read((char*)&p[0], (std::streamsize)n);
        if (!in.good())
            return false;
        out_payloads->push_back(p);
    }
}

static uint64_t DetectNextRoundFromCommitCache(const std::string& node_data_dir)
{
    const std::string cache_file = node_data_dir + "/commit_payload_cache.bin";
    std::vector< std::vector<uint8_t> > payloads;
    if (!LoadCommitPayloadCache(cache_file, &payloads) || payloads.empty())
        return 1;
    uint64_t max_round = 0;
    for (size_t i = 0; i < payloads.size(); ++i)
    {
        RoundBatch b;
        QuorumCertificate qc;
        if (!ParseCommitPayload(payloads[i], &b, &qc))
            continue;
        if (b.round > max_round)
            max_round = b.round;
    }
    return max_round + 1;
}

static bool IsCommitCacheFresh(const std::string& node_data_dir, int max_age_sec)
{
    const std::string cache_file = node_data_dir + "/commit_payload_cache.bin";
    struct stat st;
    if (stat(cache_file.c_str(), &st) != 0)
        return false;
    if (st.st_size <= 0)
        return false;
    const time_t now = time(NULL);
    if (now <= st.st_mtime)
        return true;
    return (now - st.st_mtime) <= max_age_sec;
}

static int TxStatusCmd(const char* tx_hex_file, const char* node_data_dir)
{
    std::ifstream in(tx_hex_file);
    if (!in.good())
    {
        printf("tx_status_error: tx_file_open_failed\n");
        return 40;
    }
    std::string line;
    if (!std::getline(in, line))
    {
        printf("tx_status_error: tx_file_read_failed\n");
        return 41;
    }
    std::vector<uint8_t> tx_bytes;
    if (!DecodeHexLine(line, &tx_bytes))
    {
        printf("tx_status_error: tx_hex_decode_failed\n");
        return 42;
    }
    SpendTx needle;
    size_t off = 0;
    if (!ParseSpendTxCanonical(tx_bytes.empty() ? NULL : &tx_bytes[0], tx_bytes.size(), &off, &needle) || off != tx_bytes.size())
    {
        printf("tx_status_error: tx_parse_failed\n");
        return 43;
    }
    Bytes32 needle_id;
    if (!ComputeSpendTxId(needle, &needle_id))
    {
        printf("tx_status_error: txid_failed\n");
        return 44;
    }
    const std::string cache_file = std::string(node_data_dir) + "/commit_payload_cache.bin";
    std::vector< std::vector<uint8_t> > payloads;
    if (!LoadCommitPayloadCache(cache_file, &payloads))
    {
        printf("tx_status_error: cache_load_failed path=%s\n", cache_file.c_str());
        return 45;
    }
    for (std::vector< std::vector<uint8_t> >::reverse_iterator it = payloads.rbegin(); it != payloads.rend(); ++it)
    {
        RoundBatch b;
        QuorumCertificate qc;
        if (!ParseCommitPayload(*it, &b, &qc))
            continue;
        for (size_t i = 0; i < b.spends.size(); ++i)
        {
            Bytes32 sid;
            if (!ComputeSpendTxId(b.spends[i], &sid))
                continue;
            if (memcmp(sid.v, needle_id.v, 32) == 0)
            {
                printf("tx_status=committed round=%llu txid=%s\n",
                       (unsigned long long)b.round,
                       Hex(needle_id.v, 32).c_str());
                return 0;
            }
        }
    }
    printf("tx_status=not_committed txid=%s cache_entries=%zu\n",
           Hex(needle_id.v, 32).c_str(),
           payloads.size());
    return 0;
}

static int SendCmd(int argc, char** argv)
{
    std::string to;
    std::string amount_s;
    std::string fee_s;
    std::string data_dir = DefaultPathUnderHome("/wallet");
    std::string node_data_dir;
    std::string node_ep = "127.0.0.1:19440";
    std::string magic_s = "52504f57";

    for (int i = 2; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--to" && i + 1 < argc)
            to = argv[++i];
        else if (a == "--amount" && i + 1 < argc)
            amount_s = argv[++i];
        else if (a == "--fee" && i + 1 < argc)
            fee_s = argv[++i];
        else if (a == "--data-dir" && i + 1 < argc)
            data_dir = argv[++i];
        else if (a == "--node-data-dir" && i + 1 < argc)
            node_data_dir = argv[++i];
        else if (a == "--node" && i + 1 < argc)
            node_ep = argv[++i];
        else if (a == "--magic" && i + 1 < argc)
            magic_s = argv[++i];
        else
        {
            printf("send_error: bad_arg %s\n", a.c_str());
            return 50;
        }
    }
    if (to.empty() || amount_s.empty())
    {
        printf("send usage:\n");
        printf("  send --to <address> --amount <decimal> [--data-dir <dir>] [--node-data-dir <dir>] [--node <host:port>] [--magic <hex>]\n");
        return 51;
    }
    uint64_t amount = 0, fee = 0;
    if (!ParseAmountAtomic8(amount_s, &amount))
    {
        printf("send_error: bad_amount\n");
        return 52;
    }
    if (!fee_s.empty() && !ParseAmountAtomic8(fee_s, &fee))
    {
        printf("send_error: bad_fee\n");
        return 53;
    }
    if (!fee_s.empty())
        printf("send_notice: manual_fee_ignored policy=20pct_burn_tax\n");
    if (amount == 0)
    {
        printf("send_error: zero_amount\n");
        return 54;
    }
    const uint32_t magic = ParseMagic(magic_s.c_str());
    const std::string registry = ResolveRegistryPath(data_dir.c_str(), NULL);
    if (node_data_dir.empty())
    {
        node_data_dir = data_dir;
        if (!IsCommitCacheFresh(node_data_dir, 30))
            printf("send_warning: node_data_dir_not_set_and_commit_cache_not_fresh using=%s\n", node_data_dir.c_str());
    }
    int rc = WalletSendCmd(to.c_str(), amount, fee, data_dir.c_str(), node_data_dir.c_str(), magic, registry.c_str());
    if (rc != 0)
        return rc;
    std::string draft;
    if (!FindLatestOutboxFile(data_dir, &draft))
    {
        printf("send_error: draft_not_found\n");
        return 55;
    }
    return TxSubmitCmd(draft.c_str(), node_ep.c_str(), magic);
}

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
        printf("crypto_backend_select_failed reason=liboqs_required backend=ml_dsa_65 build_hint=USE_LIBOQS=1\n");
        return 2;
    }
    WalletIdentity id;
    std::string err;
    const bool create_if_missing = (std::string(subcmd) == "init");
    std::string key_file;
    if (!LoadWalletIdentityResolved(dir, magic, crypto.get(), create_if_missing, &id, &err, &key_file))
    {
        printf("wallet_error: %s\n", err.c_str());
        return 3;
    }
    if (std::string(subcmd) == "init" || std::string(subcmd) == "show")
    {
        printf("pubkey=%s\n", AddressFromPubkey(id.pubkey, 0).substr(6, 64).c_str());
        printf("address=%s\n", id.address.c_str());
        printf("key_file=%s\n", key_file.c_str());
        return 0;
    }
    return 1;
}

static int WalletInfoCmd(const char* dir, uint32_t magic, const char* registry_file_opt)
{
    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed reason=liboqs_required backend=ml_dsa_65 build_hint=USE_LIBOQS=1\n");
        return 2;
    }
    WalletIdentity id;
    std::string err;
    std::string key_file;
    if (!LoadWalletIdentityResolved(dir, magic, crypto.get(), false, &id, &err, &key_file))
    {
        printf("wallet_error: %s\n", err.c_str());
        return 3;
    }

    std::string registry_file = ResolveRegistryPath(dir, registry_file_opt);

    std::vector<LocalUtxo> utxos;
    uint64_t balance = 0;
    bool have_registry = LoadWalletUtxosFromRegistry(registry_file, id.pubkey, &utxos, &balance);
    uint64_t total_supply = 0, total_minted = 0, total_fees_burned = 0;
    bool have_ledger = LoadLedgerTotals(registry_file + ".ledger", &total_supply, &total_minted, &total_fees_burned);

    printf("pubkey=%s\n", AddressFromPubkey(id.pubkey, 0).substr(6, 64).c_str());
    printf("address=%s\n", id.address.c_str());
    printf("key_file=%s\n", key_file.c_str());
    printf("registry_file=%s\n", registry_file.c_str());
    if (!have_registry)
        printf("wallet_registry_status=unavailable\n");
    else
    {
        printf("wallet_utxos=%zu\n", utxos.size());
        printf("wallet_balance=%llu\n", (unsigned long long)balance);
        printf("wallet_balance_drpow=%s\n", FormatAtomic8(balance).c_str());
    }
    if (!have_ledger)
        printf("ledger_status=unavailable\n");
    else
    {
        printf("ledger_total_supply=%llu\n", (unsigned long long)total_supply);
        printf("ledger_total_minted=%llu\n", (unsigned long long)total_minted);
        printf("ledger_total_fees_burned=%llu\n", (unsigned long long)total_fees_burned);
        printf("ledger_total_supply_drpow=%s\n", FormatAtomic8(total_supply).c_str());
        printf("ledger_total_minted_drpow=%s\n", FormatAtomic8(total_minted).c_str());
        printf("ledger_total_fees_burned_drpow=%s\n", FormatAtomic8(total_fees_burned).c_str());
    }
    return 0;
}

static int GetBalanceCmd(const char* dir, uint32_t magic, const char* registry_file_opt)
{
    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed reason=liboqs_required backend=ml_dsa_65 build_hint=USE_LIBOQS=1\n");
        return 2;
    }
    WalletIdentity id;
    std::string err;
    std::string key_file;
    if (!LoadWalletIdentityResolved(dir, magic, crypto.get(), false, &id, &err, &key_file))
    {
        printf("wallet_error: %s\n", err.c_str());
        return 3;
    }
    std::string registry_file = ResolveRegistryPath(dir, registry_file_opt);
    std::vector<LocalUtxo> utxos;
    uint64_t balance = 0;
    if (!LoadWalletUtxosFromRegistry(registry_file, id.pubkey, &utxos, &balance))
    {
        printf("getbalance_error: registry_unavailable path=%s\n", registry_file.c_str());
        printf("getbalance_hint: node has not committed yet or wrong data_dir/config selected\n");
        return 4;
    }
    printf("%llu\n", (unsigned long long)balance);
    printf("getbalance_drpow=%s\n", FormatAtomic8(balance).c_str());
    return 0;
}

static int GetUtxoCmd(const char* dir, uint32_t magic, const char* registry_file_opt)
{
    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed reason=liboqs_required backend=ml_dsa_65 build_hint=USE_LIBOQS=1\n");
        return 2;
    }
    WalletIdentity id;
    std::string err;
    std::string key_file;
    if (!LoadWalletIdentityResolved(dir, magic, crypto.get(), false, &id, &err, &key_file))
    {
        printf("wallet_error: %s\n", err.c_str());
        return 3;
    }
    std::string registry_file = ResolveRegistryPath(dir, registry_file_opt);
    std::vector<LocalUtxo> utxos;
    uint64_t balance = 0;
    if (!LoadWalletUtxosFromRegistry(registry_file, id.pubkey, &utxos, &balance))
    {
        printf("getutxo_error: registry_unavailable path=%s\n", registry_file.c_str());
        printf("getutxo_hint: node has not committed yet or wrong data_dir/config selected\n");
        return 4;
    }
    for (size_t i = 0; i < utxos.size(); ++i)
    {
        printf("coin_id=%s value=%llu value_drpow=%s owner=%s\n",
               Hex(utxos[i].coin_id.v, 32).c_str(),
               (unsigned long long)utxos[i].value,
               FormatAtomic8(utxos[i].value).c_str(),
               Hex(utxos[i].owner_pubkey.v, 32).c_str());
    }
    printf("utxo_count=%zu balance=%llu\n", utxos.size(), (unsigned long long)balance);
    printf("utxo_balance_drpow=%s\n", FormatAtomic8(balance).c_str());
    return 0;
}

static int WalletSendCmd(const char* to_address,
                         uint64_t amount,
                         uint64_t fee_ignored,
                         const char* dir,
                         const char* node_data_dir,
                         uint32_t magic,
                         const char* registry_file_opt)
{
    std::unique_ptr<CryptoBackend> crypto = CreateCryptoBackendFromEnv();
    if (!crypto.get())
    {
        printf("crypto_backend_select_failed reason=liboqs_required backend=ml_dsa_65 build_hint=USE_LIBOQS=1\n");
        return 2;
    }
    WalletIdentity id;
    std::string err;
    std::string key_file;
    if (!LoadWalletIdentityResolved(dir, magic, crypto.get(), true, &id, &err, &key_file))
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

    std::string registry_file = ResolveRegistryPath(dir, registry_file_opt);

    std::vector<LocalUtxo> utxos;
    uint64_t balance = 0;
    if (!LoadWalletUtxosFromRegistry(registry_file, id.pubkey, &utxos, &balance))
    {
        printf("send_error: registry_unavailable path=%s\n", registry_file.c_str());
        return 5;
    }

    (void)fee_ignored;
    const uint64_t next_round = DetectNextRoundFromCommitCache(std::string(node_data_dir ? node_data_dir : dir));
    const EconomicsPolicy policy = DefaultEconomicsPolicy();
    const uint64_t tax_ppm = TransferTaxPpmForRound(next_round, policy);
    const uint64_t burn_tax = (amount * tax_ppm + 999999ULL) / 1000000ULL;
    uint64_t required = amount + burn_tax;
    if (balance < required)
    {
        printf("send_error: insufficient_funds balance=%llu required=%llu\n",
               (unsigned long long)balance,
               (unsigned long long)required);
        printf("send_error_details balance_drpow=%s required_drpow=%s\n",
               FormatAtomic8(balance).c_str(),
               FormatAtomic8(required).c_str());
        return 6;
    }

    SpendTx tx;
    tx.transfer_amount = amount;
    tx.timestamp = (uint64_t)time(NULL);
    tx.fee = burn_tax;
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
    printf("send_amount_drpow=%s\n", FormatAtomic8(amount).c_str());
    printf("send_tax_ppm=%llu\n", (unsigned long long)tax_ppm);
    printf("send_next_round_estimate=%llu\n", (unsigned long long)next_round);
    printf("send_burn_tax=%llu\n", (unsigned long long)burn_tax);
    printf("send_burn_tax_drpow=%s\n", FormatAtomic8(burn_tax).c_str());
    printf("send_inputs=%zu\n", tx.inputs.size());
    printf("send_outputs=%zu\n", tx.outputs.size());
    printf("send_change=%llu\n", (unsigned long long)change);
    printf("send_change_drpow=%s\n", FormatAtomic8(change).c_str());
    printf("send_note=tax20_applied_autosubmit_path_supported\n");
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
    const std::string default_seed_node_dir = DetectDefaultNodeDataDir();
    const std::string default_wallet_dir = default_seed_node_dir;
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
            const char* dir = (argc >= 4) ? argv[3] : default_wallet_dir.c_str();
            const char* magic_arg = (argc >= 5) ? argv[4] : NULL;
            int rc = WalletIdentityCmd(subcmd.c_str(), dir, ParseMagic(magic_arg));
            if (rc == 1)
                WalletUsage(argv[0]);
            return rc;
        }

        if (subcmd == "info")
        {
            const char* dir = (argc >= 4) ? argv[3] : default_wallet_dir.c_str();
            const char* magic_arg = (argc >= 5) ? argv[4] : NULL;
            const char* registry_file = (argc >= 6) ? argv[5] : NULL;
            return WalletInfoCmd(dir, ParseMagic(magic_arg), registry_file);
        }

        if (subcmd == "miner-info")
        {
            const std::string miner_dir = DetectDefaultNodeDataDir();
            const std::string miner_registry = miner_dir + "/registry.bin";
            const char* magic_arg = (argc >= 4) ? argv[3] : NULL;
            const char* registry_file = (argc >= 5) ? argv[4] : miner_registry.c_str();
            return WalletInfoCmd(miner_dir.c_str(), ParseMagic(magic_arg), registry_file);
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
            const char* dir = (argc >= 7) ? argv[6] : default_wallet_dir.c_str();
            const char* magic_arg = (argc >= 8) ? argv[7] : NULL;
            const char* registry_file = (argc >= 9) ? argv[8] : NULL;
            return WalletSendCmd(to_address, amount, fee, dir, dir, ParseMagic(magic_arg), registry_file);
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
    if (cmd == "tx")
    {
        if (argc >= 3 && std::string(argv[2]) == "submit")
        {
            if (argc < 5)
            {
                printf("tx usage:\n");
                printf("  %s tx submit <tx_hex_file> <node_host:port> [network_magic_hex]\n", argv[0]);
                printf("  %s tx status <tx_hex_file> [node_data_dir]\n", argv[0]);
                return 1;
            }
            uint32_t magic = ParseMagic(argc >= 6 ? argv[5] : NULL);
            return TxSubmitCmd(argv[3], argv[4], magic);
        }
        if (argc >= 3 && std::string(argv[2]) == "status")
        {
            if (argc < 4)
            {
                printf("tx usage:\n");
                printf("  %s tx submit <tx_hex_file> <node_host:port> [network_magic_hex]\n", argv[0]);
                printf("  %s tx status <tx_hex_file> [node_data_dir]\n", argv[0]);
                return 1;
            }
            const char* node_data_dir = (argc >= 5) ? argv[4] : default_seed_node_dir.c_str();
            return TxStatusCmd(argv[3], node_data_dir);
        }
        printf("tx usage:\n");
        printf("  %s tx submit <tx_hex_file> <node_host:port> [network_magic_hex]\n", argv[0]);
        printf("  %s tx status <tx_hex_file> [node_data_dir]\n", argv[0]);
        return 1;
    }
    if (cmd == "getbalance")
    {
        const char* dir = (argc >= 3) ? argv[2] : default_wallet_dir.c_str();
        const char* magic_arg = (argc >= 4) ? argv[3] : NULL;
        const char* registry_file = (argc >= 5) ? argv[4] : NULL;
        return GetBalanceCmd(dir, ParseMagic(magic_arg), registry_file);
    }
    if (cmd == "getutxo")
    {
        const char* dir = (argc >= 3) ? argv[2] : default_wallet_dir.c_str();
        const char* magic_arg = (argc >= 4) ? argv[3] : NULL;
        const char* registry_file = (argc >= 5) ? argv[4] : NULL;
        return GetUtxoCmd(dir, ParseMagic(magic_arg), registry_file);
    }
    if (cmd == "send")
    {
        return SendCmd(argc, argv);
    }

    Usage(argv[0]);
    return 1;
}

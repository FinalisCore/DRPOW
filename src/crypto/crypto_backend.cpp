#include "crypto_backend.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include <openssl/evp.h>
#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace drpow {

namespace {

static const uint32_t kTreeHeight = 8;
static const uint32_t kLeafCount = (1u << kTreeHeight);
static const uint32_t kLamportPairs = 256;
static const size_t kHashLen = 32;

static bool Sha256Bytes(const uint8_t* data, size_t data_len, uint8_t out[32])
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;

    unsigned int out_len = 0;
    bool ok = false;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1)
    {
        if ((data_len == 0 || EVP_DigestUpdate(ctx, data, data_len) == 1) &&
            EVP_DigestFinal_ex(ctx, out, &out_len) == 1 && out_len == 32)
            ok = true;
    }

    EVP_MD_CTX_free(ctx);
    return ok;
}

static void WriteU32LE(std::vector<uint8_t>* out, uint32_t v)
{
    out->push_back((uint8_t)(v & 0xff));
    out->push_back((uint8_t)((v >> 8) & 0xff));
    out->push_back((uint8_t)((v >> 16) & 0xff));
    out->push_back((uint8_t)((v >> 24) & 0xff));
}

static bool ReadU32LE(const uint8_t* in, size_t in_len, uint32_t* out)
{
    if (!in || in_len < 4 || !out)
        return false;
    *out = ((uint32_t)in[0]) |
           (((uint32_t)in[1]) << 8) |
           (((uint32_t)in[2]) << 16) |
           (((uint32_t)in[3]) << 24);
    return true;
}

#ifdef USE_LIBOQS
struct PqcStdKeyPair {
    std::vector<uint8_t> pub;
    std::vector<uint8_t> priv;
};

static const char* kPqcStdSigAlg = OQS_SIG_alg_ml_dsa_65;
static std::map<std::string, PqcStdKeyPair> g_pqc_std_keys;
static bool g_pqc_std_keys_loaded = false;

static bool EnsureDir0700(const std::string& path)
{
    if (path.empty())
        return false;
    struct stat st;
    if (stat(path.c_str(), &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
            return false;
        (void)chmod(path.c_str(), S_IRUSR | S_IWUSR | S_IXUSR);
        return true;
    }
    if (mkdir(path.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) == 0)
        return true;
    if (errno == EEXIST)
        return true;
    return false;
}

static std::string GetPqcKeyDbPath()
{
    const char* override_path = getenv("DRPOW_PQC_KEY_DB");
    if (override_path && *override_path)
        return std::string(override_path);
    const char* drpow_home = getenv("DRPOW_HOME");
    std::string home;
    if (drpow_home && *drpow_home)
        home = drpow_home;
    else
    {
        const char* user_home = getenv("HOME");
        if (user_home && *user_home)
            home = std::string(user_home) + "/.drpow";
        else
            home = ".drpow";
    }
    return home + "/keys/pqc_keys.bin";
}

static bool EnsurePqcKeyDbParentReady(const std::string& db_path)
{
    const size_t slash = db_path.find_last_of('/');
    if (slash == std::string::npos)
        return true;
    const std::string parent = db_path.substr(0, slash);
    const size_t slash2 = parent.find_last_of('/');
    if (slash2 != std::string::npos)
    {
        const std::string grand = parent.substr(0, slash2);
        if (!grand.empty())
            (void)EnsureDir0700(grand);
    }
    return EnsureDir0700(parent);
}

static void WriteU32LEFile(std::ofstream* out, uint32_t v)
{
    uint8_t b[4];
    b[0] = (uint8_t)(v & 0xff);
    b[1] = (uint8_t)((v >> 8) & 0xff);
    b[2] = (uint8_t)((v >> 16) & 0xff);
    b[3] = (uint8_t)((v >> 24) & 0xff);
    out->write((const char*)b, 4);
}

static bool ReadU32LEFile(std::ifstream* in, uint32_t* out)
{
    if (!in || !out)
        return false;
    uint8_t b[4];
    in->read((char*)b, 4);
    if (!in->good())
        return false;
    *out = ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return true;
}

static bool LoadPqcStdKeyDb()
{
    if (g_pqc_std_keys_loaded)
        return true;
    g_pqc_std_keys_loaded = true;
    g_pqc_std_keys.clear();

    const std::string db_path = GetPqcKeyDbPath();
    if (!EnsurePqcKeyDbParentReady(db_path))
        return false;
    std::ifstream in(db_path.c_str(), std::ios::binary);
    if (!in.good())
        return true;

    char magic[8];
    in.read(magic, 8);
    if (!in.good() || memcmp(magic, "DRPOWKDB", 8) != 0)
        return true;

    while (true)
    {
        uint8_t seed[32];
        in.read((char*)seed, 32);
        if (in.eof())
            return true;
        if (!in.good())
            return false;
        uint32_t pub_len = 0;
        uint32_t priv_len = 0;
        if (!ReadU32LEFile(&in, &pub_len) || !ReadU32LEFile(&in, &priv_len))
            return true;
        if (pub_len == 0 || priv_len == 0 || pub_len > (1u << 20) || priv_len > (1u << 22))
            return true;
        PqcStdKeyPair kp;
        kp.pub.resize(pub_len);
        kp.priv.resize(priv_len);
        in.read((char*)kp.pub.data(), (std::streamsize)pub_len);
        in.read((char*)kp.priv.data(), (std::streamsize)priv_len);
        if (!in.good())
            return true;
        g_pqc_std_keys[std::string((const char*)seed, 32)] = kp;
    }
}

static bool AppendPqcStdKeyDb(const uint8_t seed32[32], const PqcStdKeyPair& kp)
{
    const std::string db_path = GetPqcKeyDbPath();
    if (!EnsurePqcKeyDbParentReady(db_path))
        return false;
    std::ifstream check(db_path.c_str(), std::ios::binary);
    bool need_header = !check.good();
    check.close();

    std::ofstream out(db_path.c_str(), std::ios::binary | std::ios::app);
    if (!out.good())
        return false;
    if (need_header)
        out.write("DRPOWKDB", 8);
    out.write((const char*)seed32, 32);
    WriteU32LEFile(&out, (uint32_t)kp.pub.size());
    WriteU32LEFile(&out, (uint32_t)kp.priv.size());
    out.write((const char*)kp.pub.data(), (std::streamsize)kp.pub.size());
    out.write((const char*)kp.priv.data(), (std::streamsize)kp.priv.size());
    if (!out.good())
        return false;
    (void)chmod(db_path.c_str(), S_IRUSR | S_IWUSR);
    return true;
}

static bool KeyIdFromPqcPub(const uint8_t* pub, size_t pub_len, uint8_t out_id[32])
{
    return Sha256Bytes(pub_len == 0 ? NULL : pub, pub_len, out_id);
}

static bool LoadOrCreatePqcStdKey(const uint8_t seed32[32], PqcStdKeyPair* out)
{
    if (!seed32 || !out)
        return false;
    if (!LoadPqcStdKeyDb())
        return false;
    std::string key((const char*)seed32, 32);
    std::map<std::string, PqcStdKeyPair>::const_iterator it = g_pqc_std_keys.find(key);
    if (it != g_pqc_std_keys.end())
    {
        *out = it->second;
        return true;
    }

    OQS_SIG* sig = OQS_SIG_new(kPqcStdSigAlg);
    if (!sig)
        return false;

    PqcStdKeyPair kp;
    kp.pub.resize(sig->length_public_key, 0);
    kp.priv.resize(sig->length_secret_key, 0);
    bool ok = (OQS_SIG_keypair(sig, kp.pub.data(), kp.priv.data()) == OQS_SUCCESS);
    OQS_SIG_free(sig);
    if (!ok)
        return false;

    g_pqc_std_keys[key] = kp;
    if (!AppendPqcStdKeyDb(seed32, kp))
        return false;
    *out = kp;
    return true;
}
#endif

static bool DeriveSecret(const uint8_t seed[32], uint32_t leaf_idx, uint32_t pair_idx, uint8_t bit, uint8_t out[32])
{
    std::vector<uint8_t> m;
    m.reserve(1 + 32 + 4 + 4 + 1);
    m.push_back(0xA5);
    m.insert(m.end(), seed, seed + 32);
    WriteU32LE(&m, leaf_idx);
    WriteU32LE(&m, pair_idx);
    m.push_back(bit);
    return Sha256Bytes(m.empty() ? NULL : &m[0], m.size(), out);
}

static bool DeriveLeafPublicHash(const uint8_t seed[32], uint32_t leaf_idx, uint8_t out_leaf_hash[32])
{
    std::vector<uint8_t> lamport_pub;
    lamport_pub.reserve(kLamportPairs * 2 * kHashLen);

    uint8_t sec[32];
    uint8_t h[32];
    for (uint32_t i = 0; i < kLamportPairs; ++i)
    {
        if (!DeriveSecret(seed, leaf_idx, i, 0, sec))
            return false;
        if (!Sha256Bytes(sec, 32, h))
            return false;
        lamport_pub.insert(lamport_pub.end(), h, h + 32);

        if (!DeriveSecret(seed, leaf_idx, i, 1, sec))
            return false;
        if (!Sha256Bytes(sec, 32, h))
            return false;
        lamport_pub.insert(lamport_pub.end(), h, h + 32);
    }

    return Sha256Bytes(lamport_pub.empty() ? NULL : &lamport_pub[0], lamport_pub.size(), out_leaf_hash);
}

static bool BuildTreeLevels(const uint8_t seed[32], std::vector< std::vector< std::vector<uint8_t> > >* levels)
{
    if (!levels)
        return false;
    levels->clear();

    std::vector< std::vector<uint8_t> > leaves;
    leaves.resize(kLeafCount, std::vector<uint8_t>(32, 0));
    for (uint32_t i = 0; i < kLeafCount; ++i)
    {
        uint8_t leaf[32];
        if (!DeriveLeafPublicHash(seed, i, leaf))
            return false;
        memcpy(&leaves[i][0], leaf, 32);
    }
    levels->push_back(leaves);

    uint32_t width = kLeafCount;
    for (uint32_t h = 0; h < kTreeHeight; ++h)
    {
        const std::vector< std::vector<uint8_t> >& prev = levels->back();
        std::vector< std::vector<uint8_t> > next;
        next.resize(width / 2, std::vector<uint8_t>(32, 0));

        for (uint32_t i = 0; i < width; i += 2)
        {
            uint8_t parent[32];
            uint8_t buf[64];
            memcpy(buf, &prev[i][0], 32);
            memcpy(buf + 32, &prev[i + 1][0], 32);
            if (!Sha256Bytes(buf, sizeof(buf), parent))
                return false;
            memcpy(&next[i / 2][0], parent, 32);
        }

        levels->push_back(next);
        width /= 2;
    }

    return levels->size() == (kTreeHeight + 1);
}

static bool MerkleRootFromLeafAndPath(const uint8_t leaf[32], uint32_t leaf_idx, const uint8_t* auth_path, size_t auth_path_len, uint8_t out_root[32])
{
    if (!leaf || !auth_path || auth_path_len != (size_t)kTreeHeight * 32 || !out_root)
        return false;

    uint8_t cur[32];
    memcpy(cur, leaf, 32);
    uint32_t idx = leaf_idx;

    for (uint32_t level = 0; level < kTreeHeight; ++level)
    {
        const uint8_t* sib = auth_path + (level * 32);
        uint8_t buf[64];
        if ((idx & 1u) == 0)
        {
            memcpy(buf, cur, 32);
            memcpy(buf + 32, sib, 32);
        }
        else
        {
            memcpy(buf, sib, 32);
            memcpy(buf + 32, cur, 32);
        }
        if (!Sha256Bytes(buf, sizeof(buf), cur))
            return false;
        idx >>= 1;
    }

    memcpy(out_root, cur, 32);
    return true;
}

static bool MessageBits(const uint8_t* msg, size_t msg_len, uint8_t out_hash[32])
{
    return Sha256Bytes(msg_len == 0 ? NULL : msg, msg_len, out_hash);
}

static std::map<std::string, uint32_t> g_next_leaf_index;

}  // namespace

bool PqcBackendStub::VerifyEd25519(const uint8_t pubkey[32],
                                   const uint8_t* msg,
                                   size_t msg_len,
                                   const uint8_t* sig,
                                   size_t sig_len) const
{
#ifdef USE_LIBOQS
    if (!pubkey || !sig)
        return false;
    if (sig_len < 8)
        return false;

    uint32_t pq_pub_len = 0;
    uint32_t pq_sig_len = 0;
    if (!ReadU32LE(sig, sig_len, &pq_pub_len) || !ReadU32LE(sig + 4, sig_len - 4, &pq_sig_len))
        return false;

    const size_t header = 8;
    if (sig_len != header + (size_t)pq_pub_len + (size_t)pq_sig_len)
        return false;
    const uint8_t* pq_pub = sig + header;
    const uint8_t* pq_sig = pq_pub + pq_pub_len;

    uint8_t key_id[32];
    if (!KeyIdFromPqcPub(pq_pub, pq_pub_len, key_id))
        return false;
    if (memcmp(key_id, pubkey, 32) != 0)
        return false;

    OQS_SIG* oqs = OQS_SIG_new(kPqcStdSigAlg);
    if (!oqs)
        return false;
    bool ok = (OQS_SIG_verify(oqs,
                              msg_len == 0 ? NULL : msg,
                              msg_len,
                              pq_sig,
                              pq_sig_len,
                              pq_pub) == OQS_SUCCESS);
    OQS_SIG_free(oqs);
    return ok;
#else
    if (!pubkey || !sig)
        return false;

    const size_t lamport_sig_len = kLamportPairs * 32;
    const size_t lamport_pub_len = kLamportPairs * 2 * 32;
    const size_t auth_len = kTreeHeight * 32;
    const size_t expected = 4 + lamport_sig_len + lamport_pub_len + auth_len;
    if (sig_len != expected)
        return false;

    uint32_t leaf_idx = 0;
    if (!ReadU32LE(sig, sig_len, &leaf_idx))
        return false;
    if (leaf_idx >= kLeafCount)
        return false;

    const uint8_t* lamport_sig = sig + 4;
    const uint8_t* lamport_pub = lamport_sig + lamport_sig_len;
    const uint8_t* auth_path = lamport_pub + lamport_pub_len;

    uint8_t msg_hash[32];
    if (!MessageBits(msg, msg_len, msg_hash))
        return false;

    for (uint32_t i = 0; i < kLamportPairs; ++i)
    {
        const uint8_t bit = (uint8_t)((msg_hash[i / 8] >> (7 - (i % 8))) & 1u);
        const uint8_t* pub_expected = lamport_pub + ((i * 2 + bit) * 32);
        uint8_t h[32];
        if (!Sha256Bytes(lamport_sig + i * 32, 32, h))
            return false;
        if (memcmp(h, pub_expected, 32) != 0)
            return false;
    }

    uint8_t leaf_hash[32];
    if (!Sha256Bytes(lamport_pub, lamport_pub_len, leaf_hash))
        return false;

    uint8_t root[32];
    if (!MerkleRootFromLeafAndPath(leaf_hash, leaf_idx, auth_path, auth_len, root))
        return false;

    return memcmp(root, pubkey, 32) == 0;
#endif
}

bool PqcBackendStub::SignEd25519(const uint8_t privkey[32],
                                 const uint8_t* msg,
                                 size_t msg_len,
                                 std::vector<uint8_t>* out_sig) const
{
#ifdef USE_LIBOQS
    if (!privkey || !out_sig)
        return false;

    PqcStdKeyPair kp;
    if (!LoadOrCreatePqcStdKey(privkey, &kp))
        return false;

    OQS_SIG* oqs = OQS_SIG_new(kPqcStdSigAlg);
    if (!oqs)
        return false;

    std::vector<uint8_t> pq_sig(oqs->length_signature, 0);
    size_t pq_sig_len = 0;
    bool ok = (OQS_SIG_sign(oqs,
                            pq_sig.data(),
                            &pq_sig_len,
                            msg_len == 0 ? NULL : msg,
                            msg_len,
                            kp.priv.data()) == OQS_SUCCESS);
    OQS_SIG_free(oqs);
    if (!ok)
        return false;
    pq_sig.resize(pq_sig_len);

    out_sig->clear();
    out_sig->reserve(8 + kp.pub.size() + pq_sig.size());
    WriteU32LE(out_sig, (uint32_t)kp.pub.size());
    WriteU32LE(out_sig, (uint32_t)pq_sig.size());
    out_sig->insert(out_sig->end(), kp.pub.begin(), kp.pub.end());
    out_sig->insert(out_sig->end(), pq_sig.begin(), pq_sig.end());
    return true;
#else
    if (!privkey || !out_sig)
        return false;

    std::string key((const char*)privkey, 32);
    uint32_t idx = 0;
    std::map<std::string, uint32_t>::iterator it = g_next_leaf_index.find(key);
    if (it != g_next_leaf_index.end())
        idx = it->second;

    if (idx >= kLeafCount)
        return false;

    std::vector< std::vector< std::vector<uint8_t> > > levels;
    if (!BuildTreeLevels(privkey, &levels))
        return false;

    uint8_t msg_hash[32];
    if (!MessageBits(msg, msg_len, msg_hash))
        return false;

    const size_t lamport_sig_len = kLamportPairs * 32;
    const size_t lamport_pub_len = kLamportPairs * 2 * 32;
    const size_t auth_len = kTreeHeight * 32;
    out_sig->clear();
    out_sig->reserve(4 + lamport_sig_len + lamport_pub_len + auth_len);

    WriteU32LE(out_sig, idx);

    std::vector<uint8_t> lamport_pub;
    lamport_pub.reserve(lamport_pub_len);

    uint8_t sec0[32], sec1[32], h0[32], h1[32];
    for (uint32_t i = 0; i < kLamportPairs; ++i)
    {
        if (!DeriveSecret(privkey, idx, i, 0, sec0) || !DeriveSecret(privkey, idx, i, 1, sec1))
            return false;
        if (!Sha256Bytes(sec0, 32, h0) || !Sha256Bytes(sec1, 32, h1))
            return false;

        lamport_pub.insert(lamport_pub.end(), h0, h0 + 32);
        lamport_pub.insert(lamport_pub.end(), h1, h1 + 32);

        const uint8_t bit = (uint8_t)((msg_hash[i / 8] >> (7 - (i % 8))) & 1u);
        const uint8_t* chosen = bit ? sec1 : sec0;
        out_sig->insert(out_sig->end(), chosen, chosen + 32);
    }

    out_sig->insert(out_sig->end(), lamport_pub.begin(), lamport_pub.end());

    uint32_t cur = idx;
    for (uint32_t level = 0; level < kTreeHeight; ++level)
    {
        uint32_t sibling = (cur ^ 1u);
        const std::vector<uint8_t>& sib = levels[level][sibling];
        out_sig->insert(out_sig->end(), sib.begin(), sib.end());
        cur >>= 1;
    }

    g_next_leaf_index[key] = idx + 1;
    return true;
#endif
}

bool PqcBackendStub::PublicFromPrivateEd25519(const uint8_t privkey[32], uint8_t out_pubkey[32]) const
{
#ifdef USE_LIBOQS
    if (!privkey || !out_pubkey)
        return false;
    PqcStdKeyPair kp;
    if (!LoadOrCreatePqcStdKey(privkey, &kp))
        return false;
    return KeyIdFromPqcPub(kp.pub.data(), kp.pub.size(), out_pubkey);
#else
    if (!privkey || !out_pubkey)
        return false;

    std::vector< std::vector< std::vector<uint8_t> > > levels;
    if (!BuildTreeLevels(privkey, &levels))
        return false;

    if (levels.size() != (kTreeHeight + 1) || levels.back().size() != 1)
        return false;

    memcpy(out_pubkey, &levels.back()[0][0], 32);
    return true;
#endif
}

std::unique_ptr<CryptoBackend> CreateCryptoBackendByName(const std::string& name)
{
    if (name == "pqc" || name == "pqc_stub" || name.empty())
    {
        if (!HasStandardPqcBackend())
            return std::unique_ptr<CryptoBackend>();
        return std::unique_ptr<CryptoBackend>(new PqcBackendStub());
    }
    return std::unique_ptr<CryptoBackend>();
}

std::unique_ptr<CryptoBackend> CreateCryptoBackendFromEnv()
{
    const char* v = getenv("DRPOW_CRYPTO_BACKEND");
    if (!v || !*v)
        return CreateCryptoBackendByName("pqc");
    return CreateCryptoBackendByName(v);
}

bool HasStandardPqcBackend()
{
#ifdef USE_LIBOQS
    return true;
#else
    return false;
#endif
}

bool GetPqcKeyDbSelfCheck(std::string* out_path,
                          bool* out_parent_owner_only,
                          bool* out_file_exists,
                          bool* out_file_owner_only)
{
    if (!out_path || !out_parent_owner_only || !out_file_exists || !out_file_owner_only)
        return false;
    *out_parent_owner_only = false;
    *out_file_exists = false;
    *out_file_owner_only = false;
#ifdef USE_LIBOQS
    const std::string db_path = GetPqcKeyDbPath();
    *out_path = db_path;
    const size_t slash = db_path.find_last_of('/');
    if (slash != std::string::npos)
    {
        const std::string parent = db_path.substr(0, slash);
        struct stat stp;
        if (stat(parent.c_str(), &stp) == 0 && S_ISDIR(stp.st_mode))
        {
            const mode_t m = stp.st_mode & 0777;
            *out_parent_owner_only = (m == (S_IRUSR | S_IWUSR | S_IXUSR));
        }
    }
    struct stat stf;
    if (stat(db_path.c_str(), &stf) == 0 && S_ISREG(stf.st_mode))
    {
        *out_file_exists = true;
        const mode_t m = stf.st_mode & 0777;
        *out_file_owner_only = (m == (S_IRUSR | S_IWUSR));
    }
    return true;
#else
    *out_path = "<unavailable_without_liboqs>";
    return true;
#endif
}

}  

#include "drpow/address.h"

#include <stdio.h>
#include <string.h>

#include <vector>

#include "drpow/tx_codec.h"

namespace drpow {

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

static bool HexToBytes(const std::string& s, uint8_t* out, size_t out_n)
{
    if (!out || s.size() != out_n * 2)
        return false;
    for (size_t i = 0; i < out_n; ++i)
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

static uint32_t Checksum4(const std::vector<uint8_t>& body)
{
    Bytes32 h;
    if (!Sha256(body, &h))
        return 0;
    uint32_t x = 0;
    x |= (uint32_t)h.v[0];
    x |= ((uint32_t)h.v[1] << 8);
    x |= ((uint32_t)h.v[2] << 16);
    x |= ((uint32_t)h.v[3] << 24);
    return x;
}

std::string AddressFromPubkey(const Bytes32& pubkey, uint32_t network_magic)
{
    std::vector<uint8_t> body;
    body.push_back((uint8_t)(network_magic & 0xff));
    body.push_back((uint8_t)((network_magic >> 8) & 0xff));
    body.push_back((uint8_t)((network_magic >> 16) & 0xff));
    body.push_back((uint8_t)((network_magic >> 24) & 0xff));
    body.insert(body.end(), pubkey.v, pubkey.v + 32);
    uint32_t cs = Checksum4(body);

    char cbuf[9];
    snprintf(cbuf, sizeof(cbuf), "%08x", cs);
    return std::string("drpow_") + Hex(body.empty() ? NULL : &body[0], body.size()) + cbuf;
}

bool ParseAddress(const std::string& address, uint32_t expected_network_magic, Bytes32* out_pubkey)
{
    if (!out_pubkey)
        return false;
    if (address.size() != 6 + (4 + 32) * 2 + 8)
        return false;
    if (address.substr(0, 6) != "drpow_")
        return false;

    const std::string payload = address.substr(6, (4 + 32) * 2);
    const std::string checksum_hex = address.substr(6 + (4 + 32) * 2, 8);

    uint8_t raw[36];
    if (!HexToBytes(payload, raw, sizeof(raw)))
        return false;

    uint32_t nm = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8) | ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24);
    if (nm != expected_network_magic)
        return false;

    std::vector<uint8_t> body(raw, raw + sizeof(raw));
    uint32_t expect_cs = Checksum4(body);
    char cbuf[9];
    snprintf(cbuf, sizeof(cbuf), "%08x", expect_cs);
    if (checksum_hex != std::string(cbuf))
        return false;

    memcpy(out_pubkey->v, raw + 4, 32);
    return true;
}

}  // namespace drpow

#include "drpow_params.h"

#include <stdio.h>
#include <string.h>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

#include "drpow/tx_codec.h"

namespace drpow {

const char* DrpowParamsVersionTag()
{
    return "drpow_params_v2";
}

bool ComputeDrpowParamsHash(Bytes32* out_hash)
{
    if (!out_hash)
        return false;
    char buf[1024];
    // Canonical serialization: fixed field order, decimal integer formatting.
    const int n = snprintf(buf,
                           sizeof(buf),
                           "%s|min_qc_votes=%llu|target_adjust_up_ppm_limit=%llu|target_adjust_down_ppm_limit=%llu",
                           DrpowParamsVersionTag(),
                           (unsigned long long)DrpowParams::kMinQcVotes,
                           (unsigned long long)DrpowParams::kTargetAdjustUpPpmLimit,
                           (unsigned long long)DrpowParams::kTargetAdjustDownPpmLimit);
    if (n <= 0 || (size_t)n >= sizeof(buf))
        return false;
    std::vector<uint8_t> bytes((const uint8_t*)buf, (const uint8_t*)buf + (size_t)n);
    return Sha256(bytes, out_hash);
}

static bool ExtractUintFromLine(const std::string& line, const char* key, uint64_t* out)
{
    if (!key || !out)
        return false;
    const std::string needle = std::string("`") + key;
    const size_t p = line.find(needle);
    if (p == std::string::npos)
        return false;
    const size_t eq = line.find('=', p);
    if (eq == std::string::npos)
        return false;
    size_t i = eq + 1;
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
        ++i;
    size_t j = i;
    while (j < line.size() && line[j] >= '0' && line[j] <= '9')
        ++j;
    if (j == i)
        return false;
    std::stringstream ss(line.substr(i, j - i));
    uint64_t v = 0;
    ss >> v;
    if (!ss.good() && !ss.eof())
        return false;
    *out = v;
    return true;
}

bool ComputeDrpowParamsHashFromSpecFile(const char* spec_file_path, Bytes32* out_hash, std::string* out_error)
{
    if (out_error)
        out_error->clear();
    if (!spec_file_path || !out_hash)
    {
        if (out_error)
            *out_error = "invalid_argument";
        return false;
    }
    std::ifstream in(spec_file_path);
    if (!in.good())
    {
        if (out_error)
            *out_error = "open_failed";
        return false;
    }
    std::map<std::string, uint64_t> kv;
    std::string line;
    while (std::getline(in, line))
    {
        uint64_t v = 0;
        if (ExtractUintFromLine(line, "kMinQcVotes", &v)) kv["kMinQcVotes"] = v;
        if (ExtractUintFromLine(line, "kTargetAdjustUpPpmLimit", &v)) kv["kTargetAdjustUpPpmLimit"] = v;
        if (ExtractUintFromLine(line, "kTargetAdjustDownPpmLimit", &v)) kv["kTargetAdjustDownPpmLimit"] = v;
    }
    static const char* required[] = {
        "kMinQcVotes",
        "kTargetAdjustUpPpmLimit",
        "kTargetAdjustDownPpmLimit"
    };
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); ++i)
    {
        if (!kv.count(required[i]))
        {
            if (out_error)
                *out_error = std::string("missing_key:") + required[i];
            return false;
        }
    }
    char buf[1024];
    const int n = snprintf(buf,
                           sizeof(buf),
                           "%s|min_qc_votes=%llu|target_adjust_up_ppm_limit=%llu|target_adjust_down_ppm_limit=%llu",
                           DrpowParamsVersionTag(),
                           (unsigned long long)kv["kMinQcVotes"],
                           (unsigned long long)kv["kTargetAdjustUpPpmLimit"],
                           (unsigned long long)kv["kTargetAdjustDownPpmLimit"]);
    if (n <= 0 || (size_t)n >= sizeof(buf))
    {
        if (out_error)
            *out_error = "format_failed";
        return false;
    }
    std::vector<uint8_t> bytes((const uint8_t*)buf, (const uint8_t*)buf + (size_t)n);
    if (!Sha256(bytes, out_hash))
    {
        if (out_error)
            *out_error = "sha256_failed";
        return false;
    }
    return true;
}

}  // namespace drpow

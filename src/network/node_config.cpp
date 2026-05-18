#include "rpov2/node_config.h"

#include <stdlib.h>
#include <fstream>
#include <sstream>

namespace rpov2 {

static std::string Trim(const std::string& s)
{
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n'))
        ++a;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n'))
        --b;
    return s.substr(a, b - a);
}

static bool ParseU32Hex(const std::string& s, uint32_t* out)
{
    if (!out)
        return false;
    std::string v = Trim(s);
    if (v.size() >= 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))
        v = v.substr(2);
    if (v.empty() || v.size() > 8)
        return false;
    uint32_t x = 0;
    for (size_t i = 0; i < v.size(); ++i)
    {
        char c = v[i];
        uint32_t d = 0;
        if (c >= '0' && c <= '9')
            d = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = (uint32_t)(10 + c - 'a');
        else if (c >= 'A' && c <= 'F')
            d = (uint32_t)(10 + c - 'A');
        else
            return false;
        x = (x << 4) | d;
    }
    *out = x;
    return true;
}

bool LoadNodeConfig(const std::string& path, NodeConfig* out, std::string* err)
{
    if (!out)
        return false;

    NodeConfig cfg;
    cfg.data_dir = "/tmp/rpov2_node";
    cfg.bind_port = 29000;
    cfg.public_endpoint = "";
    cfg.duration_sec = 15;
    cfg.autopropose = 0;
    cfg.autopropose_interval_sec = 3;
    cfg.network_magic = 0x52504f57u;
    cfg.log_level = "normal";

    std::ifstream in(path.c_str());
    if (!in.good())
    {
        if (err)
            *err = "cannot open config";
        return false;
    }

    std::string line;
    while (std::getline(in, line))
    {
        line = Trim(line);
        if (line.empty() || line[0] == '#')
            continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos)
            continue;
        std::string k = Trim(line.substr(0, eq));
        std::string v = Trim(line.substr(eq + 1));

        if (k == "data_dir")
            cfg.data_dir = v;
        else if (k == "bind_port")
            cfg.bind_port = (uint16_t)atoi(v.c_str());
        else if (k == "duration_sec")
            cfg.duration_sec = atoi(v.c_str());
        else if (k == "public_endpoint")
            cfg.public_endpoint = v;
        else if (k == "autopropose")
            cfg.autopropose = atoi(v.c_str());
        else if (k == "autopropose_interval_sec")
            cfg.autopropose_interval_sec = atoi(v.c_str());
        else if (k == "network_magic_hex")
        {
            if (!ParseU32Hex(v, &cfg.network_magic))
            {
                if (err)
                    *err = "network_magic_hex invalid";
                return false;
            }
        }
        else if (k == "signer_privkey_hex")
            cfg.signer_privkey_hex = v;
        else if (k == "genesis_hash_hex")
            cfg.genesis_hash_hex = v;
        else if (k == "log_level")
            cfg.log_level = v;
        else if (k == "validator_pubkeys_hex")
        {
            cfg.validator_pubkeys_hex.clear();
            std::stringstream ss(v);
            std::string p;
            while (std::getline(ss, p, ','))
            {
                p = Trim(p);
                if (!p.empty())
                    cfg.validator_pubkeys_hex.push_back(p);
            }
        }
        else if (k == "peers")
        {
            cfg.peers.clear();
            std::stringstream ss(v);
            std::string p;
            while (std::getline(ss, p, ','))
            {
                p = Trim(p);
                if (!p.empty())
                    cfg.peers.push_back(p);
            }
        }
    }

    if (!cfg.signer_privkey_hex.empty() && cfg.signer_privkey_hex.size() != 64)
    {
        if (err)
            *err = "signer_privkey_hex must be 64 hex chars if set";
        return false;
    }
    if (cfg.genesis_hash_hex.size() != 64)
    {
        if (err)
            *err = "genesis_hash_hex must be 64 hex chars";
        return false;
    }
    if (cfg.bind_port == 0)
    {
        if (err)
            *err = "bind_port invalid";
        return false;
    }
    if (cfg.autopropose_interval_sec <= 0)
        cfg.autopropose_interval_sec = 3;
    if (cfg.network_magic == 0)
    {
        if (err)
            *err = "network_magic_hex cannot be zero";
        return false;
    }
    for (size_t i = 0; i < cfg.validator_pubkeys_hex.size(); ++i)
    {
        if (cfg.validator_pubkeys_hex[i].size() != 64)
        {
            if (err)
                *err = "validator_pubkeys_hex entries must be 64 hex chars";
            return false;
        }
    }
    if (!(cfg.log_level == "quiet" || cfg.log_level == "normal" || cfg.log_level == "debug"))
    {
        if (err)
            *err = "log_level must be quiet|normal|debug";
        return false;
    }
    *out = cfg;
    return true;
}

}  // namespace rpov2

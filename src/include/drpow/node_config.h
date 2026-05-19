#ifndef COIN_NODE_CONFIG_H
#define COIN_NODE_CONFIG_H

#include <stdint.h>
#include <string>
#include <vector>

namespace drpow {

struct NodeConfig {
    std::string data_dir;
    uint16_t bind_port;
    std::vector<std::string> peers;
    std::string public_endpoint;
    int duration_sec;
    int autopropose;
    int autopropose_interval_sec;
    uint32_t network_magic;
    std::vector<std::string> validator_pubkeys_hex;
    std::string signer_privkey_hex;
    std::string genesis_hash_hex;
    std::string log_level;
};

bool LoadNodeConfig(const std::string& path, NodeConfig* out, std::string* err);

}  // namespace drpow

#endif

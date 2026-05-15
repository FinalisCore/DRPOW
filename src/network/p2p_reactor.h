#ifndef COIN_P2P_REACTOR_H
#define COIN_P2P_REACTOR_H

#include <stdint.h>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "p2p_wire.h"
#include "rpov2/tx_types.h"

namespace rpov2 {

class P2PReactor {
public:
    typedef std::function<void(int, const WireEnvelope&)> MessageHandler;

    P2PReactor(uint16_t bind_port, const std::vector<std::string>& peers, const Bytes32& local_node_id);
    ~P2PReactor();

    bool Start(std::string* err);
    void PollOnce();
    void Stop();
    bool Broadcast(const WireEnvelope& env);
    bool SendTo(int fd, const WireEnvelope& env);
    void SetMessageHandler(const MessageHandler& handler);
    void AddPeer(const std::string& endpoint);
    std::vector<std::string> KnownPeers() const;
    std::string PeerEndpoint(int fd) const;

private:
    struct PeerConn {
        int fd;
        std::vector<uint8_t> rx_buf;
        bool saw_hello;
        bool outbound;
        std::string endpoint;
    };

    int listen_fd_;
    uint16_t bind_port_;
    std::vector<std::string> peers_;
    std::vector<PeerConn> peers_fd_;
    std::map<std::string, int> outbound_fd_by_endpoint_;
    uint64_t last_connect_attempt_ms_;
    Bytes32 local_node_id_;
    MessageHandler on_message_;

    static bool ParseHostPort(const std::string& s, std::string* host, uint16_t* port);
    void CloseAll();
    void ConnectPeersOnce();
    uint64_t NowMs() const;
    void AcceptIncoming();
    bool SendFramed(int fd, const WireEnvelope& env);
    void OnPeerReadable(size_t idx);
    bool ParseOneFrame(std::vector<uint8_t>* in, std::vector<uint8_t>* one_frame);
};

}  // namespace rpov2

#endif

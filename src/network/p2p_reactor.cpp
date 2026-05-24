#include "p2p_reactor.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>

namespace drpow {

namespace {

static bool SendAll(int fd, const uint8_t* data, size_t n)
{
    if (!data && n != 0)
        return false;
    size_t off = 0;
    int eagain_spins = 0;
    while (off < n)
    {
        int flags = 0;
#ifdef MSG_NOSIGNAL
        flags |= MSG_NOSIGNAL;
#endif
        ssize_t w = send(fd, data + off, n - off, flags);
        if (w < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (++eagain_spins > 16)
                    return false;
                usleep(1000);
                continue;
            }
            return false;
        }
        if (w == 0)
            return false;
        off += (size_t)w;
    }
    return true;
}

}  // namespace

P2PReactor::P2PReactor(uint16_t bind_port, const std::vector<std::string>& peers, const Bytes32& local_node_id)
    : listen_fd_(-1), bind_port_(bind_port), peers_(peers), last_connect_attempt_ms_(0), local_node_id_(local_node_id)
{
}

P2PReactor::~P2PReactor()
{
    Stop();
}

bool P2PReactor::ParseHostPort(const std::string& s, std::string* host, uint16_t* port)
{
    if (!host || !port)
        return false;
    size_t c = s.rfind(':');
    if (c == std::string::npos)
        return false;
    *host = s.substr(0, c);
    *port = (uint16_t)atoi(s.substr(c + 1).c_str());
    return !host->empty() && *port != 0;
}

bool P2PReactor::Start(std::string* err)
{
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0)
    {
        if (err)
            *err = "socket failed";
        return false;
    }

    int yes = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(bind_port_);
    if (bind(listen_fd_, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        if (err)
        {
            char buf[128];
            snprintf(buf, sizeof(buf), "bind failed port=%u errno=%d msg=%s",
                     (unsigned)bind_port_, errno, strerror(errno));
            *err = buf;
        }
        CloseAll();
        return false;
    }
    if (listen(listen_fd_, 32) != 0)
    {
        if (err)
            *err = "listen failed";
        CloseAll();
        return false;
    }
    int flags = fcntl(listen_fd_, F_GETFL, 0);
    if (flags >= 0)
        fcntl(listen_fd_, F_SETFL, flags | O_NONBLOCK);

    ConnectPeersOnce();
    return true;
}

uint64_t P2PReactor::NowMs() const
{
    timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
}

void P2PReactor::SetMessageHandler(const MessageHandler& handler)
{
    on_message_ = handler;
}

void P2PReactor::AddPeer(const std::string& endpoint)
{
    if (endpoint.empty())
        return;
    for (size_t i = 0; i < peers_.size(); ++i)
        if (peers_[i] == endpoint)
            return;
    peers_.push_back(endpoint);
}

std::vector<std::string> P2PReactor::KnownPeers() const
{
    std::vector<std::string> out = peers_;
    for (size_t i = 0; i < peers_fd_.size(); ++i)
    {
        if (!peers_fd_[i].endpoint.empty())
            out.push_back(peers_fd_[i].endpoint);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::string P2PReactor::PeerEndpoint(int fd) const
{
    for (size_t i = 0; i < peers_fd_.size(); ++i)
        if (peers_fd_[i].fd == fd)
            return peers_fd_[i].endpoint;
    return "";
}

bool P2PReactor::SendFramed(int fd, const WireEnvelope& env)
{
    std::vector<uint8_t> msg;
    if (!SerializeWireEnvelope(env, &msg))
        return false;
    if (msg.size() > 0xffffffffu)
        return false;

    uint8_t hdr[4];
    const uint32_t n = (uint32_t)msg.size();
    hdr[0] = (uint8_t)(n & 0xff);
    hdr[1] = (uint8_t)((n >> 8) & 0xff);
    hdr[2] = (uint8_t)((n >> 16) & 0xff);
    hdr[3] = (uint8_t)((n >> 24) & 0xff);
    if (!SendAll(fd, hdr, sizeof(hdr)))
        return false;
    if (!msg.empty() && !SendAll(fd, &msg[0], msg.size()))
        return false;
    return true;
}

bool P2PReactor::Broadcast(const WireEnvelope& env)
{
    bool any_success = false;
    size_t fail_count = 0;
    for (size_t i = 0; i < peers_fd_.size(); ++i)
    {
        if (SendFramed(peers_fd_[i].fd, env))
        {
            any_success = true;
        }
        else
        {
            fail_count += 1;
            const std::string ep = peers_fd_[i].endpoint;
            if (!ep.empty())
                printf("p2p_send_failed endpoint=%s type=%u\n", ep.c_str(), (unsigned)env.msg_type);
            else
                printf("p2p_send_failed fd=%d type=%u\n", peers_fd_[i].fd, (unsigned)env.msg_type);
        }
    }
    if (!any_success && fail_count == 0)
        return false;  // no connected peers
    return any_success;
}

bool P2PReactor::SendTo(int fd, const WireEnvelope& env)
{
    for (size_t i = 0; i < peers_fd_.size(); ++i)
    {
        if (peers_fd_[i].fd == fd)
            return SendFramed(fd, env);
    }
    return false;
}

void P2PReactor::Disconnect(int fd)
{
    for (size_t i = 0; i < peers_fd_.size(); ++i)
    {
        if (peers_fd_[i].fd == fd)
        {
            PeerConn& c = peers_fd_[i];
            if (c.outbound && !c.endpoint.empty())
                outbound_fd_by_endpoint_.erase(c.endpoint);
            close(c.fd);
            peers_fd_.erase(peers_fd_.begin() + i);
            return;
        }
    }
}

void P2PReactor::ConnectPeersOnce()
{
    const uint64_t now_ms = NowMs();
    if (last_connect_attempt_ms_ != 0 && now_ms - last_connect_attempt_ms_ < 2000)
        return;
    last_connect_attempt_ms_ = now_ms;

    for (size_t i = 0; i < peers_.size(); ++i)
    {
        if (outbound_fd_by_endpoint_.count(peers_[i]))
            continue;
        std::string host;
        uint16_t port = 0;
        if (!ParseHostPort(peers_[i], &host, &port))
            continue;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            continue;

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_INET;
        char port_s[16];
        snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);
        struct addrinfo* res = NULL;
        if (getaddrinfo(host.c_str(), port_s, &hints, &res) != 0 || !res)
        {
            close(fd);
            continue;
        }
        bool connected = false;
        for (struct addrinfo* ai = res; ai; ai = ai->ai_next)
        {
            if (connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0)
            {
                connected = true;
                break;
            }
        }
        freeaddrinfo(res);
        if (!connected)
        {
            close(fd);
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0)
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        PeerConn c;
        c.fd = fd;
        c.saw_hello = false;
        c.outbound = true;
        c.endpoint = peers_[i];
        c.hello_deadline_ms = NowMs() + 5000;
        peers_fd_.push_back(c);
        outbound_fd_by_endpoint_[peers_[i]] = fd;

        WireEnvelope hello;
        hello.magic = WireMagicMainnet();
        hello.version = 1;
        hello.msg_type = WIRE_MSG_HELLO;
        hello.payload_len = 32;
        hello.unix_ms = 0;
        hello.payload.assign(local_node_id_.v, local_node_id_.v + 32);
        memset(hello.payload_hash.v, 0, 32);
        (void)SendFramed(fd, hello);
    }
}

void P2PReactor::AcceptIncoming()
{
    const size_t kMaxInboundPerIp = 4;
    const size_t kMaxInboundPer24 = 16;
    std::map<uint32_t, size_t> per_ip;
    std::map<uint32_t, size_t> per_24;
    for (size_t i = 0; i < peers_fd_.size(); ++i)
    {
        if (peers_fd_[i].outbound || peers_fd_[i].endpoint.empty())
            continue;
        std::string host;
        uint16_t port = 0;
        if (!ParseHostPort(peers_fd_[i].endpoint, &host, &port))
            continue;
        in_addr a;
        if (inet_pton(AF_INET, host.c_str(), &a) != 1)
            continue;
        const uint32_t ip = ntohl(a.s_addr);
        per_ip[ip] += 1;
        per_24[ip >> 8] += 1;
    }

    while (true)
    {
        sockaddr_in in_addr;
        socklen_t in_len = sizeof(in_addr);
        int fd = accept(listen_fd_, (sockaddr*)&in_addr, &in_len);
        if (fd < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            break;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0)
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        const uint32_t ip_host = ntohl(in_addr.sin_addr.s_addr);
        if (per_ip[ip_host] >= kMaxInboundPerIp || per_24[ip_host >> 8] >= kMaxInboundPer24)
        {
            close(fd);
            continue;
        }
        PeerConn c;
        c.fd = fd;
        c.saw_hello = false;
        c.outbound = false;
        c.hello_deadline_ms = NowMs() + 5000;
        char ip[64];
        const char* p = inet_ntop(AF_INET, &in_addr.sin_addr, ip, sizeof(ip));
        if (p)
        {
            char ep[96];
            snprintf(ep, sizeof(ep), "%s:%u", p, (unsigned)ntohs(in_addr.sin_port));
            c.endpoint = ep;
        }
        peers_fd_.push_back(c);
        per_ip[ip_host] += 1;
        per_24[ip_host >> 8] += 1;
        WireEnvelope hello;
        hello.magic = WireMagicMainnet();
        hello.version = 1;
        hello.msg_type = WIRE_MSG_HELLO;
        hello.payload_len = 32;
        hello.unix_ms = 0;
        hello.payload.assign(local_node_id_.v, local_node_id_.v + 32);
        memset(hello.payload_hash.v, 0, 32);
        (void)SendFramed(fd, hello);
    }
}

bool P2PReactor::ParseOneFrame(std::vector<uint8_t>* in, std::vector<uint8_t>* one_frame)
{
    if (!in || !one_frame || in->size() < 4)
        return false;
    const uint32_t n = ((uint32_t)(*in)[0]) |
                       ((uint32_t)(*in)[1] << 8) |
                       ((uint32_t)(*in)[2] << 16) |
                       ((uint32_t)(*in)[3] << 24);
    if (n > WireMaxPayloadBytes() + 64)
        return false;
    if (in->size() < 4 + n)
        return false;
    one_frame->assign(in->begin() + 4, in->begin() + 4 + n);
    in->erase(in->begin(), in->begin() + 4 + n);
    return true;
}

void P2PReactor::OnPeerReadable(size_t idx)
{
    char buf[2048];
    PeerConn& c = peers_fd_[idx];
    while (true)
    {
        int r = recv(c.fd, buf, sizeof(buf), 0);
        if (r == 0)
        {
            if (c.outbound && !c.endpoint.empty())
                outbound_fd_by_endpoint_.erase(c.endpoint);
            close(c.fd);
            peers_fd_.erase(peers_fd_.begin() + idx);
            return;
        }
        if (r < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (c.outbound && !c.endpoint.empty())
                outbound_fd_by_endpoint_.erase(c.endpoint);
            close(c.fd);
            peers_fd_.erase(peers_fd_.begin() + idx);
            return;
        }
        c.rx_buf.insert(c.rx_buf.end(), buf, buf + r);
        if (c.rx_buf.size() > (WireMaxPayloadBytes() * 2))
        {
            if (c.outbound && !c.endpoint.empty())
                outbound_fd_by_endpoint_.erase(c.endpoint);
            close(c.fd);
            peers_fd_.erase(peers_fd_.begin() + idx);
            return;
        }
    }

    while (true)
    {
        std::vector<uint8_t> framed;
        if (!ParseOneFrame(&c.rx_buf, &framed))
            break;
        WireEnvelope env;
        if (!ParseWireEnvelope(framed, &env))
            continue;
        if (env.magic != WireMagicMainnet() || env.version != 1)
            continue;
        if (!c.saw_hello)
        {
            const uint64_t now_ms = NowMs();
            if (now_ms > c.hello_deadline_ms)
            {
                if (c.outbound && !c.endpoint.empty())
                    outbound_fd_by_endpoint_.erase(c.endpoint);
                close(c.fd);
                peers_fd_.erase(peers_fd_.begin() + idx);
                return;
            }
            if (env.msg_type != WIRE_MSG_HELLO || env.payload.size() != 32)
            {
                if (c.outbound && !c.endpoint.empty())
                    outbound_fd_by_endpoint_.erase(c.endpoint);
                close(c.fd);
                peers_fd_.erase(peers_fd_.begin() + idx);
                return;
            }
            c.saw_hello = true;
        }
        if (on_message_)
            on_message_(c.fd, env);
    }
}

void P2PReactor::PollOnce()
{
    if (listen_fd_ < 0)
        return;

    ConnectPeersOnce();

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(listen_fd_, &rfds);
    int maxfd = listen_fd_;

    for (size_t i = 0; i < peers_fd_.size(); ++i)
    {
        FD_SET(peers_fd_[i].fd, &rfds);
        if (peers_fd_[i].fd > maxfd)
            maxfd = peers_fd_[i].fd;
    }

    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    int n = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    if (n <= 0)
        return;

    if (FD_ISSET(listen_fd_, &rfds))
        AcceptIncoming();

    for (size_t i = 0; i < peers_fd_.size();)
    {
        int fd = peers_fd_[i].fd;
        if (!FD_ISSET(fd, &rfds))
        {
            ++i;
            continue;
        }
        const size_t before = peers_fd_.size();
        OnPeerReadable(i);
        if (peers_fd_.size() < before)
            continue;
        ++i;
    }
}

void P2PReactor::CloseAll()
{
    if (listen_fd_ >= 0)
    {
        close(listen_fd_);
        listen_fd_ = -1;
    }
    for (size_t i = 0; i < peers_fd_.size(); ++i)
        close(peers_fd_[i].fd);
    peers_fd_.clear();
    outbound_fd_by_endpoint_.clear();
}

void P2PReactor::Stop()
{
    CloseAll();
}

}  // namespace drpow

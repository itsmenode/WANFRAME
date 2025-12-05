#include <fcntl.h>

#include "NetworkCore.hpp"
#include "../common/ByteBuffer.hpp"
#include "../common/protocol.hpp"

namespace net_ops::server
{
    int m_server_fd;
    int m_epoll_fd;
    int m_port;
    bool m_running;
    std::map<int, ClientContext> registry;

    void NetworkCore::NonBlockingMode(int fd){
        fcntl(fd, F_SETFL, O_NONBLOCK);
    }

    void NetworkCore::EpollControlAdd(int fd){
        epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd);
    }

    void NetworkCore::EpollControlRemove(int fd){
        epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd);
    }

    void NetworkCore::DisconnectClient(int fd);

    void NetworkCore::HandleNewConnection();
    void NetworkCore::HandleClientData(int fd);

    void NetworkCore::ProcessMessage(int fd, net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload);

    explicit NetworkCore::NetworkCore(int port);

    NetworkCore::~NetworkCore();

    void Init();
    void Run();
}
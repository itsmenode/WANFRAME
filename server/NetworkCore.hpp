#pragma once

#include <map>
#include <cstdint>
#include <iostream>
#include <sys/epoll.h>
#include <vector>

#include "../common/ByteBuffer.hpp"
#include "../common/protocol.hpp"

namespace net_ops::server
{
    struct ClientContext
    {
        int socketfd;
        net_ops::common::ByteBuffer buff;
    };

    class NetworkCore
    {
    private:
        int m_server_fd;
        int m_epoll_fd;
        int m_port;
        bool m_running;
        std::map<int, ClientContext> registry;

        void NonBlockingMode(int fd);
        void EpollControlAdd(int fd);
        void EpollControlRemove(int fd);
        void DisconnectClient(int fd);

        void HandleNewConnection();
        void HandleClientData(int fd);

        void ProcessMessage(int fd, net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload);

    public:
        explicit NetworkCore(int port);

        ~NetworkCore();

        void Init();
        void Run();
    };
}
#pragma once

#include <map>
#include <cstdint>
#include <iostream>
#include <sys/epoll.h>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../common/ByteBuffer.hpp"
#include "../common/protocol.hpp"

namespace net_ops::server
{
    struct ClientContext
    {
        int socketfd;
        net_ops::common::ByteBuffer buff;

        SSL* ssl_handle;
    };

    class NetworkCore
    {
    private:
        int m_server_fd;
        int m_epoll_fd;
        int m_port;
        bool m_running;
        std::map<int, ClientContext> registry;

        SSL_CTX* m_ssl_ctx;

        void LogOpenSSLErrors();

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
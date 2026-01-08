#pragma once

#include <map>
#include <cstdint>
#include <iostream>
#include <sys/epoll.h>
#include <vector>
#include <mutex>
#include <queue>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../common/ByteBuffer.hpp"
#include "../common/protocol.hpp"

namespace net_ops::server
{
    class Worker;
}

namespace net_ops::server
{
    struct OutgoingMessage
    {
        int client_fd;
        net_ops::protocol::Header header;
        std::vector<uint8_t> payload;
    };

    struct ClientContext
    {
        int socketfd;
        SSL *ssl_handle;
        net_ops::common::ByteBuffer buff;
        std::vector<uint8_t> out_buffer;
        bool is_handshake_complete;
    };

    class NetworkCore
    {
    private:
        int m_server_fd;
        int m_epoll_fd;
        int m_port;
        bool m_running;

        Worker *m_worker;

        std::map<int, ClientContext> registry;

        std::queue<OutgoingMessage> m_response_queue;
        std::mutex m_response_mutex;

        SSL_CTX *m_ssl_ctx;

        void LogOpenSSLErrors();

        void NonBlockingMode(int fd);
        void EpollControlAdd(int fd);
        void EpollControlRemove(int fd);

        void EpollControlMod(int fd, uint32_t events);

        void DisconnectClient(int fd);

        void HandleNewConnection();
        void HandleClientData(int fd);

        void SendPendingResponses();

        std::mutex m_registry_mutex;

    public:
        explicit NetworkCore(int port, Worker *worker);
        ~NetworkCore();

        void Init();
        void Run();

        void Stop() { m_running = false; }

        void QueueResponse(int client_fd, net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload);
        void BroadcastUpdate(net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload);
    };
}
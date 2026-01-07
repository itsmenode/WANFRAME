#pragma once

#include <map>
#include <cstdint>
#include <iostream>
#include <sys/epoll.h>
#include <vector>
#include <mutex>
#include <queue>
#include <sys/eventfd.h>
#include <atomic>

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
        bool is_handshake_complete;

        std::vector<uint8_t> out_buf;
        size_t out_off = 0;
        uint32_t epoll_events = EPOLLIN | EPOLLRDHUP;
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

        SSL_CTX *m_ssl_ctx;

        std::mutex m_registry_mutex;

        int m_wakeup_fd = -1;

        void EpollControlAdd(int fd, uint32_t events);
        void EpollControlMod(int fd, uint32_t events);

        void EnableWriteInterest(int fd);
        void DisableWriteInterest(int fd);

        void FlushClientWrites(int fd);

        void LogOpenSSLErrors();

        void NonBlockingMode(int fd);
        void EpollControlAdd(int fd);
        void EpollControlRemove(int fd);
        void DisconnectClient(int fd);

        void HandleNewConnection();
        void HandleClientData(int fd);

        void ProcessMessage(int fd, net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload);

        std::atomic_bool running_{false};
    public:
        explicit NetworkCore(int port, Worker *worker);
        ~NetworkCore();

        void Init();
        void Run();

        void Stop();

        void QueueResponse(int client_fd, net_ops::protocol::MessageType type, const std::string &data);
    };
}
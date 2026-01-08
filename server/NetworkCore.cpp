#include <fcntl.h>
#include <sys/epoll.h>
#include <cstring>
#include <unistd.h>
#include <stdexcept>
#include <sys/socket.h>
#include <stdio.h>
#include <iostream>
#include <netinet/in.h>

#include "NetworkCore.hpp"
#include "Worker.hpp"
#include "../common/ByteBuffer.hpp"
#include "../common/protocol.hpp"

namespace net_ops::server
{
    NetworkCore::NetworkCore(int port, Worker *worker)
        : m_port(port), m_worker(worker), m_server_fd(-1), m_epoll_fd(-1), m_running(false), m_ssl_ctx(nullptr)
    {
    }

    NetworkCore::~NetworkCore()
    {
        for (auto const &[fd, ctx] : registry)
        {
            if (ctx.ssl_handle)
            {
                SSL_shutdown(ctx.ssl_handle);
                SSL_free(ctx.ssl_handle);
            }
            close(fd);
        }
        registry.clear();

        if (m_server_fd != -1)
            close(m_server_fd);
        if (m_epoll_fd != -1)
            close(m_epoll_fd);
        if (m_ssl_ctx)
            SSL_CTX_free(m_ssl_ctx);
    }

    void NetworkCore::NonBlockingMode(int fd)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    void NetworkCore::EpollControlAdd(int fd)
    {
        struct epoll_event event;
        std::memset(&event, 0, sizeof(event));
        event.events = EPOLLIN | EPOLLET;
        event.data.fd = fd;
        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1)
            throw std::runtime_error("Failed to add FD to epoll");
    }

    void NetworkCore::EpollControlMod(int fd, uint32_t events)
    {
        struct epoll_event event;
        std::memset(&event, 0, sizeof(event));
        event.events = events;
        event.data.fd = fd;
        epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &event);
    }

    void NetworkCore::EpollControlRemove(int fd)
    {
        epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    }

    void NetworkCore::DisconnectClient(int fd)
    {
        if (registry.find(fd) == registry.end())
            return;

        EpollControlRemove(fd);
        if (registry[fd].ssl_handle)
        {
            SSL_shutdown(registry[fd].ssl_handle);
            SSL_free(registry[fd].ssl_handle);
        }
        close(fd);
        registry.erase(fd);
        std::cout << "[Server] Client " << fd << " disconnected." << std::endl;
    }

    void NetworkCore::HandleNewConnection()
    {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int client_fd = accept(m_server_fd, (struct sockaddr *)&clientAddr, &clientLen);

        if (client_fd == -1)
            return;

        NonBlockingMode(client_fd);

        ClientContext &ctx = registry[client_fd];
        ctx.socketfd = client_fd;
        ctx.is_handshake_complete = false;
        ctx.ssl_handle = SSL_new(m_ssl_ctx);
        SSL_set_fd(ctx.ssl_handle, client_fd);

        int ret = SSL_accept(ctx.ssl_handle);
        if (ret == 1)
        {
            ctx.is_handshake_complete = true;
            EpollControlAdd(client_fd);
        }
        else
        {
            int err = SSL_get_error(ctx.ssl_handle, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                EpollControlAdd(client_fd);
            }
            else
            {
                DisconnectClient(client_fd);
            }
        }
    }

    void NetworkCore::HandleClientData(int fd)
    {
        if (registry.find(fd) == registry.end())
            return;
        ClientContext &ctx = registry[fd];

        if (!ctx.is_handshake_complete)
        {
            int ret = SSL_accept(ctx.ssl_handle);
            if (ret == 1)
            {
                ctx.is_handshake_complete = true;
                std::cout << "[Server] TLS Handshake complete for client " << fd << std::endl;
            }
            else
            {
                int err = SSL_get_error(ctx.ssl_handle, ret);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                    DisconnectClient(fd);
                return;
            }
        }

        uint8_t temp[4096];
        bool connection_closed = false;
        while (true)
        {
            int bytes = SSL_read(ctx.ssl_handle, temp, sizeof(temp));
            if (bytes > 0)
            {
                ctx.buff.Append(temp, static_cast<size_t>(bytes));
            }
            else
            {
                int err = SSL_get_error(ctx.ssl_handle, bytes);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    break;
                connection_closed = true;
                break;
            }
        }

        if (connection_closed)
        {
            DisconnectClient(fd);
            return;
        }

        while (ctx.buff.HasHeader())
        {
            auto header = ctx.buff.PeekHeader();
            if (!ctx.buff.HasCompleteMessage(header))
                break;

            std::vector<uint8_t> payload = ctx.buff.ExtractPayload(header.payload_length);
            ctx.buff.Consume(net_ops::protocol::HEADER_SIZE + header.payload_length);

            if (m_worker)
                m_worker->AddJob(fd, static_cast<net_ops::protocol::MessageType>(header.msg_type), payload);
        }
    }

    void NetworkCore::SendPendingResponses()
    {
        std::lock_guard<std::mutex> lock(m_response_mutex);

        while (!m_response_queue.empty())
        {
            OutgoingMessage msg = m_response_queue.front();
            m_response_queue.pop();

            if (registry.find(msg.client_fd) == registry.end())
                continue;

            ClientContext &ctx = registry[msg.client_fd];
            std::vector<uint8_t> fullPacket(net_ops::protocol::HEADER_SIZE + msg.payload.size());
            net_ops::protocol::SerializeHeader(msg.header, fullPacket.data());
            std::memcpy(fullPacket.data() + net_ops::protocol::HEADER_SIZE, msg.payload.data(), msg.payload.size());

            ctx.out_buffer.insert(ctx.out_buffer.end(), fullPacket.begin(), fullPacket.end());
        }

        for (auto &[fd, ctx] : registry)
        {
            if (ctx.out_buffer.empty() || !ctx.is_handshake_complete)
                continue;

            int written = SSL_write(ctx.ssl_handle, ctx.out_buffer.data(), ctx.out_buffer.size());
            if (written > 0)
            {
                ctx.out_buffer.erase(ctx.out_buffer.begin(), ctx.out_buffer.begin() + written);
                
                if (ctx.out_buffer.empty()) {
                    EpollControlMod(fd, EPOLLIN | EPOLLET);
                }
            }
            else
            {
                int err = SSL_get_error(ctx.ssl_handle, written);
                if (err == SSL_ERROR_WANT_WRITE)
                {
                    EpollControlMod(fd, EPOLLIN | EPOLLOUT | EPOLLET);
                }
                else if (err != SSL_ERROR_WANT_READ)
                {
                    DisconnectClient(fd);
                }
            }
        }
    }

    void NetworkCore::Init()
    {
        SSL_library_init();
        m_ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (!m_ssl_ctx)
            throw std::runtime_error("SSL Context creation failed");

        if (SSL_CTX_use_certificate_file(m_ssl_ctx, "certs/server.crt", SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(m_ssl_ctx, "certs/server.key", SSL_FILETYPE_PEM) <= 0)
            throw std::runtime_error("Failed to load server certs/keys");

        m_server_fd = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(m_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(m_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(m_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
            throw std::runtime_error("Bind failed");

        listen(m_server_fd, SOMAXCONN);
        NonBlockingMode(m_server_fd);

        m_epoll_fd = epoll_create1(0);
        EpollControlAdd(m_server_fd);
    }

    void NetworkCore::Run()
    {
        m_running = true;
        struct epoll_event ev[128];
        while (m_running)
        {
            int count = epoll_wait(m_epoll_fd, ev, 128, 100);
            for (int i = 0; i < count; i++)
            {
                if (ev[i].data.fd == m_server_fd) {
                    HandleNewConnection();
                } else {
                    if (ev[i].events & EPOLLOUT) {
                        SendPendingResponses();
                    }
                    if (ev[i].events & EPOLLIN) {
                        HandleClientData(ev[i].data.fd);
                    }
                }
            }
            SendPendingResponses();
        }
    }

    void NetworkCore::QueueResponse(int client_fd, net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload)
    {
        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.version = net_ops::protocol::PROTOCOL_VERSION;
        header.msg_type = static_cast<uint8_t>(type);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        std::lock_guard<std::mutex> lock(m_response_mutex);
        m_response_queue.push({client_fd, header, payload});
    }
}
#include <fcntl.h>
#include <sys/epoll.h>
#include <cstring>
#include <unistd.h>
#include <stdexcept>
#include <sys/socket.h>
#include <stdio.h>
#include <iostream>

#include "NetworkCore.hpp"
#include "Worker.hpp"
#include "../common/ByteBuffer.hpp"
#include "../common/protocol.hpp"
#include <netinet/in.h>

namespace net_ops::server
{
    NetworkCore::NetworkCore(int port, Worker *worker)
    {
        m_port = port;
        m_worker = worker;
        m_server_fd = -1;
        m_epoll_fd = -1;
        m_running = false;
    }

    NetworkCore::~NetworkCore()
    {
        for (auto it : registry)
        {
            close(it.first);
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
        fcntl(fd, F_SETFL, O_NONBLOCK);
    }

    void NetworkCore::EpollControlAdd(int fd)
    {
        struct epoll_event event;
        std::memset(&event, 0, sizeof(event));
        event.events = EPOLLIN;
        event.data.fd = fd;

        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1)
        {
            throw std::runtime_error("Failed to add FD to epoll");
        }
    }

    void NetworkCore::EpollControlRemove(int fd)
    {
        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == -1)
        {
            std::cerr << "Warning: Failed to remove FD from epoll" << std::endl;
        }
    }

    void NetworkCore::DisconnectClient(int fd)
    {
        EpollControlRemove(fd);
        if (registry[fd].ssl_handle)
        {
            SSL_shutdown(registry[fd].ssl_handle);
            SSL_free(registry[fd].ssl_handle);
        }
        close(fd);
        registry.erase(fd);
    }

    void NetworkCore::HandleNewConnection()
    {
        struct sockaddr clientAddress;
        socklen_t clientAddressLength = sizeof(clientAddress);
        int m_client_fd = accept(m_server_fd, &clientAddress, &clientAddressLength);

        if (m_client_fd == -1)
            return;

        NonBlockingMode(m_client_fd);
        ClientContext &ctx = registry[m_client_fd];
        ctx.socketfd = m_client_fd;
        ctx.is_handshake_complete = false;

        SSL *ssl_handle = SSL_new(m_ssl_ctx);
        SSL_set_fd(ssl_handle, m_client_fd);
        ctx.ssl_handle = ssl_handle;

        int ret = SSL_accept(ssl_handle);
        if (ret == 1)
        {
            ctx.is_handshake_complete = true;
            EpollControlAdd(m_client_fd);
        }
        else
        {
            int err = SSL_get_error(ssl_handle, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                struct epoll_event event;
                event.data.fd = m_client_fd;
                event.events = EPOLLIN | EPOLLET;
                if (err == SSL_ERROR_WANT_WRITE)
                    event.events |= EPOLLOUT;
                epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_client_fd, &event);
            }
            else
                DisconnectClient(m_client_fd);
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

                struct epoll_event event;
                std::memset(&event, 0, sizeof(event));
                event.data.fd = fd;
                event.events = EPOLLIN | EPOLLET;
                epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &event);
            }
            else
            {
                int err = SSL_get_error(ctx.ssl_handle, ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                {
                    struct epoll_event event;
                    std::memset(&event, 0, sizeof(event));
                    event.data.fd = fd;
                    event.events = EPOLLIN | EPOLLET;
                    if (err == SSL_ERROR_WANT_WRITE)
                        event.events |= EPOLLOUT;
                    epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &event);
                    return;
                }
                else
                {
                    std::cerr << "[Server] SSL Handshake Failed for client " << fd << ". Error: " << err << std::endl;
                    DisconnectClient(fd);
                    return;
                }
            }
        }

        uint8_t temp_buffer[4096];
        while (true)
        {
            int count = SSL_read(ctx.ssl_handle, temp_buffer, sizeof(temp_buffer));
            if (count > 0)
            {
                ctx.buff.Append(temp_buffer, static_cast<size_t>(count));
            }
            else
            {
                int err = SSL_get_error(ctx.ssl_handle, count);
                if (err == SSL_ERROR_WANT_READ)
                    break;

                if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
                {
                    DisconnectClient(fd);
                    return;
                }
                break;
            }
        }

        while (ctx.buff.HasHeader())
        {
            auto header = ctx.buff.PeekHeader();
            if (!ctx.buff.HasCompleteMessage(header))
                break;

            std::vector<uint8_t> payload = ctx.buff.ExtractPayload(header.payload_length);
            ctx.buff.Consume(net_ops::protocol::HEADER_SIZE + header.payload_length);

            ProcessMessage(fd, static_cast<net_ops::protocol::MessageType>(header.msg_type), payload);
        }
    }

    void NetworkCore::ProcessMessage(int fd, net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload)
    {
        std::cout << "[Client " << fd << "] Dispatched Message Type: "
                  << static_cast<int>(type)
                  << " | Size: " << payload.size() << " bytes." << std::endl;

        if (m_worker)
        {
            m_worker->AddJob(fd, type, payload);
        }
    }

    void NetworkCore::Init()
    {
        m_ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (m_ssl_ctx == nullptr)
        {
            throw std::runtime_error("Failed to create SSL Context. Is OpenSSL installed?");
        }

        if (SSL_CTX_use_certificate_file(m_ssl_ctx, "certs/server.crt", SSL_FILETYPE_PEM) <= 0)
        {
            throw std::runtime_error("Failed to load 'certs/server.crt'. Check your paths!");
        }

        if (SSL_CTX_use_PrivateKey_file(m_ssl_ctx, "certs/server.key", SSL_FILETYPE_PEM) <= 0)
        {
            throw std::runtime_error("Failed to load 'certs/server.key'.");
        }

        if (!SSL_CTX_check_private_key(m_ssl_ctx))
        {
            throw std::runtime_error("Private Key does not match the Certificate!");
        }

        m_server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_server_fd == -1)
        {
            throw std::runtime_error("Failed to create socket.");
        }

        int opt = 1;
        if (setsockopt(m_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            throw std::runtime_error("Failed to set SO_REUSEADDR.");
        }

        NonBlockingMode(m_server_fd);

        struct sockaddr_in serverAddress;
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(m_port);
        serverAddress.sin_addr.s_addr = INADDR_ANY;

        if (bind(m_server_fd, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) != 0)
        {
            throw std::runtime_error("Failed to bind server socket. Is the port taken?");
        }

        if ((listen(m_server_fd, SOMAXCONN)) != 0)
        {
            throw std::runtime_error("Failed to listen server socket.");
        }

        m_epoll_fd = epoll_create1(0);
        if (m_epoll_fd == -1)
        {
            throw std::runtime_error("Failed to create epoll file descriptor.");
        }

        EpollControlAdd(m_server_fd);
    }

    void NetworkCore::Run()
    {
        m_running = true;
        struct epoll_event ev[128];

        while (m_running)
        {
            int count = epoll_wait(m_epoll_fd, ev, 128, 1000);

            if (count == -1)
            {
                if (errno == EINTR)
                    continue;
                break;
            }

            for (int i = 0; i < count; i++)
            {
                int current_fd = ev[i].data.fd;
                if (current_fd == m_server_fd)
                    HandleNewConnection();
                else
                    HandleClientData(current_fd);
            }

            SendPendingResponses();
        }

        std::cout << "[Network] Stopping event loop...\n";
    }

    void NetworkCore::QueueResponse(int client_fd, net_ops::protocol::MessageType type, const std::string &data)
    {
        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(type);
        header.payload_length = static_cast<uint32_t>(data.size());
        header.reserved = 0;

        std::vector<uint8_t> payload(data.begin(), data.end());

        {
            std::lock_guard<std::mutex> lock(m_response_mutex);
            m_response_queue.push({client_fd, header, payload});
        }
    }

    void NetworkCore::SendPendingResponses()
    {
        std::lock_guard<std::mutex> lock(m_response_mutex);

        while (!m_response_queue.empty())
        {
            OutgoingMessage msg = m_response_queue.front();
            if (registry.find(msg.client_fd) == registry.end())
            {
                m_response_queue.pop();
                continue;
            }

            ClientContext &ctx = registry[msg.client_fd];
            std::vector<uint8_t> fullPacket(net_ops::protocol::HEADER_SIZE + msg.payload.size());
            net_ops::protocol::SerializeHeader(msg.header, fullPacket.data());
            std::memcpy(fullPacket.data() + net_ops::protocol::HEADER_SIZE, msg.payload.data(), msg.payload.size());

            ctx.out_buffer.insert(ctx.out_buffer.end(), fullPacket.begin(), fullPacket.end());
            m_response_queue.pop();
        }

        for (auto &[fd, ctx] : registry)
        {
            if (ctx.out_buffer.empty() || !ctx.is_handshake_complete)
                continue;

            int written = SSL_write(ctx.ssl_handle, ctx.out_buffer.data(), ctx.out_buffer.size());
            if (written > 0)
            {
                ctx.out_buffer.erase(ctx.out_buffer.begin(), ctx.out_buffer.begin() + written);
            }
            else
            {
                int err = SSL_get_error(ctx.ssl_handle, written);
                if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ)
                {
                    DisconnectClient(fd);
                }
            }
        }
    }
}
#include <fcntl.h>
#include <sys/epoll.h>
#include <cstring>
#include <unistd.h>
#include <stdexcept>
#include <sys/socket.h>
#include <stdio.h>
#include <iostream>
#include <algorithm>
#include <errno.h>

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

    void NetworkCore::EpollControlAdd(int fd, uint32_t events)
    {
        epoll_event event{};
        event.events = events;
        event.data.fd = fd;

        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1)
            throw std::runtime_error("Failed to add FD to epoll");
    }

    void NetworkCore::EpollControlMod(int fd, uint32_t events)
    {
        epoll_event event{};
        event.events = events;
        event.data.fd = fd;

        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &event) == -1)
            std::cerr << "Warning: Failed to mod FD in epoll\n";
    }

    void NetworkCore::EpollControlRemove(int fd)
    {
        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == -1)
        {
            std::cerr << "Warning: Failed to remove FD from epoll" << std::endl;
        }
    }

    void NetworkCore::EnableWriteInterest(int fd)
    {
        std::lock_guard<std::mutex> lock(m_registry_mutex);
        auto it = registry.find(fd);
        if (it == registry.end())
            return;

        uint32_t want = it->second.epoll_events | EPOLLOUT;
        if (want != it->second.epoll_events)
        {
            it->second.epoll_events = want;
            EpollControlMod(fd, want);
        }
    }

    void NetworkCore::DisableWriteInterest(int fd)
    {
        std::lock_guard<std::mutex> lock(m_registry_mutex);
        auto it = registry.find(fd);
        if (it == registry.end())
            return;

        uint32_t want = it->second.epoll_events & ~EPOLLOUT;
        if (want != it->second.epoll_events)
        {
            it->second.epoll_events = want;
            EpollControlMod(fd, want);
        }
    }

    void NetworkCore::DisconnectClient(int fd)
    {
        EpollControlRemove(fd);

        std::lock_guard<std::mutex> lock(m_registry_mutex);
        auto it = registry.find(fd);
        if (it == registry.end())
            return;

        if (it->second.ssl_handle)
        {
            SSL_shutdown(it->second.ssl_handle);
            SSL_free(it->second.ssl_handle);
        }
        close(fd);
        registry.erase(it);
    }

    void NetworkCore::HandleNewConnection()
    {
        struct sockaddr clientAddress;
        socklen_t clientAddressLength = sizeof(clientAddress);
        int m_client_fd = accept(m_server_fd, static_cast<struct sockaddr *>(&clientAddress), &clientAddressLength);
        if (m_client_fd == -1)
        {
            throw std::runtime_error("Failed to accept client connection.");
        }

        NonBlockingMode(m_client_fd);
        registry[m_client_fd].socketfd = m_client_fd;

        SSL *ssl_handle = SSL_new(m_ssl_ctx);
        if (!ssl_handle)
        {
            close(m_client_fd);
            throw std::runtime_error("Failed to allocate new SSL session.");
        }

        SSL_set_fd(ssl_handle, m_client_fd);
        registry[m_client_fd].ssl_handle = ssl_handle;

        int ret = SSL_accept(ssl_handle);
        if (ret == 1)
        {
            registry[m_client_fd].is_handshake_complete = true;
            registry[m_client_fd].epoll_events = EPOLLIN | EPOLLRDHUP;
            EpollControlAdd(m_client_fd, registry[m_client_fd].epoll_events);
            std::cout << "[Server] New connection accepted and Handshake COMPLETE: " << m_client_fd << "\n";
        }
        else
        {
            int ssl_error = SSL_get_error(ssl_handle, ret);

            registry[m_client_fd].is_handshake_complete = false;
            registry[m_client_fd].epoll_events = EPOLLIN | EPOLLRDHUP;

            if (ssl_error == SSL_ERROR_WANT_WRITE)
                registry[m_client_fd].epoll_events |= EPOLLOUT;

            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
            {
                EpollControlAdd(m_client_fd, registry[m_client_fd].epoll_events);
                std::cout << "[Server] New connection accepted, Handshake PENDING: " << m_client_fd << "\n";
            }
            else
            {
                std::cerr << "[Server] Fatal SSL Handshake Error on " << m_client_fd << " err=" << ssl_error << "\n";
                close(m_client_fd);
            }
        }
    }

    void NetworkCore::HandleClientData(int fd)
    {
        ClientContext &ctx = registry[fd];

        if (ctx.is_handshake_complete == false)
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
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                {
                    return;
                }
                else
                {
                    std::cerr << "SSL Handshake Failed. Error: " << err << std::endl;
                    DisconnectClient(fd);
                    return;
                }
            }
        }

        uint8_t temp_buffer[4096];

        while (true)
        {
            ssize_t count = SSL_read(ctx.ssl_handle, temp_buffer, sizeof(temp_buffer));

            if (count > 0)
            {
                ctx.buff.Append(temp_buffer, count);
            }
            else
            {
                int err = SSL_get_error(ctx.ssl_handle, count);

                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    break;
                else if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL)
                {
                    DisconnectClient(fd);
                    return;
                }
                else
                {
                    DisconnectClient(fd);
                    return;
                }
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

        m_wakeup_fd = eventfd(0, EFD_NONBLOCK);
        if (m_wakeup_fd == -1)
            throw std::runtime_error("eventfd failed");

        epoll_event wev{};
        wev.events = EPOLLIN;
        wev.data.fd = m_wakeup_fd;

        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_wakeup_fd, &wev) == -1)
            throw std::runtime_error("Failed to add wakeup fd to epoll");

        EpollControlAdd(m_server_fd, EPOLLIN);
    }

    void NetworkCore::Run()
    {
        m_running = true;

        std::cout << "Server started on port " << m_port << "..." << std::endl;

        struct epoll_event ev[128];
        int count = 0;

        running_ = true;
        while (running_)
        {
            if ((count = epoll_wait(m_epoll_fd, ev, 128, 10)) == -1)
            {
                if (errno == EINTR)
                    continue;
                else
                    break;
            }

            for (int i = 0; i < count; i++)
            {
                int fd = ev[i].data.fd;
                uint32_t events = ev[i].events;

                if (fd == m_wakeup_fd)
                {
                    uint64_t val;
                    while (read(m_wakeup_fd, &val, sizeof(val)) == sizeof(val))
                    {
                    }

                    std::vector<int> to_flush;
                    {
                        std::lock_guard<std::mutex> lock(m_registry_mutex);
                        to_flush.reserve(registry.size());
                        for (auto &[cfd, ctx] : registry)
                        {
                            if (!ctx.out_buf.empty() && ctx.out_off < ctx.out_buf.size())
                                to_flush.push_back(cfd);
                        }
                    }

                    for (int cfd : to_flush)
                        FlushClientWrites(cfd);

                    continue;
                }

                if (fd == m_server_fd)
                {
                    HandleNewConnection();
                    continue;
                }

                if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))
                {
                    DisconnectClient(fd);
                    continue;
                }

                if (events & EPOLLOUT)
                    FlushClientWrites(fd);

                if (events & EPOLLIN)
                    HandleClientData(fd);
            }
        }
    }

    void NetworkCore::QueueResponse(int client_fd, net_ops::protocol::MessageType type, const std::string &data)
    {
        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(type);
        header.payload_length = static_cast<uint32_t>(data.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        std::vector<uint8_t> packet;
        packet.insert(packet.end(), headerBuf, headerBuf + net_ops::protocol::HEADER_SIZE);
        packet.insert(packet.end(), data.begin(), data.end());

        {
            std::lock_guard<std::mutex> lock(m_registry_mutex);
            auto it = registry.find(client_fd);
            if (it == registry.end())
                return;

            it->second.out_buf.insert(it->second.out_buf.end(), packet.begin(), packet.end());
        }

        EnableWriteInterest(client_fd);

        uint64_t one = 1;
        (void)write(m_wakeup_fd, &one, sizeof(one));
    }

    void NetworkCore::FlushClientWrites(int fd)
    {
        SSL *ssl = nullptr;

        while (true)
        {
            std::vector<uint8_t> chunk;
            size_t already_sent = 0;
            bool handshake_done = false;

            {
                std::lock_guard<std::mutex> lock(m_registry_mutex);
                auto it = registry.find(fd);
                if (it == registry.end())
                    return;

                ssl = it->second.ssl_handle;
                handshake_done = it->second.is_handshake_complete;

                if (!handshake_done)
                {
                    int ret = SSL_accept(ssl);
                    if (ret == 1)
                    {
                        it->second.is_handshake_complete = true;
                    }
                    else
                    {
                        int err = SSL_get_error(ssl, ret);
                        if (err == SSL_ERROR_WANT_READ)
                        {
                            DisableWriteInterest(fd);
                            return;
                        }
                        if (err == SSL_ERROR_WANT_WRITE)
                        {
                            EnableWriteInterest(fd);
                            return;
                        }

                        goto fatal_disconnect;
                    }
                }

                if (it->second.out_off >= it->second.out_buf.size())
                {
                    it->second.out_buf.clear();
                    it->second.out_off = 0;
                    DisableWriteInterest(fd);
                    return;
                }

                size_t remaining = it->second.out_buf.size() - it->second.out_off;
                size_t to_send = std::min<size_t>(remaining, 16 * 1024);

                chunk.assign(it->second.out_buf.begin() + it->second.out_off,
                             it->second.out_buf.begin() + it->second.out_off + to_send);

                already_sent = it->second.out_off;
            }

            int n = SSL_write(ssl, chunk.data(), static_cast<int>(chunk.size()));
            if (n > 0)
            {
                std::lock_guard<std::mutex> lock(m_registry_mutex);
                auto it = registry.find(fd);
                if (it == registry.end())
                    return;

                it->second.out_off = already_sent + static_cast<size_t>(n);

                continue;
            }
            else
            {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_WRITE)
                {
                    EnableWriteInterest(fd);
                    return;
                }
                if (err == SSL_ERROR_WANT_READ)
                {
                    DisableWriteInterest(fd);
                    return;
                }

                goto fatal_disconnect;
            }
        }

    fatal_disconnect:
        std::cerr << "[Server] Disconnecting client " << fd << " due to SSL_write/handshake fatal error\n";
        DisconnectClient(fd);
    }

    void NetworkCore::Stop()
    {
        running_ = false;

        if (m_wakeup_fd != -1)
        {
            uint64_t one = 1;
            (void)write(m_wakeup_fd, &one, sizeof(one));
        }
    }

}
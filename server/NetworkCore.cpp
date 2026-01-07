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
            std::cout << "[Server] New connection accepted and Handshake COMPLETE: " << m_client_fd << std::endl;
            EpollControlAdd(m_client_fd);
        }
        else
        {
            int ssl_error = SSL_get_error(ssl_handle, ret);
            if (ssl_error == SSL_ERROR_WANT_READ)
            {
                registry[m_client_fd].is_handshake_complete = false;
                EpollControlAdd(m_client_fd);
                std::cout << "[Server] New connection accepted, Handshake PENDING: " << m_client_fd << std::endl;
            }
            else
            {
                std::cerr << "[Server] Fatal SSL Handshake Error on " << m_client_fd << ". Disconnecting." << std::endl;
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

        EpollControlAdd(m_server_fd);
    }

    void NetworkCore::Run()
    {
        m_running = true;

        std::cout << "Server started on port " << m_port << "..." << std::endl;

        struct epoll_event ev[128];
        int count = 0;
        while (m_running)
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
                int m_current_fd = ev[i].data.fd;
                if (m_current_fd == m_server_fd)
                    HandleNewConnection();
                else
                    HandleClientData(m_current_fd);
            }

            SendPendingResponses();
        }
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
            m_response_queue.pop();

            if (registry.find(msg.client_fd) == registry.end())
            {
                continue;
            }

            SSL *ssl = registry[msg.client_fd].ssl_handle;
            if (!ssl)
                continue;

            uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
            net_ops::protocol::SerializeHeader(msg.header, headerBuf);

            int written = SSL_write(ssl, headerBuf, sizeof(headerBuf));
            if (written <= 0)
            {
                continue;
            }

            if (msg.header.payload_length > 0)
            {
                SSL_write(ssl, msg.payload.data(), msg.payload.size());
            }

            std::cout << "[Server] Sent response to Client " << msg.client_fd << "\n";
        }
    }
}
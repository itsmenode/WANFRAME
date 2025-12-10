#include <fcntl.h>
#include <sys/epoll.h>
#include <cstring>
#include <unistd.h>
#include <stdexcept>
#include <sys/socket.h>
#include <stdio.h>
#include <iostream>

#include "NetworkCore.hpp"
#include "../common/ByteBuffer.hpp"
#include "../common/protocol.hpp"
#include <netinet/in.h>

namespace net_ops::server
{

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
        close(fd);
        registry.erase(fd);
        if (registry[fd].ssl_handle)
        {
            SSL_shutdown(registry[fd].ssl_handle);
            SSL_free(registry[fd].ssl_handle);
        }
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
            std::cout << "[Server] New connection accepted: and Handshake COMPLETE: " << m_client_fd << std::endl;

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

                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) break;
                else if (err == SSL_ERROR_ZERO_RETURN) {
                    DisconnectClient(fd);
                    return;
                }
                else {
                    DisconnectClient(fd);
                    return;
                }
            }
        }

        while (ctx.buff.HasHeader()) {
            auto header = ctx.buff.PeekHeader();
            if (!ctx.buff.HasCompleteMessage(header)) break;

            std::vector<uint8_t> payload = ctx.buff.ExtractPayload(header.payload_length);
            ctx.buff.Consume(net_ops::protocol::HEADER_SIZE + header.payload_length);
            
            ProcessMessage(fd, static_cast<net_ops::protocol::MessageType>(header.msg_type), payload);

        }
    }

    void NetworkCore::ProcessMessage(int fd, net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload)
    {

        using namespace net_ops::protocol;

        std::cout << "[Client " << fd << "] Received Message Type: "
                  << static_cast<int>(type)
                  << " | Size: " << payload.size() << " bytes." << std::endl;

        switch (type)
        {
        case MessageType::Test:
            break;

        case MessageType::LoginReq:
        {
            std::string user_data(payload.begin(), payload.end());
            std::cout << " -> Login Attempt Data: " << user_data << std::endl;

            std::string response_text = "AUTH_SUCCESS_PHASE_1";
            std::vector<uint8_t> resp_payload(response_text.begin(), response_text.end());

            Header resp_header;
            resp_header.magic = EXPECTED_MAGIC;
            resp_header.msg_type = static_cast<uint8_t>(MessageType::LoginResp);
            resp_header.payload_length = static_cast<uint32_t>(resp_payload.size());
            resp_header.reserved = 0;

            uint8_t header_buf[HEADER_SIZE];
            SerializeHeader(resp_header, header_buf);

            send(fd, header_buf, HEADER_SIZE, 0);
            send(fd, resp_payload.data(), resp_payload.size(), 0);

            std::cout << " -> Sent LoginResp." << std::endl;

            break;
        }
        case MessageType::LoginResp:
            break;
        case MessageType::LogoutReq:
            break;
        case MessageType::LogoutResp:
            break;
        case MessageType::SignupReq:
            break;
        case MessageType::SignupResp:
            break;

        case MessageType::HeartbeatReq:
            break;
        case MessageType::HeartbeatResp:
            break;

        case MessageType::DeviceReportReq:
        {
            std::cout << " -> Received Device Report. (Not implemented in Phase 1)" << std::endl;
            break;
        }
        case MessageType::DeviceReportResp:
            break;

        case MessageType::GroupListReq:
            break;
        case MessageType::GroupListResp:
            break;
        case MessageType::GroupCreateReq:
            break;
        case MessageType::GroupCreateResp:
            break;
        case MessageType::GroupDeleteReq:
            break;
        case MessageType::GroupDeleteResp:
            break;
        case MessageType::GroupUpdateReq:
            break;
        case MessageType::GroupUpdateResp:
            break;
        case MessageType::GroupMembershipSetReq:
            break;
        case MessageType::GroupMembershipSetResp:
            break;

        case MessageType::LogQueryReq:
            break;
        case MessageType::LogQueryResp:
            break;
        case MessageType::LiveLogSubscribeReq:
            break;
        case MessageType::LiveLogSubscribeResp:
            break;
        case MessageType::LiveLogEvent:
            break;

        case MessageType::ErrorResp:
            break;

        default:
            std::cout << " -> Unknown or Unhandled Message Type." << std::endl;
            break;
        }
    }

    NetworkCore::NetworkCore(int port)
    {
        m_port = port;
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

        std::cout << "Server started on port 8080..." << std::endl;

        struct epoll_event ev[128];
        int count = 0;
        while (m_running)
        {
            if ((count = epoll_wait(m_epoll_fd, ev, 128, -1)) == -1)
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
        }
    }
}
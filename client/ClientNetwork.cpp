#include "ClientNetwork.hpp"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <vector>

namespace net_ops::client
{
    ClientNetwork::ClientNetwork(std::string host, int port)
        : m_host(host), m_port(port), m_socket_fd(-1), m_ssl_ctx(nullptr), m_ssl_handle(nullptr)
    {
        InitSSL();
    }

    ClientNetwork::~ClientNetwork()
    {
        Disconnect();
        CleanupSSL();
    }

    void ClientNetwork::InitSSL()
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        m_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (SSL_CTX_load_verify_locations(m_ssl_ctx, "certs/ca.crt", nullptr) <= 0)
        {
            std::cerr << "[Client] Warning: Could not load certs/ca.crt." << std::endl;
        }
        SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, nullptr);
    }

    void ClientNetwork::CleanupSSL() { if (m_ssl_ctx) SSL_CTX_free(m_ssl_ctx); }

    bool ClientNetwork::Connect()
    {
        m_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(m_port);
        inet_pton(AF_INET, m_host.c_str(), &serv_addr.sin_addr);

        if (connect(m_socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
            return false;

        m_ssl_handle = SSL_new(m_ssl_ctx);
        SSL_set_fd(m_ssl_handle, m_socket_fd);
        if (SSL_connect(m_ssl_handle) <= 0) return false;

        return true;
    }

    void ClientNetwork::Disconnect()
    {
        if (m_ssl_handle) { SSL_shutdown(m_ssl_handle); SSL_free(m_ssl_handle); m_ssl_handle = nullptr; }
        if (m_socket_fd != -1) { close(m_socket_fd); m_socket_fd = -1; }
        m_in_buffer.Consume(m_in_buffer.Size());
    }

    void ClientNetwork::SendRequest(net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload)
    {
        if (!m_ssl_handle) return;
        net_ops::protocol::Header h = {net_ops::protocol::EXPECTED_MAGIC, net_ops::protocol::PROTOCOL_VERSION, (uint8_t)type, (uint32_t)payload.size(), 0};
        uint8_t buf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(h, buf);
        SSL_write(m_ssl_handle, buf, sizeof(buf));
        if (!payload.empty()) SSL_write(m_ssl_handle, payload.data(), payload.size());
    }

    std::optional<NetworkResponse> ClientNetwork::ReceiveResponseAsObject()
    {
        if (!m_ssl_handle) return std::nullopt;

        if (m_in_buffer.HasHeader()) {
            auto h = m_in_buffer.PeekHeader();
            if (m_in_buffer.HasCompleteMessage(h)) {
                NetworkResponse r = {(net_ops::protocol::MessageType)h.msg_type, (h.msg_type != (uint8_t)net_ops::protocol::MessageType::ErrorResp), m_in_buffer.ExtractPayload(h.payload_length)};
                m_in_buffer.Consume(net_ops::protocol::HEADER_SIZE + h.payload_length);
                return r;
            }
        }

        uint8_t tmp[4096];
        int r = SSL_read(m_ssl_handle, tmp, sizeof(tmp));
        if (r > 0) {
            m_in_buffer.Append(tmp, r);
            return ReceiveResponseAsObject();
        } else {
            int e = SSL_get_error(m_ssl_handle, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) Disconnect();
            return std::nullopt;
        }
    }
}
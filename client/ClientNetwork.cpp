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
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();

        m_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!m_ssl_ctx)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_NONE, nullptr);
    }

    void ClientNetwork::CleanupSSL()
    {
        if (m_ssl_ctx)
        {
            SSL_CTX_free(m_ssl_ctx);
            m_ssl_ctx = nullptr;
        }
    }

    bool ClientNetwork::Connect()
    {
        m_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_socket_fd < 0)
        {
            perror("Socket creation failed");
            return false;
        }

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(m_port);

        if (inet_pton(AF_INET, m_host.c_str(), &serv_addr.sin_addr) <= 0)
        {
            std::cerr << "Invalid address or Host not found" << std::endl;
            return false;
        }

        if (connect(m_socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            perror("Connection failed");
            return false;
        }

        m_ssl_handle = SSL_new(m_ssl_ctx);
        SSL_set_fd(m_ssl_handle, m_socket_fd);

        if (SSL_connect(m_ssl_handle) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }

        std::cout << "[Client] Connected to Server via SSL." << std::endl;
        return true;
    }

    void ClientNetwork::Disconnect()
    {
        if (m_ssl_handle)
        {
            SSL_shutdown(m_ssl_handle);
            SSL_free(m_ssl_handle);
            m_ssl_handle = nullptr;
        }
        if (m_socket_fd != -1)
        {
            close(m_socket_fd);
            m_socket_fd = -1;
        }
    }

    void ClientNetwork::AppendString(std::vector<uint8_t> &buffer, const std::string &str)
    {
        uint32_t len = static_cast<uint32_t>(str.length());

        uint8_t *pLen = reinterpret_cast<uint8_t *>(&len);
        buffer.insert(buffer.end(), pLen, pLen + 4);

        buffer.insert(buffer.end(), str.begin(), str.end());
    }

    bool ClientNetwork::SendLogin(const std::string &username, const std::string &password)
    {
        std::vector<uint8_t> payload;
        AppendString(payload, username);
        AppendString(payload, password);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::LoginReq);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0)
            return false;
        if (SSL_write(m_ssl_handle, payload.data(), payload.size()) <= 0)
            return false;

        return true;
    }

    bool ClientNetwork::SendRegister(const std::string &username, const std::string &password)
    {
        std::vector<uint8_t> payload;
        AppendString(payload, username);
        AppendString(payload, password);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::SignupReq);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0)
            return false;
        if (SSL_write(m_ssl_handle, payload.data(), payload.size()) <= 0)
            return false;

        return true;
    }

    bool ClientNetwork::SendCreateGroup(const std::string &groupName)
    {
        if (!m_ssl_handle)
            return false;

        std::vector<uint8_t> payload;
        AppendString(payload, groupName);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::GroupCreateReq);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0)
            return false;

        if (payload.size() > 0)
        {
            if (SSL_write(m_ssl_handle, payload.data(), payload.size()) <= 0)
                return false;
        }

        return true;
    }

    bool ClientNetwork::SendListGroups()
    {
        if (!m_ssl_handle)
            return false;

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::GroupListReq);
        header.payload_length = 0;
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0)
            return false;

        return true;
    }

    void ClientNetwork::ReceiveResponse()
    {
        if (!m_ssl_handle)
            return;

        net_ops::protocol::Header header;
        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];

        int bytesRead = SSL_read(m_ssl_handle, headerBuf, sizeof(headerBuf));

        if (bytesRead <= 0)
        {
            std::cerr << "[Client] Server disconnected.\n";
            Disconnect();
            return;
        }
        header = net_ops::protocol::DeserializeHeader(headerBuf);

        if (header.magic != net_ops::protocol::EXPECTED_MAGIC)
        {
            std::cerr << "[Client] Error: Invalid Protocol Magic Number.\n";
            return;
        }

        std::vector<uint8_t> payload;
        if (header.payload_length > 0)
        {
            payload.resize(header.payload_length);
            int total = 0;
            while (total < header.payload_length)
            {
                int n = SSL_read(m_ssl_handle, payload.data() + total, header.payload_length - total);
                if (n <= 0)
                    break;
                total += n;
            }
        }

        std::string msg(payload.begin(), payload.end());

        std::cout << "[Server Reply] " << msg << "\n";

        if (msg.find("SUCCESS") != std::string::npos)
        {
            std::cout << "\n>>> ACCESS GRANTED <<<\n\n";
        }
        else
        {
            std::cout << "\n>>> ACCESS DENIED <<<\n\n";
        }
    }
}
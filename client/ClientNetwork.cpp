#include "ClientNetwork.hpp"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <vector>
#include <iomanip>

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
        if (!m_ssl_ctx)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_load_verify_locations(m_ssl_ctx, "certs/ca.crt", nullptr) <= 0)
        {
            std::cerr << "[Client] Warning: Could not load certs/ca.crt for verification." << std::endl;
        }
        SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, nullptr);
    }

    void ClientNetwork::CleanupSSL()
    {
        if (m_ssl_ctx)
            SSL_CTX_free(m_ssl_ctx);
    }

    bool ClientNetwork::Connect()
    {
        m_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_socket_fd < 0)
            return false;

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(m_port);
        if (inet_pton(AF_INET, m_host.c_str(), &serv_addr.sin_addr) <= 0)
            return false;

        if (connect(m_socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
            return false;

        m_ssl_handle = SSL_new(m_ssl_ctx);
        SSL_set_fd(m_ssl_handle, m_socket_fd);

        if (SSL_connect(m_ssl_handle) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }

        X509 *cert = SSL_get_peer_certificate(m_ssl_handle);
        if (cert)
        {
            long res = SSL_get_verify_result(m_ssl_handle);
            if (res != X509_V_OK)
                return false;
            X509_free(cert);
        }
        else
        {
            return false;
        }

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
        m_in_buffer.Consume(m_in_buffer.Size());
    }

    void ClientNetwork::SendRequest(net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload)
    {
        if (!m_ssl_handle)
            return;

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.version = net_ops::protocol::PROTOCOL_VERSION;
        header.msg_type = static_cast<uint8_t>(type);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf));
        
        if (!payload.empty())
            SSL_write(m_ssl_handle, payload.data(), payload.size());
    }

    std::optional<NetworkResponse> ClientNetwork::ReceiveResponseAsObject()
    {
        if (!m_ssl_handle)
            return std::nullopt;

        if (m_in_buffer.HasHeader())
        {
            auto hdr = m_in_buffer.PeekHeader();
            if (m_in_buffer.HasCompleteMessage(hdr))
            {
                NetworkResponse resp;
                resp.type = static_cast<net_ops::protocol::MessageType>(hdr.msg_type);
                resp.success = (resp.type != net_ops::protocol::MessageType::ErrorResp);
                resp.data = m_in_buffer.ExtractPayload(hdr.payload_length);
                m_in_buffer.Consume(net_ops::protocol::HEADER_SIZE + hdr.payload_length);
                return resp;
            }
        }

        uint8_t temp[4096];
        int bytesRead = SSL_read(m_ssl_handle, temp, sizeof(temp));
        if (bytesRead <= 0)
        {
            int err = SSL_get_error(m_ssl_handle, bytesRead);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                return std::nullopt;
            return std::nullopt;
        }

        m_in_buffer.Append(temp, static_cast<size_t>(bytesRead));

        if (m_in_buffer.HasHeader())
        {
            auto hdr = m_in_buffer.PeekHeader();
            if (m_in_buffer.HasCompleteMessage(hdr))
            {
                NetworkResponse resp;
                resp.type = static_cast<net_ops::protocol::MessageType>(hdr.msg_type);
                resp.success = (resp.type != net_ops::protocol::MessageType::ErrorResp);
                resp.data = m_in_buffer.ExtractPayload(hdr.payload_length);
                m_in_buffer.Consume(net_ops::protocol::HEADER_SIZE + hdr.payload_length);

                if (resp.type == net_ops::protocol::MessageType::LoginResp)
                {
                    std::string msg(resp.data.begin(), resp.data.end());
                    if (msg.find("LOGIN_SUCCESS:") == 0)
                        m_session_token = msg.substr(14);
                }
                return resp;
            }
        }

        return std::nullopt;
    }

    bool ClientNetwork::SendLogin(const std::string &username, const std::string &password)
    {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, username);
        net_ops::protocol::PackString(payload, password);
        SendRequest(net_ops::protocol::MessageType::LoginReq, payload);
        return true;
    }

    bool ClientNetwork::SendLogout()
    {
        if (!m_ssl_handle || m_session_token.empty())
            return true;
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, m_session_token);
        SendRequest(net_ops::protocol::MessageType::LogoutReq, payload);
        m_session_token.clear();
        return true;
    }

    bool ClientNetwork::SendRegister(const std::string &username, const std::string &password)
    {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, username);
        net_ops::protocol::PackString(payload, password);
        SendRequest(net_ops::protocol::MessageType::SignupReq, payload);
        return true;
    }

    void ClientNetwork::SendAddDevice(const std::string &name, const std::string &ip, const std::string &mac)
    {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, m_session_token);
        net_ops::protocol::PackString(payload, name);
        net_ops::protocol::PackString(payload, ip);
        net_ops::protocol::PackString(payload, mac);
        SendRequest(net_ops::protocol::MessageType::DeviceAddReq, payload);
    }

    bool ClientNetwork::SendListDevices()
    {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, m_session_token);
        SendRequest(net_ops::protocol::MessageType::DeviceListReq, payload);
        return true;
    }

    bool ClientNetwork::SendLogUpload(const std::string &source_ip, const std::string &log_msg)
    {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, m_session_token);
        net_ops::protocol::PackString(payload, source_ip);
        net_ops::protocol::PackString(payload, log_msg);
        SendRequest(net_ops::protocol::MessageType::LogUploadReq, payload);
        return true;
    }

    bool ClientNetwork::SendStatusUpdate(const std::string &ip, const std::string &status, const std::string &info)
    {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, m_session_token);
        net_ops::protocol::PackString(payload, ip);
        net_ops::protocol::PackString(payload, status);
        net_ops::protocol::PackString(payload, info);
        SendRequest(net_ops::protocol::MessageType::DeviceStatusReq, payload);
        return true;
    }

    void ClientNetwork::SendFetchLogs(int device_id)
    {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, m_session_token);
        net_ops::protocol::PackUint32(payload, static_cast<uint32_t>(device_id));
        SendRequest(net_ops::protocol::MessageType::LogQueryReq, payload);
    }

    bool ClientNetwork::ReceiveResponse() { return ReceiveResponseAsObject().has_value(); }
}
#include "ClientNetwork.hpp"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <vector>
#include <fcntl.h>
#include <openssl/x509v3.h>

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
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        m_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!m_ssl_ctx) {
            std::cerr << "[ClientNetwork] Failed to create SSL Context\n";
            return;
        }

        SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_load_verify_locations(m_ssl_ctx, "certs/server.crt", "certs") != 1) {
            std::cerr << "[ClientNetwork] Failed to load trusted certificates.\n";
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(m_ssl_ctx);
            m_ssl_ctx = nullptr;
            return;
        }
    }

    void ClientNetwork::CleanupSSL()
    {
        if (m_ssl_ctx) { SSL_CTX_free(m_ssl_ctx); m_ssl_ctx = nullptr; }
    }

    bool ClientNetwork::Connect()
    {
        if (m_socket_fd != -1) return true;
        if (!m_ssl_ctx) return false;

        m_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_socket_fd < 0) return false;

        struct sockaddr_in serv_addr;
        std::memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(m_port);
        
        if (inet_pton(AF_INET, m_host.c_str(), &serv_addr.sin_addr) <= 0) { 
            std::cerr << "[ClientNetwork] Invalid address/Address not supported: " << m_host << "\n";
            close(m_socket_fd); 
            return false; 
        }

        if (connect(m_socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { 
            close(m_socket_fd); 
            m_socket_fd = -1;
            return false; 
        }

        m_ssl_handle = SSL_new(m_ssl_ctx);
        if (!m_ssl_handle) { close(m_socket_fd); m_socket_fd = -1; return false; }
        SSL_set_fd(m_ssl_handle, m_socket_fd);
        struct in_addr addr4;
        struct in6_addr addr6;
        bool is_ipv4 = inet_pton(AF_INET, m_host.c_str(), &addr4) == 1;
        bool is_ipv6 = inet_pton(AF_INET6, m_host.c_str(), &addr6) == 1;

        if (!is_ipv4 && !is_ipv6) {
            SSL_set_tlsext_host_name(m_ssl_handle, m_host.c_str());
            SSL_set_hostflags(m_ssl_handle, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (SSL_set1_host(m_ssl_handle, m_host.c_str()) != 1) {
                std::cerr << "[ClientNetwork] Failed to set expected host for verification.\n";
                Disconnect();
                return false;
            }
        } else if (SSL_set1_ip_asc(m_ssl_handle, m_host.c_str()) != 1) {
            std::cerr << "[ClientNetwork] Failed to set expected IP for verification.\n";
            Disconnect();
            return false;
        }

        if (SSL_connect(m_ssl_handle) <= 0) { 
            ERR_print_errors_fp(stderr); 
            Disconnect(); 
            return false; 
        }
        if (SSL_get_verify_result(m_ssl_handle) != X509_V_OK) {
            std::cerr << "[ClientNetwork] Server certificate verification failed.\n";
            Disconnect();
            return false;
        }

        int flags = fcntl(m_socket_fd, F_GETFL, 0);
        fcntl(m_socket_fd, F_SETFL, flags | O_NONBLOCK);

        std::cout << "[ClientNetwork] Connected to " << m_host << ":" << m_port << "\n";
        return true;
    }

    void ClientNetwork::Disconnect()
    {
        if (m_ssl_handle) { SSL_shutdown(m_ssl_handle); SSL_free(m_ssl_handle); m_ssl_handle = nullptr; }
        if (m_socket_fd != -1) { close(m_socket_fd); m_socket_fd = -1; }
        m_in_buffer.Consume(999999);
    }

    void ClientNetwork::SendRequest(net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload)
    {
        if (!IsConnected()) return;

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.version = net_ops::protocol::PROTOCOL_VERSION;
        header.msg_type = static_cast<uint8_t>(type);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        std::vector<uint8_t> packet(net_ops::protocol::HEADER_SIZE);
        net_ops::protocol::SerializeHeader(header, packet.data());
        packet.insert(packet.end(), payload.begin(), payload.end());

        size_t total = packet.size();
        size_t sent = 0;
        while (sent < total)
        {
            int ret = SSL_write(m_ssl_handle, packet.data() + sent, total - sent);
            if (ret <= 0) {
                int err = SSL_get_error(m_ssl_handle, ret);
                if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ) {
                    std::cerr << "[ClientNetwork] Write error, disconnecting.\n";
                    Disconnect();
                    return;
                }
                usleep(1000); 
                continue;
            }
            sent += ret;
        }
    }


    bool ClientNetwork::SendLogin(const std::string &username, const std::string &password)
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, username);
        net_ops::protocol::PackString(p, password);
        SendRequest(net_ops::protocol::MessageType::LoginReq, p);
        return true;
    }

    bool ClientNetwork::SendRegister(const std::string &username, const std::string &password)
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, username);
        net_ops::protocol::PackString(p, password);
        SendRequest(net_ops::protocol::MessageType::SignupReq, p);
        return true;
    }

    void ClientNetwork::SendAddDevice(const std::string &token, const std::string &name, const std::string &ip, const std::string &mac)
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, token);
        net_ops::protocol::PackString(p, name);
        net_ops::protocol::PackString(p, ip);
        net_ops::protocol::PackString(p, mac);
        SendRequest(net_ops::protocol::MessageType::DeviceAddReq, p);
    }

    bool ClientNetwork::SendListDevices(const std::string &token)
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, token);
        SendRequest(net_ops::protocol::MessageType::DeviceListReq, p);
        return true;
    }

    bool ClientNetwork::SendLogUpload(const std::string &token, const std::string &source_ip, const std::string &log_msg)
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, token);
        net_ops::protocol::PackString(p, source_ip);
        net_ops::protocol::PackString(p, log_msg);
        SendRequest(net_ops::protocol::MessageType::LogUploadReq, p);
        return true;
    }

    bool ClientNetwork::SendStatusUpdate(const std::string &token, const std::string &ip, const std::string &status, const std::string &info)
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, token);
        net_ops::protocol::PackString(p, ip);
        net_ops::protocol::PackString(p, status);
        net_ops::protocol::PackString(p, info);
        SendRequest(net_ops::protocol::MessageType::DeviceStatusReq, p);
        return true;
    }

    void ClientNetwork::SendFetchLogs(const std::string &token, int device_id)
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, token);
        net_ops::protocol::PackUint32(p, static_cast<uint32_t>(device_id));
        SendRequest(net_ops::protocol::MessageType::LogQueryReq, p);
    }

    bool ClientNetwork::SendLogout(const std::string &token)
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, token);
        SendRequest(net_ops::protocol::MessageType::LogoutReq, p);
        return true;
    }

    bool ClientNetwork::ReceiveResponse()
    {
        auto resp = ReceiveResponseAsObject();
        return resp.has_value();
    }

    std::optional<NetworkResponse> ClientNetwork::ReceiveResponseAsObject()
    {
        if (!m_ssl_handle) return std::nullopt;

        if (m_in_buffer.HasHeader()) {
            auto h = m_in_buffer.PeekHeader();
            if (m_in_buffer.HasCompleteMessage(h)) {
                NetworkResponse r;
                r.type = (net_ops::protocol::MessageType)h.msg_type;
                r.success = (h.msg_type != (uint8_t)net_ops::protocol::MessageType::ErrorResp);
                r.data = m_in_buffer.ExtractPayload(h.payload_length);
                m_in_buffer.Consume(net_ops::protocol::HEADER_SIZE + h.payload_length);
                return r;
            }
        }

        uint8_t tmp[4096];
        while (true) {
            int r = SSL_read(m_ssl_handle, tmp, sizeof(tmp));
            if (r > 0) {
                m_in_buffer.Append(tmp, r);
                if (m_in_buffer.HasHeader()) {
                    auto h = m_in_buffer.PeekHeader();
                    if (m_in_buffer.HasCompleteMessage(h)) {
                        NetworkResponse resp;
                        resp.type = (net_ops::protocol::MessageType)h.msg_type;
                        resp.success = (h.msg_type != (uint8_t)net_ops::protocol::MessageType::ErrorResp);
                        resp.data = m_in_buffer.ExtractPayload(h.payload_length);
                        m_in_buffer.Consume(net_ops::protocol::HEADER_SIZE + h.payload_length);
                        return resp;
                    }
                }
            } else {
                int e = SSL_get_error(m_ssl_handle, r);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return std::nullopt;
                Disconnect();
                return std::nullopt;
            }
        }
    }
}

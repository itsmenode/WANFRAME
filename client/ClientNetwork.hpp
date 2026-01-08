#pragma once

#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../common/protocol.hpp"
#include "../common/ByteBuffer.hpp"

namespace net_ops::client
{
    struct NetworkResponse
    {
        net_ops::protocol::MessageType type;
        bool success;
        std::vector<uint8_t> data;
    };

    class ClientNetwork
    {
    private:
        std::string m_host;
        int m_port;
        int m_socket_fd;
        
        std::mutex m_sendMutex;

        SSL_CTX *m_ssl_ctx;
        SSL *m_ssl_handle;

        net_ops::common::ByteBuffer m_in_buffer;

        void InitSSL();
        void CleanupSSL();

    public:
        ClientNetwork(std::string host, int port);
        ~ClientNetwork();

        bool Connect();
        void Disconnect();
        bool IsConnected() const { return m_socket_fd != -1 && m_ssl_handle != nullptr; }
        SSL *GetSSLHandle() const { return m_ssl_handle; }

        bool SendLogin(const std::string &username, const std::string &password);
        bool SendRegister(const std::string &username, const std::string &password);

        bool SendLogout(const std::string &token);
        void SendAddDevice(const std::string &token, const std::string &name, const std::string &ip, const std::string &mac);
        bool SendListDevices(const std::string &token);
        bool SendLogUpload(const std::string &token, const std::string &source_ip, const std::string &log_msg);
        bool SendStatusUpdate(const std::string &token, const std::string &ip, const std::string &status, const std::string &info);
        void SendFetchLogs(const std::string &token, int device_id);

        void SendRequest(net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload);

        bool ReceiveResponse();
        std::optional<NetworkResponse> ReceiveResponseAsObject();
    };
}

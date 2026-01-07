#pragma once

#include <string>
#include <vector>
#include <optional>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../common/protocol.hpp"

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
        std::string m_session_token;
        SSL_CTX *m_ssl_ctx;
        SSL *m_ssl_handle;
        void InitSSL();
        void CleanupSSL();

    public:
        ClientNetwork(std::string host, int port);
        ~ClientNetwork();

        bool Connect();
        void Disconnect();
        SSL *GetSSLHandle() const { return m_ssl_handle; }

        bool SendLogout();
        bool SendLogin(const std::string &username, const std::string &password);
        bool SendRegister(const std::string &username, const std::string &password);

        void SendRequest(net_ops::protocol::MessageType type, const std::vector<uint8_t> &payload);
        void SendAddDevice(const std::string &name, const std::string &ip, const std::string &mac);
        bool SendListDevices();
        bool SendLogUpload(const std::string &source_ip, const std::string &log_msg);
        bool SendStatusUpdate(const std::string &ip, const std::string &status, const std::string &info);
        void SendFetchLogs(int device_id);

        bool ReceiveResponse();
        std::optional<NetworkResponse> ReceiveResponseAsObject();
    };
}
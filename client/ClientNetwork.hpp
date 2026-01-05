#pragma once

#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../common/protocol.hpp"

namespace net_ops::client
{
    class ClientNetwork
    {
    private:
        std::string m_host;
        int m_port;
        int m_socket_fd;
        
        std::string m_session_token;
        
        SSL_CTX* m_ssl_ctx;
        SSL* m_ssl_handle;

        void InitSSL();
        void CleanupSSL();
        
        void AppendString(std::vector<uint8_t>& buffer, const std::string& str);

    public:
        ClientNetwork(std::string host, int port);
        ~ClientNetwork();

        bool Connect();
        void Disconnect();

        bool SendLogin(const std::string& username, const std::string& password);
        bool SendRegister(const std::string& username, const std::string& password);
        
        bool SendCreateGroup(const std::string& groupName);
        bool SendListGroups();

        bool ReceiveResponse(); 
    };
}
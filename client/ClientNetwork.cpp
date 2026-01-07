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

    bool ClientNetwork::SendCreateGroup(const std::string& groupName)
    {
        if (!m_ssl_handle) return false;

        if (m_session_token.empty()) {
            std::cerr << "[Client] Error: No session token. Please login first.\n";
            return false;
        }

        std::vector<uint8_t> payload;
        
        AppendString(payload, m_session_token);
        
        AppendString(payload, groupName);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::GroupCreateReq);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0) return false;
        if (SSL_write(m_ssl_handle, payload.data(), payload.size()) <= 0) return false;

        return true;
    }

    bool ClientNetwork::SendListGroups()
    {
        if (!m_ssl_handle) return false;

        if (m_session_token.empty()) {
            std::cerr << "[Client] Error: No session token.\n";
            return false;
        }

        std::vector<uint8_t> payload;
        AppendString(payload, m_session_token);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::GroupListReq);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0) return false;
        if (SSL_write(m_ssl_handle, payload.data(), payload.size()) <= 0) return false;

        return true;
    }

    bool ClientNetwork::SendAddMember(int groupId, const std::string& username)
    {
        if (!m_ssl_handle) return false;

        if (m_session_token.empty()) {
            std::cerr << "[Client] Error: No session token.\n";
            return false;
        }

        std::vector<uint8_t> payload;
        
        AppendString(payload, m_session_token);

        size_t currentSize = payload.size();
        payload.resize(currentSize + 4);
        std::memcpy(payload.data() + currentSize, &groupId, 4);

        AppendString(payload, username);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::GroupAddMemberReq);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0) return false;
        if (SSL_write(m_ssl_handle, payload.data(), payload.size()) <= 0) return false;

        return true;
    }

    bool ClientNetwork::SendAddDevice(const std::string& name, const std::string& ip, int groupId)
    {
        if (!m_ssl_handle) return false;

        if (m_session_token.empty()) {
            std::cerr << "[Client] Error: No session token.\n";
            return false;
        }

        std::vector<uint8_t> payload;

        AppendString(payload, m_session_token);

        size_t currentSize = payload.size();
        payload.resize(currentSize + 4);
        std::memcpy(payload.data() + currentSize, &groupId, 4);

        AppendString(payload, name);

        AppendString(payload, ip);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::DeviceAddReq);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0) return false;
        if (SSL_write(m_ssl_handle, payload.data(), payload.size()) <= 0) return false;

        return true;
    }

    bool ClientNetwork::SendListDevices()
    {
        if (!m_ssl_handle) return false;

        std::vector<uint8_t> payload;
        AppendString(payload, m_session_token);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::DeviceListReq);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0) return false;
        if (SSL_write(m_ssl_handle, payload.data(), payload.size()) <= 0) return false;

        return true;
    }

    bool ClientNetwork::SendLogUpload(const std::string& source_ip, const std::string& log_msg) {
        if (!m_ssl_handle) return false;
        
        std::vector<uint8_t> payload;
        AppendString(payload, m_session_token);
        AppendString(payload, source_ip);
        AppendString(payload, log_msg);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::LogUploadReq);
        header.payload_length = static_cast<uint32_t>(payload.size());
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        if (SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf)) <= 0) return false;
        if (SSL_write(m_ssl_handle, payload.data(), payload.size()) <= 0) return false;
        
        return true;
    }

    bool ClientNetwork::SendStatusUpdate(const std::string& ip, const std::string& status, const std::string& info) {
        
        if (!m_ssl_handle) return false;

        std::vector<uint8_t> payload;
        AppendString(payload, m_session_token);
        AppendString(payload, ip);
        AppendString(payload, status);
        AppendString(payload, info);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::DeviceStatusReq);
        header.payload_length = payload.size();
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf));
        SSL_write(m_ssl_handle, payload.data(), payload.size());
        
        return true;
    }

    void ClientNetwork::SendFetchLogs(int device_id) {
        if (!m_ssl_handle) return;
        
        std::vector<uint8_t> payload;
        
        uint32_t tokenLen = htonl(static_cast<uint32_t>(m_session_token.length()));
        
        const uint8_t* lenBytes = reinterpret_cast<const uint8_t*>(&tokenLen);
        payload.insert(payload.end(), lenBytes, lenBytes + 4);
        
        payload.insert(payload.end(), m_session_token.begin(), m_session_token.end());
        
        uint32_t netId = htonl(static_cast<uint32_t>(device_id));
        const uint8_t* idBytes = reinterpret_cast<const uint8_t*>(&netId);
        payload.insert(payload.end(), idBytes, idBytes + 4);

        net_ops::protocol::Header header;
        header.magic = net_ops::protocol::EXPECTED_MAGIC;
        header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::LogQueryReq);
        header.payload_length = payload.size();
        header.reserved = 0;

        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];
        net_ops::protocol::SerializeHeader(header, headerBuf);

        SSL_write(m_ssl_handle, headerBuf, sizeof(headerBuf));
        SSL_write(m_ssl_handle, payload.data(), payload.size());
        
        std::cout << "[Client Debug] Sent LogQueryReq. TokenLen: " << m_session_token.length() 
                  << " DevID: " << device_id << " Total Payload: " << payload.size() << "\n";
    }

    bool ClientNetwork::ReceiveResponse()
    {
        if (!m_ssl_handle) return false;

        net_ops::protocol::Header header;
        uint8_t headerBuf[net_ops::protocol::HEADER_SIZE];

        int bytesRead = SSL_read(m_ssl_handle, headerBuf, sizeof(headerBuf));
        if (bytesRead <= 0) {
            std::cerr << "[Client] Server disconnected.\n";
            Disconnect();
            return false;
        }

        header = net_ops::protocol::DeserializeHeader(headerBuf);

        std::vector<uint8_t> body;
        if (header.payload_length > 0) {
            body.resize(header.payload_length);
            int total = 0;
            while (total < header.payload_length) {
                int n = SSL_read(m_ssl_handle, body.data() + total, header.payload_length - total);
                if (n <= 0) break; 
                total += n;
            }
        }

        if (header.msg_type == static_cast<uint8_t>(net_ops::protocol::MessageType::ErrorResp)) {
            std::string errMsg(body.begin(), body.end());
            std::cout << "[Server Error] " << errMsg << "\n";
            return false;
        }

        if (header.msg_type == static_cast<uint8_t>(net_ops::protocol::MessageType::DeviceListResp)) {
            std::string list(body.begin(), body.end());
            if (list == "NO_DEVICES") {
                std::cout << "No devices found.\n";
                return true;
            }

            std::cout << "\n--- DEVICE LIST ---\n";
            std::cout << std::left << std::setw(5) << "ID" 
                      << std::setw(20) << "NAME" 
                      << std::setw(16) << "IP" 
                      << std::setw(10) << "STATUS" 
                      << std::setw(30) << "INFO" 
                      << "\n";
            std::cout << "--------------------------------------------------------------------------------\n";

            size_t pos = 0;
            while ((pos = list.find(',')) != std::string::npos) {
                std::string token = list.substr(0, pos);
                
                std::vector<std::string> parts;
                size_t partPos = 0;
                while ((partPos = token.find(':')) != std::string::npos) {
                    parts.push_back(token.substr(0, partPos));
                    token.erase(0, partPos + 1);
                }
                parts.push_back(token);

                if (parts.size() >= 6) { 
                     std::cout << std::left << std::setw(5) << parts[0]
                               << std::setw(20) << parts[1]
                               << std::setw(16) << parts[2]
                               << std::setw(10) << parts[3]
                               << std::setw(30) << parts[5]
                               << "\n";
                }
                list.erase(0, pos + 1);
            }
            std::cout << "\n";
            return true;
        }

        if (header.msg_type == static_cast<uint8_t>(net_ops::protocol::MessageType::LogQueryResp)) {
            size_t offset = 0;
            if (offset + 4 > body.size()) { std::cout << "[Info] No logs found.\n"; return true; }
            
            uint32_t netCount = 0;
            std::memcpy(&netCount, &body[offset], 4);
            int count = static_cast<int>(ntohl(netCount));
            offset += 4;

            std::cout << "\n--- DEVICE LOGS (" << count << ") ---\n";
            std::cout << std::left << std::setw(22) << "TIMESTAMP" << " | MESSAGE\n";
            std::cout << "-----------------------+-----------------------------------\n";

            for(int i=0; i<count; i++) {
                if (offset + 4 > body.size()) break;
                uint32_t tsLen = 0; std::memcpy(&tsLen, &body[offset], 4); tsLen = ntohl(tsLen); offset += 4;
                if (offset + tsLen > body.size()) break;
                std::string ts(body.begin() + offset, body.begin() + offset + tsLen); offset += tsLen;

                if (offset + 4 > body.size()) break;
                uint32_t msgLen = 0; std::memcpy(&msgLen, &body[offset], 4); msgLen = ntohl(msgLen); offset += 4;
                if (offset + msgLen > body.size()) break;
                std::string msg(body.begin() + offset, body.begin() + offset + msgLen); offset += msgLen;

                std::cout << std::left << std::setw(22) << ts << " | " << msg << "\n";
            }
            std::cout << "\n";
            return true;
        }

        std::string msg(body.begin(), body.end());
        std::cout << "[Server Reply] " << msg << "\n";

        if (msg.find("LOGIN_SUCCESS:") == 0) {
            m_session_token = msg.substr(14);
            return true;
        }

        if (msg.find("LOGIN_FAILURE") != std::string::npos || 
            msg.find("AUTH_FAILED") != std::string::npos) {
            return false;
        }
        
        return true; 
    }
}
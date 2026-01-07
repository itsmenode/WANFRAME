#include "ClientNetwork.hpp"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <vector>
#include <fcntl.h>

namespace net_ops::client
{

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

        int flags = fcntl(m_socket_fd, F_GETFL, 0);
        fcntl(m_socket_fd, F_SETFL, flags | O_NONBLOCK);

        return true;
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
            } 
            else {
                int e = SSL_get_error(m_ssl_handle, r);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                    return std::nullopt; 
                }
                
                Disconnect();
                return std::nullopt;
            }
        }
    }
}
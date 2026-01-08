#include "SnmpClient.hpp"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>

namespace net_ops::client {

    SnmpClient::SnmpClient() {
        m_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        setsockopt(m_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    }

    SnmpClient::~SnmpClient() {
        if (m_sockfd >= 0) close(m_sockfd);
    }

    void SnmpClient::AppendTLV(std::vector<uint8_t>& buf, uint8_t type, const std::vector<uint8_t>& value) {
        buf.push_back(type);
        buf.push_back(static_cast<uint8_t>(value.size())); 
        buf.insert(buf.end(), value.begin(), value.end());
    }

    void SnmpClient::AppendInteger(std::vector<uint8_t>& buf, int value) {
        std::vector<uint8_t> valBytes;
        valBytes.push_back(static_cast<uint8_t>(value)); 
        AppendTLV(buf, 0x02, valBytes); 
    }

    void SnmpClient::AppendString(std::vector<uint8_t>& buf, const std::string& str) {
        std::vector<uint8_t> valBytes(str.begin(), str.end());
        AppendTLV(buf, 0x04, valBytes); 
    }

    std::vector<uint8_t> SnmpClient::GetSysDescrOID() { return {0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}; }
    std::vector<uint8_t> SnmpClient::GetSysUpTimeOID() { return {0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00}; }

    long SnmpClient::GetUptime(const std::string& ip, const std::string& community) {
        struct sockaddr_in servaddr;
        std::memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(161);
        inet_pton(AF_INET, ip.c_str(), &servaddr.sin_addr);

        std::vector<uint8_t> pdu_body, var_bind, seq_content, whole_packet;
        
        AppendInteger(pdu_body, 0);
        AppendInteger(pdu_body, 0);
        AppendInteger(pdu_body, 0);

        std::vector<uint8_t> oid = GetSysUpTimeOID();
        seq_content.push_back(0x06);
        seq_content.push_back(oid.size());
        seq_content.insert(seq_content.end(), oid.begin(), oid.end());
        seq_content.push_back(0x05);
        seq_content.push_back(0x00); 

        AppendTLV(var_bind, 0x30, seq_content); 
        AppendTLV(pdu_body, 0x30, var_bind);

        AppendInteger(whole_packet, 1);
        AppendString(whole_packet, community); 
        AppendTLV(whole_packet, 0xA0, pdu_body);

        std::vector<uint8_t> final_packet;
        AppendTLV(final_packet, 0x30, whole_packet); 

        sendto(m_sockfd, final_packet.data(), final_packet.size(), 0, (const struct sockaddr*)&servaddr, sizeof(servaddr));

        uint8_t buffer[1024];
        socklen_t len = sizeof(servaddr);
        ssize_t n = recvfrom(m_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&servaddr, &len);

        if (n > 0) {
            for (size_t i = 0; i < n - 6; ++i) {
                if (buffer[i] == 0x43) { 
                    int len = buffer[i+1];
                    long ticks = 0;
                    for(int j=0; j<len; ++j) ticks = (ticks << 8) | buffer[i+2+j];
                    return ticks;
                }
            }
        }
        return -1;
    }

    DeviceStats SnmpClient::QueryDevice(const std::string& ip, const std::string& community) {
        DeviceStats stats; stats.ip = ip; stats.success = false; stats.description = "Unknown";
        return stats;
    }
}
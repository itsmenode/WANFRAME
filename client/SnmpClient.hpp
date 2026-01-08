#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace net_ops::client {

    struct DeviceStats {
        std::string ip;
        bool success;
        std::string description;
    };

    class SnmpClient {
    public:
        SnmpClient();
        ~SnmpClient();

        DeviceStats QueryDevice(const std::string& ip, const std::string& community = "public");
        long GetUptime(const std::string& ip, const std::string& community = "public");

    private:
        int m_sockfd;
        void AppendTLV(std::vector<uint8_t>& buf, uint8_t type, const std::vector<uint8_t>& value);
        void AppendInteger(std::vector<uint8_t>& buf, int value);
        void AppendString(std::vector<uint8_t>& buf, const std::string& str);
        std::vector<uint8_t> GetSysDescrOID();
        std::vector<uint8_t> GetSysUpTimeOID();
    };
}
#pragma once
#include <string>
#include <vector>

namespace net_ops::client {

    struct ScannedHost {
        std::string ip;
        std::string mac;
        std::string name;
        bool is_alive;
    };

    class NetworkScanner {
    public:

        static std::string GetMacFromArp(const std::string& target_ip);

        static std::vector<ScannedHost> ScanLocalNetwork();

        static std::string GetSubnetFromIP(const std::string& ip);
        
        static std::string GetLocalIPAddress();

        static bool Ping(const std::string& ip);
    };
}
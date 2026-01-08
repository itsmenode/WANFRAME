#pragma once

#include <string>
#include <vector>

namespace net_ops::client
{
    struct ScannedHost
    {
        std::string ip;
        std::string mac;
        std::string name;
    };

    class NetworkScanner
    {
    public:
        static std::vector<ScannedHost> ScanLocalNetwork();
    };
}
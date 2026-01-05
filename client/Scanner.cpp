#include "Scanner.hpp"
#include <iostream>
#include <cstdlib>

#define PING_CMD "ping -c 1 -W 1 "

namespace net_ops::client {

    bool NetworkScanner::Ping(const std::string& ip) {
        std::string command = std::string(PING_CMD) + ip + " > /dev/null 2>&1";
        
        int result = std::system(command.c_str());
        
        if (result == -1) return false;
        return (WEXITSTATUS(result) == 0);
    }

    std::vector<ScannedHost> NetworkScanner::ScanSubnet(const std::string& base_ip) {
        std::vector<ScannedHost> found_hosts;
        
        std::cout << "[Scanner] Sweeping " << base_ip << ".1 - .254 ...\n";

        for (int i = 1; i < 255; ++i) {
            std::string target = base_ip + "." + std::to_string(i);
            
            if (Ping(target)) {
                std::cout << "\r[Scanner] Found active host: " << target << "      \n";
                ScannedHost host;
                host.ip = target;
                host.name = "Linux Device";
                host.is_alive = true;
                found_hosts.push_back(host);
            } else {
                std::cout << "\rScanning: " << target << std::flush;
            }
        }
        std::cout << "\n[Scanner] Scan complete. Found " << found_hosts.size() << " devices.\n";
        return found_hosts;
    }
}
#include "Scanner.hpp"
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <array>
#include <algorithm>

#include <ifaddrs.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <net/if.h>

namespace net_ops::client {

    std::string NetworkScanner::GetLocalIPAddress() {
        struct ifaddrs *ifap, *ifa;
        std::string local_ip = "";

        if (getifaddrs(&ifap) == -1) {
            return "";
        }

        for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;

            if (ifa->ifa_addr->sa_family == AF_INET) {
                if (std::string(ifa->ifa_name) == "lo") continue;

                void* addr_ptr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, addr_ptr, buf, INET_ADDRSTRLEN);

                local_ip = buf;
                break;
            }
        }

        freeifaddrs(ifap);
        return local_ip;
    }

    std::string NetworkScanner::GetSubnetFromIP(const std::string& ip) {
        size_t last_dot = ip.find_last_of('.');
        if (last_dot == std::string::npos) return "";
        return ip.substr(0, last_dot);
    }

    bool NetworkScanner::Ping(const std::string& ip) {
        if (ip.empty()) return false;

        std::string command = "ping -c 1 -W 1 " + ip + " | grep 'bytes from' > /dev/null 2>&1";
        
        int result = std::system(command.c_str());
        
        return (result == 0);
    }

    std::vector<ScannedHost> NetworkScanner::ScanLocalNetwork() {
        std::vector<ScannedHost> found_hosts;

        std::string my_ip = GetLocalIPAddress();
        if (my_ip.empty()) {
            std::cerr << "[Scanner] Could not detect local IP.\n";
            return found_hosts;
        }

        std::string subnet = GetSubnetFromIP(my_ip);
        std::cout << "[Scanner] Detected Local IP: " << my_ip << "\n";
        std::cout << "[Scanner] Scanning Subnet:   " << subnet << ".1 - .254\n";

        for (int i = 1; i < 255; ++i) {
            std::string target = subnet + "." + std::to_string(i);
            
            if (target == my_ip) continue;

            std::cout << "\rScanning: " << target << "   " << std::flush;

            if (Ping(target)) {
                std::cout << "\r\033[K"; 
                std::cout << "[Scanner] FOUND: " << target << "\n";
                
                ScannedHost host;
                host.ip = target;
                host.name = "Discovered Device";
                host.is_alive = true;
                found_hosts.push_back(host);
            }
        }
        std::cout << "\r\033[K[Scanner] Scan complete. Found " << found_hosts.size() << " devices.\n";
        return found_hosts;
    }
}
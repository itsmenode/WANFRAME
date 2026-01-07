#include "Scanner.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <future>
#include <mutex>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <vector>
#include <cstdlib>

namespace net_ops::client
{
    std::string NetworkScanner::GetLocalIPAddress() {
        struct ifaddrs *ifap, *ifa;
        std::string local_ip = "";
        if (getifaddrs(&ifap) == -1) return "";
        for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                if (std::string(ifa->ifa_name) == "lo") continue;
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, buf, INET_ADDRSTRLEN);
                local_ip = buf;
                break;
            }
        }
        freeifaddrs(ifap);
        return local_ip;
    }

    std::string NetworkScanner::GetSubnetFromIP(const std::string &ip) {
        size_t last_dot = ip.find_last_of('.');
        return (last_dot == std::string::npos) ? "" : ip.substr(0, last_dot);
    }

    bool NetworkScanner::Ping(const std::string &ip) {
        if (ip.empty()) return false;
        std::string command = "ping -c 1 -W 0.2 " + ip + " > /dev/null 2>&1";
        return (std::system(command.c_str()) == 0);
    }

    std::string NetworkScanner::GetMacFromArp(const std::string &target_ip) {
        std::ifstream arpFile("/proc/net/arp");
        if (!arpFile.is_open()) return "00:00:00:00:00:00";
        
        std::string line;
        std::getline(arpFile, line);
        while (std::getline(arpFile, line)) {
            std::stringstream ss(line);
            std::string ip, hw, fl, mac, msk, dev;
            if (ss >> ip >> hw >> fl >> mac >> msk >> dev && ip == target_ip) {
                return mac;
            }
        }
        return "00:00:00:00:00:00";
    }

    std::vector<ScannedHost> NetworkScanner::ScanLocalNetwork() {
        std::vector<ScannedHost> hosts;
        std::mutex mtx;
        std::string my_ip = GetLocalIPAddress();
        std::string subnet = GetSubnetFromIP(my_ip);
        
        if (subnet.empty()) {
            std::cerr << "[Scanner] Could not determine subnet for IP: " << my_ip << std::endl;
            return hosts;
        }

        std::cout << "[Scanner] Starting parallel scan on " << subnet << ".0/24" << std::endl;

        std::vector<std::future<void>> tasks;
        for (int i = 1; i < 255; ++i) {
            std::string target = subnet + "." + std::to_string(i);
            
            tasks.push_back(std::async(std::launch::async, [target, &hosts, &mtx]() {
                if (Ping(target)) {
                    std::string mac = GetMacFromArp(target);
                    std::lock_guard<std::mutex> lock(mtx);
                    hosts.push_back({target, mac, "Discovered Device", true});
                }
            }));
        }

        for (auto &t : tasks) {
            t.get();
        }

        std::cout << "[Scanner] Scan finished. Found " << hosts.size() << " active devices." << std::endl;
        return hosts;
    }
}
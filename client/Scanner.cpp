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
#include <thread>
#include <chrono>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

namespace net_ops::client
{
    std::string GetInterfaceMac(const std::string &ifaceName) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return "00:00:00:00:00:00";
        
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, ifaceName.c_str(), IFNAMSIZ - 1);
        
        std::string macStr = "00:00:00:00:00:00";
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
            unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
            char buf[18];
            std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            macStr = std::string(buf);
        }
        close(fd);
        return macStr;
    }

    void GetLocalInfo(std::string &ip_out, std::string &iface_out) {
        struct ifaddrs *ifap, *ifa;
        ip_out = "";
        iface_out = "";
        if (getifaddrs(&ifap) == -1) return;
        
        for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                if (std::string(ifa->ifa_name) == "lo") continue;
                
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, buf, INET_ADDRSTRLEN);
                ip_out = buf;
                iface_out = ifa->ifa_name;
                break;
            }
        }
        freeifaddrs(ifap);
    }

    std::string NetworkScanner::GetLocalIPAddress() {
        std::string ip, iface;
        GetLocalInfo(ip, iface);
        return ip;
    }

    std::string NetworkScanner::GetSubnetFromIP(const std::string &ip) {
        size_t last_dot = ip.find_last_of('.');
        return (last_dot == std::string::npos) ? "" : ip.substr(0, last_dot);
    }

    bool NetworkScanner::Ping(const std::string &ip) {
        if (ip.empty()) return false;
        std::string command = "ping -c 1 -W 0.5 -n " + ip + " > /dev/null 2>&1";
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
            if (ss >> ip >> hw >> fl >> mac >> msk >> dev) {
                if (ip == target_ip) {
                    if (fl == "0x0" || mac == "00:00:00:00:00:00") return "00:00:00:00:00:00";
                    return mac;
                }
            }
        }
        return "00:00:00:00:00:00";
    }

    std::vector<ScannedHost> NetworkScanner::ScanLocalNetwork() {
        std::vector<ScannedHost> hosts;
        std::mutex mtx;
        
        std::string my_ip, my_iface;
        GetLocalInfo(my_ip, my_iface);
        
        std::string subnet = GetSubnetFromIP(my_ip);
        if (subnet.empty()) return hosts;

        std::cout << "[Scanner] Scanning " << subnet << ".0/24. My IP: " << my_ip << "\n";

        if (!my_ip.empty()) {
            std::string my_mac = GetInterfaceMac(my_iface);
            hosts.push_back({my_ip, my_mac, "My Computer (Local)", true});
        }

        std::vector<std::future<void>> tasks;
        for (int i = 1; i < 255; ++i) {
            std::string target = subnet + "." + std::to_string(i);
            if (target == my_ip) continue;
            tasks.push_back(std::async(std::launch::async, [target, &hosts, &mtx]() {
                if (Ping(target)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500)); 
                    
                    std::string mac = GetMacFromArp(target);
                    std::lock_guard<std::mutex> lock(mtx);
                    hosts.push_back({target, mac, "Discovered Device", true});
                }
            }));
        }

        for (auto &t : tasks) {
            t.get();
        }

        return hosts;
    }
}